/***************************************************************
 * icmp_client.c
 * Basit ICMP (Echo Request) paketi gönderen ve yanıtları dinleyen örnek
 ***************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

// Basit bir Ethernet header tanımı.
// Bu struct, Ethernet seviyesindeki kaynakh hedef MAC adreslerini
// ve üst protokol tipini tutar. 
struct ethheader {
    unsigned char h_dest[ETH_ALEN];   // Destination MAC adresi
    unsigned char h_source[ETH_ALEN]; // Source MAC adresi
    unsigned short h_proto;           // Ethernet çerçevesindeki protokol türü (IP, ARP vs.)
};

// ICMP mesajlarında kullanılan checksum fonksiyonu.
// IP ya da ICMP başlığındaki verileri alıp toplar, 16 bitlik bir çıktı döndürür.
unsigned short calculate_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    // 16 bitlik verileri tek tek toplayıp elde edilen toplama göre bir checksum üretir.
    for (; len > 1; len -= 2) {
        sum += *buf++;
    }
    // Eğer uzunluk tek bayt kalmışsa onu da ekler.
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    // Yukarıya taşan 16 bitlik parçaları toplama ekler.
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    // Tüm toplama sonucunun bitwise NOT'u nihai checksum değeri olur.
    result = ~sum;
    return result;
}

// Belirtilen ağ arayüzünün (device) MAC adresini çekmek için kullanılır.
// Socket üzerinden SIOCGIFHWADDR ioctl'i ile MAC adresi öğrenilir.
void get_mac_address(const char *device, unsigned char *mac) {
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // MAC adresi ifr.ifr_hwaddr.sa_data içerisinde yer alır, ETH_ALEN=6 baytlık bir diziye kopyalanır.
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(fd);
}

// Belirtilen ağ arayüzünün (device) IP adresini öğrenmek için kullanılır.
// SIOCGIFADDR ioctl çağrısıyla interface IP adresi çekilir.
void get_ip_address(const char *device, char *ip_address) {
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // ifr_addr kısmını sockaddr_in'e cast edip sin_addr değerini alıyoruz.
    struct sockaddr_in *ip = (struct sockaddr_in *)&ifr.ifr_addr;
    strcpy(ip_address, inet_ntoa(ip->sin_addr));
    close(fd);
}

/**
 * ICMP Echo Request paketi oluşturarak gönderir.
 * Şu anda hedef IP: "192.168.1.1" olarak sabitlenmiştir.
 * (İsterseniz argv[2] üzerinden alabilir veya kodda değiştirebilirsiniz.)
 */
void send_icmp_packet(pcap_t *handle, const char *device) {
    // Göndereceğimiz paketi saklayacağımız bir buffer: 1500 byte
    unsigned char packet[1500];
    memset(packet, 0, sizeof(packet));

    // Gönderici MAC ve IP adreslerini alalım
    unsigned char src_mac[ETH_ALEN];
    get_mac_address(device, src_mac);

    char src_ip[INET_ADDRSTRLEN];
    get_ip_address(device, src_ip);

    // Ethernet header yapısını packet'in başlangıcına koyuyoruz
    struct ethheader *eth = (struct ethheader *)packet;
    // Hedef MAC olarak broadcast adresi (FF:FF:FF:FF:FF:FF) kullanıyoruz
    // (pratikte unicast yapmak için ARP ile hedef MAC bulmak daha doğru olurdu).
    unsigned char dest_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(eth->h_dest, dest_mac, ETH_ALEN);
    memcpy(eth->h_source, src_mac, ETH_ALEN);
    // Ethernet header içindeki protokol alanı -> IP
    eth->h_proto = htons(ETHERTYPE_IP);

    // IP header'ı Ethernet header'dan sonra geliyor
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethheader));
    ip->version = 4;  // IPv4
    ip->ihl = 5;      // 5 x 32bit words -> 20 byte'lık IP header
    ip->tos = 0;
    // Toplam IP uzunluğu = IP başlığı (20) + ICMP başlığı (8) + 4 byte veri
    int icmp_data_len = 4; 
    int ip_total_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + icmp_data_len;
    ip->tot_len = htons(ip_total_len);
    ip->id = htons(1234);  // Rastgele bir ID
    ip->frag_off = 0;      // Fragment yok
    ip->ttl = 64;          // Time to Live
    ip->protocol = IPPROTO_ICMP;  // IP protokol numarası (ICMP=1)
    ip->saddr = inet_addr(src_ip);     // Kaynak IP 
    // Burada hedef IP sabit: 192.168.1.1
    ip->daddr = inet_addr("192.168.1.1");
    ip->check = 0;
    // IP header checksum'u hesaplayıp ip->check içine yaz
    ip->check = calculate_checksum((unsigned short *)ip, sizeof(struct iphdr));

    // ICMP header, IP header'dan sonra yer alır
    struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct ethheader) + sizeof(struct iphdr));
    icmp->type = ICMP_ECHO;  // Echo Request
    icmp->code = 0;          // Code = 0
    icmp->un.echo.id = htons(0x1234);     // Rastgele ID
    icmp->un.echo.sequence = htons(1);    // Rastgele sequence
    icmp->checksum = 0;                  // Başlangıçta 0

    // ICMP verisi (4 byte örneği) header'dan hemen sonra koyuluyor
    unsigned char *data = (unsigned char *)icmp + sizeof(struct icmphdr);
    data[0] = 'T'; 
    data[1] = 'E'; 
    data[2] = 'S'; 
    data[3] = 'T';

    // ICMP header + veri uzunluğu (8 + 4=12 byte)
    int icmp_len = sizeof(struct icmphdr) + icmp_data_len;
    // ICMP checksum hesaplanıp icmp->checksum alanına yazılır
    icmp->checksum = calculate_checksum((unsigned short *)icmp, icmp_len);

    // Artık paketi pcap_inject ile kabloya (veya arayüze) enjekte edelim
    if (pcap_inject(handle, packet, sizeof(struct ethheader) + ip_total_len) == -1) {
        pcap_perror(handle, "pcap_inject");
    } else {
        printf("[CLIENT] ICMP Echo Request sent to %s\n", "192.168.1.1");
    }
}

/**
 * pcap_loop için callback fonksiyonu:
 * Gelen paket IP+ICMP mi bakar, eğer Echo Reply ise ekrana log basar;
 * aksi halde "ICMP (type, code) received" şeklinde yazdırır.
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)header; // header kullanılmıyor, bu satır warning engellemek için
    pcap_t *handle = (pcap_t *)args;

    // Ethernet header'ı packet'in başında
    struct ethheader *eth = (struct ethheader *)packet;
    // Ethernet protokolü IP mi diye kontrol ediyoruz
    if (ntohs(eth->h_proto) != ETHERTYPE_IP) {
        // IP değilse bu paketi yok say
        return;
    }

    // IP header, Ethernet header'dan sonra gelir
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethheader));
    // Protokol ICMP mi (ip->protocol == 1)?
    if (ip->protocol != IPPROTO_ICMP) {
        // ICMP dışında bir protokolse yok say
        return;
    }

    // ICMP header, IP header'dan sonra
    int ip_header_len = ip->ihl * 4;
    struct icmphdr *icmp = (struct icmphdr *)((unsigned char*)ip + ip_header_len);

    // Eğer aldığımız paket bir ICMP Echo Reply ise:
    if (icmp->type == ICMP_ECHOREPLY) {
        // Kaynak IP adresini ekrana yazalım
        struct in_addr src_addr;
        src_addr.s_addr = ip->saddr;
        printf("[CLIENT] ICMP Echo Reply received from %s\n", inet_ntoa(src_addr));

        // İsterseniz burada Round Trip Time (RTT) hesabı vs. yapabilirsiniz.
        // Tek paketten sonra pcap_loop'u sonlandırmak için:
        pcap_breakloop(handle);
    } else {
        // Echo Reply haricindeki ICMP tipleri (Destination Unreachable, Time Exceeded vb.)
        struct in_addr src_addr;
        src_addr.s_addr = ip->saddr;
        // Burada tip ve kod'u ekrana basarak hangi ICMP mesajı geldiğini görebiliriz
        printf("[CLIENT] ICMP (type=%d, code=%d) received from %s\n", 
               icmp->type, icmp->code, inet_ntoa(src_addr));
    }
}

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devs, *d;
    pcap_t *handle;
    char *dev = NULL;

    // 1) libpcap ile sistemdeki tüm ağ arayüzlerini bul (pcap_findalldevs)
    // errbuf, hata mesajlarını tutmak için kullanılır
    if (pcap_findalldevs(&all_devs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs() error: %s\n", errbuf);
        return 1;
    }

    // 2) Kullanıcı bir arayüz ismi vermişse onu al, yoksa ilk bulduğu arayüzü seç
    if (argc > 1) {
        dev = argv[1];
    } else {
        dev = all_devs->name; // ilk bulduğumuz device
    }

    printf("[CLIENT] Using device: %s\n", dev);

    // 3) pcap_open_live ile seçilen arayüzü aç
    // Bu arayüzden gelen paketleri yakalayacağız (snaplen=BUFSIZ, promiscuous=1, read_timeout=1000)
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        pcap_freealldevs(all_devs);
        return 1;
    }

    // 4) İsteğe bağlı: ICMP filtre kuralı derleyip uygula
    // Böylece sadece ICMP paketleri yakalanacak.
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net, mask;
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }
    // Filtre ifadesini derle
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "pcap_compile error: %s\n", pcap_geterr(handle));
    } else {
        // Derlenmiş filtreyi uygula
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "pcap_setfilter error: %s\n", pcap_geterr(handle));
        }
        pcap_freecode(&fp);
    }

    // 5) ICMP paketini gönder (Echo Request)
    send_icmp_packet(handle, dev);

    // 6) Gelen yanıt paketlerini yakalamak için pcap_loop kullan
    printf("[CLIENT] Listening for ICMP replies...\n");
    pcap_loop(handle, -1, packet_handler, (u_char*)handle);

    // Herhangi bir nedenle pcap_loop bittiğinde, kaynakları serbest bırakalım
    pcap_close(handle);
    pcap_freealldevs(all_devs);

    return 0;
}

