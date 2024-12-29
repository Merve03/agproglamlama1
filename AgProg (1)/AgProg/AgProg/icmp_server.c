/***************************************************************
 * icmp_server.c
 * 
 * Gelen ICMP paketlerini dinleyen ve yanıtlayan basit "sunucu" örneği.
 *
 * Derleme:
 *   gcc icmp_server.c -o icmp_server -lpcap
 *
 * Çalıştırma:
 *   sudo ./icmp_server enp0s3
 *   (ya da hangi arayüzü dinlemek istiyorsanız onu parametre verin)
 ***************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

/* 
 * Bazı sistemlerde netinet/ip_icmp.h içinde ICMP_TIMESTAMP vb. tanımlar olmayabiliyor.
 * Yoksa kendimiz tanımlayalım:
 */
#ifndef ICMP_TIMESTAMP
#define ICMP_TIMESTAMP      13
#define ICMP_TIMESTAMPREPLY 14
#endif

/**************************************************************
 * ICMP "Timestamp" başlık yapısı.
 * Modern Linux'ta struct icmphdr'un altındaki union 'un' 
 * içerisinde .timestamp alanı yoktur.
 * Bu nedenle bu özel yapıyı kullanarak (cast edip)
 * timestamp alanlarını yönetiyoruz.
 **************************************************************/
struct icmp_ts_hdr {
    uint8_t  type;    /* 13 (Timestamp Request) veya 14 (Timestamp Reply) */
    uint8_t  code;    /* Genellikle 0 */
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
    uint32_t originate_timestamp;
    uint32_t receive_timestamp;
    uint32_t transmit_timestamp;
} __attribute__((packed));

/**************************************************************
 * Ethernet header yapısı
 * Bu struct, gelen/giden Ethernet çerçevesinde yer alan
 * kaynak ve hedef MAC adreslerini ve üst protokol tipini barındırır.
 **************************************************************/
struct ethheader {
    unsigned char  ether_dhost[ETH_ALEN]; // Hedef MAC adresi
    unsigned char  ether_shost[ETH_ALEN]; // Kaynak MAC adresi
    unsigned short ether_type;            // Üst protokolün türü (IP, ARP vs.)
};

/**************************************************************
 * Basit checksum fonksiyonu
 * ICMP veya IP başlıkları için 16 bitlik bir toplam alıp
 * bitwise NOT uygulanmış sonucu döndürür.
 **************************************************************/
unsigned short calculate_checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/**************************************************************
 * get_mac_address
 * Verilen 'dev' adlı arayüzün MAC adresini socket/ioctl aracılığıyla alır.
 **************************************************************/
void get_mac_address(const char *dev, unsigned char *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        exit(1);
    }
    // MAC adresi ifr.ifr_hwaddr.sa_data içinde ETH_ALEN (6) bayt olarak saklanır.
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(fd);
}

/**************************************************************
 * get_ip_address
 * Verilen 'dev' arayüzünün IP adresini (string formatta) döndürür.
 **************************************************************/
void get_ip_address(const char *dev, char *ip_str) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        exit(1);
    }
    // ifr.ifr_addr'ı sockaddr_in'e cast edip sin_addr kısmından IP'yi çekiyoruz
    struct sockaddr_in *ip = (struct sockaddr_in *)&ifr.ifr_addr;
    strcpy(ip_str, inet_ntoa(ip->sin_addr));
    close(fd);
}

/**************************************************************
 * Global değişken:
 * Bu sunucu hangi arayüzde çalışıyorsa ismini burada saklayacağız.
 **************************************************************/
static char g_device[IFNAMSIZ];

/**************************************************************
 * send_icmp_reply
 * 
 * Gelen ICMP paketine uygun şekilde (Echo Reply, Timestamp Reply 
 * veya hata mesajı) yeni bir Ethernet+IP+ICMP paketi oluşturup gönderir.
 **************************************************************/
void send_icmp_reply(
    pcap_t *handle,               // pcap handle (cihaz)
    const char *dev,             // hangi arayüz
    struct iphdr *recv_iphdr,    // gelen paketin IP header'ı
    struct icmphdr *recv_icmphdr,// gelen paketin ICMP header'ı
    const u_char *packet         // tam gelen paketin pointer'ı (Ethernet dahil)
) {
    // Yeni oluşturacağımız paket için bir buffer
    unsigned char buffer[1500];
    memset(buffer, 0, sizeof(buffer));

    // 1) Sadece ilk kez kaynak MAC ve IP'yi al (static init ile)
    static unsigned char my_mac[ETH_ALEN];
    static char my_ip_str[INET_ADDRSTRLEN];
    static int init = 0;
    if (!init) {
        get_mac_address(dev, my_mac);
        get_ip_address(dev, my_ip_str);
        init = 1;
    }

    // 2) Ethernet header
    // recv_eth: gelen paketin Ethernet header'ı
    struct ethheader *recv_eth = (struct ethheader *)packet;
    // send_eth: oluşturacağımız giden paket içindeki Ethernet header
    struct ethheader *send_eth = (struct ethheader *)buffer;

    // Gelen paketteki kaynak MAC -> yeni paketin hedef MAC
    memcpy(send_eth->ether_dhost, recv_eth->ether_shost, ETH_ALEN);
    // Kendi MAC adresimiz -> yeni paketin kaynak MAC
    memcpy(send_eth->ether_shost, my_mac, ETH_ALEN);
    // Ethernet protokol tipi -> IP
    send_eth->ether_type = htons(ETHERTYPE_IP);

    // 3) IP header
    // Yeni pakette Ethernet'ten sonraki kısımda IP header olacak
    struct iphdr *send_iphdr = (struct iphdr *)(buffer + sizeof(struct ethheader));
    send_iphdr->ihl = 5; 
    send_iphdr->version = 4;
    send_iphdr->tos = 0;
    send_iphdr->id = htons(54321);
    send_iphdr->frag_off = 0;
    send_iphdr->ttl = 64;
    send_iphdr->protocol = IPPROTO_ICMP;

    // Kaynak IP: Sunucunun kendi IP'si
    send_iphdr->saddr = inet_addr(my_ip_str);
    // Hedef IP: Gelen IP paketinin kaynak IP'si (yani paketi yollayanın IP'si)
    send_iphdr->daddr = recv_iphdr->saddr;

    // 4) ICMP header
    // IP header'dan sonra gelecek kısım. 
    // Boş bir icmphdr oluştur, sonra tipine göre dolduracağız.
    struct icmphdr *send_icmphdr = (struct icmphdr *)(buffer + sizeof(struct ethheader) + sizeof(struct iphdr));
    memset(send_icmphdr, 0, sizeof(struct icmphdr));

    // Verinin kaldığı alan; eğer orijinal paketten data kopyalayacaksak kullanacağız
    unsigned char *send_data = (unsigned char *)send_icmphdr + sizeof(struct icmphdr);
    int icmp_data_len = 0; // yanıt paketinde kaç byte ek data olacak

    // 5) Gelen paket tipine göre yanıt
    if (recv_icmphdr->type == ICMP_ECHO) {
        // ECHO REQUEST -> ECHO REPLY
        send_icmphdr->type = ICMP_ECHOREPLY; 
        send_icmphdr->code = 0;
        // ID ve sequence numarasını koru
        send_icmphdr->un.echo.id = recv_icmphdr->un.echo.id;
        send_icmphdr->un.echo.sequence = recv_icmphdr->un.echo.sequence;

        // Eğer gelen pakette ek data varsa onu da kopyalayalım
        int ip_header_len = recv_iphdr->ihl * 4;
        int icmp_len_in_recv = ntohs(recv_iphdr->tot_len) - ip_header_len;
        int icmp_header_len = sizeof(struct icmphdr);
        icmp_data_len = icmp_len_in_recv - icmp_header_len;
        if (icmp_data_len < 0) icmp_data_len = 0;

        // Gelen ICMP verisini (header'ın hemen sonrası) kopyala
        const unsigned char *recv_icmp_data = (const unsigned char *)recv_icmphdr + icmp_header_len;
        memcpy(send_data, recv_icmp_data, icmp_data_len);
    }
    else if (recv_icmphdr->type == ICMP_TIMESTAMP) {
        // TIMESTAMP REQUEST -> TIMESTAMP REPLY
        // Gelen paketi icmp_ts_hdr'e cast edelim
        struct icmp_ts_hdr *recv_ts = (struct icmp_ts_hdr *)recv_icmphdr;
        struct icmp_ts_hdr *send_ts = (struct icmp_ts_hdr *)send_icmphdr;

        send_ts->type = ICMP_TIMESTAMPREPLY; // = 14
        send_ts->code = 0;
        // ID ve sequence koru
        send_ts->id       = recv_ts->id;
        send_ts->sequence = recv_ts->sequence;
        // Originate timestamp (gönderenin doldurduğu)
        send_ts->originate_timestamp = recv_ts->originate_timestamp;
        // receive_timestamp ve transmit_timestamp olarak time(NULL)
        // (daha doğru RFC uyumluluğu için 24 saat modunda ms cinsinden doldurmak gerekir)
        send_ts->receive_timestamp  = htonl(time(NULL));
        send_ts->transmit_timestamp = htonl(time(NULL));

        // Timestamp header boyutu (icmp_ts_hdr), icmphdr'ın üstüne ek data sayılacak
        icmp_data_len = sizeof(struct icmp_ts_hdr) - sizeof(struct icmphdr);
    }
    else {
        // Diğer tiplere basitçe Destination Unreachable (type=3) gönderiyoruz.
        // code=0 -> Network Unreachable
        // Sizin projede isterler farklı olabilir, ama örnek olarak böyle bırakıyoruz.
        send_icmphdr->type = 3; 
        send_icmphdr->code = 0; 
        icmp_data_len = 0;
    }

    // 6) IP header'ın total length'i = IP header (20 byte) + ICMP header + data
    int send_icmp_len = sizeof(struct icmphdr) + icmp_data_len;
    int total_len = sizeof(struct iphdr) + send_icmp_len;
    send_iphdr->tot_len = htons(total_len);

    // IP checksum
    send_iphdr->check = 0;
    send_iphdr->check = calculate_checksum((unsigned short *)send_iphdr, sizeof(struct iphdr));

    // ICMP checksum
    send_icmphdr->checksum = 0;
    send_icmphdr->checksum = calculate_checksum((unsigned short *)send_icmphdr, send_icmp_len);

    // 7) Paketi gönder
    int packet_size = sizeof(struct ethheader) + total_len;
    if (pcap_inject(handle, buffer, packet_size) == -1) {
        pcap_perror(handle, "pcap_inject");
    } else {
        // Gönderdiğimiz paketin tipini ekranda gösterelim
        printf("[SERVER] ICMP reply (type=%d) sent.\n", send_icmphdr->type);
    }
}

/**************************************************************
 * packet_handler
 * 
 * pcap_loop tarafından her yeni paket geldiğinde çağrılacak callback.
 * Gelen paketin IP+ICMP olup olmadığını kontrol eder,
 * ICMP Echo ise "Echo Request received" der,
 * Timestamp vs. ise ayırt eder, 
 * Ve sonrasında yanıt göndermek için send_icmp_reply fonksiyonunu çağırır.
 **************************************************************/
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)header;  // header kullanılmıyor
    pcap_t *handle = (pcap_t *)args;

    // Ethernet header'ını al
    struct ethheader *eth = (struct ethheader *)packet;
    // Protokol tipi IP değilse çık
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return;
    }

    // IP header
    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethheader));
    // Protokol ICMP mi? (ip->protocol == 1)
    if (iph->protocol != IPPROTO_ICMP) {
        return;
    }

    // ICMP header
    int ip_header_len = iph->ihl * 4;
    struct icmphdr *icmph = (struct icmphdr *)((unsigned char*)iph + ip_header_len);

    // Kendi gönderdiğimiz Echo Reply paketlerini tekrar yakalayabiliriz; yok say
    if (icmph->type == ICMP_ECHOREPLY) {
        printf("[SERVER] (Ignoring our own Echo Reply)\n");
        return;
    }

    // Log için basit mesajlar
    if (icmph->type == ICMP_ECHO) {
        printf("[SERVER] ICMP Echo Request received.\n");
    } 
    else if (icmph->type == ICMP_TIMESTAMP) {
        printf("[SERVER] ICMP Timestamp Request received.\n");
    } 
    else {
        // Diğer ICMP tipleri
        printf("[SERVER] ICMP type=%d, code=%d received.\n", icmph->type, icmph->code);
    }

    // TTL kontrolü -> eğer TTL=1 veya daha düşükse "Time Exceeded" üretmeyi gösterebilirsiniz
    if (iph->ttl <= 1) {
        printf("[SERVER] TTL=1, Time Exceeded (ICMP type=11) gönderebilirsiniz.\n");
        // Burada benzer şekilde send_icmp_reply veya özel bir fonksiyonla type=11 paket hazırlayabilirsiniz.
        return;
    }

    // Asıl yanıt oluşturma fonksiyonu
    extern char g_device[];
    send_icmp_reply(handle, g_device, iph, icmph, packet);
}

/**************************************************************
 * main
 * 
 * Komut satırından arayüz adı alınır (örn. enp0s3), 
 * pcap_open_live ile o arayüzde paket dinlenmeye başlanır, 
 * sadece ICMP paketleri için bir filtre uygulanır,
 * pcap_loop ile sonsuz şekilde packet_handler çalışır.
 **************************************************************/
int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = NULL;
    pcap_t *handle;

    // Argüman varsa onu al, yoksa pcap_lookupdev ile varsayılan arayüz
    if (argc > 1) {
        dev = argv[1];
    } else {
        dev = pcap_lookupdev(errbuf);
        if (!dev) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return 2;
        }
    }

    // Global değişkene kaydedelim (packet_handler içinden de erişeceğiz)
    strncpy(g_device, dev, IFNAMSIZ - 1);

    printf("[SERVER] Listening on device: %s\n", g_device);

    // pcap_open_live ile arayüzü aç, gelen paketleri yakala
    handle = pcap_open_live(g_device, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", g_device, errbuf);
        return 2;
    }

    // ICMP paketlerini dinlemek için bir BPF filtre yazalım
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net, mask;
    if (pcap_lookupnet(g_device, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }
    // Derle
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    // Filtreyi uygula
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    pcap_freecode(&fp);

    printf("[SERVER] Start capturing...\n");
    // Sonsuza dek paketleri yakala, her paket packet_handler fonksiyonuna gider
    pcap_loop(handle, -1, packet_handler, (u_char *)handle);

    // Döngü biterse (ör. Ctrl+C ile), kapatalım
    pcap_close(handle);
    return 0;
}
