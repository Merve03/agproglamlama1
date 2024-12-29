# ICMP İstemci-Sunucu Uygulaması

Bu proje, ICMP (Internet Control Message Protocol) kullanarak basit bir istemci-sunucu iletişim uygulamasını göstermektedir.
Proje, ham paket (raw packet) programlama ve `libpcap` kütüphanesinin kullanımını içermektedir.

## Proje Hakkında

- **ICMP İstemci (icmp_client):**
  - ICMP Echo Request (ping) paketi oluşturur ve hedef IP adresine gönderir.
  - Gelen ICMP yanıtlarını (Echo Reply, vb.) dinler ve yorumlar.

- **ICMP Sunucu (icmp_server):**
  - Belirli bir ağ arayüzünü dinler ve gelen ICMP paketlerini yakalar.
  - ICMP Echo Reply, Timestamp Reply gibi yanıtlar üretir ve hata mesajlarını işleyebilir (Destination Unreachable vb.).

## Gereksinimler

- Linux (Ubuntu, Debian veya benzeri bir dağıtım)
- `gcc` derleyicisi
- `libpcap` kütüphanesi (kurulum talimatı aşağıdadır)

## Kurulum

### Gerekli Kütüphanelerin Kurulumu

```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev
```

### Derleme

Proje dosyalarının bulunduğu dizine gidin ve aşağıdaki komutları çalıştırın:

- **ICMP Sunucu Derleme:**
  ```bash
  gcc icmp_server.c -o icmp_server -lpcap
  ```

- **ICMP İstemci Derleme:**
  ```bash
  gcc icmp_client.c -o icmp_client -lpcap
  ```

## Kullanım

### 1. ICMP Sunucuyu Çalıştırma

Sunucu uygulamasını, ICMP paketlerini dinleyecek şekilde çalıştırın. Örnek:

```bash
sudo ./icmp_server enp0s3
```

- `enp0s3` yerine sisteminizdeki aktif ağ arayüzünün adını yazabilirsiniz (eth0, wlan0 vb.).

Sunucu şu mesajı gösterecektir:
```
[SERVER] Listening on device: enp0s3
[SERVER] Start capturing...
```

### 2. ICMP İstemciyi Çalıştırma

İstemci uygulamasını başlatın ve belirli bir hedefe ICMP Echo Request gönderin:

```bash
sudo ./icmp_client enp0s3
```

- Sunucu loglarında şu mesajları görmelisiniz:
  ```
  [SERVER] ICMP Echo Request received.
  [SERVER] ICMP reply (type=0) sent.
  ```

- İstemci tarafında şu mesajlar görünmelidir:
  ```
  [CLIENT] ICMP Echo Reply received from <hedef_IP>.
  ```

### 3. tcpdump ile Paketleri İzleme (Opsiyonel)

Canlı ICMP trafiğini izlemek için:

```bash
sudo tcpdump -i enp0s3 icmp -n
```

### 4. Ping Testi

Bir ping testi yaparak sunucuya ICMP Echo Request gönderip yanıtlarını doğrulayabilirsiniz:

```bash
ping <sunucu_IP_adresi>
```

## Test ve Senaryolar

### Temel Test
1. **Sunucuyu başlatın:** `sudo ./icmp_server enp0s3`
2. **İstemciyi çalıştırın:** `sudo ./icmp_client enp0s3`
3. **Ping testi yapın:** `ping <sunucu_IP_adresi>`

### Ek Testler
- Destination Unreachable (ICMP type=3)
- TTL Time Exceeded (ICMP type=11)
- Timestamp Request/Reply (ICMP type=13/14)

## Notlar

- Aynı makinede test yaparken kernel (Linux çekirdeği) seviyesi ICMP cevap mekanizması çakışabilir. Daha kesin test için:
  ```bash
  sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
  ```

## Lisans

Bu proje, eğitim amaçlı hazırlanmıştır ve açık kaynak olarak paylaşılmaktadır.
```

