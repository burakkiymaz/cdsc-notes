# CDSC Notları

> 14 Temmuz
## Ağ mimarileri

**Gopher:** Bir index sayfası şeklinde açılan ve ağaç üzerinde çalışılan sistem.

**ARPA:** Advanced Request Project Agency

### Katmanlar arası iletişim
```
               |Başlık|........|CRC|
        |Başlık|        ...        |CRC|
 |Başlık|               ...            |CRC|
```

---

- **Ethernet:**
    - MAC protokolü kullanır.
    - CSMA/CD (Carrier Sense Multiple Access Collision Detection) Ortam erişim denetimi kullanır.
    - **Preamble:** 7 byte, Çerçeve ayracı (frame delimiter) : 1 byte
    - **Hedef adres:** Alıcının 48 bitlik MAC adresi
    - **Kaynak adres:** Göndericinin 48 bitlik MAC adresi
    - Çerçeve türü: 2 byte
    - Veri
        - En az 46 byte
        - En fazla 1500 byte
    - 4 byte CRC (Cyclic Redundancy Check) veri bütünlüğü kontrolü yapılır.

tür | açıklama
----|---------
0800|IP veri bloğu
0806|ARP(28 byte) + Dolgu
0808|RARP (28 byte) + Dolgu

**/etc/protocols**: Kullanılabilecek tüm protokollerin bulunduğu dosya.

---

- **Switch**
    - HUB ın daha gelişmiş versiyonudur.
    - Hangi ucunda hangi MAC adresli istemci bulunduğuna dair bir tablo tutar.
    - Kendisine gelen bir çerçevenin hedef adrsine bakarak ilgili uca gönderir.
    - Eğer hangi uca gideceği bilinmiyorsa hepsine gönderir.
    - Uzaktan yönetilebilir.
- **Repeater**
    - Uzak mesafeli iletişim için kendisine gelen fiziksel sinyaller güçendirerek diğer ağ parçasına yollar.
- **Köprü**
    - İki farklı ağ yapısını birbirine bağlamak için kullanılır. (Örneğin Ethernet veya Token ring)
- **Güvenlik Duvarı (Firewall)**
    - OSI nin 2 ve daha yukarı katmanlarında çalışır.
    - Üzerinden geçen trafiği kontrol eder.
    - Belirlenen politika uyarınca yazılacak olan kurallara göre üzerinden trafiğin geçisini engelleyebilir/müsade edebilir.
- **Sanal ağlar (VLAN)**
    - 802.1q standardına sahiptir.
    - Switch i mantıksal olarak ayrı switchlere bölmemizi sağlar. (Örneğin switche 0..3 portu 4..5 portu ile iletişim kuramasın diyebiliriz.)
- **Özel Sanal Ağ (VPN)**
    - İnternet üzerinde iletişimde bulunan iki noktanın şifreli olarak birbirleri ile görüşmeleridir.

**TCP/IP Katmanları**

 4|Uygulama katmanı
---|---
3|İletim katmanı (TCP)
2|Ağ katanı (IP)
1|Ağ erişim katmanı (MAC)

---

`ifconfig eth0 mtu 1490` komutu gönderilecek maksimum veri boyutunu 1490 olarak değiştirmemizi sağlar. Bu değeri düşürürsek sıkıntı olmaz fakat yükseltirsek 1500 ile alan alıcılar için sıkıntı olacaktır.

---

Diyelim bilişim güvenliği departmanında sniffer geliştiriyoruz. Eğer biz bu sniffer ı gizlemek istersek sniffer ı down tutup active olduğu için kendini ele vermeyecektir.

## ARP ve RARP protokolleri

### Ethernet/IP iletişimi
- **ARP**

Her işletim sistemi bir ARP tablosu tutar. Bu tablo Hangi MAC adresi hangi ip adresi ile eşleştirildiğini tutar. ARP yayını yapılırken yayın yapacak bilgisayar Source IP, Source MAC ve Dest. IP adresini verir ve Dest MAC adresi olarak `FF:FF:FF:FF:FF:FF` kodlayarak gönderir. Bu MAC adresini gören swtich broadcast yapar. O IP adresine sahip cihaz MAC adresini gönderir ve eşleşme tamamlanmış olur bundan sonra bu ip adresi ile iletişime geçileceği zaman yeniden broadcast yayını yapmadan bu mac adresi ile iletişime geçilir.

ARP tablosuna statik olarak ARP bilgisi girilebilir (`tcpdump -s` ile) Bu durumdan sonra bu cihaza ARP sorgusu gönderilmeyecektir. Fakat eğer diğer cihaz bağlanmak isterse ARP sorgusu yapmalı ya da o cihaza da statik olarak girilmeli

- **RARP (Reverse ARP)**

MAC adresi bilinen fakat IP adrsi bilinmeyen cihazlar için kullanılır. Mesajı gönderen MAC adresi olarak gönderen makinenin MAC adresi, mesajın alıcı olan MAC adresi olarak ise tüm cihazlara yayın (broadcast) adresi olan `FF:FF:FF:FF:FF:FF` yazılır.


## Alt Ağlar
Uygun Alt ağ maskeleri (Subnet Mask) verilerek ağları daha küçük alt ağlara ayırabiliriz.

Örneğin;
`192.168.2.1` ağına `255.255.255.128` alt ağ maskesini verirsek bu ağı 2'ye ayırmış oluruz.
Bunun mantığını ise subnet mask ın bitlerine bakarak anlayabiliriz.

Subnet Mask | Bit Dağıtımı | kısa tanımı ('1 Biti sayısı')
---|---|---
255.255.255.0|11111111.11111111.11111111.00000000| /24
255.255.255.128 | 11111111.11111111.11111111.10000000| /25
255.255.255.192 | 11111111.11111111.11111111.11000000|/26
255.255.255.224 | 11111111.11111111.11111111.11100000|/27

---

Eğer paket parçalanıyorsa her parçaya bir IP header kopyalanır. Son parçası hariç tüm parçacıklara "Bölüm devamı" bayrağı konur.

---

* Kaynak ve hedef adrsleri: `127.0.0.1`
* Bilgisayar açılışta kendine `0.0.0.0` adrsini verir.
* Broadcast IP adresleri: `255.255.255.255`

`ping -b 255.255.255.255` komutu o ağda bulunan bütün bilgisayarlara broadcast yayını yapar ve o ağdaki bilgisayarlar bu broadcast a cevap verir.

---

Linux üzerinde `/usr/include/linux/ip.h` dosyası ip header bilgilerini yazmayı sağlayan struct yapıyı tutar.

`proc/sys/net/ipv4/ip_forward` dosyasına 1 yazıldığı zaman gateway e dönüşür. Sistemi yeniden başlatınca uçar.

- Noktadan Noktaya Yönlendirme
    - Dağıtım ile ilgili bilgiler yönlendirme tablosunda tutulur.

Hedef | Ağ geçidi | Ağ Maskesi | Bayraklar | Arayüz
---|---|---|---|---
192.140.236.44|0.0.0.0|255.255.255.255|UH|eth0
192.140.236.0|0.0.0.0|255.255.255.0|U|eth0
127.0.0.1|0.0.0.0|255.0.0.0|U|lo
0.0.0.0|192.140.236.1|0.0.0.0|UG|eth0

Bayraklar
- U (up) Yönlendirme çalışıyor
- G (gateway) Hedef bir ağ geçidi
- H (host) Hedef bir bilgisayar
- D Yönlendirme bir tekrar iletim mesajı ile oluşturuldu
- M Yönlendirme bir tekrar mesajı ile değişti.

## Port

ip adreslerindeki kapı olarak tanımlanabilir.

- **UDP (17)**
    - Bağlantsız
    - Güvenilmez
    - hızlı

Soru cevap  mekanizmaları ile çalışan uygulamalar ile kullanılabilir. (DNS, NFS, vs.)

- **TCP (6)**
    - Bağlantı devamlı
    - güvenilir.
    - UDP ye oranla yavaş bir iletim ortamı sağlar.
    - Verinin
        - iletimi
        - bütünlüğü
        - varıp varmadığını kontrol eder.


`tcpdump -s0 -enAvi en0 port 80` komutunu çalıştırınca bizim bilgisayarımız S(SYN) biti göndererek 80 nolu port ile iletişime geçileceğini söylüyor. Daha sonrasında 3way handshake tamamlanıyor.

`netstat -nt | grep ESTABLISHED` ile bakarsak bağlantının başarılı olduğunu görebiliriz.
1024 altı portlarda çalışan programlar root yetkisiyle çalışmaktadır.

- **ICMP (Internet Control Message Protocol)**

istemleri yanıtları veya hata mesajlarını içerebilir. IP paketinin ilk 8 byteını içerir.

**Traceroute** gidene kadar kaç makine var onu gösterir.

**Hping** uzaklığın ölçülmesini sağlar.

**Nmap**
- Port taraması yapmaya yarayan bir programdır. Ayrıca;
    - IP taraması
    - UDP Kapı taraması
    - TCP Taraması
    - İşletim sistemi parmak izi alma işlemlerini de yapar

## TCP iletişiminin anatomisi

inetd üzerinde yzdığımız bir servis ile bizim belirlediğimiz bir port üzerinde çalışan bir script çalıştırabiliriz

**TCP mesajı bölümlendirilmez Uygulama mesajı parçalara ayrılır.**

TCP bölğmlendemeden uyugulama katmanının haberi olmaz iletişim katmanı tarafından yapılır.

- **TELNET Protokolü**

    - Uzaktan oturum açmaya yarar.
    - TCP tabanlıdır
    - 23. portta çalışır.
    - Çalışma mekanizması ise şöyledir;
        - İstemci sunucuya bağlanmak ister
        - Telnet sunucusu "login" görevini çalıştırır.
        - istemci kullanıcı ad parola gönderir.
        - Onaylama mekanizması doğrular ise kabuk açılır.
        - komutlar sunucuya çıktı olarak gönderilir.
    - Avantajları: hızlı, kullanımı ve kurulumu kolay
    - Dezavantajları: Kullanıcı adı ve parola açık gönderilir şifrelenmez. Dinlemeye ve ele geçirmeye açıktır.


### Rlogin
Telnet gibi ağ üzerindeki başka bir sunucuya uzakta bulunan bir başka makineden bağlantı sağlayan bir protokoldür. Telnet'e benzer şekilde çalışır ve aynı Telnet gibi veri alışverişini şifrelemez.

### FTP

Dosya iletişimi yapmaya yarar. Verilerin iletişimi farklı bir port ile yapılır.(Varsayılan olarak 20 ve 21. portları kullanır.)

### SSH

kullanıcıyı onaylamak için;
- parola
- kullanııcı anahtarı
- Kerberos
- Sunucu bazlı açık anahtar kullanır.

### SNMP BAsit Ağ protkolü
- UDP/TCP bazlıdır.
- 161-162 portunu kullanır.
- ürüm 1-2-3 şeklinde sürümleri var.
- en çok 1. sürümü kullanılır.

### DNS
Alan adı sistemi
- İsimlerden IP lere,
- IP lerden isimlere dönüşüm sağlar.

### DNS Sunucuları
- DNS Sunucuları DNS isteklerine cevap vermekle yükümlü olan sunuculardır.
- Kök sunucular hiyerarşinin en tepesinde olup,gelen sorguları dağıtmakla yükümlüdürler.
- Sunucu Türleri;
    - Birincil; Alanın esas sorumlusudur. Bilgileri diskten yükler.
    - İkincil; Yedek sunucudur. Bilgileri periyodik olarak birinci sunucudan alır.
    - Önbellekleme: Hiçbir alanın sorumlusu değildir. yalnızca sorgu sonuçlarını geçici olarak depolar.
    - Yönlendirici, hiçbir sorguya direk cevap vermez, gelen sorguları tanımlı olan bir sunucuya yönlendirir.
- Sonuçlar tekar kullanım maksadı ile bir süre saklanır.

### TFTP
Diskleri olmayan sistemler için işletim sistemi çakirdeki çekmek için kullanılır.

### BOOTP Protokolü

BOOTP genellikle bir bilgisayar açılıyorken önyükleme işlemi esnasında kullanılır. BOOTP yapılandırma sunucusu bir adres havuzundan her bir istemciye bir IP adresi tahsis eder. BOOTP yalnızca IPv4 ağları üzerinde taşınan User Datagram Protocol (UDP) kullanır.

### SMTP
- Basit posta iletim protokolü
- TCP Tabanlıdır.
- 25.portu kullanır.
- Sunucular arası posta transferini sağlar.
- SMTP Komutları;
    - HELLO <alan adı>
        - Bir oturum başlatmak için kullanılır.
    - MAIL FROM: < e-posta adresi >
        - iletilecek olan e-postanın gönderenini belirler.
    - RCPT TO: < eposta adresi >
        - epostanın ulaştırılacağı eposta hesabıdır.
    - DATA
        - Tek bir satırda "." karakteri ile biter.
        - Mesajın başlıklar dahil tüm içeriğidir.
    - QUIT
        - Oturumu sonlandırır.

## Fingerprint alma
### Aktif fingerprint
### Pasif fingerprint

## Siber Güvenlik Temelleri
### Karşınızdaki kim?
- Hacker
    - din/Irk
    - terör
    - rakip
- Bilinçsizlik
    - Eitimsiz personel hataları
    - Çalışanlar ve çalıştıkları yerler
- Art Niyet
    - işten kovulmuş kişi
    - Insider
    - Nefret ve intikam duygusu
- Malware
    - Hedef odaklı ise APT
    - Herhangi bir zararlı yazılım
    - Botnet

### Etkileri neler olabilir
- Finansal kayıplar
- Kurumun prestije uğraması
- Kurum işlerinin aksaması

### Süreç nasıl ilerlemeli
Tanımlama --> Analiz --> Aksiyon --> İzleme --> Kontrol

### iletişim kanalları
- Haberleşme
    - Whatsapp
    - Telegram
    - Signal
- Takip
    - IRC -- Önemli
    - Jabber
    - Forumlar
### Derin internet
- underground
- deep web
- dark web
### Derin İnternet Ağları
- Tor Network
- Choas Network

### Genel Kavramlar
- **Penetration Test:** Hacker ların kullandıkları teknik ve araçları kullanarak hedef sistemlere sızma girişimi
- **Pentester:** Penetration Test kavramını uygulayan kendini siber güvenlik alanında geliştiren kişi

### Sızma Testi Adımları
Biligi Toplama --> Zafiyet Keşfi --> İstismar Etme --> Yetki Yükseltme --> İzleri Silme

### Sizma Testi Metodolojileri
- OWASP
    - Web Güvenliği Testleri
    - Mobil Uygulama Güvenliği Testleri
    - IoT Güvenlik Testleri
- OSSTMM
