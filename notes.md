# CDSC Notları
---

---

# Defensive
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

Hedef         |Ağ geçidi      |Ağ Maskesi     |Bayraklar  |Arayüz
--------------|---------------|---------------|-----------|-------
192.140.236.44|0.0.0.0        |255.255.255.255|UH         |eth0
192.140.236.0 |0.0.0.0        |255.255.255.0  |U          |eth0
127.0.0.1     |0.0.0.0        |255.0.0.0      |U          |lo
0.0.0.0       |192.140.236.1  |0.0.0.0        |UG      | eth0

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


## Uygulama Protokolleri
### DNS
Kök sunucular --  .

.__ com
|__ edu
|__ tr __ av
...  |___ com
     |___ edu
     ...

bir domaini okurken tersten bakmalıyız. Örneğin, burak.kiymaz.com.tr

. (kök sunucu) | tr sunucusu | com (tr sunucusuna bağlı com sunucusu) | kiymaz (domain) | burak (subdomain)
---------------|-------------|----------------------------------------|-----------------|------------------

32 bit sayılar ezberlenemediği için bunlar 4 oktet olarak düzenlenmiştir. Bunu da ezberlemek zor olduğu için bu 4 okteti alanadına çevirmişler.

bind - name.d

bir DNS server bir veya daha fazla zone u tutabilir. Bir istemci kendisine tanımlı olan nameserver ı `/etc/resolver.conf` dosyasında bulunur

bu dosyanın içerisinde;

```
nameserver [IPadresi]
nameserver [IPadresi]
```
şeklinde nameserver tanımları var

```
zone "bk.com"{
    type master; # master zone olduğunu söyler
    file "/etc/bind/db.bk.com" # bu zoneun ayar dosyasının yerini belirtir.
}

```

bu ayar dosyasında köklü bir ayar yapmamız gerekecekse mesela MX kaydı değiştirilecekse TTL değerlerini küçültmemiz gerekli. Bunun sebebi DNS kayıtları varsayılan olarak dünya genelinde 24 saatte yayılır. Biz bu değişikliği yaparak yaptığımız değişikliğin dünya genelinde daha hızlı yayılmasını sağlarız. Değişikliği yaptıktan sonra TTL değerini normale çekebiliriz.

```
nslookup
> server 8.8.8.8
> burakkiymaz.com
google ın serverlarında burakkiymaz.com u sorgular.
```
### telnetle mail gönderme

dig ile smtp ip adrsi bulunur.
```
telnet IPADRESI smtp
MAIL FROM: <mailadresi>
RCPT TO: <mailadresi>
DATA

From: Burak Kıymaz <mail adresi>
To: Birisi <mailadresi>
Subject: Deneme iletisi

Bu bir deneme

.

```
Bu şekilde mail atılabilir fakat spam ile mücadele amaçlı gönderici mail adresinin reverse kaydı var mı kontrol edilir. Eğer yoksa selamlamayı bile yapmadan işlem durdurulur.
SPF Kaydı (Domaine ait TXT kaydı) tutmuyorsa yine reject edilir. Bunu dışında henüz resmi olarak zorunlu olmayan DKIM kaydı bulunmakta. (Mailin header kısmına bakılırsa bu dkim public key i görülebilir.)

e postayı göndermek için <kbd>Enter</kbd><kbd>.</kbd><kbd>Enter</kbd> tuş kombinasyonu kullanılır.

### HTTP

(`telnet IPADRESI http` komutu ile bağlanabiliriz yine)

```
GET / HTTP/1.0 #kök sunucuyu istedik.
```

HTTP1.0 ile her domain adresine bir IP adresi verilebiliyordu. Zamanla burada bir ihtiyaç hissedildi ve HTTP1.1 icat edildi. Daha sonra burada `Host:` satırı ile bu bu subdomainlere ulaşılabilir.

```
telnet IPADRESI 80
Host: SITEADRESI
GET / HTTP1.1
```

CGI (Common Gateway Interface)

### SSH
SSH bağlantısı bir sunuucuya bağlanmanın dışında başka bir sunucuya yönlendirme amaçlı da kullanılabilir.

`ssh -L 22222:192.168.8.128:22 ubuntu@10.5.41.220` 22222. portu dinle (sondaki) ubuntu makinesi dinlenen porta kim gelirse gelsin 192.168.8.128 IP adresine sahip makinenin 22. portuna gitsin  (-L localde dinle -g ile çalışırsa global olarak Port forwarding yapar) local makineme aktar.

`ssh -p 22222 ubuntu1@10.5.153.180`
`10.5.153.180` -> -g ile paylaşan biligisayarın IPsi
`ubuntu1` -> o bilgisayarın ssh tunnel yaptığı bilgisayarın kullanıcı adı
`22222` -> port forwarding yapılan port numarası


#### Remote port forwarding

Bir server ın dışarıdan bir makine için ssh bağlantısı yönlendirme olayı.


## İşletim Sistemlerine Giriş

**İşletim Sistemi Nedir?** Kullanıcı ile donanım arasında bulunan arayüz.

Von Neumann modele göre işletim sisteminin 3 temel bileşeni var
- Porcessing unit
- I/O işlemleri
- Device

İşletim sistemi;
- doğru
- verimli
- kullnımı kolay olmalı

İşletim sistemi kaynak yöneticisidir.
Sistem kaynakları;
- CPU
- Memory
- Device


**Persistence**

Bir program yazıldığında kaydettiğimiz bir program dosyasını çalıştırdığımızda artık o program memory ye iner.

bir program içerisinde oluşturulan değişken ifadeler bellekte "Stack" alanında tutulur. Eğer `malloc` ile bir yer açıp o yere bakan bir pointer tanımlarsak `malloc`la aırdığımız kısım bellekte "heap" alanında tutulur, pointer ise "stack" alanında tutulur.

CPU üzerinde 3 tip çalışma sırası uygulanır:
- Önce gelen önce işler
    - Hangi işlem daha önce geldiyse daha önce işleme alınır.
- Kısa olan önce işler
    - İşlemlerin sürelerine göre işleme alınır ve önce en kısa işlem CPU dan faydalanır.
- Öncelikli olan önce işler
    - Önceliğe göre işleme alınır fakat burada bir sorun var sisteme önceliği yüksek fazla miktarda işlem gelebilir ve önceliği düşük olan işlemler CPU laynaklarından faydalanamayabilir

**Concurrency**

Aynı anda farklı işler yapma işlemine veriilen isim. Diğer adıyla paralelleme
paralelleme için 2 kural var.
- Data paralelleme
- Task paralelleme

Yazdığımız bir kodu OpenMP kullanara paraleleştirebiliriz.

`#pragma omp parallel` eğer bir for döngüsünü threat lere bölmek için`#pragma omp parallel for` deriz.

bu işlemi elimizle yapmak istersek **pthreat** kullanılabilir. Fakat bunu da bir sorunu var. Bir işlem shared değişken üzerinde birden fazla sürekli kontrol edildiği için boş CPU cycle harcar. Eğer zaman önemli değilse bu fonksiyonun yerine **Mutex** kullanılabilir. Mutex ise eğer işleyeceği deişken kilitli ise uyur ve işletim sistemini onu uyandırmasını bekler.


Semafor(Semaphore) mantık olarak mutex e daha çok benzer. Ama daha çok birden fazla paylaşımlı değişkenimiz varsa kullanılır. Biri üretiyor, biri tüketiyor mantığına dayanır. Mutex e benzemesinin sebebi işlem yapmayan threat uyur ve işletim sisteminin uyandırmasını bekler

**Barriers**, tüm işlemlerin belirli bir noktaya geldiğini teyit etmek için kullanılır.

**Persistence**
- IPC
- Filesystem
- I/O


## Linux 1

Yeni bir Linux dağıtımı yapmak için **linux from scratch** kullanılabilir.

**/etc/login.defs** dosyası ile default kullanılan şifleme algoritmasını ayarlayabiliyoruz. **SHA512** kullanılabilecek en iyi şifreleme algoritması

**johntheripper** basit şifreleri kırmaya yarayan bir uygulama

Özellikle apache üzerinde erişilen `/etc/passwd` dosyalarını `john /temp/test_pass` şeklinde verdiğimiz zaman şifreler kırılabiliyor. (Eğer kolay bir şefre koyulmuşsa)

Redhat üzerinde root kullanıcısını kısıtlamak için SELINUX (`/etc/selinux/config`) kullanılır.

`/etc/profile` içerisinde yapılan düzenleme tüm kullanıcılar için geçerli olur. Fakat bu doğru bir yöntem değildir. `/etc/profile.d` içerisinde bir dosya oluşturmak daha mantıklı.

**ldd** - print shared object dependencies

`export LD_LIBRARY burakkiymaz ` binary ler için `burakkiymaz` dizininin altına bak demek. Bu sadece o terminal oturumu için geçerlidir.

`ps -aux` - `/proc` dizinini analiz ederek çalşan uygulamaları gösterir.

`lsof` : ls openfile diyebiliriz


eğer temp dizinini ayrı bir partition olarak mount edersek noexec olarak mount edersek orada bir program çalıştırıldığı zaman permission denied hatası alacaktır. Fakat buraya burada programlar çalıştrılabilir dosyalarını kopyaladığı için sistem hata verebilir.

 kullanıcı UID leri 1000 ile başlar. root ise 0 dır.

---
**&** - stdout ve stderror çıktılarını temsil eder.

**1** - stdout

**2** - stderror

**/dev/null** karadelik

---
Otomatik oluşturulacak görevler `/etc/cron.d` dizini altında tutulması daha iyidir.
crondaki tüm programların çıktıları bir yere yönlendirilmezse root kullanıcısına mail olarak atılır. Fakat bu bizim istediğimiz bir şey değildir. Bunu örneğin `bk.sh &>> /tmp/bk-log.log` şeklinde log olarak tutulabilir.

`last` hangi kullanııcının ne zaman girdiğini gösteren bir komut

**puppet** Configuration manager

**ac4** birden fazla mainede cron yönetimini sağlar

**nbtscan** bulunulan networkte hangi makineler var onu taramayı sağlıyor.

**nmap** standartlaşmış ağ tarama programıprogram.

**hpnig3** header bilgileri değiştirilmiş paket gönderimine kadar bir çok işi yapan bir program.

**netcat (nc)** TCP - UDP bağlantı dinleme aracı
```bash
nc -l -vvv -p 7777
```
`-vvv` (verbose mode) porta yapılan erişimler ile bilgileri verir.

### dig

dig +short burakkiymaz.com -> nameserver ip adresini verir.
dig +short NS burakkiymaz.com @8.8.8.8 -> google sunucusuna bu alan adının NS kayıtlarını sorar.

### tcpdump

- `tcpdump -D` kullanılabilecek network arayüzlerini gösterir.
    - `-s0` gelen tüm paketleri al (size bilgisi)
    - `ip src IPADRESI` bu ip adresinden bağlantı geliyor mu
    - `-w test.pcap` test.pcap olarak kaydet

## Linux Güvenliğine Giriş

### Sistem sıkılaştırması
Bilgisayar sistemlerinin güvenliğinin artırımasına sistem sıkılaştırması (system hardening) denir.

**sysctl -a : kerneldeki tüm ayarlanabilir değişkenleri verir. Buradaki ayarlar sistem açılışında kontrol edilir.**


#### Fiziksel Güvenlik
- Sistem kilitleri
- BIOS Şifrelemesi
- Bootloader Güvenliği
- USB Sürücü engellemesi
- GRUB Şifrelemesi

#### Disk Güvenliği
- Disklerin şifrelenmesi
    - Disklere kaydedilen veriler şifrelenebilir.
- Disklerin sonradan şifrelenmesi
    - cryptsetup programı kullanılabilir.
- Disklerin güvenli mount edilmesi

#### Dosya Güvenliği
- Dosya İzinleri
- "777" li dosyaların taranıp düzenlenmesi
  ```
  `find /var/ -type f -perm 777 -exec chmod 644 {} \;`
  ```
- .host dosyaşarın bulunması
- SUID ve SGUID bitleri aktif dosyaların bulunmaması
- UMASK değerleri

#### Kullanıcı Güvenliği
- Kullanıcı şifresi olmayan kullanıcılar
- root harici UIDsi 0 olan kullanıcıların tespiti
- Şifre politikası (`login.defs` ile şekillendriilebilir.)
- Kullanıcı kaynak tüketiminin sınırlanması (`/etc/security/limits.conf`)
    - user1 hard core 0
    - user1 hard nproc 50
    - user1 hard rss 5000
- `~/.bashrc` dosyası aracılığıyla dosyaların düzenlenmesi
- Kullanıcı bazlı kota uygulamaları
    - `fstab` ile `usrquota` ve `grpquota` özelliklerini ekler ve yeniden bağlarız
- Dosya boyutu kotası ve limiti
- Dosya sayısı kotası
- Root güvenliği
- Terminalden root erişiminin kapatılması
- Silme işlemleri için parola koruması
- PAM modülü (kernel seviyesinde kimlik denetleme işlemi yapar.)
- SU kullanımının kapatılamsı
- `/etc/sudoers.d` altında bir dosyaya sudo yetkisi vereceğimiz kullanıcıyı barındıran bir dosya atılabilir.

#### IP Tables Sıkılaştırması

- IP Tables Rate Limiting
    - tek bir IP adresinden apachenin 80. portuna gelen 20 den fazla istekte o IP adresini bloklar
- IP Tables Limit Burst
    - 6 saniye içerinde fazla miktarda SYN paketi gelirse loglanır.
- IP Tables BOOYER MOORE Algoritması
    - wget kullanan saldırganları engellemek için IP Tables'a koruma mekanizması uygulanabilir.
- Local File Inclusion
    ```
    iptables -t filter -I INPUT -m string -string "passwd" -algo -m -j drop
    ```
- Ping yanıtını kapatma
- Başka işletim sistemlerine ping atıldığı zaman TTL değerine göre işletim sistemi tahmin edilebilir.
- TCP Wrappers kullanımı
    - Kullanılacak servislere kısıtlama getirmek için kullanılır.
- SYSCTL dosyasında gerekli önlemlerin alınması
    - Ipv4 routing engelleme (`net.ipv4.ip_forward = 0`)
    - Ip spoofing engellemek için (`net.ipv4.conf.default.rp_filter = 1`)
    - ip v6 üzerinden erişimi kapatmak

#### SSH Sıkılıştırması
- root kullanıcısının root erişimini kapatmak için
    ```
    cat /etc/ssh/sshd_config

    ...
    PermitRootLogin = no
    ...

    service sshd reboot
    ```
- `scponly` : kullanıcılara ssh erişimi vermeden sftp üzerinden dosya paylaşımı yapılabilir.
- Google authenticator kulanımı ile 2 aşamalı kullanıcı denetimi
- Ard arda login fail olmuş kullanıcıları engelleme
- **Kippo**: ssh servisi için hazırlanmış bir honeypot tur.

#### Apache Sıkılaştırması
- `httpd.conf` içerisinde versiyon hakkında bilgi vermesini kapatabiliriz.
- `keep alive off` olması gerekiyor.

#### PHP Sıkılaşması
- `disable_funtions`ları eklemezsek sunucuya sızdırılan shell ve scriptler çalıştırılabilir.
- php versiyonu görinmemesi için `expose_php = off` yapılamalı
- PHP de gösterilen hatalar kapatılmalı

#### Gereksiz servisler kapatılmalı
- `chkconfig --list` sunucu tarafıdna gereksiz servislerin taspiti

#### Rootkit taraması
- Linux sistemler içerisinde çalışan zararlı bir yazılmdır.
- netstattan bakıldığında kapalı görünür fakat açıktır. Aynı şekilde işlem yaptığını da gizleyebilir.

#### Virüs Taraması
- ClamAV virüs Tarama yazılımı (OpenSource)

#### CHROOT Yapılanamsı
- `chroot`: risk teşkil eden bir yazılımı izole bir ortama almamızı sağlar.

`resolve.conf` üzerinde 127.0.0.1 yazabilir fakat `dnsmasq` ile dns sorgusu yönlendiriliyor olabilir.

bir inteface in ip sini yok etmek için `ifconfig [INTERFACE_ADI] 0.0.0.0` komutu kullanılabilir.

`pstree` ps çıktısını parent ve child processleri gösterir.

---

## Windows Fundamentals

ilk defa 1985 yılında Windows 1 olarak piyasaya çıkmış.
Windows 3.1 text based den çıkıp ile bir arayüze sahip olmuş.

Varsayılan olarak gelen `Adminstrator` kullanıcısı bulunur.

Her dosyanın bir `archive bit`i vardır. Bu bit o dosyanın yedeğinin alınıp alınmadığını gösteren bittir. Windows işletim sistemleri birbiri üzerinden iletişim kurmak için "Remote Prosedure Call" (RPC) Prosedürünü kullanır. Remote Registry ile karşı taraftaki makinenin Registry dosyasına ulaşılabilir düzenlenebilir. RPC servisi kullanılmayacaksa kapatılmalıdır. (`Computer Management > Services and Appliaitons > Services`)

Bir paylaşım alanı sonuna "`$`" işareti konularak paylaşılırsa gizli olarak paylaşılmıştır fakat yine de ulaşılabilir. Bu alanlar yetki olarak sadece ADMIN kullanıcılarının erişebileceği bir alandır.

Güvenlik için paylaşımlı alanlar kapatılabilir.

**Task Scheduler** - Linux üzerindeki cron gibi düşünülebilir.

`Event Viewer/Windows Logs/System` : Burada belirlenen bir hafıza boyutunca log toplanır. O belirlenen boyut dolunca üzerine yazar. `Log Forwarding` ile bilgisayarda oluşan logları başka bir Windows sunucuda toplama imkanı sunar.

`C/ProgramData`: Programların geçici olarak dosya yazdığı alanlardır.

Dosya isimlerinin mavi olması işletim sistemi seviyesinde sıkıştırma yapıldığını gösterir. Yaşil olması ise encrypted oluğunu gösterir. Başka bir makine işletim sistemi veya makine tarafından okunamaz.

Windows'un sistem dosyaları `C/Windows/System` dizini altında tutulur. Antivirüs programları bu dizindeki bütün dosyaları kontrol eder. Buradaki bütün dosyaların Windows tarafından imzalanmış olması gerekmektedir. Eğer aksi bir durum fark ederse bunu virüs olarak kabul eder.

`C/Windows/System32/drivers` dizini driverların oluşturduğu dosyaları barındırır. Antivirüs programları burayı da konrol eder ve bütünlüğünü korumaya çalışır.


cmd üzerinde `net \\10.5.5.5 start` komutu RPC üzerinden başka bir makinede oturum açmayı sağlar.

### Active Directory
Windowsun tercih edilmesinin en önemli sebebidir. Bir dizin ile o sisteme bağlı tüm bilgisayarlardaki sistem ayarları düzenlenebilir.

#### Domain
- Boundary of security
- Authentication
- Replication
- DNS Namespace
- Administration

#### Trees
- Domain şeması (birnevi database)
- Domainler arası iletişim
- Domainler arsı iletişimde
    - Şema
    - Configuration
    - Global Catalog
#### Forests
ağaçlar arası iletişim yapısı

#### Organizational unit
kullanıcı isimleri, bilgisayar veya politikalar bulundurur.

#### Domain Controller (DC)
Bir domainda birden fazla DC olabilir. KMS (Key Managemet Service) burada çalışır.

**Primary Domain Controller**: domainin ilk kurulduğu bilgisayar. PDC altındaki bilgisayarlar DC bilgilerini buradan alır.

### Group Policies
İşletimi sistemi seviyesinde standart configuration yapmamızı sağlar.
tutarlı bir masaüstü ayarlayabiliriz.

### Local Computer Policy
Bilgisayar üzeindeki politikaları tanımlar. Eğer bilgisayar açılışında veya kapanışında belirli bir script çalıştırmak istersek `Local Computer Policy/Computer Configuration/ Windows Setting/Scrpits` kısmına ekleyebiliriz. İşletim sisteminin desteklediği tüm dillerde scriptler eklenebilir. Fakat genel olarak **Batch, Visual Basic, Powershell** dilinde yazılabilir.

Kullanıcı bazında bazı scriptler çalıştırmal istersek "`logon - logoff`" kısmına ekleyebiliriz. Buraya eklenen scriptler kullanıcı haklarıyla çalıştırılır.

`Security setting` kısmında buradaki politikalar user setting içerisindeki politikaları ezer. Domain politikaları ise Local Computer Politikalarını ezer.

Overwrite sırası aşağıdaki gibidir.
1. Local Group Policy
2. Site
3. Domain
4. OU (Organization Unit)

`rsop.msc` -> Resultant set of Policy --- Burada security kısmında parola politikalarını belirleyebiliriz. (Ne kadar süre geçerli olsun, minimum uzunluk, kaç parola hatılansın vs. )

---

### Güvenlik Mekanizmaları (DEP, ASLR, UAC)

- **ASLR(Address space layout randomization)**: Programın başalrken rastgele bir memory alanı tahsisini sağlar. Bu şekilde Her uygulamaya tahsis edilen binary alanını random bir yere atadığı için tahmini zorlaştırıyor.
- **DEP(Data Execution Prevention)**:
- **UAC(User Account Control)**
- **Secure boot**: Açılışta UEFI ın hangi işletim sisteminin çağırılacağını söyler. Aynı zamanda yüklenecek driverların bilgisayar açılmadan virüs kontrolünü yapar. Bu sayede Bilgisayar açılmadan çalışan virüsler engellenmiş olur.

## Windows Network Security

### Güvenlik Duvarı nedir?
Ağ geçidinde çalışan (Gateway- OSI-2/3 arası) Router ların yerine çalışabilen güvenlik duvarları kullanabiliriz.

- Ağı parçalara böler,
- Tüm trafiğin kendi üzerinden akmasını sağlar. Bu sayede bir güvenlik duvarının;
    - Ayırıcı,
    - İnceleyici,
    - Kısıtlayıcı özellikleri kullanılır.

Üç temel Güvenlik duvarı mimarisi kullanılmaktadır.
- Paket filtreleri
- Devre seviyedi geçitleri
- Uygulama düzeyi geçitleri

Mimariler arasındaki en teml fark denetimin hangi katmada ya da katmanlarda gerçekleştirildiğidir.


**ÖNEMLİ: Bir subnetin birden fazla gateway i olabilir. Fakat Bir tane default gatewayi olması gerekmektedir. Route Table üzerinde tanımladğımız ip adreslerinin ağ maskesi dar olanı geniş olanı ezer.**

Firewall kuralı örneği
SrcIP | SrcPORT | DestIP | DstPORT | Service | Action
---|---|---|---|---|---
10.0.0.5|ANY|192.168.1.5|TCP-22|?SSH|ALLOW
ANY|ANY|ANY|ANY|ANY|DROP/DENY

en başta kurallar tanımlandıktan sonra en alta `ANY` satırı eklenir. Kuralın dışındaki işlemlerde güvenlik duvarının nasıl davranacağını belirlememizi sağlar.

`DROP` işlemi istek yapan kişinin sistemimiz hakkında bilgi sahibi olmaması için kullanılır.
`DENY` genelde iç istemdeki kişiler için yetkisiz olduğunu bildirmemiz sağlar.

Router lar ACL ile firewall olarak kullanılabilir fakat Stateful özelliği olmadığı için bir gidiş kuralı bir de dönüş kuralı da yazmamız gereklidir. Firewall lar `Stateful` cihazla olduğu için özerinde `State Table` tutulur. Bu tabloda paketlerin gönderici IP si hedef IP si ve seq numarası bulunur. Bu da trafiğin sadece iç taraftan başlatılacağını söyler ve gelen paketler için kural yazmamızı gerektirmez. Gelen paketler giden paletlerin `seq` numarasının 1 fazlası ise kabul edilir.

### DMZ (DeMilitarized Zone)
Değerli kaynakların önüne herkesin ulaşabildiği yere konan makinelere verilen isim. Bu alan kuruluş ağı dışında kalan kısımdır ve tampon bölgedir. Eğer DMZ sunucusu ele geçirilirse kuruluş ağına zarara gelmemesi için kullanılır.

### Proxy Sunucuları
İstemci tarafından yapılan bir bağlantı proxy sunucusu tarafından sonlandırılır. Kontroller sonrasında gelen isteği tekrar başlatır.

### NAT (Network Address Translation) / PAT (Port Address Translation)
**NAT**: Local IP ile gelen istekleri Global IP ye çeviren veya bunun tam tersini yapan sisteme denir.

**PAT**: Local ile global arasında port değişimi yapan sistemdir.

### Next Generation Firewall
- Applicaiton Layer da çalışabilir.
    - Bir işlemin çalıştığı porta bakmadan uygulama bazında kural yapılabilir.
    - IPS gibi kullanılabilir.
- Userbased kural yazılabilir.
    - Bir kullanıcıya özel kurallar yazılabilir.

### Unified Threat Managemet (UTM)

...

### Web Application Firewall (WAF)

...

### IPS
...



![a secure network](img/secure-network.png)
---

## Sunucu ve Uç sistem Güvenliği

- **Sunucu Nedir? (server)**: Servis süresi yüksek olan bilgisayarlardır. Bu bilgisayarlar kritik bilgiler tutabilir.
- **Uç Sistem (client)**: Sunucuların dışında kalan tüm bilgisayar sistemlerine verilen isimdir.
- **Yama Yönetimi?..**
    - Yönetime duyulan ihtiyaç
        - **NAC (Network Access Control):** İnternet erişimini denetleyen yazılımdır. Bilgisayarların ağa katılımı denetleyen yazılımlardır. Sadece bizim yönetebileceğimiz bir cihazların ağa katılmasını sağlarız. Bu sayede ağımızı tehditlerden daha rahat koruyabiliriz.
        - Uzaktan yönetim değil, ağa bağlanan sistemlerin bizim istediğimiz şekilde ayarlanmasını istememizdir.
        - **Kural #1** Yönetemediğin cihazı ağa alma..!
    - Başına buyruk uç sistemler
        - istediğimiz bişey değildir. Ağı zararlı yazılımlardan korumamızı zorlar.
    - Kontrol
    - Fazlar;
        - Tanımlama
        - Belirleme
        - Planlama / Önceliklendirme
        - Dağıtım
- Saldırı Yüzeyi Daraltma
    - Gereksiz Servisler
        - Ne kadar az açık servisin varsa o kadar az saldırılacak alan vardır.
    - Hardening
        - Kullanılmayan yapıları kapat
        - En iyi sıkılaştıma, sadece ihtiyaç olan yazılımların çalışması ve bu yazılmların sadece benim istediğim yerde çalışması
    - The Principle of Least Privilige (PoLP)
        - Her servis kullanılabilecek minimum yetki ile çalıştırılmalıdır.
    - Yetki Yönetimi (Authorization)
    - Erişim Kontrolü (Access Control)
    - Kimlik Doğrulama (Authentication)
        - kimsin
        - neyin var
        - ne biliyorsun
    - Parola
    - White listing / HIDS (Hostbased IDS/IPS)
- Zararlı Yazılımlar
    - Virüs
    - Worm
    - Trojan
    - Spyware
        - Girdiği sistemden veri kaçırmaya çalıştığı için sistemden gizlenirler.
    - Ransomware
    - Rootkit
        - Sistemlerde yetki yükseltme amacıyla çalışan yazılımlardır.
- Zararlı yazılımlarla nasıl mücadele edilir?
    - Firewall
    - IPS
    - Antivirüs
    - Machine Learning
    - Heuristic
        - Sezgisel yaklaşımları kontrol eder. Nereden gelmiş nereye gidiyor, Hangi dosyalara erişiyor.
    - Reputation
    - Device Control
    - White Listing
- Şifreleme
    - Email
    - File/Folder
    - Disk
- Fiziksel Güvenlik
    - Çalınma
    - Yetkisiz Erişim
    - BIOS / GRUB
    - Veri Kaybı Yedekleme
    - Felaket Kurtarma Merkezi


## APT (Advenced Persistent Threat)
Anonim bir şekilde çalışan programlara APT denir. Genelde 0day kullanırlar. Spesifik bir hedefe odaklanırlar. Yaygın olmaması sebebiylr yakalanmaları zordur. Kalıcı bir virüstür. (Bilgisayar yeniden başlatıldığında tekrar çalışmaya başlar. )

![0DAY Attack](img/0day.png)

Targetted Attack'larda bulunulan açık denemeleri belirli zaman aralıklırıyla uygulanır. Birden yapılırsa Saldırı yapılacak sistem uyanabilir.


Attack Lifecycle:

Initial Recon | Initial Comppromise | Establish Foothold | Escalate priviliges | Internal Recon | Complete Mission
---|---|---|---|---|---

Exploit ettikten sonra Malware indirirken encrypted olarak indrimek gerekir. Çünkü Güvenlik yazılımlarının Malwareımızı görmesini istemeyiz.

APT çözümlerinin hedefi yapılan saldırı zincirlerini bir noktada kırabilmek.

### APT Çözüm Yöntemleri
- MailAPT Çözümleri
    - En çok saldırı e-posta üzerinden yapılmakta.
    - Cloud ve On Premise olmak üzere iki çözüm var
        - **Cloud** gelen mail bir bulut üzerinde test edilir.
            - Daha detaylı bir inceleme yapar.
        - **On-Premise** ise iki çesiti var:
            - Emulator
                - Bir sanal makine değil fakat sanal makine gibi tepki veren uygulamalara denir. Debugger olarak çalışır.
                - Avantajı çok hızlı çalışır.
            - Simulator(Virtual Machine)
                - Mesela gelen mail bir text dosyası içeriyorsa kendi içerisinde çalıştırır ve ne yaptığını izler. Eğer arkada bir işlem çalılştırmaya çalışıyorsa bunu malware olarak işaretler
                - Bazı uygulmalar hem emulator hem simulator kullanır. Burada amaç emulator ile sonuca hızlı karar vermek ve simulator yardımıyla detaylı sonuç almak.
            - Bare-bone

![mail-apt](img/mail-apt.png)

- WEB APT
    - Görevi WEB in arasına girip analiz yapmak
    - ilk gelen dosya geçer ve kopyası alınır. Analiz sonrasında eğer APT tespit edilirse daha sonraki paketler gönderilmez. Burada ilk bağlanan client kurban olmuş olr fakat diğer clientlara bulaşmaz.
- Endpoint APT
    - Ajanları var. Anormal davranışlı dosyaları APT sunucusuna gönderir. Buradan çıkacak karara göre bu dosyanın bloklanıp bloklanmayacağına karar verilir. Bu sayede Bir tanesinden yakalanan bir 0day diğerlerinden de bloklanabilir.
    - EP APT Server'a ihtiyaç duyar.
    - WEB APT ile çalışırsa ilk kurban olan client sorununu çözebiliriz.
- Content APT
    - Ortak alan olarka kullanılan File Serverların önüne koyulan APT çözümleridir.
- Forensic APT
    - Adli bilişim incelemesi için kullanılan çözümlerden bir tanesidir. Detaylı inceleme yapmamızı sağlar.

### APT Tespit Yöntemleri
- Advanced Machine Learning
    - Machine Learning algoritmasına bir tane malware bir tane de düzgün dosya verilir ve makine öğrenmesi yapması sağlanır. Daha sonrasında gelecek verilerin malware mi değil mi olduğunu belirliyor.
- Exploit Protection
    - Uygulamaları bir sendbox ile çalıştırır ve arkaplanda çalışan uygulamalarını araya girerek sürekli kontro eder ve işletim sistemi ile olan ilişkisini izler.
        - Heap Spray
        - DEP Circumvention UASLR tarzı yaptığı hareketler
        - Utilize OS Functionalrını kontrol eder.




































---
# Offensive

## Pasif Bilgi Toplama

**Bu konu çook önemli**

Senaryo: Ankara Üniversitesine saldırı yapılacak bilgi topluyoruz.

1. Ankara university
2. www.ankara.edu.tr
3. 80.251.40.153
4. ip2location -> RIPE
5. buradan sistem yöneticisinin ve networkün mail adresini aldık
    - Buradan bulduğumuz NET-NAME i tekrar arattık. Buradan oranın tüm ip aralıklarını bulduk.
6. Whois kaydı
7. Reverse whois kaydı
    - Bu kayda sahip olanın başka hani kayıtları var..
8. subdomainlerin tespiti
    - theharvester ile tarama yaptık
    - virtual hostlar keşfedilir.
    - biz buradaki virtual hostlardan birisinden içeriye girebilirsek (www-data yetkisi ile sızarız.) root olup diğer subdomainlere geçebiliriz.
9. Email adrslerinin tespiti
10. DNS bilgileri
    - DNS çok önemli buradan gol atarsan acıtır.
    - Robex.com üzerinden Analiz - grafik veriyor
    - MXtoolbox.com üzerinden Analiz - mail sunucusunu test ediyor.
    - dnsstuff.com üzerinden Analiz - dns analiz ediyor.
    - dig ile analiz - dns üzerine sorgu yapılabilen bir araç
        - `dig A ankara.edu.tr`
11. Diğer kullanışlı bilgiler
    - netcraft.com
    - yougetsignal
    - shodan.io
    - web.archive.net
        - Dizin kültürünü keşfetmek için kullanılabilir.
    - haveibeenpwned.com
    - virustotal.com
12. Geliştirici Siteleri
    - Alexa.com
        - burada sitelerle ilişkilendirilir.
    - pastebin
    - stackoverflow
    - github üzerinden analiz
13. Google Hacking DB - Google dork
    - `site:` belirtilen site/domain üzerinde arama yapmamızı sağlar.
    - `intitle:` kullanılarak dizinler listelenir basitçe belirtilen dorkdaki istenilen dizin/girdi ye sahip hedeflerin listelenmesine yarar
    - `inurl:` url kısmında bizim istediimiz parametrelerin geçmesini sağlarız.
    - `intitle: ` site başlıklarında yapmamızı sağlar.
    - `numrange:` sayı aralığı girmemizi sağlar.

Soru: Aramalar ankara.edu.tr ile yapılacak "www" gelmeyecek. sayfanın text i içerisinde ca ile başlayan r ile biten (ca**r) bir metin veya a.r veya 0-1000 arası syafaları getir...
```
site:ankara.edu.tr -inurl:www intext:ca*r | a.r | numrange:0-10000
```

14. Arama motorları ve Sosyal medya
    - Kullanıcı giriş ekranları
        - Bu şekilde sosyal mühendislik saldırısı yapacaksak phising yapabiliriz.
    - iş ilanları
        - kurum hakkında bilgi almaamızı sağlar
        - en rahat sistemlere sızma yöntemleridir.
            - Bu ilan üzerinden mail gönderebiliriz.
        - neyi bypasslayacağımızı öğrneme şansımız var.
    - Sosyal medya analizi
    - Kaynak kod ve geliştirici siteleri analizi
        - eğer bu yazılımı yapan firma başka yazılımlar da yaptıysa onlardaki açıkları kontrol etmek gerek
15. Metadata analizi
    - kaynaklar (Oluşturulan dosyalarda DC ve usernameler alınabilir. **Bu bilgi çok önemli** )
        - ofis dosyaları
        - pdfler
        - resimler
    - Araçlar
        - exif-reader
        - foca (otomatize - win üzerinde çalışıyor)
        - Metagoofil
16. Hacker Kaynakları
    - theharvester
    - SpiderFoot
    - Recon-ng
    - Foca
    - Metagoofil
    - Maltego
    - Searchsploit

## Aktip Bilgi toplama
- Genel Mantık
    - Pasif bilgileri doğrula
    - IP aralığında aktif olan sistemler
    - Portlar ve servisler
    - Yazılımlar ve versiyonlar
    - İşletim sistemleri
    - Detaylı verileri elde et
- Nmap
    - Ağ keşif
    - Port Servis tarama
    - Version tarama
    - İşletim sistemi tespiti
    - Zafiyet tespiti
    - Firewall/IDS Atlatma
    - Port durumları ve anlamalrı
        - Open
        - Closed
        - Filtered
        - Unfiltered
        - Open | Filtered
        - Close | Filtered
    - varsayılan olarak top1000 portu tarar.
    - -sS : sadece SYN gönderir. - Anonimlik açısından daha güvenli bir tarama
    - -sT : 3wayhs tamamlanır. - SYN proxy ihtimaline karşı daha emin olunur.
    - -sU : UDP tarama
    - -NULL / FIN / XMAS Scan
        - Gönderilen pakette RST+ACK dönüyorsa portun kapalı, hiç paket dönmüyorsa portun açık olduğu anlaşılır. Cevap ICMP Unreachable ise filtrelidir.
        - -sN
        - -sF
        - -sX
    - -sA ACK scan
    - -sW Window Scan
    - -Pn : Ping atma bodoslama dal... Bunun sebebi karşı taraf ping'e cevap verme komutu varsa kaçar.
    - -O işletim sistemi tespiti işletim sisteminin daha gerçekçi tespiti için bir açık bir kapalı port gerekiyor. Bulmak için TTL değerlerne bakıyor.
    - -p- tüm portları tara
    - -A bulunan portlar için küçük scriptler çalıştır.
    - -oA output All
    - -T hız ayarı 1-5 Default olarak 3 (Firewall varsa bu ayar düşürülür. )
    - -v Çıktı ayrıntıları
    - --open Yalnızca açık portları göster
    - -6 IPv6 aktifleştiriyor.
    - -sC Scripting Engine
        - /usr/share/nmap/scripts dizini altında
        - --script=[script-adı]
    - Nmap Firewall Atlatma
        - -f Paket parçalama
            - -ff daha çok böl demek
        - -D ipspoofing
        - -mac-spoofing MAC zehirlenmesi
        - -script firewall-bypass
- Fierce
    - önce zone transfer dener bulamazsa bodoslama dalar.
- enum4linux
- nbtscan - netBIOS scan
- onesixtyone karşı taraftan veri transfer yapmaya yarar SNMP üzerinden çalışır.
- snmpwalk

### Anonim Tarama
- Tor
    - apt-get install Tor
    - Service tor start
- Proxychain
- Nipe - perl
