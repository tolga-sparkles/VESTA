# Vesta — yazılım açıklaması

Vesta, bir **genel IP adresi veya alan adı** hakkında birden fazla tehdit istihbaratı kaynağından bilgi toplayan yerel analiz panelidir. Girilen göstergeyi destekleyen servislere aynı anda sorgu gönderir; her yanıtı geldiği anda ekranda gösterir. Böylece bir servisin yavaşlığı diğer sonuçları bekletmez.

## Kullanıcı ne görür?

- Her kaynak için eşleşme, kayıt yok, destek dışı, limit doldu veya hata durumu; kısa bulgu, yanıt süresi ve açılabilir JSON ayrıntıları.
- Shodan InternetDB yanıtında IPv4 adresi için görülen açık portlar, olası zafiyet kimlikleri, hostname ve CPE sayıları.
- Kaynak bulgularından hesaplanan **0–100 genel risk puanı** ve her kaynağın puana katkısı. Bazı kaynaklar yanıtlamadıysa puan **ön sonuç** olarak işaretlenir.
- Açık ve koyu tema. Dar ekranlarda kaynak tablosu yatay kaydırılabilir.
- Sorgu alanının altında küçük bir kullanım satırı: son 24 saatteki arama sayısı, VirusTotal ve AbuseIPDB sayaçları. Ayrıntısı açıldığında kaynak başına HTTP istek sayısı görünür.

## Bağlı kaynaklar

| Kaynak | Sorgu türü | Panelde kullanılan başlıca veri |
| --- | --- | --- |
| AbuseIPDB | IPv4, IPv6 | Kötüye kullanım puanı, rapor sayısı |
| AlienVault OTX | IPv4, IPv6, alan adı | Pulse kayıtları |
| VirusTotal | IPv4, IPv6, alan adı | Zararlı ve şüpheli tespit sayıları |
| ThreatFox | IPv4, alan adı | Kesin eşleşen IOC kayıtları |
| URLhaus | IPv4, alan adı | Zararlı URL kayıtları |
| Siber Güvenlik Başkanlığı | IPv4, IPv6, alan adı | Kesin eşleşen adres kayıtları |
| Shodan InternetDB | IPv4 | Açık portlar ve olası zafiyetler |

Desteklenmeyen gösterge türünde kaynak sorgulanmaz; panel bunu açıkça belirtir. InternetDB sorgusu bir **canlı port taraması değildir**: servis daha önce gözlediği verileri döndürür. Vesta dosya veya URL yüklemez.

## Genel puan nasıl hesaplanır?

Puan, kaynakların kendi puanlarını birebir toplamaz. Vesta'nın önceliklendirme için kullandığı basit bir ağırlıklı kuraldır. Ağırlıklar gösterge türüne göre toplam 100 eder:

| Kaynak | IPv4 | IPv6 | Alan adı |
| --- | ---: | ---: | ---: |
| AbuseIPDB | 35 | 45 | — |
| VirusTotal | 25 | 30 | 45 |
| AlienVault OTX | 10 | 15 | 20 |
| ThreatFox | 10 | — | 15 |
| URLhaus | 7 | — | 10 |
| Siber Güvenlik Başkanlığı | 5 | 10 | 10 |
| Shodan InternetDB zafiyetleri | 8 | — | — |

AbuseIPDB katkısı kendi 0–100 puanıyla orantılıdır. VirusTotal'da zararlı tespitler 4, şüpheli tespitler 2 puan ekler; katkı kaynak ağırlığını aşmaz. OTX Pulse başına 2, InternetDB olası zafiyeti başına 4 puan ekler; bunlar da ilgili ağırlıkla sınırlıdır. ThreatFox ve Siber Güvenlik Başkanlığı kesin eşleşmede kendi ağırlığını ekler. URLhaus en az bir kayıt varsa ağırlığını ekler. **Açık port sayısı puanı yükseltmez.**

Hata, hız sınırı veya eksik yanıt puana sıfır katkı gibi gösterilmez; katkı bilinmiyor olarak kalır ve genel puan **ön sonuç** sayılır. Puan kesin bir güvenlik kararı değildir. Kayıt bulunmaması da göstergenin güvenli olduğunu kanıtlamaz.

## Çalışma şekli ve veriler

Tarayıcı `POST /api/search` isteği gönderir. FastAPI sunucusu girdinin genel IP adresi veya geçerli alan adı olduğunu doğrular; özel/yerel IP adreslerini ve URL'leri reddeder. `httpx` ile uygun kaynaklara eşzamanlı istek yapar. Sonuçlar NDJSON akışıyla tarayıcıya iletilir; arayüz bulguları ve puanı her yeni yanıtta günceller.

Arayüz React tabanlı bir SPA'dır (`web/` klasörü) ve derlenmiş çıktısı (`web/dist`) FastAPI tarafından sunulur; API istekleri aynı origin üzerinden yapılır.

API anahtarları sunucudaki `.env` dosyasından okunur ve tarayıcıya gönderilmez. Giriş, ortak parolanın Argon2id özetiyle doğrulanır; oturum çerezi kullanılır. VirusTotal için bütün oturumların paylaştığı yerel sayaç **4 istek/dakika ve 500 istek/24 saat** sınırını uygular. Arama geçmişi tutulmaz; yerel sayaç veritabanlarında yalnızca istek zamanları ve kaynak adları bulunur. Sorgulanan IP veya alan adı, yanıt almak için ilgili üçüncü taraf servislere gönderilir.

## Sorgu sınırları ve sayaçlar

| Kaynak | Panelde gösterilen sınır | Ölçüm dönemi |
| --- | --- | --- |
| VirusTotal ücretsiz API | [4 istek/dakika, 500 istek/gün](https://docs.virustotal.com/v2.0/reference/public-vs-private-api) | Uygulama 60 saniye ve kayan 24 saat penceresi uygular |
| AbuseIPDB ücretsiz `check` API | [1.000 istek/gün](https://docs.abuseipdb.com/) | API v2 için UTC gün başında sıfırlanır |
| OTX, ThreatFox, URLhaus, Siber Güvenlik Başkanlığı, Shodan InternetDB | Bu uygulamada sabit sayısal kota tanımlı değil | Yerel istek sayısı son 24 saat için gösterilir |

Sorgu alanının altındaki sayaç yalnızca **bu Vesta kurulumunun** kullanımını gösterir; aynı anahtarla başka yazılımlardan yapılan istekleri göremez. AbuseIPDB'de hesabınız ücretsiz plandan farklıysa gerçek sınırınız da farklı olabilir. VirusTotal sayacı uygulamanın ayırdığı istekleri, diğer kaynakların sayaçları gönderilmeye başlanan HTTP isteklerini sayar. Siber Güvenlik Başkanlığı araması sayfalama nedeniyle tek gösterge için birden çok HTTP isteği yapabilir. Bu yeni kaynak sayaçları geçmiş kullanımı geriye dönük hesaplamaz. Sayaçlarda IP, alan adı veya API anahtarı tutulmaz.

## Açma ve kapatma

```sh
cd /Users/a512/vesta/tehdit-ekrani
./run.sh
```

Ardından `http://127.0.0.1:8000` adresini açın. Sunucu yalnızca bu bilgisayardaki `127.0.0.1` adresinde dinler. Kapatmak için çalıştığı Terminal penceresinde **Ctrl+C** kullanın. Ayrıntılı komutlar [acma-kapatma.txt](acma-kapatma.txt) dosyasındadır.

## Proje dosyaları

| Dosya | Görev |
| --- | --- |
| `app.py` | Giriş, gösterge doğrulama, kaynak sorguları, akış ve puanlama; derlenmiş arayüzü sunar |
| `web/` | React arayüzü (kaynak kodu); `web/dist/` FastAPI'nin sunduğu derlenmiş çıktıdır |
| `run.sh` | Gerekirse arayüzü derler ve yerel HTTP sunucusunu başlatır |
| `tests/test_app.py` | Girdi, oturum, eşzamanlı akış, kota, InternetDB, puanlama ve SPA sunumu testleri |
| `.env` | Sunucunun okuduğu gizli ayarlar ve API anahtarları; paylaşılmamalıdır |

Testleri çalıştırmak için:

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Arayüz testleri ve denetimi `web/` klasöründe `npm test` ve `npm run lint` ile yapılır.
