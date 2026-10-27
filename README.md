# Vesta — tehdit sorgulama

IP adresi veya alan adını AbuseIPDB, AlienVault OTX, VirusTotal, ThreatFox, URLhaus, T.C. Siber Güvenlik Başkanlığı, Shodan InternetDB ve MXToolbox kaynaklarında eşzamanlı arayan kişisel analiz paneli.

## Ekran görüntüleri

Görseller, gerçek servis sorgusu veya oturum bilgisi kullanılmadan temsili API yanıtlarıyla oluşturuldu. `203.0.113.42` belgeleme için ayrılmış bir IP adresidir; gösterilen risk puanı ve haber başlıkları gerçek istihbarat verisi değildir.

### IP analizi

![VESTA IP analizi: kaynak sonuçları, risk puanı, teknik profil ve açık portlar](docs/screenshots/analiz.png)

### Haber akışı

![VESTA haber akışı: kaynaklar, filtreler ve temsili haberler](docs/screenshots/haberler.png)

### Giriş ve mobil görünüm

<img src="docs/screenshots/giris.png" alt="VESTA konsola giriş ekranı" width="700">

<img src="docs/screenshots/mobil.png" alt="VESTA mobil analiz görünümü" width="390">

## Kaynak koddan ilk kurulum

Depo API anahtarı, giriş parolası, sertifika, veritabanı veya derlenmiş arayüz içermez. Yeni bir kopyada önce bağımlılıkları ve yerel yapılandırmayı hazırlayın:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
```

`.env` içindeki servis anahtarlarını kendi hesaplarınızdan doldurun. `APP_PASSWORD_HASH` için Argon2id özeti, `SESSION_SECRET` için rastgele bir değer üretin; aşağıdaki komutların çıktısını `.env` içindeki ilgili alanlara yazın:

```sh
.venv/bin/python -c 'from getpass import getpass; from argon2 import PasswordHasher; print(PasswordHasher().hash(getpass("VESTA parolası: ")))'
.venv/bin/python -c 'import secrets; print(secrets.token_hex(32))'
```

Seçtiğiniz giriş parolasını güvenli bir yerde saklayın. `./run.sh` eksik frontend bağımlılıklarını kurup arayüzü derler. `twitter_pipeline/manuel` klasöründeki yerel X verileri isteğe bağlıdır ve bu depoya dahil değildir.

## Bu bilgisayarda açma

Terminalde bu klasöre girin:

```sh
cd /Users/a512/vesta/tehdit-ekrani
./run.sh
```

Ardından tarayıcıda **http://127.0.0.1:8000** adresini açın. Bu bilgisayardaki mevcut kurulumun giriş parolası yalnızca sizin okuyabildiğiniz `ilk-giris.txt` dosyasındadır; dosya GitHub'a gönderilmez. Yeni kopyada kurulum sırasında seçtiğiniz parolayı kullanın. Sunucu sadece `127.0.0.1` üzerinde dinler; yerel ağdaki başka cihazlar erişemez.

Arayüz `web/` klasöründeki React uygulamasıdır ve derlenmiş hali (`web/dist`) FastAPI tarafından sunulur. `web/dist` yoksa `run.sh` ilk açılışta bağımlılıkları kurar ve derler (`npm install` + `npm run build`). Arayüzde değişiklik yapıldığında yeniden derlemek için:

```sh
cd /Users/a512/vesta/tehdit-ekrani/web
npm run build
```

API anahtarları bu klasördeki `.env` dosyasında tutulur. `.env` ve `ilk-giris.txt` dosyaları `600` iznine sahiptir ve Git dışında tutulur. Anahtar veya parola değiştirmek için `.env` içindeki ilgili değeri güncelleyin ve sunucuyu yeniden başlatın. Parola özeti Argon2id biçimindedir.

## Notlar

- Haberler modülü RSS, resmî bildirim ve yerel X kayıtlarını ayrı doğrulama durumlarıyla gösterir. Öncelik ve doğrulama birbirinden bağımsızdır; sıralama puanı gerçekleşme olasılığı değildir. Aynı olaya ait haberler kaynak bağlantıları ve zaman çizelgesiyle gruplanır.
- CVE Radar ilk yayın tarihini NVD'den, bilinen istismar eşleşmesini CISA KEV kataloğundan alır. RSS tarihi yalnızca akışa eklenme tarihidir. Veriye erişilemezse tarih veya KEV durumu bilinmiyor olarak gösterilir. NVD sorguları istek başına en fazla beş kayıtla sınırlıdır; sonuçlar 24 saat, KEV kataloğu 12 saat önbellekte tutulur.
- `GET /api/news` arama ve `source`, `content_type`, `priority`, `verification`, `region`, `active_exploitation`, `from_date`, `to_date`, `sort`, `page`, `page_size` filtrelerini destekler. Ham kayıtlar `items` içinde kalır; değerlendirme `evaluation`, tarih ayrımı `dates` ve olay ilişkileri `events` alanlarıyla döner. Haber kartındaki **VESTA'da Analiz Et** göstergesi Analiz ekranına taşır; sorguyu kullanıcı başlatır.
- Kaynak paneli erişilebilirliği, son kontrolü, son başarılı çekimi, son içerik tarihini ve önbellek yaşını ayrı gösterir. Resmî kaynakta uzun süre yeni duyuru olmaması otomatik hata sayılmaz.

- Yalnızca genel IPv4/IPv6 adresleri ve geçerli alan adları kabul edilir. URL ve yerel IP adresleri dış servislere gönderilmez.
- VirusTotal ücretsiz kotası bütün oturumlar için 4 istek/dakika ve 500 istek/24 saat olarak yönetilir. Sayaç yalnızca istek zamanlarını `.data/quota.sqlite3` içinde tutar.
- Sorgu alanının altındaki kullanım satırı son 24 saatteki arama ve kaynak başına HTTP istek sayılarını gösterir. Bu sayılar `.data/usage.sqlite3` içinde IP veya alan adı saklanmadan tutulur. AbuseIPDB ücretsiz `check` sınırı 1.000/UTC gün olarak gösterilir; diğer kaynaklar için uygulama sabit kota varsaymaz.
- Her kaynak sonucu geldikçe görünür. Eşleşme yokluğu güvenli olduğu anlamına gelmez.
- Shodan InternetDB, genel IPv4 adresleri için açık port, olası zafiyet, hostname ve CPE verisi gösterir. Alan adı ve IPv6 sorgusunda destek dışı olarak işaretlenir. Bu veriler Shodan'ın önceki gözlemleridir; canlı port taraması yapılmaz.
- IP haritası CARTO Dark Matter katmanını kullanır. `CARTO_BASEMAP_API_KEY` sunucudaki `.env` dosyasından okunur; tarayıcı harita karolarını oturum gerektiren `/api/map-tiles/` yolundan alır. Harita üzerinde OpenStreetMap ve CARTO atıfları görünür.
- Genel risk puanı 0–100 aralığında basit bir önceliklendirme göstergesidir. IPv4 için AbuseIPDB (35), VirusTotal (25), OTX (10), ThreatFox (10), URLhaus (7), SGB (5) ve InternetDB zafiyetleri (8); IPv6 ve alan adı için desteklenen kaynaklara göre ayrı ağırlıklar kullanılır. Açık portlar puanı artırmaz. Yanıtlanmayan veya limit dolan kaynaklar için puan eklenmez ve sonuç **ön sonuç** olarak kalır. Katkılar panelde açılabilir.
- Arama geçmişi tutulmaz. Anahtarlar tarayıcıya gönderilmez.
- Yerel ağda kullanmak isterseniz ayrıca HTTPS kurulumu gerekir; `Caddyfile` ve `run-https.sh` bunun için saklandı. O durumda `.env` içine `APP_LOCAL_ONLY=0` ekleyin ve HTTPS sertifikasını kullanan cihazlarda güvenilir hale getirin.

## Test

Backend testleri:

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Arayüz testleri ve denetimi (`web/` içinde):

```sh
npm test
npm run lint
```
