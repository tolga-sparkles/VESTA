# VESTA web (frontend)

React 19 + Vite + TanStack Router + Tailwind v4 tabanlı SPA. Tüm veri, aynı origin'deki
FastAPI backend'inden (`../app.py`) gelir: oturum, arama akışı (NDJSON) ve kullanım sayaçları.

- API erişimi yalnızca `src/lib/vesta-data.ts` üzerinden yapılır; bileşenler doğrudan fetch kullanmaz.
- Kaynak kimlikleri backend ile birebir aynıdır: `abuseipdb, otx, virustotal, threatfox, urlhaus, sgb, internetdb`.
- Görsel token'lar ve yeniden kullanılabilir ekran stilleri `src/styles.css` içinde tanımlıdır; bileşenlerde satır içi stil yerine bu sınıflar tercih edilir.

## Komutlar

```sh
npm install      # bağımlılıklar
npm run build    # dist/ üretim çıktısı (FastAPI bunu serve eder)
npm run lint
npm test
```
