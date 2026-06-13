# NmapGUI

Herkesin kullanabileceği, basitleştirilmiş bir nmap grafik arayüzü. Karmaşık komut satırı bayrakları yerine "Hızlı Tara", "Cihaz Bul", "Güvenlik Taraması" gibi anlaşılır kartlar sunar — ve her zaman arkada çalışacak gerçek `nmap` komutunu şeffaf şekilde gösterir.

## Gereksinimler
- [Node.js](https://nodejs.org) (geliştirme için)
- [nmap](https://nmap.org/download.html) (Windows yükleyicisi, Npcap dahil). Uygulama nmap'i otomatik tespit eder; yoksa indirme yönergesi gösterir.

## Çalıştırma (geliştirme)
```bash
npm install
npm start
```

## Kurulabilir .exe üretme
```bash
npm run dist
```
Çıktı `dist/` klasöründe NSIS yükleyici olarak oluşur.

## Mimari
- `src/main/main.js` — Electron ana süreç. nmap'i `child_process` ile çalıştırır, canlı çıktıyı arayüze aktarır.
- `src/main/preload.js` — Güvenli IPC köprüsü (contextIsolation açık).
- `src/renderer/` — React tabanlı arayüz (şu an build adımı olmadan, CDN React + Babel).

## Özellikler (v2)
- **XML tabanlı parser** (`-oX`) — sağlam, yapısal sonuç
- **Cihaz tablosu** (IP, ağ adı, MAC, üretici, cihaz türü ikonu, risk) + **açık port tablosu**
- **Cihaz detay paneli** (drill-down): portlar, OS tahmini, zafiyetler (CVE linkleri)
- **Ağ topoloji haritası** (SVG radyal görünüm)
- **Basit / Gelişmiş mod** — port aralığı, timing, -Pn, UDP, OS tespiti, servis sürümü
- **NSE script tarayıcı** — kategorili, aranabilir katalog
- **Hazır port grupları** (web, veritabanı, uzak erişim, e-posta)
- **Canlı ilerleme yüzdesi** (`--stats-every`)
- **Tarama geçmişi** (dosya tabanlı), yükle/sil
- **JSON + zengin PDF rapor**
- **i18n** (TR/EN), **açık/koyu tema**, ayarlar ekranı
- **Yönetici tespiti** + "yönetici olarak yeniden başlat"
- **Güvenli mod** (yalnızca özel ağ aralıkları)
- **Otomatik izleme** (periyodik tarama + yeni cihaz bildirimi)
- **Loglama** (userData/nmapgui.log), nmap otomatik kur, özel ikon, etik onay, offline

## Yol haritası (sonraki adımlar)
- [ ] Tarama geçmişi
- [ ] Renderer'ı Vite + gerçek React bundle'a taşımak
- [ ] Kod imzalama sertifikası (SmartScreen uyarısını önlemek için)
- [ ] XML (`-oX`) tabanlı daha sağlam parse

## ⚠️ Etik
Yalnızca kendi ağınızda veya tarama yapmaya açıkça yetkili olduğunuz sistemlerde kullanın.
