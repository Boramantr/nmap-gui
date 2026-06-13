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

## Özellikler (v3)
- **Portable pentest araçları (WSL'siz)** — nuclei, gobuster, httpx, subfinder gibi Go ile yazılmış araçların resmi Windows binary'lerini GitHub release'lerden indirip uygulamanın veri klasörüne kurar. WSL kurulumu, yeniden başlatma veya UAC gerektirmez. Portable kuruluysa otomatik olarak WSL'e tercih edilir.
- **NVD CVSS zenginleştirme** — tespit edilen CVE'ler için NVD API'den gerçek CVSS skoru, severity ve açıklama (yerel önbellekli, rate-limit dostu)
- **Oto-exploit eşleme** — açık servis sürümlerini (örn. `vsftpd 2.3.4`) searchsploit/ExploitDB ile otomatik eşler
- **Önerilen sonraki adımlar** — tarama sonucuna göre önceliklendirilmiş, tek tıkla çalıştırılabilir aksiyon listesi (nuclei, web enum, SMB enum, exploit arama)
- **Komut bayrak açıklayıcı** — çalışacak her nmap bayrağının sade Türkçe açıklaması
- **Gelişmiş tarama diff'i** — host/port farkına ek olarak servis sürüm değişikliklerini de gösterir
- **Çoklu-OS desteği** — yönetici/ARP/araç çalıştırma Windows (WSL), Linux ve macOS'ta çalışır

## Yol haritası (sonraki adımlar)
- [ ] Tarama geçmişi
- [ ] Renderer'ı Vite + gerçek React bundle'a taşımak
- [ ] Kod imzalama sertifikası (SmartScreen uyarısını önlemek için)
- [ ] XML (`-oX`) tabanlı daha sağlam parse

## ⚠️ Etik
Yalnızca kendi ağınızda veya tarama yapmaya açıkça yetkili olduğunuz sistemlerde kullanın.
