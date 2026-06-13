const { useState, useEffect, useRef } = React;

/* ============ i18n ============ */
const I18N = {
  tr: {
    scan: 'Tarama', history: 'Geçmiş', scripts: 'Scriptler', settings: 'Ayarlar',
    target: 'Hedef (IP, alan adı veya aralık)', findNet: '🌐 Ağımı otomatik bul',
    profile: 'Tarama Profili', simple: 'Basit', advanced: 'Gelişmiş',
    command: 'Çalışacak komut (şeffaflık):', start: '▶ Taramayı Başlat', stop: '■ Durdur',
    results: 'Sonuçlar', raw: 'Ham Çıktı', devices: 'Bulunan Cihazlar', openPorts: 'Açık Portlar',
    noResult: 'Henüz sonuç yok. "🌐 Ağımı otomatik bul"a basıp "Taramayı Başlat"a tıklayın.',
    scanning: '⏳ Tarama sürüyor...', status: 'Durum', device: 'cihaz', port: 'açık port',
    ip: 'IP Adresi', netname: 'Ağ Adı', state: 'Durum', latency: 'Gecikme', mac: 'MAC',
    vendor: 'Üretici', type: 'Tür', risk: 'Risk', active: 'aktif',
    portCol: 'Port', proto: 'Protokol', service: 'Servis', version: 'Sürüm',
    detail: 'Cihaz Detayı', os: 'İşletim Sistemi', vulns: 'Zafiyetler', close: 'Kapat',
    portRange: 'Port aralığı (boş=varsayılan)', timing: 'Hız (timing)', noPing: 'Ping atlamadan tara (-Pn)',
    udp: 'UDP taraması', osDetect: 'İşletim sistemi tespiti', svcVer: 'Servis sürümü',
    selScripts: 'Seçili scriptler', searchScript: 'Script ara...', addScript: 'Ekle', remove: 'Kaldır',
    noHistory: 'Henüz kayıtlı tarama yok.', load: 'Yükle', delete: 'Sil', compare: 'Karşılaştır',
    lang: 'Dil', theme: 'Tema', dark: 'Koyu', light: 'Açık', safeMode: 'Güvenli mod (sadece özel ağlar)',
    autoMon: 'Otomatik izleme', off: 'Kapalı', save: 'Kaydet', saved: 'Kaydedildi',
    adminWarn: '⚠️ Yönetici değil — OS tespiti, MAC ve SYN tarama kısıtlı olabilir.',
    runAdmin: 'Yönetici olarak yeniden başlat', nmapReady: 'nmap hazır', nmapMissing: 'nmap yok',
    topology: 'Ağ Haritası', list: 'Liste', exportJson: '⬇ JSON', exportPdf: '📄 PDF',
    safeBlock: 'Güvenli mod açık: yalnızca özel ağ aralıkları (192.168.x, 10.x, 172.16-31.x) taranabilir.',
    newDevices: 'yeni cihaz bulundu', noChange: 'değişiklik yok', portsPreset: 'Hazır port grupları',
    engagement: 'Çalışma Alanı', workspace: 'Çalışma Alanı', mode: 'Mod', lab: 'Lab', engMode: 'Engagement',
    scope: 'Kapsam (scope)', scopeHint: 'İzinli hedefler — virgülle: 192.168.0.0/24, 10.0.0.5',
    assets: 'Varlıklar', auditLog: 'Denetim Kaydı', newWs: 'Yeni Çalışma Alanı', wsName: 'Ad',
    createWs: 'Oluştur', activeWs: 'Aktif', scopeBlock: 'Engagement modu: hedef kapsam (scope) dışında — engellendi.',
    scopeWarn: 'Kapsam tanımlı değil. Engagement modunda önce scope belirleyin.',
    totalHosts: 'host', totalServices: 'servis', totalVulns: 'zafiyet', totalScans: 'tarama',
    wslReady: 'WSL hazır', wslMissing: 'WSL yok', tools: 'Araçlar', osint: 'OSINT',
  },
  en: {
    scan: 'Scan', history: 'History', scripts: 'Scripts', settings: 'Settings',
    target: 'Target (IP, host or range)', findNet: '🌐 Detect my network',
    profile: 'Scan Profile', simple: 'Simple', advanced: 'Advanced',
    command: 'Command to run (transparency):', start: '▶ Start Scan', stop: '■ Stop',
    results: 'Results', raw: 'Raw Output', devices: 'Discovered Devices', openPorts: 'Open Ports',
    noResult: 'No results yet. Click "Detect my network" then "Start Scan".',
    scanning: '⏳ Scanning...', status: 'Status', device: 'device', port: 'open port',
    ip: 'IP Address', netname: 'Hostname', state: 'State', latency: 'Latency', mac: 'MAC',
    vendor: 'Vendor', type: 'Type', risk: 'Risk', active: 'up',
    portCol: 'Port', proto: 'Protocol', service: 'Service', version: 'Version',
    detail: 'Device Detail', os: 'OS', vulns: 'Vulnerabilities', close: 'Close',
    portRange: 'Port range (empty=default)', timing: 'Timing', noPing: 'Skip host discovery (-Pn)',
    udp: 'UDP scan', osDetect: 'OS detection', svcVer: 'Service version',
    selScripts: 'Selected scripts', searchScript: 'Search script...', addScript: 'Add', remove: 'Remove',
    noHistory: 'No saved scans yet.', load: 'Load', delete: 'Delete', compare: 'Compare',
    lang: 'Language', theme: 'Theme', dark: 'Dark', light: 'Light', safeMode: 'Safe mode (private nets only)',
    autoMon: 'Auto monitoring', off: 'Off', save: 'Save', saved: 'Saved',
    adminWarn: '⚠️ Not admin — OS detection, MAC and SYN scan may be limited.',
    runAdmin: 'Restart as administrator', nmapReady: 'nmap ready', nmapMissing: 'nmap missing',
    topology: 'Network Map', list: 'List', exportJson: '⬇ JSON', exportPdf: '📄 PDF',
    safeBlock: 'Safe mode on: only private ranges (192.168.x, 10.x, 172.16-31.x) allowed.',
    newDevices: 'new device(s) found', noChange: 'no change', portsPreset: 'Port presets',
    engagement: 'Workspace', workspace: 'Workspace', mode: 'Mode', lab: 'Lab', engMode: 'Engagement',
    scope: 'Scope', scopeHint: 'Allowed targets — comma separated: 192.168.0.0/24, 10.0.0.5',
    assets: 'Assets', auditLog: 'Audit Log', newWs: 'New Workspace', wsName: 'Name',
    createWs: 'Create', activeWs: 'Active', scopeBlock: 'Engagement mode: target out of scope — blocked.',
    scopeWarn: 'No scope defined. Set a scope first in engagement mode.',
    totalHosts: 'hosts', totalServices: 'services', totalVulns: 'vulns', totalScans: 'scans',
    wslReady: 'WSL ready', wslMissing: 'WSL missing', tools: 'Tools', osint: 'OSINT',
  },
};

// Hedef, scope listesi içinde mi? (CIDR/IP ön ek eşleşmesi — Faz 1 basit kontrol)
function inScopeList(target, scope) {
  if (!scope || !scope.trim()) return null; // tanımsız
  const t = target.trim();
  const entries = scope.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
  return entries.some((e) => {
    const base = e.split('/')[0];
    const prefix = base.split('.').slice(0, 3).join('.'); // /24 yaklaşık
    return t === base || t.startsWith(prefix + '.') || t.startsWith(base);
  });
}

/* ============ Kataloglar ============ */
const PROFILES = [
  // Genel
  { id: 'discover-full', cat: 'general', icon: 'radar', recommended: true,
    title: 'Tam Keşif', desc: 'Host keşfi, port taraması, OS tespiti, servis/sürüm tespiti ve script taraması.',
    tags: [{ label: 'Yoğun', tone: 'intense' }, { label: 'Yavaş', tone: 'time' }, { label: 'Tümü', tone: 'scope' }],
    args: ['-sn', '-PR', '-PE', '-PP', '-PM', '-PS21,22,23,25,80,135,139,443,445,3389,8080', '-PA80,443,3389', '-PU53,161,137', '-T4'] },
  { id: 'discover', cat: 'general', icon: 'radar',
    title: 'Cihaz Bul', desc: 'ARP + ping ile ağdaki cihazları ve MAC adreslerini bulur.',
    tags: [{ label: 'Hızlı', tone: 'fast' }, { label: 'Hafif', tone: 'time' }, { label: 'TCP', tone: 'scope' }],
    args: ['-sn', '-PR', '-PE', '-PS21,22,23,80,443,3389', '-PA80,443', '-T4'] },
  { id: 'quick', cat: 'general', icon: 'bolt',
    title: 'Hızlı Tara', desc: 'En yaygın 1000 portun hızlı taraması ve servis tespiti.',
    tags: [{ label: 'Hızlı', tone: 'fast' }, { label: 'Hafif', tone: 'time' }, { label: 'TCP', tone: 'scope' }],
    args: ['-F', '-T4'] },
  { id: 'detailed', cat: 'general', icon: 'server',
    title: 'Detaylı Tara', desc: 'Servis sürümleri ve işletim sistemi tespitini içerir.',
    tags: [{ label: 'Yoğun', tone: 'intense' }, { label: 'Yavaş', tone: 'time' }, { label: 'TCP', tone: 'scope' }],
    args: ['-sV', '-O', '-T4'] },
  { id: 'allports', cat: 'general', icon: 'server',
    title: 'Tüm Portlar', desc: 'Tüm 65535 portu tarar (yavaş ama eksiksiz).',
    tags: [{ label: 'Yoğun', tone: 'intense' }, { label: 'Yavaş', tone: 'time' }, { label: 'Tümü', tone: 'scope' }],
    args: ['-p-', '-T4'] },
  // Pentest
  { id: 'srv-full',cat: 'pentest', icon: 'server', recommended: true, title: 'Sunucu Tam Tarama',
    desc: 'Tüm port + servis + script + işletim sistemi. Sunucular için kapsamlı tarama.',
    tags: [{label:'Yoğun',tone:'intense'},{label:'Yavaş',tone:'time'},{label:'TCP',tone:'scope'}],
    args: ['-sS', '-sV', '-sC', '-O', '-p-', '-T4'] },
  { id: 'aggressive',cat: 'pentest', icon: 'bolt', title: 'Agresif (-A)',
    desc: 'OS+sürüm+script+traceroute tek seferde.',
    tags: [{label:'Yoğun',tone:'intense'},{label:'Orta',tone:'time'},{label:'TCP',tone:'scope'}], args: ['-A', '-T4'] },
  { id: 'vuln-deep',cat: 'pentest', icon: 'shield', title: 'Derin Zafiyet',
    desc: 'vuln + vulners script seti ile derinlemesine CVE eşleme.',
    tags: [{label:'Yoğun',tone:'intense'},{label:'Yavaş',tone:'time'},{label:'CVE',tone:'scope'}],
    args: ['-sV', '--script', 'vuln,vulners'] },
  { id: 'web', cat: 'pentest', icon: 'web', title: 'Web Sunucu',
    desc: 'HTTP/S servis tespiti ve web scriptleri (http-enum, ssl-cert).',
    tags: [{label:'Orta',tone:'intense'},{label:'Orta',tone:'time'},{label:'HTTP',tone:'scope'}],
    args: ['-p', '80,443,8080,8443', '-sV', '--script', 'http-enum,http-title,http-headers,ssl-cert'] },
  { id: 'smb', cat: 'pentest', icon: 'server', title: 'SMB Enum',
    desc: 'SMB paylaşım sayımı + MS17-010 (EternalBlue) kontrolü.',
    tags: [{label:'Orta',tone:'intense'},{label:'Orta',tone:'time'},{label:'SMB',tone:'scope'}],
    args: ['-p', '139,445', '--script', 'smb-os-discovery,smb-enum-shares,smb-vuln-ms17-010'] },
  { id: 'topports',cat: 'pentest', icon: 'bolt', title: 'Top 1000 + Sürüm',
    desc: 'En yaygın 1000 port + servis sürüm tespiti.',
    tags: [{label:'Hızlı',tone:'fast'},{label:'Hafif',tone:'time'},{label:'TCP',tone:'scope'}], args: ['--top-ports', '1000', '-sV'] },
  { id: 'udp-top', cat: 'pentest', icon: 'bolt', title: 'UDP Top 50',
    desc: 'En yaygın 50 UDP portu hızlıca.',
    tags: [{label:'Hızlı',tone:'fast'},{label:'Orta',tone:'time'},{label:'UDP',tone:'scope'}], args: ['-sU', '--top-ports', '50', '-T4'] },
  { id: 'stealth', cat: 'pentest', icon: 'shield', title: 'Stealth / Yavaş',
    desc: 'SYN + yavaş timing + paket fragmenti ile düşük profil.',
    tags: [{label:'Düşük',tone:'fast'},{label:'Yavaş',tone:'time'},{label:'TCP',tone:'scope'}], args: ['-sS', '-T2', '-f'] },
];

// Servis/port bazlı pentest playbook — açık porta göre önerilen sonraki adım.
const PORT_PLAYBOOK = {
  '21': 'FTP — anonim giriş kontrolü (ftp-anon), banner, zayıf kimlik',
  '22': 'SSH — sürüm/zayıf anahtar, yetkili ise kimlik denemesi',
  '23': 'Telnet — şifresiz protokol, banner yakalama',
  '25': 'SMTP — açık relay testi, VRFY ile kullanıcı sayımı',
  '53': 'DNS — zone transfer (AXFR), alt alan adı keşfi',
  '80': 'HTTP — dizin keşfi (http-enum/gobuster), başlık, teknoloji tespiti',
  '110': 'POP3 — kimlik doğrulama, banner',
  '135': 'MSRPC — endpoint mapper sayımı',
  '139': 'NetBIOS — SMB sayımı, host bilgisi',
  '143': 'IMAP — kimlik doğrulama',
  '161': 'SNMP — public community testi (snmp-brute), bilgi sızıntısı',
  '443': 'HTTPS — SSL/TLS analizi (ssl-cert, ssl-enum-ciphers), Heartbleed',
  '445': 'SMB — paylaşım sayımı, EternalBlue (MS17-010), null session',
  '1433': 'MSSQL — zayıf kimlik (sa), sürüm tespiti',
  '1521': 'Oracle — SID sayımı, zayıf kimlik',
  '3306': 'MySQL — zayıf kimlik, sürüm tabanlı CVE',
  '3389': 'RDP — BlueKeep (CVE-2019-0708), NLA durumu',
  '5432': 'PostgreSQL — zayıf kimlik',
  '5900': 'VNC — kimlik doğrulama atlatma, zayıf parola',
  '6379': 'Redis — kimliksiz erişim kontrolü',
  '8080': 'HTTP-alt — yönetim paneli, proxy, web uygulaması',
  '27017': 'MongoDB — kimliksiz erişim, veri sızıntısı',
};
const PORT_PRESETS = [
  { name: 'Web (80,443,8080)', ports: '80,443,8080,8443' },
  { name: 'Veritabanı (3306,5432,1433)', ports: '3306,5432,1433,1521,27017' },
  { name: 'Uzak erişim (22,3389,5900)', ports: '22,3389,5900,23' },
  { name: 'E-posta (25,110,143,587)', ports: '25,110,143,465,587,993,995' },
];
const NSE_SCRIPTS = [
  { id: 'vuln', cat: 'Zafiyet', desc: 'Bilinen zafiyetleri (CVE) kontrol eder' },
  { id: 'http-title', cat: 'Keşif', desc: 'Web sayfası başlığını alır' },
  { id: 'http-headers', cat: 'Keşif', desc: 'HTTP başlıklarını listeler' },
  { id: 'ssl-cert', cat: 'Keşif', desc: 'SSL sertifika bilgisi' },
  { id: 'ssh-hostkey', cat: 'Keşif', desc: 'SSH anahtar parmak izi' },
  { id: 'banner', cat: 'Keşif', desc: 'Servis banner bilgisi' },
  { id: 'smb-os-discovery', cat: 'Keşif', desc: 'SMB üzerinden OS tespiti' },
  { id: 'dns-brute', cat: 'Keşif', desc: 'Alt alan adı keşfi' },
  { id: 'ftp-anon', cat: 'Kimlik', desc: 'Anonim FTP girişi kontrolü' },
  { id: 'http-enum', cat: 'Keşif', desc: 'Web dizinlerini sayar' },
  { id: 'vulners', cat: 'Zafiyet', desc: 'Vulners veritabanı ile CVE eşleştirme' },
  { id: 'http-sql-injection', cat: 'Zafiyet', desc: 'SQL injection testi' },
  { id: 'smb-vuln-ms17-010', cat: 'Zafiyet', desc: 'EternalBlue (WannaCry) kontrolü' },
  { id: 'ssl-heartbleed', cat: 'Zafiyet', desc: 'Heartbleed zafiyeti' },
];
const DEVICE_ICONS = { router: '📶', phone: '📱', printer: '🖨️', camera: '📷', computer: '🖥️', unknown: '❓' };
const NAV_ICONS = { scan: '🎯', engagement: '🗂️', tools: '🧰', osint: '🌐', history: '🕘', scripts: '📜', settings: '⚙️' };

// Açık porta göre önerilen enumerasyon aracı (servise özel oto-enum).
const SERVICE_TOOLS = {
  '80': [{ tool: 'whatweb', label: 'WhatWeb' }, { tool: 'gobuster', label: 'Gobuster (dizin)' }, { tool: 'nikto', label: 'Nikto' }],
  '443': [{ tool: 'whatweb', label: 'WhatWeb' }, { tool: 'nikto', label: 'Nikto' }],
  '8080': [{ tool: 'whatweb', label: 'WhatWeb' }, { tool: 'gobuster', label: 'Gobuster' }],
  '8443': [{ tool: 'whatweb', label: 'WhatWeb' }],
  '139': [{ tool: 'enum4linux', label: 'enum4linux (SMB)' }],
  '445': [{ tool: 'enum4linux', label: 'enum4linux (SMB)' }],
};
function toolsForHost(host) {
  const set = {};
  (host.ports || []).filter((p) => p.state === 'open').forEach((p) => {
    (SERVICE_TOOLS[p.port] || []).forEach((x) => { set[x.tool + x.label] = x; });
  });
  return Object.values(set);
}

function ProfileIcon({ name }) {
  const c = 'currentColor';
  if (name === 'radar') return (
    <svg viewBox="0 0 48 48" width="44" height="44" fill="none" stroke={c} strokeWidth="2">
      <circle cx="24" cy="24" r="20" opacity=".35" />
      <circle cx="24" cy="24" r="13" opacity=".55" />
      <circle cx="24" cy="24" r="6" opacity=".8" />
      <line x1="24" y1="4" x2="24" y2="44" opacity=".25" />
      <line x1="4" y1="24" x2="44" y2="24" opacity=".25" />
      <path d="M24 24 L24 4 A20 20 0 0 1 42 16 Z" fill={c} opacity=".55" stroke="none" />
      <circle cx="24" cy="24" r="2.5" fill={c} stroke="none" />
    </svg>);
  if (name === 'server') return (
    <svg viewBox="0 0 48 48" width="44" height="44" fill="none" stroke={c} strokeWidth="2">
      <rect x="7" y="9" width="34" height="9" rx="2" />
      <rect x="7" y="20" width="34" height="9" rx="2" />
      <rect x="7" y="31" width="34" height="9" rx="2" />
      <circle cx="13" cy="13.5" r="1.4" fill={c} stroke="none" />
      <circle cx="13" cy="24.5" r="1.4" fill={c} stroke="none" />
      <circle cx="13" cy="35.5" r="1.4" fill={c} stroke="none" />
      <line x1="19" y1="13.5" x2="35" y2="13.5" opacity=".6" />
      <line x1="19" y1="24.5" x2="35" y2="24.5" opacity=".6" />
      <line x1="19" y1="35.5" x2="35" y2="35.5" opacity=".6" />
    </svg>);
  if (name === 'bolt') return (
    <svg viewBox="0 0 48 48" width="44" height="44" fill={c} stroke="none">
      <path d="M27 4 L10 27 L22 27 L19 44 L37 20 L25 20 Z" />
    </svg>);
  if (name === 'shield') return (
    <svg viewBox="0 0 48 48" width="44" height="44" fill="none" stroke={c} strokeWidth="2">
      <path d="M24 4 L40 10 V24 C40 34 32 42 24 44 C16 42 8 34 8 24 V10 Z" />
      <path d="M17 24 l5 5 9-11" stroke={c} strokeWidth="2.5" strokeLinecap="round" />
    </svg>);
  if (name === 'web') return (
    <svg viewBox="0 0 48 48" width="44" height="44" fill="none" stroke={c} strokeWidth="2">
      <circle cx="24" cy="24" r="18" />
      <ellipse cx="24" cy="24" rx="9" ry="18" />
      <line x1="6" y1="24" x2="42" y2="24" />
    </svg>);
  return null;
}

function VendorLogo({ vendor }) {
  const logos = window.VENDOR_LOGOS || {};
  const v = (vendor || '').toLowerCase();
  let hit = null;
  for (const kw of Object.keys(logos)) { if (v.includes(kw)) { hit = logos[kw]; break; } }
  if (!hit) {
    const initial = (vendor || '?').trim().charAt(0).toUpperCase();
    return <span className="vlogo-fallback">{initial}</span>;
  }
  return (
    <svg className="vlogo" viewBox="0 0 24 24" width="15" height="15" fill={hit.c} aria-hidden="true">
      <path d={hit.p} />
    </svg>
  );
}

function DeltaTag({ n, invert }) {
  if (n == null) return null;
  const up = n > 0, down = n < 0;
  // invert: artış kötü (zafiyet/port) -> kırmızı; azalış iyi -> yeşil
  const good = invert ? down : up;
  const color = n === 0 ? 'var(--muted)' : (good ? 'var(--green)' : 'var(--red)');
  const arrow = n === 0 ? '' : (up ? '▲' : '▼');
  return <span className="delta-tag" style={{ color }}>{arrow} {n > 0 ? '+' : ''}{n} vs son tarama</span>;
}

function Sparkline({ color, seed }) {
  const n = 12, w = 120, h = 32, pts = [];
  for (let i = 0; i < n; i++) {
    const r = Math.sin(seed * 9.7 + i * 1.3) * 18 + Math.cos(seed * 2.1 + i * 0.7) * 12;
    pts.push(30 + ((r + 60) % 50));
  }
  const max = Math.max(...pts), min = Math.min(...pts), rng = max - min || 1;
  const line = pts.map((p, i) => `${((i / (n - 1)) * w).toFixed(1)},${(h - ((p - min) / rng) * (h - 4) - 2).toFixed(1)}`).join(' ');
  return (
    <svg className="spark" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <polyline points={line} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

function stateColor(s) {
  if (s === 'open') return 'var(--green)';
  if (s === 'closed') return 'var(--red)';
  if (s === 'filtered') return 'var(--amber)';
  return 'var(--muted)';
}
function riskOf(host) {
  const n = (host.vulns || []).length;
  if (n >= 3) return { label: 'Yüksek', color: 'var(--red)' };
  if (n >= 1) return { label: 'Orta', color: 'var(--amber)' };
  return { label: 'Düşük', color: 'var(--green)' };
}
function isPrivate(target) {
  // CIDR/IP başlangıcına bak
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(target.trim()) ||
         /^localhost$/i.test(target.trim());
}

/* ============ Modallar ============ */
function EthicsModal({ onAccept }) {
  return (
    <div className="overlay"><div className="modal">
      <h2>⚠️ Kullanım Onayı</h2>
      <p>Bu araç ağ tarama yapar. <b>Yalnızca kendi ağınızda veya tarama yapmaya açıkça
      yetkili olduğunuz sistemlerde</b> kullanın. İzinsiz tarama yasalara aykırıdır.</p>
      <div className="actions"><button className="btn-accept" onClick={onAccept}>Anladım, kabul ediyorum</button></div>
    </div></div>
  );
}
function NmapMissingModal({ onInstall, onRecheck, progress, installing }) {
  return (
    <div className="overlay"><div className="modal">
      <h2>nmap bulunamadı</h2>
      <p>Tarama motoru <b>nmap</b> kurulu değil. Aşağıdaki butonla resmi kurulumu (Npcap dahil)
      otomatik indirip kurabilirsiniz. Bitince "Tekrar Kontrol Et"e basın.</p>
      {installing && (
        <div className="progress"><div className="progress-bar" style={{ width: progress + '%' }}></div>
          <span>{progress < 100 ? `İndiriliyor... %${progress}` : 'Kurulum başlatılıyor...'}</span></div>
      )}
      <div className="actions">
        <button className="btn-accept" onClick={onInstall} disabled={installing}>
          {installing ? 'Lütfen bekleyin...' : 'Otomatik İndir & Kur'}</button>
        <button className="btn-cancel" onClick={onRecheck}>Tekrar Kontrol Et</button>
      </div>
    </div></div>
  );
}

/* ============ Topoloji haritası ============ */
function Topology({ hosts, gateway, onSelect }) {
  const up = hosts.filter((h) => h.status === 'up');
  if (up.length === 0) return <div className="empty">Cihaz yok.</div>;
  const cx = 300, cy = 220, R = 160;
  const center = up.find((h) => h.ip === gateway) || up[0];
  const others = up.filter((h) => h !== center);
  return (
    <svg viewBox="0 0 600 440" className="topo">
      {others.map((h, i) => {
        const a = (2 * Math.PI * i) / others.length - Math.PI / 2;
        const x = cx + R * Math.cos(a), y = cy + R * Math.sin(a);
        const risk = riskOf(h);
        return (
          <g key={i} className="topo-node" onClick={() => onSelect(h)}>
            <line x1={cx} y1={cy} x2={x} y2={y} stroke="var(--border)" strokeWidth="2" />
            <circle cx={x} cy={y} r="22" fill="var(--panel-2)" stroke={risk.color} strokeWidth="2.5" />
            <text x={x} y={y + 5} textAnchor="middle" fontSize="18">{DEVICE_ICONS[h.deviceType]}</text>
            <text x={x} y={y + 40} textAnchor="middle" fontSize="11" fill="var(--text)">{h.ip}</text>
          </g>
        );
      })}
      <g className="topo-node" onClick={() => onSelect(center)}>
        <circle cx={cx} cy={cy} r="30" fill="var(--accent)" />
        <text x={cx} y={cy + 6} textAnchor="middle" fontSize="22">📶</text>
        <text x={cx} y={cy + 50} textAnchor="middle" fontSize="12" fill="var(--text)">{center.ip}</text>
      </g>
    </svg>
  );
}

/* ============ Cihaz detay paneli ============ */
function DeviceDetail({ host, t, onClose, onScan, onNuclei, onTool, onExploit, onShodan, onEvidence, onShot, note, onNote }) {
  if (!host) return null;
  const risk = riskOf(host);
  const enumTools = toolsForHost(host);
  return (
    <div className="detail-panel">
      <div className="detail-head">
        <span>{DEVICE_ICONS[host.deviceType]} {host.ip}</span>
        <button onClick={onClose}>✕</button>
      </div>
      <div className="detail-body">
        <button className="scan-device-btn" onClick={() => onScan(host.ip)}>🔍 Bu cihazı detaylı tara</button>
        <button className="nuclei-device-btn" onClick={() => onNuclei(host.ip)}>🛡️ Nuclei ile zafiyet tara</button>
        {enumTools.length > 0 && (
          <div className="enum-tools">
            <div className="et-label">⚙️ Oto-enumerasyon</div>
            {enumTools.map((x, i) => (
              <button key={i} className="enum-btn" onClick={() => onTool(x.tool, host.ip)}>{x.label}</button>
            ))}
          </div>
        )}
        <div className="dd-actions">
          <button className="dd-act" onClick={() => onShodan(host.ip)}>🛰️ Shodan</button>
          <button className="dd-act" onClick={() => onEvidence(host.ip)}>📁 Kanıt</button>
          <button className="dd-act" onClick={() => onShot(host.ip)}>📸 Ekran</button>
        </div>
        <h4>📝 Not</h4>
        <textarea className="note-area" placeholder="Bu cihaz hakkında not..." value={note || ''}
          onChange={(e) => onNote(host.ip, e.target.value)} />
        <div className="kv"><span>{t.netname}</span><b>{host.name || '-'}</b></div>
        <div className="kv"><span>{t.mac}</span><b>{host.mac || '-'}</b></div>
        <div className="kv"><span>{t.vendor}</span><b>{host.vendor || '-'}</b></div>
        <div className="kv"><span>{t.os}</span><b>{host.osGuess ? `${host.osGuess} (%${host.osAccuracy})` : '-'}</b></div>
        <div className="kv"><span>{t.risk}</span><b style={{ color: risk.color }}>{risk.label}</b></div>
        <h4>{t.openPorts} ({host.ports.length})</h4>
        {host.ports.length === 0 ? <p className="muted">-</p> : (
          <table className="results"><tbody>
            {host.ports.map((p, i) => (
              <tr key={i}><td><b>{p.port}</b>/{p.proto}</td>
                <td><span style={{ color: stateColor(p.state) }}>● {p.state}</span></td>
                <td>{p.service}</td>
                <td className="muted">{p.version || '-'}
                  {(p.version || p.service) && <button className="mini-exploit" title="Exploit ara"
                    onClick={() => onExploit((p.version || p.service))}>🔎</button>}</td></tr>
            ))}
          </tbody></table>
        )}
        {host.vulns.length > 0 && (
          <>
            <h4 style={{ color: 'var(--red)' }}>{t.vulns} ({host.vulns.length})</h4>
            <ul className="vuln-list">{host.vulns.map((v, i) =>
              <li key={i}><a href="#" onClick={(e) => { e.preventDefault(); window.open('https://nvd.nist.gov/vuln/detail/' + v.cve); }}>{v.cve}</a> (port {v.port})</li>)}</ul>
          </>
        )}
        {(() => {
          const tips = host.ports.filter((p) => p.state === 'open' && PORT_PLAYBOOK[p.port]);
          if (!tips.length) return null;
          return (
            <>
              <h4>🎯 Pentest Önerileri</h4>
              <ul className="play-list">
                {tips.map((p, i) => (
                  <li key={i}><b>{p.port}/{p.proto}</b> — {PORT_PLAYBOOK[p.port]}</li>
                ))}
              </ul>
            </>
          );
        })()}
      </div>
    </div>
  );
}

/* ============ Ana uygulama ============ */
function App() {
  const [accepted, setAccepted] = useState(false);
  const [settings, setSettings] = useState({ lang: 'tr', theme: 'dark', safeMode: true, timing: 'T4', monitor: 'off' });
  const [view, setView] = useState('scan');
  const [nmap, setNmap] = useState({ checked: false, installed: false, version: '' });
  const [admin, setAdmin] = useState(true);
  const [target, setTarget] = useState('');
  const [gateway, setGateway] = useState('');
  const [mode, setMode] = useState('simple');
  const [profile, setProfile] = useState(PROFILES[0]);
  const [profileCat, setProfileCat] = useState('general');
  const [adv, setAdv] = useState({ ports: '', timing: 'T4', noPing: false, udp: false, osDetect: false, svcVer: false });
  const [selScripts, setSelScripts] = useState([]);
  const [scriptQuery, setScriptQuery] = useState('');
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [output, setOutput] = useState('');
  const [result, setResult] = useState({ hosts: [] });
  const [statDelta, setStatDelta] = useState(null);
  const shownStatsRef = useRef({ hosts: 0, ports: 0, vulns: 0 });
  const [resTab, setResTab] = useState('list');
  const [selHost, setSelHost] = useState(null);
  const [status, setStatus] = useState('hazır');
  const [filterText, setFilterText] = useState('');
  const [sortBy, setSortBy] = useState({ key: 'ip', dir: 1 });
  const [page, setPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [notes, setNotes] = useState({});
  const [toasts, setToasts] = useState([]);
  const [installing, setInstalling] = useState(false);
  const [dlProgress, setDlProgress] = useState(0);
  const [history, setHistory] = useState([]);
  const [workspaces, setWorkspaces] = useState([]);
  const [activeWs, setActiveWs] = useState(null);
  const [wsAssets, setWsAssets] = useState({ hosts: [], services: [], vulns: [], scans: [] });
  const [wsAudit, setWsAudit] = useState([]);
  const [newWsName, setNewWsName] = useState('');
  const [wsl, setWsl] = useState({ checked: false, installed: false });
  const [toolCatalog, setToolCatalog] = useState([]);
  const [toolStatus, setToolStatus] = useState({ wsl: false, tools: {} });
  const [installLog, setInstallLog] = useState('');
  const [installingTool, setInstallingTool] = useState(null);
  const [nucleiTarget, setNucleiTarget] = useState('');
  const [nucleiSev, setNucleiSev] = useState('medium,high,critical');
  const [nucleiRunning, setNucleiRunning] = useState(false);
  const [nucleiFindings, setNucleiFindings] = useState([]);
  const [toolConsole, setToolConsole] = useState({ open: false, tool: '', target: '', output: '', running: false });
  const [masscanTarget, setMasscanTarget] = useState('');
  const [masscanPorts, setMasscanPorts] = useState('1-1000');
  const [exploitTerm, setExploitTerm] = useState('');
  const [exploitOut, setExploitOut] = useState('');
  const [exploitBusy, setExploitBusy] = useState(false);
  const [hydra, setHydra] = useState({ target: '', service: 'ssh', user: '', userList: '', passList: '' });
  const [hydraConfirm, setHydraConfirm] = useState(false);
  const [msfTerm, setMsfTerm] = useState('');
  const [msfResults, setMsfResults] = useState([]);
  const [msfBusy, setMsfBusy] = useState(false);
  const [msfRunModal, setMsfRunModal] = useState(null); // { module, target }
  const [osintDomain, setOsintDomain] = useState('');
  const [subdomains, setSubdomains] = useState([]);
  const [dnsRecords, setDnsRecords] = useState(null);
  const [shodanIp, setShodanIp] = useState('');
  const [shodanData, setShodanData] = useState(null);
  const [osintBusy, setOsintBusy] = useState('');
  const [evidence, setEvidence] = useState([]);
  const [diffPick, setDiffPick] = useState([]);
  const [diffResult, setDiffResult] = useState(null);
  const [avatarMenu, setAvatarMenu] = useState(false);
  const outputRef = useRef(null);
  const toolConsoleRef = useRef(null);
  const activeWsRef = useRef(null);
  const lastDevices = useRef([]);
  const monitorTimer = useRef(null);
  const targetRef = useRef('');

  const t = I18N[settings.lang];

  /* toast */
  const toast = (msg, type = 'info') => {
    const id = Date.now() + Math.random();
    setToasts((ts) => [...ts, { id, msg, type }]);
    setTimeout(() => setToasts((ts) => ts.filter((x) => x.id !== id)), 3500);
  };

  /* notlar (localStorage) */
  useEffect(() => {
    try { setNotes(JSON.parse(localStorage.getItem('deviceNotes') || '{}')); } catch (e) {}
  }, []);
  const saveNote = (ip, text) => {
    const next = { ...notes, [ip]: text };
    setNotes(next);
    localStorage.setItem('deviceNotes', JSON.stringify(next));
  };

  /* init */
  useEffect(() => {
    window.api.getSettings().then((s) => { setSettings((p) => ({ ...p, ...s })); });
    checkNmap();
    window.api.checkAdmin().then((r) => setAdmin(r.admin));
    window.api.localRange().then((r) => { if (r.ok) { setTarget(r.cidr); setGateway(r.gateway); } });
    refreshWorkspaces();
    window.api.wslCheck().then((r) => setWsl({ checked: true, installed: r.installed, distros: r.distros }));
    window.api.toolsCatalog().then(setToolCatalog);
    refreshTools();
    // nuclei + kurulum olayları
    window.api.onNucleiFinding((f) => setNucleiFindings((arr) => [...arr, f]));
    window.api.onNucleiDone(({ count }) => {
      setNucleiRunning(false);
      toast(`nuclei bitti: ${count} bulgu`, count > 0 ? 'warn' : 'success');
      const aws = activeWsRef.current;
      if (aws) { window.api.wsAssets(aws.id).then(setWsAssets); window.api.wsAudit(aws.id).then(setWsAudit); }
    });
    window.api.onToolsInstallOut((d) => setInstallLog((o) => o + d));
    window.api.onToolsInstallDone(() => { setInstallingTool(null); refreshTools(); toast('Kurulum tamamlandı', 'success'); });
    // genel araç konsolu
    window.api.onToolOut((d) => setToolConsole((c) => ({ ...c, output: c.output + d })));
    window.api.onToolDone(({ tool, code, count }) => {
      setToolConsole((c) => ({ ...c, running: false, output: c.output + `\n=== ${tool} bitti (kod ${code}) ===\n` }));
      if (tool === 'masscan') {
        toast(`masscan bitti: ${count} açık port`, 'success');
        const aws = activeWsRef.current;
        if (aws) { window.api.wsAssets(aws.id).then(setWsAssets); window.api.wsAudit(aws.id).then(setWsAudit); }
      } else toast(`${tool} tamamlandı`, 'success');
    });
  }, []);

  const runTool = async (tool, target, opts) => {
    if (!toolStatus.tools[tool]) { toast(`${tool} kurulu değil — Araçlar sekmesinden kurun`, 'error'); setView('tools'); return; }
    setToolConsole({ open: true, tool, target, output: '', running: true });
    const r = await window.api.toolRun({ tool, target, opts: opts || {} });
    if (!r.ok) { setToolConsole((c) => ({ ...c, running: false, output: 'Başlatılamadı: ' + r.error })); toast(r.error, 'error'); }
    else toast(`${tool} başladı`, 'info');
  };
  const runMasscan = () => {
    if (!masscanTarget.trim()) { toast('masscan hedefi girin', 'warn'); return; }
    runTool('masscan', masscanTarget.trim(), { ports: masscanPorts, rate: 1000 });
  };
  const searchExploit = async (term) => {
    const q = (term || exploitTerm).trim();
    if (!q) { toast('Arama terimi girin', 'warn'); return; }
    if (!toolStatus.tools.searchsploit) { toast('searchsploit kurulu değil', 'error'); setView('tools'); return; }
    setExploitTerm(q); setExploitBusy(true); setExploitOut(''); setView('tools');
    const r = await window.api.exploitSearch(q);
    setExploitBusy(false);
    setExploitOut(r.ok ? (r.output || 'Sonuç yok') : 'Hata: ' + r.error);
  };
  const runHydra = async () => {
    if (!hydra.target.trim()) { toast('Hydra hedefi girin', 'warn'); return; }
    setHydraConfirm(false);
    setToolConsole({ open: true, tool: 'hydra', target: hydra.target, output: '', running: true });
    const r = await window.api.hydraRun({ ...hydra, confirmed: true });
    if (!r.ok) { setToolConsole((c) => ({ ...c, running: false, output: 'Reddedildi: ' + r.error })); toast(r.error, 'error');
      const aws = activeWsRef.current; if (aws) window.api.wsAudit(aws.id).then(setWsAudit); }
  };
  const prepareRoot = async () => {
    toast('Distro hazırlanıyor (root)...', 'info');
    const r = await window.api.wslPrepareRoot();
    if (r.ok) { toast('Distro hazır: ' + r.output, 'success'); refreshTools(); }
    else toast('Hazırlama hatası: ' + r.error, 'error');
  };
  const searchMsf = async (term) => {
    const q = (term || msfTerm).trim();
    if (!q) { toast('Modül arama terimi girin', 'warn'); return; }
    if (!toolStatus.tools.msfconsole) { toast('Metasploit kurulu değil', 'error'); return; }
    setMsfTerm(q); setMsfBusy(true); setMsfResults([]);
    toast('Metasploit aranıyor (başlatması yavaştır)...', 'info');
    const r = await window.api.msfSearch(q);
    setMsfBusy(false);
    if (r.ok) { setMsfResults(r.modules); if (!r.modules.length) toast('Modül bulunamadı', 'warn'); }
    else toast('Arama hatası: ' + r.error, 'error');
  };
  const msfInfo = async (module) => {
    setToolConsole({ open: true, tool: 'msf info', target: module, output: 'Yükleniyor (msfconsole yavaş başlar)...', running: true });
    const r = await window.api.msfInfo(module);
    setToolConsole((c) => ({ ...c, running: false, output: r.ok ? r.output : 'Hata: ' + r.error }));
  };
  const runMsf = async () => {
    const m = msfRunModal; setMsfRunModal(null);
    setToolConsole({ open: true, tool: 'metasploit', target: m.target, output: '', running: true });
    const r = await window.api.msfRun({ module: m.module, target: m.target, options: [], confirmed: true });
    if (!r.ok) { setToolConsole((c) => ({ ...c, running: false, output: 'Reddedildi: ' + r.error })); toast(r.error, 'error');
      const aws = activeWsRef.current; if (aws) window.api.wsAudit(aws.id).then(setWsAudit); }
  };

  // OSINT
  const runSubdomains = async () => {
    if (!osintDomain.trim()) { toast('Alan adı girin', 'warn'); return; }
    setOsintBusy('sub'); setSubdomains([]);
    const r = await window.api.subdomains(osintDomain.trim());
    setOsintBusy('');
    if (r.ok) { setSubdomains(r.subdomains); toast(`${r.subdomains.length} subdomain bulundu`, 'success'); }
    else toast(r.error, 'error');
  };
  const runDns = async () => {
    if (!osintDomain.trim()) { toast('Alan adı girin', 'warn'); return; }
    setOsintBusy('dns'); setDnsRecords(null);
    const r = await window.api.dnsRecords(osintDomain.trim());
    setOsintBusy('');
    if (r.ok) setDnsRecords(r.records); else toast(r.error, 'error');
  };
  const runShodan = async (ip) => {
    const t = (ip || shodanIp).trim();
    if (!t) { toast('IP girin', 'warn'); return; }
    setShodanIp(t); setOsintBusy('shodan'); setShodanData(null); setView('osint');
    const r = await window.api.shodan(t);
    setOsintBusy('');
    if (r.ok) setShodanData(r.data); else toast('Shodan: ' + r.error, 'error');
  };

  // Kanıt
  const refreshEvidence = async () => { const aws = activeWsRef.current; if (aws) setEvidence(await window.api.evidenceList(aws.id)); };
  useEffect(() => { if (view === 'engagement') refreshEvidence(); }, [view, activeWs]);
  const addEvidence = async (hostIp) => { const r = await window.api.evidenceAdd({ hostIp: hostIp || '' }); if (r.ok) { toast('Kanıt eklendi', 'success'); refreshEvidence(); } };
  const shotEvidence = async (hostIp) => { const r = await window.api.evidenceShot({ hostIp: hostIp || '' }); if (r.ok) { toast('Ekran görüntüsü kaydedildi', 'success'); refreshEvidence(); } else toast(r.error, 'error'); };
  const delEvidence = async (id) => { await window.api.evidenceDelete(id); refreshEvidence(); };

  // Diff (karşılaştırmalı retest)
  const toggleDiffPick = (id) => setDiffPick((p) => p.includes(id) ? p.filter((x) => x !== id) : (p.length < 2 ? [...p, id] : [p[1], id]));
  const runDiff = async () => {
    if (diffPick.length !== 2) { toast('Karşılaştırmak için 2 tarama seçin', 'warn'); return; }
    const [r1, r2] = await Promise.all([window.api.historyGet(diffPick[0]), window.api.historyGet(diffPick[1])]);
    // Eski/yeni sırala (tarihe göre)
    const [oldR, newR] = (r1.date < r2.date) ? [r1, r2] : [r2, r1];
    const portSet = (rec) => { const s = new Set(); (rec.parsed.hosts || []).forEach((h) => (h.ports || []).forEach((p) => s.add(`${h.ip}:${p.port}/${p.proto}`))); return s; };
    const hostSet = (rec) => new Set((rec.parsed.hosts || []).filter((h) => h.status === 'up').map((h) => h.ip));
    const oh = hostSet(oldR), nh = hostSet(newR), op = portSet(oldR), np = portSet(newR);
    setDiffResult({
      oldDate: oldR.date, newDate: newR.date,
      newHosts: [...nh].filter((x) => !oh.has(x)),
      goneHosts: [...oh].filter((x) => !nh.has(x)),
      newPorts: [...np].filter((x) => !op.has(x)),
      gonePorts: [...op].filter((x) => !np.has(x)),
    });
  };

  const refreshTools = async () => { try { setToolStatus(await window.api.toolsCheck()); } catch (e) {} };
  const installTool = async (id) => {
    setInstallingTool(id); setInstallLog('');
    const r = await window.api.toolsInstall(id);
    if (!r.ok) { setInstallingTool(null); toast('Kurulum başlatılamadı: ' + r.error, 'error'); }
  };
  const installWsl = async () => {
    const r = await window.api.wslInstall();
    if (r.ok) toast('WSL kurulumu başladı (UAC). Bitince bilgisayarı YENİDEN BAŞLATIN.', 'info');
    else toast('WSL kurulumu başlatılamadı: ' + r.error, 'error');
  };
  const runNuclei = async (tgt) => {
    const target = tgt || nucleiTarget;
    if (!target.trim()) { toast('nuclei hedefi girin', 'warn'); return; }
    if (!toolStatus.tools.nuclei) { toast('nuclei kurulu değil — Araçlar sekmesinden kurun', 'error'); setView('tools'); return; }
    setNucleiFindings([]); setNucleiRunning(true);
    const r = await window.api.nucleiRun({ target: target.trim(), severity: nucleiSev });
    if (!r.ok) { setNucleiRunning(false); toast('nuclei başlatılamadı: ' + r.error, 'error'); }
    else toast('nuclei taraması başladı', 'info');
  };

  const refreshWorkspaces = async () => {
    const list = await window.api.wsList();
    const act = await window.api.wsActive();
    setWorkspaces(list); setActiveWs(act); activeWsRef.current = act;
    if (act) { setWsAssets(await window.api.wsAssets(act.id)); setWsAudit(await window.api.wsAudit(act.id)); }
  };
  const selectWs = async (id) => { await window.api.wsSetActive(id); await refreshWorkspaces(); };
  const createWs = async () => {
    if (!newWsName.trim()) { toast('Çalışma alanı adı girin', 'warn'); return; }
    await window.api.wsCreate({ name: newWsName.trim(), mode: 'lab', scope: target || '' });
    setNewWsName(''); await refreshWorkspaces(); toast('Çalışma alanı oluşturuldu', 'success');
  };
  const deleteWs = async (id) => { await window.api.wsDelete(id); await refreshWorkspaces(); toast('Silindi', 'info'); };
  const updateWsField = async (fields) => { if (!activeWs) return; await window.api.wsUpdate(activeWs.id, fields); await refreshWorkspaces(); };

  useEffect(() => { document.documentElement.dataset.theme = settings.theme; }, [settings.theme]);

  const checkNmap = async () => {
    const r = await window.api.checkNmap();
    setNmap({ checked: true, installed: r.installed, version: r.version || '' });
  };

  /* olaylar */
  useEffect(() => {
    window.api.onStdout((d) => setOutput((o) => o + d));
    window.api.onStderr((d) => setOutput((o) => o + d));
    window.api.onProgress((p) => setProgress(p));
    window.api.onError((err) => { setRunning(false); setStatus('hata'); setOutput((o) => o + `\n[HATA] ${err}\n`); });
    window.api.onDownloadProgress((p) => setDlProgress(p));
    window.api.onDone(async ({ code, parsed }) => {
      setRunning(false); setProgress(100);
      setStatus(code === 0 ? 'bitti' : 'hata');
      const res = parsed && parsed.hosts ? parsed : { hosts: [] };
      // V2: önceki taramaya göre delta
      const upH = res.hosts.filter((h) => h.status === 'up');
      const nu = { hosts: upH.length, ports: upH.reduce((a, h) => a + (h.ports || []).length, 0),
        vulns: upH.reduce((a, h) => a + (h.vulns || []).length, 0) };
      const prev = shownStatsRef.current;
      if (prev.hosts || prev.ports || prev.vulns) {
        setStatDelta({ hosts: nu.hosts - prev.hosts, ports: nu.ports - prev.ports, vulns: nu.vulns - prev.vulns });
      }
      setResult(res);
      // İzleme karşılaştırması
      const up = res.hosts.filter((h) => h.status === 'up').map((h) => h.ip);
      if (lastDevices.current.length) {
        const news = up.filter((ip) => !lastDevices.current.includes(ip));
        if (news.length) window.api.notify({ title: 'NmapGUI', body: `${news.length} ${t.newDevices}: ${news.join(', ')}` });
      }
      lastDevices.current = up;
      // Geçmişe kaydet
      window.api.historySave({ date: new Date().toISOString(), target: targetRef.current, command: commandTextRef.current, parsed: res });
      // Aktif workspace asset/audit tazele (main DB'ye yazdı)
      const aws = activeWsRef.current;
      if (aws) { window.api.wsAssets(aws.id).then(setWsAssets); window.api.wsAudit(aws.id).then(setWsAudit); }
    });
  }, []);

  useEffect(() => { if (outputRef.current) outputRef.current.scrollTop = outputRef.current.scrollHeight; }, [output]);
  useEffect(() => { if (toolConsoleRef.current) toolConsoleRef.current.scrollTop = toolConsoleRef.current.scrollHeight; }, [toolConsole.output]);

  /* komut argümanlarını üret */
  function buildArgs() {
    let a = [];
    if (mode === 'simple') { a = [...profile.args]; }
    else {
      if (adv.noPing) a.push('-Pn');
      if (adv.udp) a.push('-sU'); else a.push('-sS');
      if (adv.osDetect) a.push('-O');
      if (adv.svcVer) a.push('-sV');
      if (adv.ports) a.push('-p', adv.ports);
      a.push('-' + adv.timing);
      if (selScripts.length) a.push('--script', selScripts.join(','));
    }
    return a;
  }
  const baseArgs = buildArgs();
  const fullArgs = [...baseArgs, ...(target.trim() ? [target.trim()] : [])];
  const commandText = 'nmap ' + fullArgs.join(' ');
  const commandTextRef = useRef(commandText);
  commandTextRef.current = commandText;
  targetRef.current = target;

  const upHosts = result.hosts.filter((h) => h.status === 'up');
  const allPorts = [];
  upHosts.forEach((h) => h.ports.forEach((p) => allPorts.push({ host: h.ip, ...p })));
  // Pentest bulguları özeti
  const allCves = [];
  upHosts.forEach((h) => h.vulns.forEach((v) => allCves.push({ host: h.ip, ...v })));
  const interesting = allPorts.filter((p) => p.state === 'open' && PORT_PLAYBOOK[p.port]);
  const highRiskHosts = upHosts.filter((h) => h.vulns.length > 0);
  shownStatsRef.current = { hosts: upHosts.length, ports: allPorts.length, vulns: allCves.length };

  // Filtre + sıralama
  const viewHosts = upHosts.filter((h) => {
    if (!filterText.trim()) return true;
    const q = filterText.toLowerCase();
    return [h.ip, h.name, h.mac, h.vendor, h.deviceType, notes[h.ip]].some((x) => (x || '').toLowerCase().includes(q));
  }).sort((a, b) => {
    const k = sortBy.key;
    let av, bv;
    if (k === 'ports') { av = a.ports.length; bv = b.ports.length; }
    else if (k === 'risk') { av = a.vulns.length; bv = b.vulns.length; }
    else { av = (a[k] || '').toString(); bv = (b[k] || '').toString(); }
    if (typeof av === 'number') return (av - bv) * sortBy.dir;
    return av.localeCompare(bv, undefined, { numeric: true }) * sortBy.dir;
  });
  const setSort = (key) => setSortBy((s) => ({ key, dir: s.key === key ? -s.dir : 1 }));
  const sortArrow = (key) => sortBy.key === key ? (sortBy.dir === 1 ? ' ▲' : ' ▼') : '';
  const totalPages = Math.max(1, Math.ceil(viewHosts.length / rowsPerPage));
  const curPage = Math.min(page, totalPages);
  const pagedHosts = viewHosts.slice((curPage - 1) * rowsPerPage, curPage * rowsPerPage);

  const scanDevice = (ip) => {
    setTarget(ip); setMode('simple'); setProfileCat('pentest');
    const p = PROFILES.find((x) => x.id === 'srv-full') || profile;
    setProfile(p); setSelHost(null);
    setTimeout(() => { handleStartWith([...p.args, ip]); }, 50);
  };

  /* aksiyonlar */
  const handleStartWith = async (args) => {
    const tgt = args[args.length - 1] || '';
    // Engagement modu: scope enforcement
    if (activeWs && activeWs.mode === 'engagement') {
      const ok = inScopeList(tgt, activeWs.scope);
      if (ok === null) { toast(t.scopeWarn, 'warn'); return; }
      if (ok === false) {
        toast(t.scopeBlock, 'error');
        window.api.wsLogAudit(activeWs.id, 'blocked', `Kapsam dışı hedef engellendi: ${tgt}`);
        window.api.wsAudit(activeWs.id).then(setWsAudit);
        return;
      }
    } else if (settings.safeMode && !isPrivate(tgt)) { toast(t.safeBlock, 'warn'); return; }
    setOutput(''); setProgress(0); setResult({ hosts: [] }); setSelHost(null);
    setStatus('çalışıyor'); setRunning(true); setResTab('list');
    const r = await window.api.startScan(args);
    if (!r.ok) { setRunning(false); setStatus('hata'); toast('Tarama başlatılamadı: ' + r.error, 'error'); }
    else toast('Tarama başladı', 'info');
  };
  const handleStart = () => {
    if (!target.trim()) { toast('Lütfen bir hedef girin.', 'warn'); return; }
    handleStartWith(fullArgs);
  };
  const handleStop = async () => { await window.api.stopScan(); setRunning(false); setStatus('hazır'); };
  const handleFindNetwork = async () => {
    const r = await window.api.localRange();
    if (r.ok) { setTarget(r.cidr); setGateway(r.gateway); setMode('simple'); setProfile(PROFILES[0]); }
  };
  const saveSettings = async (s) => { setSettings(s); await window.api.saveSettings(s); };
  const handleInstall = async () => {
    setInstalling(true); setDlProgress(0);
    const r = await window.api.installNmap();
    if (!r.ok) toast('Kurulum başlatılamadı: ' + (r.error || ''), 'error');
    setInstalling(false);
  };

  const loadHistory = async () => setHistory(await window.api.historyList());
  useEffect(() => { if (view === 'history') loadHistory(); }, [view]);
  const openHistory = async (id) => {
    const rec = await window.api.historyGet(id);
    if (rec) { setResult(rec.parsed || { hosts: [] }); setTarget(rec.target || ''); setView('scan'); setResTab('list'); }
  };
  const deleteHistory = async (id) => { await window.api.historyDelete(id); loadHistory(); };

  const downloadBlob = (content, type, ext) => {
    const blob = new Blob([content], { type }); const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `nmap-${Date.now()}.${ext}`; a.click(); URL.revokeObjectURL(url);
  };
  const handleExport = () => downloadBlob(JSON.stringify({ target, command: commandText, date: new Date().toISOString(), result }, null, 2), 'application/json', 'json');
  const handleExportCsv = () => {
    const head = 'host,hostname,mac,vendor,type,port,proto,state,service,version,risk\n';
    const lines = [];
    upHosts.forEach((h) => {
      const r = riskOf(h).label;
      if (h.ports.length === 0) lines.push([h.ip, h.name, h.mac, h.vendor, h.deviceType, '', '', '', '', '', r].join(','));
      h.ports.forEach((p) => lines.push([h.ip, h.name, h.mac, h.vendor, h.deviceType, p.port, p.proto, p.state, p.service, (p.version || '').replace(/,/g, ' '), r].join(',')));
    });
    downloadBlob(head + lines.join('\n'), 'text/csv', 'csv');
  };
  const handleSaveRaw = () => downloadBlob(output, 'text/plain', 'txt');
  const handleCopyCmd = () => { navigator.clipboard.writeText(commandText); toast('Komut panoya kopyalandı', 'success'); };
  const handlePdf = async () => {
    const rows = upHosts.map((h) => `<tr><td>${h.ip}</td><td>${h.name || '-'}</td><td>${h.mac || '-'}</td><td>${h.vendor || '-'}</td><td>${h.ports.length}</td><td>${riskOf(h).label}</td></tr>`).join('');
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><style>
      body{font-family:Segoe UI,sans-serif;padding:30px;color:#111}h1{color:#1e3a5f}
      .meta{color:#555;font-size:13px;margin-bottom:20px}table{width:100%;border-collapse:collapse;font-size:13px}
      th{background:#1e3a5f;color:#fff;text-align:left;padding:8px}td{padding:7px 8px;border-bottom:1px solid #ddd}
      .foot{margin-top:24px;color:#888;font-size:11px}</style></head><body>
      <h1>🛰️ Nmap Tarama Raporu</h1>
      <div class="meta"><b>Hedef:</b> ${target}<br><b>Komut:</b> ${commandText}<br>
      <b>Tarih:</b> ${new Date().toLocaleString('tr-TR')}<br><b>Cihaz:</b> ${upHosts.length} · <b>Açık port:</b> ${allPorts.length}</div>
      <table><thead><tr><th>IP</th><th>Ağ Adı</th><th>MAC</th><th>Üretici</th><th>Port</th><th>Risk</th></tr></thead>
      <tbody>${rows || '<tr><td colspan=6>Sonuç yok</td></tr>'}</tbody></table>
      <div class="foot">NmapGUI ile üretildi.</div></body></html>`;
    const r = await window.api.savePdf(html);
    if (r.ok) toast('PDF kaydedildi: ' + r.path, 'success'); else if (r.error !== 'iptal') toast('Hata: ' + r.error, 'error');
  };

  /* otomatik izleme */
  useEffect(() => {
    if (monitorTimer.current) clearInterval(monitorTimer.current);
    if (settings.monitor && settings.monitor !== 'off') {
      const mins = parseInt(settings.monitor, 10);
      monitorTimer.current = setInterval(() => {
        if (!running && nmap.installed && target.trim()) { setMode('simple'); setProfile(PROFILES[0]); handleStart(); }
      }, mins * 60 * 1000);
    }
    return () => { if (monitorTimer.current) clearInterval(monitorTimer.current); };
  }, [settings.monitor, running, nmap.installed, target]);

  if (!accepted) return <EthicsModal onAccept={() => setAccepted(true)} />;

  const filteredScripts = NSE_SCRIPTS.filter((s) =>
    s.id.includes(scriptQuery.toLowerCase()) || s.cat.toLowerCase().includes(scriptQuery.toLowerCase()));

  return (
    <div className="app">
      <div className="toasts">
        {toasts.map((ts) => <div key={ts.id} className={'toast ' + ts.type}>{ts.msg}</div>)}
      </div>

      {toolConsole.open && (
        <div className="overlay" onClick={(e) => { if (e.target.className === 'overlay') setToolConsole((c) => ({ ...c, open: false })); }}>
          <div className="console-modal">
            <div className="console-head">
              <span>🖥️ {toolConsole.tool} → {toolConsole.target} {toolConsole.running && <span className="run-pulse">● çalışıyor</span>}</span>
              <div>
                {toolConsole.running && <button onClick={() => window.api.toolStop()}>■ Durdur</button>}
                <button onClick={() => setToolConsole((c) => ({ ...c, open: false }))}>✕</button>
              </div>
            </div>
            <pre className="console-body" ref={toolConsoleRef}>{toolConsole.output || 'Başlatılıyor...'}</pre>
          </div>
        </div>
      )}
      <header>
        <img className="logo-img" src="logo.png" alt="nmapGUI" />
        <div className="brand">
          <h1><span className="b-red">nmap</span><span className="b-light">GUI</span></h1>
          <div className="brand-sub">Network Exploration &amp; Security Scanner</div>
        </div>
        <nav className="topnav">
          {['scan', 'engagement', 'tools', 'osint', 'history', 'scripts', 'settings'].map((v) => (
            <button key={v} className={view === v ? 'active' : ''} onClick={() => setView(v)}>
              <span className="nav-ic">{NAV_ICONS[v]}</span>{t[v]}</button>
          ))}
        </nav>
        <div className="hbar">
          {activeWs && (
            <div className="ws-box">
              <span className="ws-ic">🗂️</span>
              <div className="ws-inner">
                <div className="ws-mini">{t.workspace}</div>
                <select value={activeWs.id} onChange={(e) => selectWs(parseInt(e.target.value, 10))}>
                  {workspaces.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
                </select>
              </div>
              <span className={'mode-chip ' + activeWs.mode}>{activeWs.mode === 'engagement' ? '🎯' : '🧪'}</span>
            </div>
          )}
          {/* Engine (tarama motoru) */}
          <div className={'hpill ' + (running ? 'run' : nmap.installed ? 'ok' : 'bad')} title={nmap.version || ''}>
            <span className="hp-dot"></span>
            <div className="hp-txt"><div className="hp-l1">Tarama Motoru</div>
              <div className="hp-l2">{running ? 'Çalışıyor' : nmap.installed ? 'Hazır' : 'Yok'}</div></div>
          </div>
          {/* Database */}
          <div className="hpill ok" title="SQLite asset graph">
            <span className="hp-dot"></span>
            <div className="hp-txt"><div className="hp-l1">Veritabanı</div><div className="hp-l2">Güncel</div></div>
          </div>
          {wsl.checked && <span className={'mini-badge ' + (wsl.installed ? 'ok' : 'bad')} title="WSL2">WSL {wsl.installed ? '✓' : '✕'}</span>}
          {!admin && <span className="mini-badge warn" title={t.adminWarn}>admin?</span>}
          <div className="avatar-wrap">
            <button className={'avatar-box' + (avatarMenu ? ' open' : '')} onClick={() => setAvatarMenu((v) => !v)}>
              <img className="avatar-img" src="logo.png" alt="nmapGUI" />
              <span className="av-chev">▾</span>
            </button>
            {avatarMenu && (
              <>
                <div className="av-overlay" onClick={() => setAvatarMenu(false)}></div>
                <div className="av-menu">
                  <div className="av-menu-head">
                    <img src="logo.png" alt="" />
                    <div><div className="avm-name">nmapGUI</div><div className="avm-sub">{nmap.version || 'nmap 7.95'}</div></div>
                  </div>
                  <button className="av-item" onClick={() => { setView('settings'); setAvatarMenu(false); }}>⚙️ Ayarlar</button>
                  <button className="av-item" onClick={() => { saveSettings({ ...settings, theme: settings.theme === 'dark' ? 'light' : 'dark' }); }}>
                    {settings.theme === 'dark' ? '☀️ Açık tema' : '🌙 Koyu tema'}</button>
                  <button className="av-item" onClick={() => { saveSettings({ ...settings, lang: settings.lang === 'tr' ? 'en' : 'tr' }); }}>
                    🌐 Dil: {settings.lang === 'tr' ? 'Türkçe → English' : 'English → Türkçe'}</button>
                  <button className="av-item" onClick={() => { checkNmap(); refreshTools(); window.api.checkAdmin().then((r) => setAdmin(r.admin)); toast('Durum yenilendi', 'info'); setAvatarMenu(false); }}>🔄 Durumu yenile</button>
                  <div className="av-sep"></div>
                  <button className="av-item" onClick={() => { window.api.openDownload(); setAvatarMenu(false); }}>↗ nmap.org</button>
                  <button className="av-item" onClick={() => { toast('NmapGUI · Pentest Orkestratörü · Frontend 1.4.0', 'info'); setAvatarMenu(false); }}>ℹ️ Hakkında</button>
                </div>
              </>
            )}
          </div>
          <div className="win-ctrl">
            <button className="wc-btn" onClick={() => window.api.winMinimize()} title="Küçült">─</button>
            <button className="wc-btn" onClick={() => window.api.winMaximize()} title="Büyüt">▢</button>
            <button className="wc-btn wc-close" onClick={() => window.api.winClose()} title="Kapat">✕</button>
          </div>
        </div>
      </header>

      {nmap.checked && !nmap.installed && view === 'scan' && (
        <NmapMissingModal onInstall={handleInstall} onRecheck={checkNmap} progress={dlProgress} installing={installing} />
      )}

      {/* ---------- SCAN VIEW ---------- */}
      {view === 'scan' && (
        <div className="main">
          <div className="sidebar">
            {!admin && (
              <div className="admin-warn">{t.adminWarn}
                <button onClick={() => window.api.relaunchAdmin()}>{t.runAdmin}</button></div>
            )}
            <div className="sb-section-lbl">TARGET</div>
            <div className="sb-target-lbl">Hedef (CIDR, IP veya hostname)</div>
            <div className="sb-target-input">
              <input type="text" value={target} onChange={(e) => setTarget(e.target.value)}
                placeholder="192.168.0.0/24" />
              <button className="sb-target-aim" onClick={handleFindNetwork} title={t.findNet}>
                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="3" />
                  <line x1="12" y1="2" x2="12" y2="6" /><line x1="12" y1="18" x2="12" y2="22" />
                  <line x1="2" y1="12" x2="6" y2="12" /><line x1="18" y1="12" x2="22" y2="12" /></svg>
              </button>
            </div>

            <div className="sb-section-head">
              <div className="sb-section-lbl">Tarama Profilleri</div>
              <button className="sb-plus" title="Profil ekle" onClick={() => setMode('advanced')}>+</button>
            </div>
            <div className="cat-switch sb-cat">
              <button className={profileCat === 'general' ? 'active' : ''} onClick={() => setProfileCat('general')}>🌐 Genel</button>
              <button className={profileCat === 'pentest' ? 'active' : ''} onClick={() => setProfileCat('pentest')}>🎯 Pentest</button>
            </div>
            {mode === 'simple' ? (
              <div className="sb-profiles">
                {PROFILES.filter((p) => p.cat === profileCat).map((p) => {
                  const active = profile.id === p.id;
                  return (
                    <button key={p.id} className={'sb-profile' + (active ? ' active' : '')} onClick={() => setProfile(p)}>
                      <div className="sp-icon"><ProfileIcon name={p.icon || 'server'} /></div>
                      <div className="sp-body">
                        <div className="sp-head">
                          <span className="sp-title">{p.title}</span>
                          {active ? <span className="sp-radio on">✓</span> : <span className="sp-radio" />}
                        </div>
                        {p.recommended && <div className="sp-rec">Önerilen</div>}
                        <div className="sp-desc">{p.desc}</div>
                        <div className="sp-tags">
                          {(p.tags || []).map((tg, i) => (
                            <span key={i} className={'sp-tag ' + tg.tone}>
                              {tg.tone === 'time' && '🕒 '}{tg.label}
                            </span>
                          ))}
                        </div>
                      </div>
                    </button>);
                })}
              </div>
            ) : (
              <div className="field adv">
                <label>{t.portRange}</label>
                <input type="text" value={adv.ports} onChange={(e) => setAdv({ ...adv, ports: e.target.value })} placeholder="1-1000 veya 80,443" />
                <div className="presets">{PORT_PRESETS.map((pp) => (
                  <button key={pp.name} onClick={() => setAdv({ ...adv, ports: pp.ports })}>{pp.name}</button>))}</div>
                <label>{t.timing}</label>
                <select value={adv.timing} onChange={(e) => setAdv({ ...adv, timing: e.target.value })}>
                  {['T0','T1','T2','T3','T4','T5'].map((x) => <option key={x}>{x}</option>)}</select>
                <label className="chk"><input type="checkbox" checked={adv.noPing} onChange={(e) => setAdv({ ...adv, noPing: e.target.checked })} /> {t.noPing}</label>
                <label className="chk"><input type="checkbox" checked={adv.udp} onChange={(e) => setAdv({ ...adv, udp: e.target.checked })} /> {t.udp}</label>
                <label className="chk"><input type="checkbox" checked={adv.osDetect} onChange={(e) => setAdv({ ...adv, osDetect: e.target.checked })} /> {t.osDetect}</label>
                <label className="chk"><input type="checkbox" checked={adv.svcVer} onChange={(e) => setAdv({ ...adv, svcVer: e.target.checked })} /> {t.svcVer}</label>
                {selScripts.length > 0 && <div className="sel-scripts">{t.selScripts}: {selScripts.join(', ')}</div>}
              </div>
            )}

            <details className="sb-options">
              <summary><span>⚙️ Tarama Seçenekleri</span></summary>
              <div className="sb-options-body">
                <div className="cmd-preview" style={{ marginTop: 8 }}>
                  <div className="label">{t.command}
                    <button className="copy-btn" onClick={handleCopyCmd} title="Panoya kopyala">⧉</button></div>
                  {commandText}
                </div>
              </div>
            </details>

            {running ? (
              <button className="sb-start danger" onClick={handleStop}><span className="sb-start-ic">■</span> DURDUR</button>
            ) : (
              <button className="sb-start" onClick={handleStart} disabled={!nmap.installed}><span className="sb-start-ic">▶</span> TARAMAYI BAŞLAT</button>
            )}
            {running && <div className="progress mini"><div className="progress-bar" style={{ width: progress + '%' }}></div><span>%{progress.toFixed(0)}</span></div>}

            <button className="sb-template" onClick={() => toast('Şablon kaydı yakında', 'info')}>
              <span className="sb-template-ic">⎘</span> ŞABLON OLARAK KAYDET</button>

            <div className="sb-foot">
              <div className="sb-foot-left"><span className="sb-eye">👁</span> nmap</div>
              <div className="sb-foot-right">
                <div>NMAP {nmap.version ? (nmap.version.match(/[\d.]+/) || ['7.95'])[0] : '7.95'}</div>
                <div>Frontend 1.4.0</div>
              </div>
            </div>
          </div>

          <div className="content">
            <div className="status-bar">
              <span className={'dot ' + (running ? 'running' : (status === 'bitti' ? 'done' : ''))}></span>
              <span>{t.status}: {status}</span>
              {upHosts.length > 0 && <span className="count">{upHosts.length} {t.device}</span>}
              {allPorts.length > 0 && <span className="count">{allPorts.length} {t.port}</span>}
              <div className="tabs">
                <button className={resTab === 'list' ? 'active' : ''} onClick={() => setResTab('list')}>{t.list}</button>
                <button className={resTab === 'topo' ? 'active' : ''} onClick={() => setResTab('topo')}>{t.topology}</button>
                <button className={resTab === 'raw' ? 'active' : ''} onClick={() => setResTab('raw')}>{t.raw}</button>
              </div>
              <button className="export" onClick={handleExport} disabled={!result.hosts.length}>{t.exportJson}</button>
              <button className="export" onClick={handleExportCsv} disabled={!result.hosts.length}>📑 CSV</button>
              <button className="export" onClick={handleSaveRaw} disabled={!output}>📃 TXT</button>
              <button className="export" onClick={handlePdf} disabled={!result.hosts.length}>{t.exportPdf}</button>
            </div>

            <div className="content-row">
              <div className="results-main">
                {resTab === 'list' && (
                  <div className="output table-wrap">
                    {upHosts.length === 0 ? <div className="empty">{running ? t.scanning : t.noResult}</div> : (
                      <div className="results-area">
                        <div className="v2-stats">
                          <div className="v2-stat">
                            <div className="v2-s-top"><div><div className="v2-s-num">{upHosts.length}</div><div className="v2-s-lbl">CANLI HOST</div></div>
                              <span className="v2-s-ic">🖥️</span></div>
                            <DeltaTag n={statDelta && statDelta.hosts} />
                            <Sparkline color="var(--accent)" seed={3} /></div>
                          <div className="v2-stat">
                            <div className="v2-s-top"><div><div className="v2-s-num">{allPorts.length}</div><div className="v2-s-lbl">AÇIK PORT</div></div>
                              <span className="v2-s-ic">🔌</span></div>
                            <DeltaTag n={statDelta && statDelta.ports} invert />
                            <Sparkline color="var(--orange)" seed={7} /></div>
                          <div className="v2-stat danger">
                            <div className="v2-s-top"><div><div className="v2-s-num" style={{ color: 'var(--red)' }}>{allCves.length}</div><div className="v2-s-lbl">ZAFİYET</div></div>
                              <span className="v2-s-ic">🛡️</span></div>
                            <DeltaTag n={statDelta && statDelta.vulns} invert />
                            <Sparkline color="var(--red)" seed={11} /></div>
                        </div>
                        {(allCves.length > 0 || interesting.length > 0) && (
                          <div className="findings">
                            <div className="f-title">🎯 Pentest Bulguları</div>
                            <div className="f-grid">
                              <div className="f-stat"><b>{upHosts.length}</b><span>canlı host</span></div>
                              <div className="f-stat"><b>{allPorts.length}</b><span>açık port</span></div>
                              <div className="f-stat danger"><b>{allCves.length}</b><span>CVE bulgusu</span></div>
                              <div className="f-stat warn"><b>{highRiskHosts.length}</b><span>riskli host</span></div>
                            </div>
                            {allCves.length > 0 && (
                              <div className="f-cves">
                                {allCves.slice(0, 12).map((c, i) => (
                                  <a key={i} href="#" onClick={(e) => { e.preventDefault(); window.open('https://nvd.nist.gov/vuln/detail/' + c.cve); }}>
                                    {c.cve} <span>({c.host}:{c.port})</span></a>
                                ))}
                                {allCves.length > 12 && <span className="more">+{allCves.length - 12} daha</span>}
                              </div>
                            )}
                            {interesting.length > 0 && (
                              <div className="f-svc">İlgi çekici servisler: {[...new Set(interesting.map((p) => `${p.service || p.port}`))].join(', ')}</div>
                            )}
                          </div>
                        )}
                        <div className="section-head">
                          <h3 className="section-title">📡 {t.devices} ({viewHosts.length}/{upHosts.length})</h3>
                          <input className="filter-input" placeholder="🔎 Filtrele (IP, MAC, üretici, not...)"
                            value={filterText} onChange={(e) => setFilterText(e.target.value)} />
                        </div>
                        <table className="results v2-table"><thead><tr>
                          <th className="sortable" onClick={() => setSort('ip')}>IP ADRESİ{sortArrow('ip')}</th>
                          <th className="sortable" onClick={() => setSort('vendor')}>ÜRETİCİ{sortArrow('vendor')}</th>
                          <th className="sortable" onClick={() => setSort('mac')}>MAC ADRESİ{sortArrow('mac')}</th>
                          <th className="sortable" onClick={() => setSort('deviceType')}>CİHAZ TÜRÜ{sortArrow('deviceType')}</th>
                          <th>AÇIK PORTLAR</th>
                          <th className="sortable" onClick={() => setSort('ports')}>{sortArrow('ports') || ''}#</th>
                          <th className="sortable" onClick={() => setSort('risk')}>RİSK{sortArrow('risk')}</th>
                          <th>SON GÖRÜLME</th></tr></thead>
                          <tbody>{pagedHosts.map((h, i) => { const r = riskOf(h); return (
                            <tr key={i} className={'clickable' + (selHost && selHost.ip === h.ip ? ' selected' : '')} onClick={() => setSelHost(h)}>
                              <td><span className="row-dot"></span><b className="mono">{h.ip}</b>
                                {h.source === 'arp' && <span className="src-tag" title="ARP tablosundan">ARP</span>}
                                {notes[h.ip] && <span className="note-dot" title={notes[h.ip]}>📝</span>}</td>
                              <td><span className="vendor-cell"><VendorLogo vendor={h.vendor} /><span className="muted">{h.vendor || '—'}</span></span></td>
                              <td className="muted mono">{h.mac || '—'}</td>
                              <td><span className="dt-cell">{DEVICE_ICONS[h.deviceType]} <span className="muted">{h.deviceType}</span></span></td>
                              <td className="muted mono small">{h.ports.length ? h.ports.slice(0, 5).map((p) => p.port).join(', ') + (h.ports.length > 5 ? '…' : '') : '—'}</td>
                              <td className="muted">{h.ports.length || '—'}</td>
                              <td><span className="risk-pill" style={{ background: r.color + '22', color: r.color }}>{r.label}</span></td>
                              <td className="muted small">şimdi</td></tr>); })}</tbody>
                        </table>
                        <div className="pager">
                          <span className="pager-info">{viewHosts.length === 0 ? '0' : ((curPage - 1) * rowsPerPage + 1)}–{Math.min(curPage * rowsPerPage, viewHosts.length)} / {viewHosts.length} cihaz</span>
                          <div className="pager-nav">
                            <button disabled={curPage <= 1} onClick={() => setPage(1)}>«</button>
                            <button disabled={curPage <= 1} onClick={() => setPage(curPage - 1)}>‹</button>
                            <span className="pager-cur">{curPage} / {totalPages}</span>
                            <button disabled={curPage >= totalPages} onClick={() => setPage(curPage + 1)}>›</button>
                            <button disabled={curPage >= totalPages} onClick={() => setPage(totalPages)}>»</button>
                            <select value={rowsPerPage} onChange={(e) => { setRowsPerPage(parseInt(e.target.value, 10)); setPage(1); }}>
                              <option value={10}>10 / sayfa</option><option value={25}>25 / sayfa</option><option value={50}>50 / sayfa</option>
                            </select>
                          </div>
                        </div>
                        {allPorts.length > 0 && (<>
                          <h3 className="section-title">🔓 {t.openPorts} ({allPorts.length})</h3>
                          <table className="results"><thead><tr>
                            <th>Host</th><th>{t.portCol}</th><th>{t.proto}</th><th>{t.state}</th><th>{t.service}</th><th>{t.version}</th></tr></thead>
                            <tbody>{allPorts.map((p, i) => (
                              <tr key={i}><td>{p.host}</td><td><b>{p.port}</b></td><td>{p.proto}</td>
                                <td><span style={{ color: stateColor(p.state) }}>● {p.state}</span></td>
                                <td>{p.service}</td><td className="muted">{p.version || '-'}</td></tr>))}</tbody>
                          </table></>)}
                      </div>
                    )}
                  </div>
                )}
                {resTab === 'topo' && (
                  <div className="output"><Topology hosts={result.hosts} gateway={gateway} onSelect={setSelHost} /></div>
                )}
                {resTab === 'raw' && (
                  <div className="output" ref={outputRef}>{output || 'Ham nmap çıktısı burada görünecek.'}</div>
                )}
              </div>
              {selHost && <DeviceDetail host={selHost} t={t} onClose={() => setSelHost(null)}
                onScan={scanDevice} onNuclei={(ip) => { setNucleiTarget(ip); setView('tools'); runNuclei(ip); }}
                onTool={(tool, ip) => runTool(tool, ip)}
                onExploit={(term) => searchExploit(term)}
                onShodan={(ip) => runShodan(ip)}
                onEvidence={(ip) => addEvidence(ip)} onShot={(ip) => shotEvidence(ip)}
                note={notes[selHost.ip]} onNote={saveNote} />}
            </div>
          </div>
        </div>
      )}

      {/* ---------- ENGAGEMENT VIEW ---------- */}
      {view === 'engagement' && activeWs && (
        <div className="page">
          <div className="eng-top">
            <h2>🎯 {t.engagement}: {activeWs.name}</h2>
            <button className="primary report-btn" onClick={async () => {
              const r = await window.api.reportPro(activeWs.id);
              if (r.ok) toast('Profesyonel rapor kaydedildi: ' + r.path, 'success');
              else if (r.error !== 'iptal') toast('Rapor hatası: ' + r.error, 'error');
            }}>📄 Profesyonel Rapor (PDF)</button>
          </div>

          <div className="eng-grid">
            <div className="eng-card">
              <label>{t.mode}</label>
              <div className="mode-switch">
                <button className={activeWs.mode === 'lab' ? 'active' : ''} onClick={() => updateWsField({ mode: 'lab' })}>🧪 {t.lab}</button>
                <button className={activeWs.mode === 'engagement' ? 'active' : ''} onClick={() => updateWsField({ mode: 'engagement' })}>🎯 {t.engMode}</button>
              </div>
              <label style={{ marginTop: 12 }}>{t.scope}</label>
              <input type="text" defaultValue={activeWs.scope} placeholder={t.scopeHint}
                onBlur={(e) => updateWsField({ scope: e.target.value })} />
              <p className="muted small">{t.scopeHint}</p>
            </div>

            <div className="eng-card">
              <label>{t.newWs}</label>
              <input type="text" value={newWsName} onChange={(e) => setNewWsName(e.target.value)} placeholder={t.wsName} />
              <button className="primary" style={{ marginTop: 10 }} onClick={createWs}>+ {t.createWs}</button>
              <div className="ws-list">
                {workspaces.map((w) => (
                  <div key={w.id} className={'ws-row' + (w.id === activeWs.id ? ' active' : '')}>
                    <span onClick={() => selectWs(w.id)}>{w.id === activeWs.id ? '● ' : '○ '}{w.name} <i>({w.mode})</i></span>
                    {workspaces.length > 1 && <button onClick={() => deleteWs(w.id)}>✕</button>}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="stat-cards">
            <div className="stat-card"><b>{wsAssets.hosts.length}</b><span>{t.totalHosts}</span></div>
            <div className="stat-card"><b>{wsAssets.services.length}</b><span>{t.totalServices}</span></div>
            <div className="stat-card danger"><b>{wsAssets.vulns.length}</b><span>{t.totalVulns}</span></div>
            <div className="stat-card"><b>{wsAssets.scans.length}</b><span>{t.totalScans}</span></div>
          </div>

          <h3 className="section-title">📦 {t.assets} ({wsAssets.hosts.length})</h3>
          {wsAssets.hosts.length === 0 ? <p className="muted">Henüz varlık yok. Tarama yapın; sonuçlar bu çalışma alanında birikir.</p> : (
            <table className="results wide"><thead><tr>
              <th>{t.ip}</th><th>{t.netname}</th><th>{t.type}</th><th>{t.mac}</th><th>{t.vendor}</th>
              <th>{t.os}</th><th>{t.totalServices}</th><th>{t.totalVulns}</th><th>İlk/Son görülme</th></tr></thead>
              <tbody>{wsAssets.hosts.map((h) => {
                const svc = wsAssets.services.filter((s) => s.host_ip === h.ip).length;
                const vl = wsAssets.vulns.filter((v) => v.host_ip === h.ip).length;
                return (<tr key={h.id}>
                  <td><b>{h.ip}</b></td><td className="muted">{h.name || '-'}</td>
                  <td>{DEVICE_ICONS[h.device_type] || ''} {h.device_type}</td>
                  <td className="mono muted">{h.mac || '-'}</td><td className="muted">{h.vendor || '-'}</td>
                  <td className="muted">{h.os || '-'}</td><td>{svc}</td>
                  <td>{vl > 0 ? <span style={{ color: 'var(--red)' }}>{vl}</span> : '0'}</td>
                  <td className="muted small">{new Date(h.first_seen).toLocaleDateString()} / {new Date(h.last_seen).toLocaleTimeString()}</td></tr>);
              })}</tbody>
            </table>
          )}

          <div className="section-head">
            <h3 className="section-title">📎 Kanıtlar ({evidence.length})</h3>
            <div>
              <button className="export" onClick={() => addEvidence('')}>📁 Dosya ekle</button>
              <button className="export" onClick={() => shotEvidence('')}>📸 Ekran görüntüsü</button>
            </div>
          </div>
          {evidence.length === 0 ? <p className="muted">Henüz kanıt yok. Dosya ekleyin veya ekran görüntüsü alın; rapora gömülür.</p> : (
            <div className="evidence-grid">
              {evidence.map((ev) => (
                <div key={ev.id} className="ev-card">
                  <div className="ev-label">{/\.(png|jpg|jpeg|gif)$/i.test(ev.path) ? '🖼️' : '📄'} {ev.label}</div>
                  {ev.host_ip && <div className="ev-host">{ev.host_ip}</div>}
                  <div className="ev-date">{new Date(ev.created).toLocaleString()}</div>
                  <div className="ev-actions">
                    <button onClick={() => window.api.evidenceOpen(ev.path)}>Aç</button>
                    <button onClick={() => delEvidence(ev.id)}>Sil</button>
                  </div>
                </div>
              ))}
            </div>
          )}

          <h3 className="section-title">📋 {t.auditLog}</h3>
          <div className="audit-log">
            {wsAudit.length === 0 ? <p className="muted">-</p> : wsAudit.map((a) => (
              <div key={a.id} className={'audit-row ' + a.action}>
                <span className="a-time">{new Date(a.date).toLocaleString()}</span>
                <span className={'a-tag ' + a.action}>{a.action}</span>
                <span className="a-detail">{a.detail}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ---------- OSINT VIEW ---------- */}
      {view === 'osint' && (
        <div className="page">
          <h2>🔍 OSINT — Pasif Keşif</h2>

          <h3 className="section-title">🌐 Subdomain & DNS Keşfi</h3>
          <div className="nuclei-bar">
            <input type="text" placeholder="Alan adı (ör. example.com)" value={osintDomain}
              onChange={(e) => setOsintDomain(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && runSubdomains()} />
            <button className="primary" style={{ width: 'auto', margin: 0 }} onClick={runSubdomains} disabled={osintBusy === 'sub'}>
              {osintBusy === 'sub' ? 'Aranıyor...' : '🌐 Subdomain (crt.sh)'}</button>
            <button className="export" onClick={runDns} disabled={osintBusy === 'dns'}>🧭 DNS Kayıtları</button>
          </div>
          {dnsRecords && (
            <div className="dns-box">
              {Object.entries(dnsRecords).map(([k, v]) => v.length > 0 && (
                <div key={k} className="dns-row"><b>{k}</b><span>{v.join(', ')}</span></div>
              ))}
            </div>
          )}
          {subdomains.length > 0 && (
            <div className="sub-list">
              <div className="sub-head">{subdomains.length} subdomain</div>
              {subdomains.map((s, i) => (
                <div key={i} className="sub-item"><span>{s}</span>
                  <button className="export" onClick={() => { setTarget(s); setView('scan'); toast('Hedef ayarlandı: ' + s, 'info'); }}>Tara</button></div>
              ))}
            </div>
          )}

          <h3 className="section-title">🛰️ Shodan Sorgu</h3>
          {(() => { return null; })()}
          <div className="nuclei-bar">
            <input type="text" placeholder="IP adresi (ör. 8.8.8.8)" value={shodanIp} onChange={(e) => setShodanIp(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && runShodan()} />
            <button className="primary" style={{ width: 'auto', margin: 0 }} onClick={() => runShodan()} disabled={osintBusy === 'shodan'}>
              {osintBusy === 'shodan' ? 'Sorgulanıyor...' : '🛰️ Shodan'}</button>
          </div>
          {!settings.shodanKey && <p className="muted small">Shodan için Ayarlar'dan API anahtarı girin (ücretsiz: account.shodan.io).</p>}
          {shodanData && (
            <div className="shodan-box">
              <div className="sd-grid">
                <div><span>Organizasyon</span><b>{shodanData.org || '-'}</b></div>
                <div><span>ISP</span><b>{shodanData.isp || '-'}</b></div>
                <div><span>Ülke</span><b>{shodanData.country || '-'}</b></div>
                <div><span>OS</span><b>{shodanData.os || '-'}</b></div>
              </div>
              <div className="sd-row"><b>Açık portlar:</b> {(shodanData.ports || []).join(', ') || '-'}</div>
              {shodanData.hostnames.length > 0 && <div className="sd-row"><b>Hostnames:</b> {shodanData.hostnames.join(', ')}</div>}
              {shodanData.vulns.length > 0 && (
                <div className="sd-row"><b style={{ color: 'var(--red)' }}>Zafiyetler:</b> {shodanData.vulns.map((c, i) =>
                  <a key={i} href="#" onClick={(e) => { e.preventDefault(); window.open('https://nvd.nist.gov/vuln/detail/' + c); }}>{c} </a>)}</div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ---------- TOOLS VIEW ---------- */}
      {view === 'tools' && (
        <div className="page">
          <h2>🧰 {t.tools}</h2>
          <div className="wsl-status">
            {toolStatus.wsl
              ? <span className="badge ok">● WSL hazır</span>
              : <span className="badge bad">● WSL yok — pentest araçları için gerekli</span>}
            {!toolStatus.wsl && (
              <>
                <button className="primary" style={{ width: 'auto', margin: 0 }} onClick={installWsl}>⬇ WSL'i otomatik kur (root)</button>
                <button className="export" onClick={prepareRoot}>⚙️ Distroyu hazırla</button>
                <p className="muted">Root distro olarak kurulur — <b>kullanıcı/şifre sorusu çıkmaz</b>. UAC onayı verin, kurulum bitince
                  <b> bilgisayarı yeniden başlatın</b>, sonra "Distroyu hazırla" → "Yenile".</p>
              </>
            )}
            {toolStatus.wsl && (
              <button className="primary" style={{ width: 'auto', margin: 0 }}
                disabled={installingTool} onClick={() => installTool('all')}>
                {installingTool === 'all' ? 'Tümü kuruluyor...' : '⬇ Tüm araçları tek tıkla kur'}</button>
            )}
            <button className="export" onClick={refreshTools}>↻ Yenile</button>
          </div>

          <div className="tool-grid">
            {/* nmap her zaman var (Windows-doğal) */}
            <div className="tool-card">
              <div className="tc-head"><b>Nmap</b><span className="tc-cat">Keşif</span></div>
              <div className="tc-desc">Port/servis tarayıcı (Windows-doğal)</div>
              <span className={'tc-status ' + (nmap.installed ? 'ok' : 'no')}>{nmap.installed ? '✓ kurulu' : '✕ yok'}</span>
            </div>
            {toolCatalog.map((tl) => {
              const found = toolStatus.tools[tl.id];
              return (
                <div key={tl.id} className="tool-card">
                  <div className="tc-head"><b>{tl.name}</b><span className="tc-cat">{tl.cat}</span></div>
                  <div className="tc-desc">{tl.desc}</div>
                  <span className={'tc-status ' + (found ? 'ok' : 'no')}>{found ? '✓ kurulu' : '✕ kurulu değil'}</span>
                  {!found && toolStatus.wsl && (
                    <button className="tc-install" disabled={installingTool === tl.id}
                      onClick={() => installTool(tl.id)}>
                      {installingTool === tl.id ? 'Kuruluyor...' : '⬇ WSL\'e kur'}</button>
                  )}
                  {!found && (
                    <button className="copy-cmd" onClick={() => { navigator.clipboard.writeText(tl.install); toast('Kurulum komutu kopyalandı', 'success'); }}>
                      ⧉ komutu kopyala</button>
                  )}
                </div>
              );
            })}
          </div>

          {installingTool && (
            <div className="install-log"><div className="il-head">📦 Kurulum: {installingTool}</div>
              <pre>{installLog || 'Başlatılıyor...'}</pre></div>
          )}

          {/* masscan hızlı tarama */}
          <h3 className="section-title">⚡ Masscan ile Hızlı Tarama (büyük ağlar)</h3>
          <div className="nuclei-bar">
            <input type="text" placeholder="Hedef (ör. 192.168.0.0/24)" value={masscanTarget} onChange={(e) => setMasscanTarget(e.target.value)} />
            <input type="text" style={{ flex: '0 0 140px' }} placeholder="Portlar (1-1000)" value={masscanPorts} onChange={(e) => setMasscanPorts(e.target.value)} />
            <button className="primary" style={{ width: 'auto', margin: 0 }} onClick={runMasscan} disabled={!toolStatus.tools.masscan}>▶ Tara</button>
          </div>
          <p className="muted small">Bulunan açık portlar otomatik olarak aktif çalışma alanına (asset graph) yazılır.</p>

          {/* nuclei hızlı tarama */}
          <h3 className="section-title">🛡️ Nuclei ile Zafiyet Taraması</h3>
          <div className="nuclei-bar">
            <input type="text" placeholder="Hedef (ör. http://192.168.0.1 veya 192.168.0.10)"
              value={nucleiTarget} onChange={(e) => setNucleiTarget(e.target.value)} />
            <select value={nucleiSev} onChange={(e) => setNucleiSev(e.target.value)}>
              <option value="all">Tüm seviyeler</option>
              <option value="low,medium,high,critical">Low+</option>
              <option value="medium,high,critical">Medium+</option>
              <option value="high,critical">High+</option>
              <option value="critical">Sadece Critical</option>
            </select>
            {nucleiRunning
              ? <button className="primary danger" style={{ width: 'auto', margin: 0 }} onClick={() => window.api.nucleiStop()}>■ Durdur</button>
              : <button className="primary" style={{ width: 'auto', margin: 0 }} onClick={() => runNuclei()} disabled={!toolStatus.tools.nuclei}>▶ Tara</button>}
          </div>
          {nucleiFindings.length > 0 && (
            <table className="results wide"><thead><tr>
              <th>Seviye</th><th>Host</th><th>Şablon</th><th>Ad</th><th>CVE</th></tr></thead>
              <tbody>{nucleiFindings.map((f, i) => (
                <tr key={i}><td><span className={'sev sev-' + f.severity}>{f.severity}</span></td>
                  <td>{f.host}</td><td className="mono small">{f.templateId}</td><td>{f.name}</td>
                  <td>{f.cve ? <a href="#" onClick={(e) => { e.preventDefault(); window.open('https://nvd.nist.gov/vuln/detail/' + f.cve); }}>{f.cve}</a> : '-'}</td></tr>))}</tbody>
            </table>
          )}
          {nucleiRunning && <p className="muted">⏳ nuclei çalışıyor, bulgular geldikçe listelenir...</p>}

          {/* searchsploit — exploit arama (salt-okunur, güvenli) */}
          <h3 className="section-title">🔎 Exploit Arama (SearchSploit / ExploitDB)</h3>
          <div className="nuclei-bar">
            <input type="text" placeholder="ör. apache 2.4 veya vsftpd 2.3.4" value={exploitTerm}
              onChange={(e) => setExploitTerm(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && searchExploit()} />
            <button className="primary" style={{ width: 'auto', margin: 0 }} onClick={() => searchExploit()} disabled={!toolStatus.tools.searchsploit || exploitBusy}>
              {exploitBusy ? 'Aranıyor...' : '🔎 Ara'}</button>
          </div>
          {exploitOut && <pre className="exploit-out">{exploitOut}</pre>}

          {/* hydra — saldırgan modül, sıkı kapı */}
          <h3 className="section-title" style={{ color: 'var(--red)' }}>💥 Hydra — Kimlik Denemesi (saldırgan)</h3>
          {(!activeWs || activeWs.mode !== 'engagement') ? (
            <div className="gate-warn">🔒 Saldırgan modüller yalnızca <b>Engagement modunda</b> ve <b>scope tanımlıyken</b> çalışır.
              Çalışma Alanı sekmesinden modu <b>Engagement</b> yapın ve kapsam (scope) belirleyin.</div>
          ) : (
            <div className="hydra-form">
              <div className="hf-row">
                <input type="text" placeholder="Hedef (scope içinde)" value={hydra.target} onChange={(e) => setHydra({ ...hydra, target: e.target.value })} />
                <select value={hydra.service} onChange={(e) => setHydra({ ...hydra, service: e.target.value })}>
                  {['ssh','ftp','rdp','smb','telnet','mysql','postgres','vnc'].map((s) => <option key={s}>{s}</option>)}
                </select>
              </div>
              <div className="hf-row">
                <input type="text" placeholder="Kullanıcı (tek, boş=liste)" value={hydra.user} onChange={(e) => setHydra({ ...hydra, user: e.target.value })} />
                <input type="text" placeholder="Parola listesi yolu (boş=rockyou)" value={hydra.passList} onChange={(e) => setHydra({ ...hydra, passList: e.target.value })} />
              </div>
              <button className="primary danger" style={{ width: 'auto', margin: 0 }} onClick={() => setHydraConfirm(true)}>💥 Saldırıyı Başlat</button>
              <p className="muted small">Her deneme audit kaydına yazılır. Yalnızca yazılı yetkin olan hedeflerde kullanın.</p>
            </div>
          )}

          {/* Metasploit (Faz 4) */}
          <h3 className="section-title">🧨 Metasploit Modülleri</h3>
          <div className="nuclei-bar">
            <input type="text" placeholder="Modül ara (ör. ms17_010, vsftpd, smb)" value={msfTerm}
              onChange={(e) => setMsfTerm(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && searchMsf()} />
            <button className="primary" style={{ width: 'auto', margin: 0 }} onClick={() => searchMsf()} disabled={!toolStatus.tools.msfconsole || msfBusy}>
              {msfBusy ? 'Aranıyor...' : '🔎 Modül Ara'}</button>
          </div>
          {!toolStatus.tools.msfconsole && <p className="muted small">Metasploit kurulu değil — yukarıdaki katalogdan kurun.</p>}
          {msfResults.length > 0 && (
            <table className="results wide"><thead><tr>
              <th>Modül</th><th>Rank</th><th>Check</th><th>Açıklama</th><th></th></tr></thead>
              <tbody>{msfResults.map((m, i) => (
                <tr key={i}>
                  <td className="mono small">{m.name}</td>
                  <td><span className={'msf-rank r-' + m.rank}>{m.rank}</span></td>
                  <td>{m.check === 'Yes' ? '✓' : '-'}</td>
                  <td className="small">{m.desc}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <button className="export" onClick={() => msfInfo(m.name)}>ℹ Bilgi</button>
                    <button className="export" style={{ color: 'var(--red)' }}
                      onClick={() => {
                        if (!activeWs || activeWs.mode !== 'engagement') { toast('Çalıştırma için Engagement modu + scope gerekir', 'warn'); return; }
                        setMsfRunModal({ module: m.name, target: (selHost && selHost.ip) || target.split('/')[0] });
                      }}>▶ Çalıştır</button>
                  </td></tr>))}</tbody>
            </table>
          )}
        </div>
      )}

      {/* Metasploit çalıştırma onay kapısı */}
      {msfRunModal && (
        <div className="overlay" onClick={(e) => e.target.className === 'overlay' && setMsfRunModal(null)}>
          <div className="modal">
            <h2 style={{ color: 'var(--red)' }}>🧨 Metasploit Modülü Çalıştır</h2>
            <p><b>Modül:</b> <span className="mono">{msfRunModal.module}</span></p>
            <label>Hedef (RHOSTS, scope içinde)</label>
            <input type="text" value={msfRunModal.target} onChange={(e) => setMsfRunModal({ ...msfRunModal, target: e.target.value })} />
            <p style={{ marginTop: 14 }}>Bu, hedefe karşı <b>aktif bir exploit çalıştırır</b> ve audit'e işlenir.
              Bu hedefte <b>yazılı test yetkiniz olduğunu</b> onaylıyor musunuz?</p>
            <div className="actions">
              <button className="btn-accept" style={{ background: 'var(--red)' }} onClick={runMsf}>Onaylıyorum, çalıştır</button>
              <button className="btn-cancel" onClick={() => setMsfRunModal(null)}>İptal</button>
            </div>
          </div>
        </div>
      )}

      {/* Hydra onay kapısı */}
      {hydraConfirm && (
        <div className="overlay" onClick={(e) => e.target.className === 'overlay' && setHydraConfirm(false)}>
          <div className="modal">
            <h2 style={{ color: 'var(--red)' }}>⚠️ Saldırgan Modül Onayı</h2>
            <p><b>Hedef:</b> {hydra.target}<br /><b>Servis:</b> {hydra.service}<br /><b>Mod:</b> Engagement · <b>Kapsam:</b> {activeWs && activeWs.scope}</p>
            <p>Bu işlem aktif bir kimlik denemesi saldırısıdır ve audit kaydına işlenir. Bu hedefte
              <b> yazılı test yetkisine sahip olduğunuzu</b> onaylıyor musunuz?</p>
            <div className="actions">
              <button className="btn-accept" style={{ background: 'var(--red)' }} onClick={runHydra}>Onaylıyorum, başlat</button>
              <button className="btn-cancel" onClick={() => setHydraConfirm(false)}>İptal</button>
            </div>
          </div>
        </div>
      )}

      {/* ---------- HISTORY VIEW ---------- */}
      {view === 'history' && (
        <div className="page">
          <div className="section-head">
            <h2>{t.history}</h2>
            <button className="primary" style={{ width: 'auto', margin: 0 }} onClick={runDiff} disabled={diffPick.length !== 2}>
              🔀 Seçili 2'yi Karşılaştır</button>
          </div>
          {diffResult && (
            <div className="diff-box">
              <div className="diff-head">🔀 {new Date(diffResult.oldDate).toLocaleString()} → {new Date(diffResult.newDate).toLocaleString()}</div>
              <div className="diff-cols">
                <div className="diff-col added"><b>+ Yeni host ({diffResult.newHosts.length})</b>{diffResult.newHosts.map((x, i) => <div key={i}>{x}</div>)}</div>
                <div className="diff-col removed"><b>− Kaybolan host ({diffResult.goneHosts.length})</b>{diffResult.goneHosts.map((x, i) => <div key={i}>{x}</div>)}</div>
                <div className="diff-col added"><b>+ Yeni açık port ({diffResult.newPorts.length})</b>{diffResult.newPorts.map((x, i) => <div key={i}>{x}</div>)}</div>
                <div className="diff-col removed"><b>− Kapanan port ({diffResult.gonePorts.length})</b>{diffResult.gonePorts.map((x, i) => <div key={i}>{x}</div>)}</div>
              </div>
            </div>
          )}
          {history.length === 0 ? <p className="muted">{t.noHistory}</p> : (
            <table className="results wide"><thead><tr>
              <th>✓</th><th>{t.status === 'Durum' ? 'Tarih' : 'Date'}</th><th>{t.target}</th><th>{t.device}</th><th>{t.port}</th><th></th></tr></thead>
              <tbody>{history.map((h) => (
                <tr key={h.id} className={diffPick.includes(h.id) ? 'selected' : ''}>
                  <td><input type="checkbox" checked={diffPick.includes(h.id)} onChange={() => toggleDiffPick(h.id)} /></td>
                  <td>{new Date(h.date).toLocaleString()}</td><td>{h.target}</td>
                  <td>{h.deviceCount}</td><td>{h.portCount}</td>
                  <td><button className="export" onClick={() => openHistory(h.id)}>{t.load}</button>
                    <button className="export" onClick={() => deleteHistory(h.id)}>{t.delete}</button></td></tr>))}</tbody>
            </table>
          )}
        </div>
      )}

      {/* ---------- SCRIPTS VIEW ---------- */}
      {view === 'scripts' && (
        <div className="page">
          <h2>{t.scripts} (NSE)</h2>
          <input type="text" className="search" placeholder={t.searchScript} value={scriptQuery} onChange={(e) => setScriptQuery(e.target.value)} />
          <div className="script-grid">
            {filteredScripts.map((s) => {
              const on = selScripts.includes(s.id);
              return (
                <div key={s.id} className={'script-card' + (on ? ' on' : '')}>
                  <div className="sc-head"><b>{s.id}</b><span className="cat">{s.cat}</span></div>
                  <div className="sc-desc">{s.desc}</div>
                  <button onClick={() => setSelScripts(on ? selScripts.filter((x) => x !== s.id) : [...selScripts, s.id])}>
                    {on ? '✓ ' + t.remove : '+ ' + t.addScript}</button>
                </div>);
            })}
          </div>
          <p className="muted">Seçilenler Gelişmiş modda taramaya eklenir.</p>
        </div>
      )}

      {/* ---------- SETTINGS VIEW ---------- */}
      {view === 'settings' && (
        <div className="page">
          <h2>{t.settings}</h2>
          <div className="set-row"><label>{t.lang}</label>
            <select value={settings.lang} onChange={(e) => saveSettings({ ...settings, lang: e.target.value })}>
              <option value="tr">Türkçe</option><option value="en">English</option></select></div>
          <div className="set-row"><label>{t.theme}</label>
            <select value={settings.theme} onChange={(e) => saveSettings({ ...settings, theme: e.target.value })}>
              <option value="dark">{t.dark}</option><option value="light">{t.light}</option></select></div>
          <div className="set-row"><label>{t.safeMode}</label>
            <input type="checkbox" checked={settings.safeMode} onChange={(e) => saveSettings({ ...settings, safeMode: e.target.checked })} /></div>
          <div className="set-row"><label>{t.autoMon}</label>
            <select value={settings.monitor} onChange={(e) => saveSettings({ ...settings, monitor: e.target.value })}>
              <option value="off">{t.off}</option><option value="15">15 dk</option><option value="60">60 dk</option></select></div>
          <div className="set-row"><label>Shodan API anahtarı</label>
            <input type="text" style={{ flex: 1 }} defaultValue={settings.shodanKey || ''} placeholder="account.shodan.io"
              onBlur={(e) => saveSettings({ ...settings, shodanKey: e.target.value })} /></div>
          <div className="set-row"><label>nmap</label><span className="muted">{nmap.version || '-'}</span></div>
          <p className="muted">Ayarlar otomatik kaydedilir.</p>
        </div>
      )}
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
