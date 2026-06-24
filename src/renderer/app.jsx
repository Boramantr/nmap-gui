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
    findings: 'Bulgular', client: 'Müşteri', startDate: 'Başlangıç', endDate: 'Bitiş',
    roe: 'Engagement Kuralları (ROE)', roeHint: 'Test izinleri, kısıtlamalar, iletişim — rapora gömülür.',
    status: 'Durum', notes: 'Notlar', mitre: 'MITRE ATT&CK',
    statusOpen: 'Açık', statusFixed: 'Düzeltildi', statusFp: 'Yanlış pozitif',
    statusAccepted: 'Kabul edildi', statusInProgress: 'İncelemede',
    hideClosed: 'Kapalı bulguları gizle', noFindings: 'Henüz bulgu yok. Tarama veya nuclei çalıştırın.',
    severity: 'Seviye', autoEvidence: 'Otomatik kanıt (tarama/araç çıktısı)',
    loot: 'Loot', credentials: 'Kimlik Bilgileri', revshell: 'Reverse Shell', listeners: 'Dinleyiciler',
    host: 'Host', username: 'Kullanıcı', password: 'Parola', hash: 'Hash', hashType: 'Tip',
    addCred: 'Ekle', reveal: 'Göster', hideRevealed: 'Gizle', copy: 'Kopyala', hashcatCmd: 'hashcat komutu',
    johnCmd: 'john komutu', vaultEnc: 'Şifreli (DPAPI/Keychain)', vaultPlain: 'Şifrelenmemiş kasa (uyarı)',
    noCreds: 'Henüz kayıt yok.', payload: 'Payload', listener: 'Dinleyici',
    listenerHint: 'TCP reverse shell yakalayıcısı; HTTP dosya sunucusu; SMB share (impacket).',
    lStart: 'Başlat', lStop: 'Durdur',
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
    findings: 'Findings', client: 'Client', startDate: 'Start', endDate: 'End',
    roe: 'Rules of Engagement (ROE)', roeHint: 'Authorized actions, restrictions, contacts — embedded in report.',
    status: 'Status', notes: 'Notes', mitre: 'MITRE ATT&CK',
    statusOpen: 'Open', statusFixed: 'Fixed', statusFp: 'False positive',
    statusAccepted: 'Accepted', statusInProgress: 'In progress',
    hideClosed: 'Hide closed findings', noFindings: 'No findings yet. Run a scan or nuclei.',
    severity: 'Severity', autoEvidence: 'Auto-evidence (scan/tool transcripts)',
    loot: 'Loot', credentials: 'Credentials', revshell: 'Reverse Shell', listeners: 'Listeners',
    host: 'Host', username: 'Username', password: 'Password', hash: 'Hash', hashType: 'Type',
    addCred: 'Add', reveal: 'Reveal', hideRevealed: 'Hide', copy: 'Copy', hashcatCmd: 'hashcat command',
    johnCmd: 'john command', vaultEnc: 'Encrypted (DPAPI/Keychain)', vaultPlain: 'Vault not encrypted (warning)',
    noCreds: 'No records yet.', payload: 'Payload', listener: 'Listener',
    listenerHint: 'TCP reverse shell catcher; HTTP file server; SMB share (impacket).',
    lStart: 'Start', lStop: 'Stop',
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

// Launcher şablonları — her araç için minimum gerekli alan ve hedef ipucu.
//   target: input placeholder
//   fields: ek opsiyonel alanlar [{ key, label, placeholder, default }]
const TOOL_LAUNCHERS = {
  naabu:      { target: '192.168.0.0/24 veya example.com', hint: 'Hızlı port keşfi',          fields: [{ key: 'ports', label: 'Portlar (boş=top1000)', placeholder: '1-65535 veya 80,443' }] },
  masscan:    { target: '192.168.0.0/24',                  hint: 'Çok hızlı port tarama',    fields: [{ key: 'ports', label: 'Portlar', default: '1-1000' }, { key: 'rate', label: 'Hız (paket/sn)', default: '1000' }] },
  subfinder:  { target: 'example.com',                     hint: 'Pasif subdomain keşfi',    fields: [] },
  amass:      { target: 'example.com',                     hint: 'OWASP derin recon (yavaş)', fields: [] },
  dnsx:       { target: 'example.com',                     hint: 'Tüm DNS kayıtları',        fields: [] },
  httpx:      { target: 'https://example.com',             hint: 'HTTP tech / başlık / kod', fields: [] },
  katana:     { target: 'https://example.com',             hint: 'Web crawler (derinlik 2)', fields: [] },
  gobuster:   { target: 'https://example.com',             hint: 'Dizin brute-force',        fields: [{ key: 'wordlist', label: 'Wordlist yolu (WSL içi)', default: '/usr/share/wordlists/dirb/common.txt' }] },
  ffuf:       { target: 'https://example.com/FUZZ veya https://example.com', hint: 'Hızlı web fuzzer', fields: [{ key: 'wordlist', label: 'Wordlist', default: '/usr/share/wordlists/dirb/common.txt' }] },
  nikto:      { target: 'https://example.com',             hint: 'Web sunucu zafiyet tarama', fields: [] },
  whatweb:    { target: 'https://example.com',             hint: 'Teknoloji parmak izi',     fields: [] },
  enum4linux: { target: '192.168.0.10',                    hint: 'SMB / Samba enum',         fields: [] },
  sqlmap:     { target: 'https://example.com/page?id=1',   hint: 'SQL injection testi',      fields: [] },
  hashcat:    { target: '/path/to/hashes.txt (WSL içi)',   hint: 'Hash kırma',               fields: [{ key: 'mode', label: 'Hash modu (-m)', default: '0', placeholder: '0=MD5, 1000=NTLM, 22000=WPA' }, { key: 'wordlist', label: 'Wordlist', default: '/usr/share/wordlists/rockyou.txt' }] },
  john:       { target: '/path/to/hashes.txt (WSL içi)',   hint: 'John the Ripper',          fields: [{ key: 'wordlist', label: 'Wordlist', default: '/usr/share/wordlists/rockyou.txt' }] },
};

// Kill-chain fazları (Kanban kolonları için).
const KILL_CHAIN = [
  { id: 'recon',   title: 'KEŞİF',   icon: '🛰️', color: '#1e3a5f', desc: 'Hedef tespiti ve yüzey alanı haritalama' },
  { id: 'enum',    title: 'ENUM',    icon: '🔍', color: '#6b4513', desc: 'Servis, zafiyet ve içerik enumerasyonu' },
  { id: 'exploit', title: 'EXPLOIT', icon: '💥', color: '#6b1d1d', desc: 'Zafiyetlerden faydalanma' },
  { id: 'post',    title: 'POST',    icon: '👻', color: '#4a2358', desc: 'Sonrası: pivot, kimlik kırma, lateral' },
];
const NAV_ICONS = { scan: '🎯', engagement: '🗂️', findings: '🔎', loot: '🗝️', tools: '🧰', osint: '🌐', history: '🕘', scripts: '📜', settings: '⚙️' };
const SEV_COLORS = { critical: '#b91c1c', high: '#ef4444', medium: '#f59e0b', low: '#3b82f6', info: '#888', unknown: '#666' };
const sevColorMap = SEV_COLORS;

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

// nmap bayraklarının sade Türkçe açıklaması (komut şeffaflığı için).
const FLAG_DOC = {
  '-sn': 'Yalnızca host keşfi (port taraması yok)',
  '-sS': 'SYN (yarı-açık) TCP taraması — hızlı ve gizli',
  '-sT': 'Tam TCP connect taraması',
  '-sU': 'UDP port taraması',
  '-sV': 'Servis sürüm tespiti',
  '-sC': 'Varsayılan NSE script seti',
  '-O': 'İşletim sistemi tespiti',
  '-A': 'Agresif: OS + sürüm + script + traceroute',
  '-Pn': 'Ping atlamadan tara (host up varsay)',
  '-F': 'Hızlı tarama (en yaygın 100 port)',
  '-p-': 'Tüm 65535 portu tara',
  '-p': 'Belirli port aralığı',
  '-v': 'Ayrıntılı çıktı',
  '-f': 'Paket parçalama (IDS atlatma)',
  '--top-ports': 'En yaygın N portu tara',
  '--script': 'Belirtilen NSE scriptlerini çalıştır',
  '-PR': 'ARP ile host keşfi (yerel ağ)',
  '-PE': 'ICMP echo ping', '-PP': 'ICMP timestamp ping', '-PM': 'ICMP netmask ping',
  '-PS': 'TCP SYN ping', '-PA': 'TCP ACK ping', '-PU': 'UDP ping',
  '-T0': 'Çok yavaş (paranoyak)', '-T1': 'Yavaş (sinsi)', '-T2': 'Kibar',
  '-T3': 'Normal', '-T4': 'Hızlı (önerilen)', '-T5': 'Çok hızlı (agresif)',
};
function explainArgs(args) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith('-')) continue;
    const tFlag = a.match(/^-T[0-5]$/) ? a : null;
    if (tFlag && FLAG_DOC[tFlag]) { out.push({ flag: a, desc: FLAG_DOC[tFlag] }); continue; }
    if (FLAG_DOC[a]) {
      // Argüman alan bayraklar için değeri de göster
      const takesVal = ['-p', '--script', '--top-ports'].includes(a);
      const val = takesVal && args[i + 1] && !args[i + 1].startsWith('-') ? ' ' + args[i + 1] : '';
      out.push({ flag: a + val, desc: FLAG_DOC[a] });
    }
  }
  return out;
}

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0, unknown: -1 };
const SEV_COLOR = { critical: '#b91c1c', high: '#ef4444', medium: '#f59e0b', low: '#3b82f6', info: '#888', unknown: 'var(--muted)' };
function CvssBadge({ info }) {
  if (!info) return null;
  const sev = info.severity || 'unknown';
  const color = SEV_COLOR[sev] || 'var(--muted)';
  const label = info.cvss != null ? `${info.cvss} ${sev}` : sev;
  return <span className="cvss-badge" style={{ background: color + '22', color, borderColor: color + '55' }}
    title={info.desc || ''}>{label}</span>;
}

// Tarama sonucundan önceliklendirilmiş "sonraki adım" önerileri üret.
function buildNextSteps(upHosts) {
  const steps = [];
  const seen = new Set();
  const add = (s) => { if (!seen.has(s.key)) { seen.add(s.key); steps.push(s); } };
  upHosts.forEach((h) => {
    const open = (h.ports || []).filter((p) => p.state === 'open');
    // 1) Zafiyetli host -> en yüksek öncelik
    if ((h.vulns || []).length) {
      add({ key: 'nuclei-' + h.ip, prio: 0, icon: '🛡️', title: `${h.ip} — Nuclei zafiyet taraması`,
        detail: `${h.vulns.length} CVE işareti var; şablon taramasıyla doğrula.`, action: { type: 'nuclei', ip: h.ip } });
    }
    open.forEach((p) => {
      const port = p.port;
      // 2) Servis sürümü biliniyorsa exploit ara
      if (p.version && /\d/.test(p.version)) {
        add({ key: 'exp-' + p.version, prio: 1, icon: '🔎', title: `Exploit ara: ${p.version}`,
          detail: `${h.ip}:${port} üzerinde tespit edildi.`, action: { type: 'exploit', term: p.version } });
      }
      // 3) Web servisleri
      if (['80', '443', '8080', '8443'].includes(port)) {
        add({ key: 'web-' + h.ip, prio: 2, icon: '🌐', title: `${h.ip} — Web enumerasyonu`,
          detail: `Port ${port} açık; WhatWeb + dizin keşfi (gobuster) önerilir.`, action: { type: 'tool', tool: 'whatweb', ip: h.ip } });
      }
      // 4) SMB
      if (['139', '445'].includes(port)) {
        add({ key: 'smb-' + h.ip, prio: 1, icon: '🗄️', title: `${h.ip} — SMB enumerasyonu`,
          detail: `Port ${port} açık; enum4linux + MS17-010 kontrolü.`, action: { type: 'tool', tool: 'enum4linux', ip: h.ip } });
      }
      // 5) Sürüm yoksa derin tara
      if (!p.version && !['80', '443', '8080', '8443', '139', '445'].includes(port)) {
        add({ key: 'deep-' + h.ip, prio: 3, icon: '🔬', title: `${h.ip} — Servis sürüm tespiti`,
          detail: `Açık portlar var ama sürüm bilinmiyor; -sV ile derin tara.`, action: { type: 'scan', ip: h.ip } });
      }
    });
  });
  return steps.sort((a, b) => a.prio - b.prio).slice(0, 8);
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
function DeviceDetail({ host, t, onClose, onScan, onNuclei, onTool, onExploit, onShodan, onEvidence, onShot, note, onNote,
  cveInfo, autoExploit, onAutoExploit, autoExpBusy, onEnrich, cveBusy, arpCut, arpBusy, onCut }) {
  if (!host) return null;
  const risk = riskOf(host);
  const enumTools = toolsForHost(host);
  const versions = [...new Set((host.ports || []).filter((p) => p.state === 'open' && p.version && /\d/.test(p.version)).map((p) => p.version))];
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
        {versions.length > 0 && (
          <button className="autoexp-btn" disabled={autoExpBusy} onClick={() => onAutoExploit(host)}>
            {autoExpBusy ? '⏳ ExploitDB...' : '🧨 Servis sürümlerini exploit\'e eşle'}</button>
        )}
        <div className="dd-actions">
          <button className="dd-act" onClick={() => onShodan(host.ip)}>🛰️ Shodan</button>
          <button className="dd-act" onClick={() => onEvidence(host.ip)}>📁 Kanıt</button>
          <button className="dd-act" onClick={() => onShot(host.ip)}>📸 Ekran</button>
        </div>
        <button className={'arpcut-btn' + (arpCut ? ' active' : '')} disabled={arpBusy}
          title="Bu cihazı ağdan koparır (ARP). Yalnızca kendi ağında kullan!"
          onClick={() => onCut(host.ip)}>
          {arpBusy ? '⏳ İşleniyor...' : arpCut ? '✅ Bağlantıyı geri aç' : '🚫 Cihazı ağdan kes'}
        </button>
        {versions.some((v) => autoExploit[v]) && (
          <div className="autoexp-res">
            {versions.filter((v) => autoExploit[v]).map((v, i) => (
              <div key={i} className="ae-group">
                <div className="ae-ver">{v} <span className="muted">— {autoExploit[v].length} eşleşme</span></div>
                {autoExploit[v].slice(0, 6).map((ex, j) => (
                  <div key={j} className="ae-item" title={ex.path}>💣 {ex.title}{ex.edb ? ` (EDB-${ex.edb})` : ''}</div>
                ))}
                {autoExploit[v].length === 0 && <div className="ae-item muted">Eşleşme yok</div>}
              </div>
            ))}
          </div>
        )}
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
            <h4 style={{ color: 'var(--red)' }}>{t.vulns} ({host.vulns.length})
              <button className="enrich-btn sm" disabled={cveBusy}
                onClick={() => onEnrich(host.vulns.map((v) => v.cve))}>{cveBusy ? '⏳' : '🔬 CVSS'}</button></h4>
            <ul className="vuln-list">{[...host.vulns].sort((a, b) => ((cveInfo[b.cve] && cveInfo[b.cve].cvss) || 0) - ((cveInfo[a.cve] && cveInfo[a.cve].cvss) || 0)).map((v, i) =>
              <li key={i}><a href="#" onClick={(e) => { e.preventDefault(); window.open('https://nvd.nist.gov/vuln/detail/' + v.cve); }}>{v.cve}</a> (port {v.port})<CvssBadge info={cveInfo[v.cve]} /></li>)}</ul>
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
  const [settings, setSettings] = useState({ lang: 'tr', theme: 'dark', safeMode: true, timing: 'T4', monitor: 'off', scanProfile: 'normal' });
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
  // Faz 1: findings triyaj
  const [findings, setFindings] = useState([]);
  const [findingsHideClosed, setFindingsHideClosed] = useState(true);
  const [findingsSevFilter, setFindingsSevFilter] = useState('all');
  const [findingsBusy, setFindingsBusy] = useState(false);
  // Faz 2: Loot
  const [lootTab, setLootTab] = useState('creds');
  const [creds, setCreds] = useState([]);
  const [vaultStatus, setVaultStatus] = useState({ encryptionAvailable: false });
  const [credForm, setCredForm] = useState({ host: '', service: '', username: '', password: '', hash: '', source: 'manual', notes: '' });
  const [revealed, setRevealed] = useState({}); // id -> plain
  const [hashDetected, setHashDetected] = useState({ type: '', mode: '' });
  const [revshellTpl, setRevshellTpl] = useState([]);
  const [revshell, setRevshell] = useState({ lhost: '', lport: '4444', tplId: 'bash-i' });
  const [listenerState, setListenerState] = useState({});
  const [listenerOut, setListenerOut] = useState({ nc: '', http: '', smb: '' });
  const [listenerCfg, setListenerCfg] = useState({ nc: { port: '4444' }, http: { port: '8000', dir: '' }, smb: { dir: '' } });
  const [ncInput, setNcInput] = useState('');
  // Faz 3
  const [adModules, setAdModules] = useState([]);
  const [adForm, setAdForm] = useState({ target: '', user: '', pass: '', hash: '', domain: '' });
  const [adModule, setAdModule] = useState('null');
  const [adOut, setAdOut] = useState('');
  const [adBusy, setAdBusy] = useState(false);
  const [web, setWeb] = useState({ target: '', subdomains: false, nuclei: true });
  const [webBusy, setWebBusy] = useState(false);
  const [webSteps, setWebSteps] = useState([]);
  const [findingsView, setFindingsView] = useState('table'); // table | graph | mitre
  const [mitreTactics, setMitreTactics] = useState([]);
  // Faz 4
  const [scanProfiles, setScanProfiles] = useState([]);
  const [pivot, setPivot] = useState({ lhost: '', lport: '8000', targetIp: '', targetPort: '3389', tpl: null });
  const [localIps, setLocalIps] = useState([]);
  const [noteModal, setNoteModal] = useState(null); // { host, content, original }
  const [waybackUrls, setWaybackUrls] = useState([]);
  const [ghDorks, setGhDorks] = useState([]);
  const [hostNotes, setHostNotes] = useState({}); // host_ip -> content snippet
  // OSINT genişletme
  const [asnQ, setAsnQ] = useState('');
  const [asnRes, setAsnRes] = useState(null);
  const [favRes, setFavRes] = useState(null);
  const [bucketName, setBucketName] = useState('');
  const [bucketRes, setBucketRes] = useState(null);
  const [mailSec, setMailSec] = useState(null);
  const [googleDorks, setGoogleDorks] = useState([]);
  // OSINT 2. paket
  const [whoisRes, setWhoisRes] = useState(null);
  const [revIpRes, setRevIpRes] = useState(null);
  const [tlsRes, setTlsRes] = useState(null);
  const [takeoverRes, setTakeoverRes] = useState(null);
  const [httpRecon, setHttpRecon] = useState(null);
  const [diffPick, setDiffPick] = useState([]);
  const [diffResult, setDiffResult] = useState(null);
  const [launcher, setLauncher] = useState(null); // { tool, target, opts }
  const [portableStatus, setPortableStatus] = useState({}); // id -> {supported, installed, path}
  const [portableProg, setPortableProg] = useState({}); // id -> {phase, pct, msg}
  const [portableBusy, setPortableBusy] = useState(false);
  const [cveInfo, setCveInfo] = useState({});       // CVE -> { cvss, severity, desc }
  const [cveBusy, setCveBusy] = useState(false);
  const [autoExploit, setAutoExploit] = useState({}); // sürüm/term -> [{title, edb, path}]
  const [autoExpBusy, setAutoExpBusy] = useState(false);
  const [avatarMenu, setAvatarMenu] = useState(false);
  const outputRef = useRef(null);
  const toolConsoleRef = useRef(null);
  const activeWsRef = useRef(null);
  const lastDevices = useRef([]);
  const monitorTimer = useRef(null);
  const targetRef = useRef('');

  const t = I18N[settings.lang];
  const isWin = window.api.platform === 'win32';

  /* toast */
  const toast = (msg, type = 'info') => {
    const id = Date.now() + Math.random();
    setToasts((ts) => [...ts, { id, msg, type }]);
    setTimeout(() => setToasts((ts) => ts.filter((x) => x.id !== id)), 3500);
  };

  /* ARP cihaz kesme durumu (ip -> true) */
  const [arpCutSet, setArpCutSet] = useState({});
  const [arpBusy, setArpBusy] = useState({});
  useEffect(() => {
    window.api.onArpState && window.api.onArpState(({ target, active }) => {
      setArpCutSet((s) => { const n = { ...s }; if (active) n[target] = true; else delete n[target]; return n; });
      setArpBusy((s) => { const n = { ...s }; delete n[target]; return n; });
    });
    window.api.arpList && window.api.arpList().then((list) => {
      if (Array.isArray(list)) setArpCutSet(Object.fromEntries(list.map((ip) => [ip, true])));
    });
  }, []);
  const toggleCut = async (ip) => {
    if (!ip) return;
    const gw = gateway || (target ? target.replace(/\.\d+(\/\d+)?$/, '.1') : '');
    if (arpCutSet[ip]) {
      setArpBusy((s) => ({ ...s, [ip]: true }));
      const r = await window.api.arpRestore(ip);
      if (!r.ok) { toast(r.error || 'Geri alınamadı', 'error'); setArpBusy((s) => { const n = { ...s }; delete n[ip]; return n; }); }
      else toast('Bağlantı geri açıldı: ' + ip, 'success');
      return;
    }
    if (!gw) { toast('Gateway IP bilinmiyor — önce ağı tara.', 'error'); return; }
    setArpBusy((s) => ({ ...s, [ip]: true }));
    const chk = await window.api.arpCheck(gw);
    if (!chk.ok) {
      setArpBusy((s) => { const n = { ...s }; delete n[ip]; return n; });
      if (!chk.hasTool) {
        toast('arpspoof kuruluyor, bekleyin...', 'info');
        const ins = await window.api.arpInstall();
        if (!ins.ok) { toast('Kurulum başarısız. WSL kurulu mu?', 'error'); return; }
        toast('arpspoof kuruldu, tekrar deneyin.', 'success');
      } else {
        toast(chk.hint || 'WSL ağı göremiyor (mirrored mod gerekli).', 'error');
      }
      return;
    }
    const r = await window.api.arpCut(ip, gw);
    if (!r.ok) { toast(r.error || 'Kesilemedi', 'error'); setArpBusy((s) => { const n = { ...s }; delete n[ip]; return n; }); }
    else toast('🚫 Cihaz ağdan kesildi: ' + ip, 'success');
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

  /* init — paint hızı için faz faz yükle */
  useEffect(() => {
    // FAZ 1 (paint için kritik): tema, ws, hedef
    window.api.getSettings().then((s) => { setSettings((p) => ({ ...p, ...s })); });
    refreshWorkspaces();
    window.api.localRange().then((r) => { if (r.ok) { setTarget(r.cidr); setGateway(r.gateway); } });

    // FAZ 2 (paint'ten sonra, ~100 ms): nmap + admin
    setTimeout(() => {
      checkNmap();
      window.api.checkAdmin().then((r) => setAdmin(r.admin));
    }, 100);

    // FAZ 3 (idle): araç katalogu + WSL — Tools sekmesi açılana kadar acelesi yok
    const idle = window.requestIdleCallback || ((cb) => setTimeout(cb, 600));
    idle(() => {
      window.api.wslCheck().then((r) => setWsl({ checked: true, installed: r.installed, distros: r.distros }));
      window.api.toolsCatalog().then(setToolCatalog);
      refreshTools();
      refreshPortable();
    });

    // Event listener'lar (ucuz — sadece kanal kaydı)
    window.api.onPortableProgress((p) => setPortableProg((m) => ({ ...m, [p.id]: p })));
    window.api.onPortableDone((d) => {
      setPortableProg((m) => ({ ...m, [d.id]: { phase: 'done', pct: 100, msg: d.ok ? 'Kuruldu' : ('Hata: ' + d.error) } }));
      refreshPortable(); refreshTools();
      toast(d.ok ? `✓ ${d.id} portable kuruldu` : `${d.id} hata: ${d.error}`, d.ok ? 'success' : 'error');
    });
    window.api.onPortableAllDone(() => { setPortableBusy(false); toast('Tüm portable kurulumlar bitti', 'success'); });
    // nuclei + kurulum olayları
    window.api.onNucleiFinding((f) => setNucleiFindings((arr) => [...arr, f]));
    window.api.onNucleiDone(({ count }) => {
      setNucleiRunning(false);
      toast(`nuclei bitti: ${count} bulgu`, count > 0 ? 'warn' : 'success');
      const aws = activeWsRef.current;
      if (aws) { window.api.wsAssets(aws.id).then(setWsAssets); window.api.wsAudit(aws.id).then(setWsAudit); }
    });
    window.api.onToolsInstallOut((d) => setInstallLog((o) => o + d));
    window.api.onToolsInstallDone(({ code } = {}) => {
      setInstallingTool(null);
      refreshTools();
      if (code === 0) toast('Kurulum tamamlandı', 'success');
      else toast(`Kurulum başarısız (kod ${code}) — kurulum logunu kontrol edin`, 'error');
    });
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

  // Findings (Faz 1)
  const refreshFindings = async () => {
    const aws = activeWsRef.current; if (!aws) return;
    setFindingsBusy(true);
    try { setFindings(await window.api.findingsList(aws.id)); }
    finally { setFindingsBusy(false); }
  };
  useEffect(() => { if (view === 'findings') refreshFindings(); }, [view, activeWs]);
  const patchFinding = async (id, fields) => {
    await window.api.findingsUpdate(id, fields);
    setFindings((arr) => arr.map((f) => f.id === id ? { ...f, ...fields } : f));
  };
  const removeFinding = async (id) => {
    if (!confirm('Bu bulguyu silmek istediğinize emin misiniz?')) return;
    await window.api.findingsDelete(id);
    setFindings((arr) => arr.filter((f) => f.id !== id));
  };

  // Loot (Faz 2)
  const refreshCreds = async () => {
    const aws = activeWsRef.current; if (!aws) return;
    setCreds(await window.api.credsList(aws.id));
  };
  useEffect(() => {
    if (view !== 'loot') return;
    refreshCreds();
    window.api.credsVaultStatus().then(setVaultStatus).catch(() => {});
    window.api.revshellTemplates().then(setRevshellTpl).catch(() => {});
    window.api.listenerList().then((arr) => {
      const m = {}; arr.forEach((l) => { m[l.type] = { running: true, port: l.port, dir: l.dir }; });
      setListenerState(m);
    }).catch(() => {});
  }, [view, activeWs]);
  useEffect(() => {
    if (!window.api.onListenerOut) return;
    window.api.onListenerOut(({ type, data }) => {
      setListenerOut((m) => ({ ...m, [type]: (m[type] || '').slice(-12000) + data }));
    });
    window.api.onListenerState(({ type, running, port, dir }) => {
      setListenerState((m) => ({ ...m, [type]: running ? { running, port, dir } : null }));
    });
  }, []);
  // Hash tipi canlı tespit (form input)
  useEffect(() => {
    if (!credForm.hash) { setHashDetected({ type: '', mode: '' }); return; }
    const id = setTimeout(() => {
      window.api.credsDetectHash(credForm.hash).then(setHashDetected).catch(() => {});
    }, 200);
    return () => clearTimeout(id);
  }, [credForm.hash]);

  const submitCred = async () => {
    if (!credForm.username && !credForm.hash && !credForm.password) {
      toast('En az bir alan dolu olmalı', 'warn'); return;
    }
    const r = await window.api.credsAdd(credForm);
    if (r.ok) {
      toast('Eklendi', 'success');
      setCredForm({ host: '', service: '', username: '', password: '', hash: '', source: 'manual', notes: '' });
      refreshCreds();
    } else toast(r.error, 'error');
  };
  const revealCred = async (id) => {
    if (revealed[id] != null) {
      setRevealed((m) => { const n = { ...m }; delete n[id]; return n; });
      return;
    }
    const r = await window.api.credsReveal(id);
    if (r.ok) setRevealed((m) => ({ ...m, [id]: r.password || '' }));
  };
  const removeCred = async (id) => {
    if (!confirm('Bu kaydı silmek istediğinize emin misiniz?')) return;
    await window.api.credsDelete(id);
    refreshCreds();
  };
  const copyText = async (s) => {
    try { await navigator.clipboard.writeText(s); toast('Kopyalandı', 'success'); }
    catch (e) { toast('Kopyalama hatası', 'error'); }
  };
  const renderPayload = () => {
    const tpl = revshellTpl.find((x) => x.id === revshell.tplId);
    if (!tpl) return '';
    return tpl.template.replaceAll('{LHOST}', revshell.lhost || 'LHOST').replaceAll('{LPORT}', revshell.lport || 'LPORT');
  };
  const startListener = async (type) => {
    const cfg = listenerCfg[type] || {};
    const r = await window.api.listenerStart({ type, port: cfg.port, dir: cfg.dir });
    if (!r.ok) toast(r.error, 'error');
  };
  const stopListener = async (type) => {
    const r = await window.api.listenerStop(type);
    if (!r.ok) toast(r.error || 'durduralamadı', 'warn');
  };
  const pickShareDir = async (type) => {
    const r = await window.api.listenerPickDir();
    if (r.ok) setListenerCfg((m) => ({ ...m, [type]: { ...m[type], dir: r.dir } }));
  };
  const sendNc = async () => {
    if (!ncInput.trim()) return;
    const r = await window.api.listenerSend({ type: 'nc', data: ncInput });
    if (r.ok) setNcInput('');
    else toast(r.error, 'warn');
  };

  // Faz 3 — AD recon
  useEffect(() => {
    if (!window.api.adModules) return;
    window.api.adModules().then(setAdModules).catch(() => {});
    window.api.mitreTactics().then(setMitreTactics).catch(() => {});
    if (window.api.onAdOut) {
      window.api.onAdOut((s) => setAdOut((o) => (o + s).slice(-20000)));
      window.api.onAdDone(() => setAdBusy(false));
    }
    if (window.api.onWebStep) {
      window.api.onWebStep((step) => {
        setWebSteps((s) => [...s, step].slice(-200));
        if (step.step === 'done') setWebBusy(false);
      });
    }
  }, []);
  const runAd = async () => {
    if (!adForm.target.trim()) { toast('Hedef girin', 'warn'); return; }
    setAdOut(''); setAdBusy(true);
    const r = await window.api.adRun({ module: adModule, ...adForm });
    if (!r.ok) { setAdBusy(false); toast(r.error, 'error'); }
  };
  const stopAd = async () => { await window.api.adStop(); setAdBusy(false); };
  const runWeb = async () => {
    if (!web.target.trim()) { toast('Hedef girin', 'warn'); return; }
    setWebSteps([]); setWebBusy(true);
    const r = await window.api.webPipeline({ target: web.target.trim(), opts: { subdomains: web.subdomains, nuclei: web.nuclei } });
    if (!r.ok) { setWebBusy(false); toast(r.error, 'error'); }
  };
  const stopWeb = async () => { await window.api.webStop(); setWebBusy(false); };

  // Faz 4 — başlangıç yüklemeleri
  useEffect(() => {
    if (window.api.scanProfiles) window.api.scanProfiles().then(setScanProfiles).catch(() => {});
    if (window.api.localIps) window.api.localIps().then((arr) => {
      setLocalIps(arr);
      if (arr[0] && !pivot.lhost) setPivot((p) => ({ ...p, lhost: arr[0].ip }));
    }).catch(() => {});
  }, []);
  useEffect(() => {
    if (!activeWs || !window.api.notesList) return;
    window.api.notesList(activeWs.id).then((arr) => {
      const m = {}; arr.forEach((n) => { m[n.host_ip] = n.content; });
      setHostNotes(m);
    }).catch(() => {});
  }, [activeWs, view]);
  // Pivot şablonlarını LHOST/port değişince yenile
  useEffect(() => {
    if (lootTab !== 'pivot' || !window.api.pivotTemplates) return;
    window.api.pivotTemplates({
      lhost: pivot.lhost, lport: pivot.lport, targetIp: pivot.targetIp, targetPort: pivot.targetPort,
    }).then((t) => setPivot((p) => ({ ...p, tpl: t }))).catch(() => {});
  }, [lootTab, pivot.lhost, pivot.lport, pivot.targetIp, pivot.targetPort]);

  // Notes
  const openNoteModal = async (host) => {
    if (!activeWs) return;
    const n = await window.api.noteGet(activeWs.id, host);
    setNoteModal({ host, content: n ? n.content : '', original: n ? n.content : '' });
  };
  const saveHostNote = async () => {
    if (!noteModal || !activeWs) return;
    if (noteModal.content !== noteModal.original) {
      await window.api.noteSet(activeWs.id, noteModal.host, noteModal.content);
      setHostNotes((m) => ({ ...m, [noteModal.host]: noteModal.content }));
      toast('Not kaydedildi', 'success');
    }
    setNoteModal(null);
  };

  // Wayback + GH Dorks
  const runWayback = async () => {
    if (!osintDomain.trim()) { toast('Alan adı girin', 'warn'); return; }
    setOsintBusy('wayback'); setWaybackUrls([]);
    const r = await window.api.wayback(osintDomain.trim());
    setOsintBusy('');
    if (r.ok) { setWaybackUrls(r.urls); toast(`${r.urls.length} URL`, 'success'); }
    else toast(r.error, 'error');
  };
  const runGhDorks = async () => {
    if (!osintDomain.trim()) { toast('Hedef girin', 'warn'); return; }
    const r = await window.api.ghDorks(osintDomain.trim());
    if (r.ok) setGhDorks(r.dorks); else toast(r.error, 'error');
  };
  // OSINT genişletme
  const runAsn = async () => {
    const q = (asnQ || osintDomain).trim();
    if (!q) { toast('IP, ASN veya domain girin', 'warn'); return; }
    setOsintBusy('asn'); setAsnRes(null);
    const r = await window.api.osintAsn(q);
    setOsintBusy('');
    if (r.ok) setAsnRes(r); else toast(r.error, 'error');
  };
  const runFavicon = async () => {
    if (!osintDomain.trim()) { toast('Hedef girin', 'warn'); return; }
    setOsintBusy('fav'); setFavRes(null);
    const r = await window.api.osintFavicon(osintDomain.trim());
    setOsintBusy('');
    if (r.ok) setFavRes(r); else toast(r.error, 'error');
  };
  const runBuckets = async () => {
    const n = (bucketName || osintDomain.split('.')[0]).trim().toLowerCase();
    if (!n) { toast('Şirket adı girin', 'warn'); return; }
    setOsintBusy('buckets'); setBucketRes(null);
    const r = await window.api.osintBuckets(n);
    setOsintBusy('');
    if (r.ok) { setBucketRes(r); toast(`${r.hits.length}/${r.total} hit`, r.hits.length ? 'success' : 'info'); }
    else toast(r.error, 'error');
  };
  const runMailSec = async () => {
    if (!osintDomain.trim()) { toast('Alan adı girin', 'warn'); return; }
    setOsintBusy('mail'); setMailSec(null);
    const r = await window.api.osintMailSec(osintDomain.trim());
    setOsintBusy('');
    if (r.ok) setMailSec(r); else toast(r.error, 'error');
  };
  const runGoogleDorks = async () => {
    if (!osintDomain.trim()) { toast('Hedef girin', 'warn'); return; }
    const r = await window.api.osintGoogleDorks(osintDomain.trim());
    if (r.ok) setGoogleDorks(r.dorks); else toast(r.error, 'error');
  };
  const runWhois = async () => {
    if (!osintDomain.trim()) { toast('Alan adı girin', 'warn'); return; }
    setOsintBusy('whois'); setWhoisRes(null);
    const r = await window.api.osintWhois(osintDomain.trim());
    setOsintBusy('');
    if (r.ok) setWhoisRes(r); else toast(r.error, 'error');
  };
  const runReverseIp = async () => {
    const q = (asnQ || osintDomain).trim();
    if (!q) { toast('IP veya domain girin', 'warn'); return; }
    setOsintBusy('rev'); setRevIpRes(null);
    const r = await window.api.osintReverseIp(q);
    setOsintBusy('');
    if (r.ok) { setRevIpRes(r); toast(`${r.count} host`, r.count ? 'success' : 'info'); }
    else toast(r.error, 'error');
  };
  const runTls = async () => {
    if (!osintDomain.trim()) { toast('Hedef girin', 'warn'); return; }
    setOsintBusy('tls'); setTlsRes(null);
    const r = await window.api.osintTlsCert(osintDomain.trim());
    setOsintBusy('');
    if (r.ok) setTlsRes(r); else toast(r.error, 'error');
  };
  const runTakeover = async () => {
    // Crt.sh sonuçları varsa onları kullan; yoksa kullanıcıdan iste
    let list = subdomains;
    if (!list.length) {
      if (!osintDomain.trim()) { toast('Önce subdomain bulun veya domain girin', 'warn'); return; }
      // tek hedef olarak çalıştır
      list = [osintDomain.trim()];
    }
    setOsintBusy('takeover'); setTakeoverRes(null);
    const r = await window.api.osintSubTakeover(list);
    setOsintBusy('');
    if (r.ok) { setTakeoverRes(r); toast(`${r.hits.length} olası takeover (${r.total} tarandı)`, r.hits.length ? 'warn' : 'success'); }
    else toast(r.error, 'error');
  };
  const runHttpRecon = async () => {
    if (!osintDomain.trim()) { toast('Hedef girin', 'warn'); return; }
    setOsintBusy('http'); setHttpRecon(null);
    const r = await window.api.osintHttpRecon(osintDomain.trim());
    setOsintBusy('');
    if (r.ok) setHttpRecon(r); else toast(r.error, 'error');
  };

  // Diff (karşılaştırmalı retest)
  const toggleDiffPick = (id) => setDiffPick((p) => p.includes(id) ? p.filter((x) => x !== id) : (p.length < 2 ? [...p, id] : [p[1], id]));
  const runDiff = async () => {
    if (diffPick.length !== 2) { toast('Karşılaştırmak için 2 tarama seçin', 'warn'); return; }
    const [r1, r2] = await Promise.all([window.api.historyGet(diffPick[0]), window.api.historyGet(diffPick[1])]);
    // Eski/yeni sırala (tarihe göre)
    const [oldR, newR] = (r1.date < r2.date) ? [r1, r2] : [r2, r1];
    const portSet = (rec) => { const s = new Set(); (rec.parsed.hosts || []).forEach((h) => (h.ports || []).forEach((p) => s.add(`${h.ip}:${p.port}/${p.proto}`))); return s; };
    const hostSet = (rec) => new Set((rec.parsed.hosts || []).filter((h) => h.status === 'up').map((h) => h.ip));
    // Servis sürüm haritası: "ip:port/proto" -> version
    const verMap = (rec) => { const m = {}; (rec.parsed.hosts || []).forEach((h) => (h.ports || []).forEach((p) => { if (p.version) m[`${h.ip}:${p.port}/${p.proto}`] = p.version; })); return m; };
    const ov = verMap(oldR), nv = verMap(newR);
    const verChanges = Object.keys(nv).filter((k) => ov[k] && ov[k] !== nv[k]).map((k) => ({ key: k, from: ov[k], to: nv[k] }));
    const oh = hostSet(oldR), nh = hostSet(newR), op = portSet(oldR), np = portSet(newR);
    setDiffResult({
      oldDate: oldR.date, newDate: newR.date,
      newHosts: [...nh].filter((x) => !oh.has(x)),
      goneHosts: [...oh].filter((x) => !nh.has(x)),
      newPorts: [...np].filter((x) => !op.has(x)),
      gonePorts: [...op].filter((x) => !np.has(x)),
      verChanges,
    });
  };

  // NVD ile CVE zenginleştirme (CVSS + severity + açıklama)
  const enrichCves = async (ids) => {
    const list = [...new Set((ids || []).filter(Boolean))];
    if (!list.length) { toast('Zenginleştirilecek CVE yok', 'warn'); return; }
    setCveBusy(true);
    toast(`${list.length} CVE NVD'den sorgulanıyor...`, 'info');
    const r = await window.api.enrichCve(list);
    setCveBusy(false);
    if (r.ok) {
      setCveInfo((m) => ({ ...m, ...r.info }));
      const aws = activeWsRef.current;
      if (aws) window.api.wsAssets(aws.id).then(setWsAssets);
      toast('CVE bilgileri güncellendi (CVSS)', 'success');
    } else toast('NVD hatası: ' + r.error, 'error');
  };

  // Servis sürümlerini searchsploit ile otomatik exploit'e eşle
  const autoMatchExploits = async (host) => {
    if (!toolStatus.tools.searchsploit) { toast('searchsploit kurulu değil — Araçlar sekmesinden kurun', 'error'); setView('tools'); return; }
    const terms = [...new Set((host.ports || [])
      .filter((p) => p.state === 'open' && p.version && /\d/.test(p.version))
      .map((p) => p.version))];
    if (!terms.length) { toast('Eşlenecek servis sürümü yok (önce -sV ile tara)', 'warn'); return; }
    setAutoExpBusy(true);
    toast(`${terms.length} servis sürümü ExploitDB'de aranıyor...`, 'info');
    const r = await window.api.exploitAuto(terms);
    setAutoExpBusy(false);
    if (r.ok) {
      setAutoExploit((m) => ({ ...m, ...r.results }));
      const total = Object.values(r.results).reduce((a, l) => a + l.length, 0);
      toast(`${total} olası exploit eşleşti`, total > 0 ? 'warn' : 'success');
    } else toast('Hata: ' + r.error, 'error');
  };

  // Bir aracı launcher modalıyla aç (akıllı hedef varsayılanı)
  const openLauncher = (tool) => {
    const meta = TOOL_LAUNCHERS[tool];
    if (!meta) { runTool(tool, target || ''); return; }
    const defaultTarget = (selHost && selHost.ip) || target || '';
    const opts = {}; (meta.fields || []).forEach((f) => { if (f.default) opts[f.key] = f.default; });
    setLauncher({ tool, target: defaultTarget, opts });
  };
  const submitLauncher = () => {
    if (!launcher) return;
    const { tool, target: lt, opts } = launcher;
    if (!lt.trim()) { toast('Hedef gerekli', 'warn'); return; }
    // Engagement modunda scope kontrolü
    if (activeWs && activeWs.mode === 'engagement') {
      const ok = inScopeList(lt, activeWs.scope);
      if (ok === false) { toast(t.scopeBlock, 'error'); return; }
    }
    setLauncher(null);
    if (tool === 'nuclei') { setNucleiTarget(lt); setView('tools'); runNuclei(lt); return; }
    if (tool === 'searchsploit') { searchExploit(lt); return; }
    runTool(tool, lt.trim(), opts);
  };

  // Sonraki adım önerisini çalıştır
  const runNextStep = (action) => {
    if (action.type === 'nuclei') { setNucleiTarget(action.ip); setView('tools'); runNuclei(action.ip); }
    else if (action.type === 'tool') { runTool(action.tool, action.ip); }
    else if (action.type === 'exploit') { searchExploit(action.term); }
    else if (action.type === 'scan') { scanDevice(action.ip); }
  };

  const refreshTools = async () => { try { setToolStatus(await window.api.toolsCheck()); } catch (e) {} };
  const refreshPortable = async () => { try { setPortableStatus(await window.api.portableStatus()); } catch (e) {} };
  const installPortable = async (id) => {
    setPortableProg((m) => ({ ...m, [id]: { phase: 'start', pct: 0, msg: 'Başlatılıyor...' } }));
    const r = await window.api.portableInstall(id);
    if (!r.ok) toast(`${id} kurulumu başlatılamadı: ` + r.error, 'error');
  };
  const installAllPortable = async () => {
    setPortableBusy(true);
    toast('Tüm portable araçlar indiriliyor (paralel değil, sırayla)...', 'info');
    await window.api.portableInstallAll();
  };
  const uninstallPortable = async (id) => {
    await window.api.portableUninstall(id);
    refreshPortable(); refreshTools();
    toast(`${id} portable kaldırıldı`, 'info');
  };
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
    // Faz 4: stealth profil flag'lerini ekle (varsa, kullanıcı zaten -T, --min-rate, -f koymadıysa)
    const prof = scanProfiles.find((p) => p.id === settings.scanProfile);
    let finalArgs = args;
    if (prof && settings.scanProfile !== 'normal') {
      const userKeys = new Set(args.filter((a) => a.startsWith('-T') || a === '-f' || a === '--min-rate' || a === '--source-port' || a === '--data-length' || a === '--randomize-hosts' || a === '--scan-delay'));
      const merged = prof.args.filter((a, i, arr) => !userKeys.has(a) && !(arr[i - 1] && userKeys.has(arr[i - 1])));
      finalArgs = [...merged, ...args];
    }
    const r = await window.api.startScan(finalArgs);
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

      {launcher && (() => {
        const meta = TOOL_LAUNCHERS[launcher.tool] || {};
        return (
          <div className="overlay" onClick={(e) => { if (e.target.className === 'overlay') setLauncher(null); }}>
            <div className="modal launcher-modal">
              <h2>▶ {launcher.tool}</h2>
              <p className="muted small" style={{ marginTop: -4 }}>{meta.hint || 'Aracı çalıştır'}</p>
              <label>Hedef</label>
              <input type="text" autoFocus placeholder={meta.target || ''} value={launcher.target}
                onChange={(e) => setLauncher({ ...launcher, target: e.target.value })}
                onKeyDown={(e) => e.key === 'Enter' && submitLauncher()} />
              {(meta.fields || []).map((f) => (
                <div key={f.key} style={{ marginTop: 10 }}>
                  <label>{f.label}</label>
                  <input type="text" placeholder={f.placeholder || f.default || ''}
                    value={launcher.opts[f.key] || ''}
                    onChange={(e) => setLauncher({ ...launcher, opts: { ...launcher.opts, [f.key]: e.target.value } })}
                    onKeyDown={(e) => e.key === 'Enter' && submitLauncher()} />
                </div>
              ))}
              <div className="actions">
                <button className="btn-accept" onClick={submitLauncher}>▶ Çalıştır</button>
                <button className="btn-cancel" onClick={() => setLauncher(null)}>İptal</button>
              </div>
            </div>
          </div>
        );
      })()}

      {/* Faz 4: Host notes drawer */}
      {noteModal && (
        <div className="overlay" onClick={(e) => { if (e.target.className === 'overlay') setNoteModal(null); }}>
          <div className="console-modal" style={{ maxWidth: 720 }}>
            <div className="console-head">
              <span>📝 Not: <b>{noteModal.host}</b></span>
              <div>
                <button className="primary" onClick={saveHostNote}>💾 Kaydet</button>
                <button onClick={() => setNoteModal(null)}>✕</button>
              </div>
            </div>
            <div style={{ padding: 10 }}>
              <textarea
                value={noteModal.content}
                placeholder="Markdown notlar: gözlemler, denenmiş kimlikler, sıradaki adımlar, bulgular..."
                onChange={(e) => setNoteModal({ ...noteModal, content: e.target.value })}
                onKeyDown={(e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') saveHostNote(); }}
                style={{ width: '100%', minHeight: 320, fontFamily: 'monospace', fontSize: 13, resize: 'vertical' }} />
              <div className="muted small" style={{ marginTop: 6 }}>
                Ctrl+Enter: kaydet · Notlar workspace silindiğinde silinir · raporda görünmez (gizli)
              </div>
            </div>
          </div>
        </div>
      )}
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
          {['scan', 'engagement', 'findings', 'loot', 'tools', 'osint', 'history', 'scripts', 'settings'].map((v) => (
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
          {isWin && wsl.checked && <span className={'mini-badge ' + (wsl.installed ? 'ok' : 'bad')} title="WSL2">WSL {wsl.installed ? '✓' : '✕'}</span>}
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
            {/* Faz 4: stealth profil seçici */}
            {scanProfiles.length > 0 && (
              <div style={{ background: 'var(--panel)', padding: 10, borderRadius: 8, marginBottom: 10 }}>
                <div className="sb-section-lbl" style={{ marginTop: 0 }}>🥷 STEALTH PROFİLİ</div>
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {scanProfiles.map((p) => {
                    const icon = { loud: '📢', normal: '⚖️', stealth: '🌒', paranoid: '👻' }[p.id] || '•';
                    const isActive = settings.scanProfile === p.id;
                    return (
                      <button key={p.id}
                        className={isActive ? 'active' : ''}
                        title={p.desc + ' · ' + p.args.join(' ')}
                        onClick={() => saveSettings({ ...settings, scanProfile: p.id })}
                        style={{ fontSize: 11, padding: '4px 8px', flex: 1, minWidth: 60 }}>
                        {icon} {p.label}
                      </button>
                    );
                  })}
                </div>
                <div className="muted small" style={{ marginTop: 6 }}>
                  {(scanProfiles.find((p) => p.id === settings.scanProfile) || {}).desc || ''}
                </div>
              </div>
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
                {explainArgs(baseArgs).length > 0 && (
                  <div className="flag-doc">
                    <div className="fd-title">🧩 Bayraklar ne yapıyor?</div>
                    {explainArgs(baseArgs).map((f, i) => (
                      <div key={i} className="fd-row"><code>{f.flag}</code><span>{f.desc}</span></div>
                    ))}
                  </div>
                )}
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
                            <div className="f-title">🎯 Pentest Bulguları
                              {allCves.length > 0 && (
                                <button className="enrich-btn" disabled={cveBusy}
                                  onClick={() => enrichCves(allCves.map((c) => c.cve))}>
                                  {cveBusy ? '⏳ NVD...' : '🔬 NVD ile CVSS getir'}</button>
                              )}</div>
                            <div className="f-grid">
                              <div className="f-stat"><b>{upHosts.length}</b><span>canlı host</span></div>
                              <div className="f-stat"><b>{allPorts.length}</b><span>açık port</span></div>
                              <div className="f-stat danger"><b>{allCves.length}</b><span>CVE bulgusu</span></div>
                              <div className="f-stat warn"><b>{highRiskHosts.length}</b><span>riskli host</span></div>
                            </div>
                            {allCves.length > 0 && (
                              <div className="f-cves">
                                {[...allCves].sort((a, b) => ((cveInfo[b.cve] && cveInfo[b.cve].cvss) || 0) - ((cveInfo[a.cve] && cveInfo[a.cve].cvss) || 0))
                                  .slice(0, 12).map((c, i) => (
                                  <a key={i} href="#" onClick={(e) => { e.preventDefault(); window.open('https://nvd.nist.gov/vuln/detail/' + c.cve); }}>
                                    {c.cve} <span>({c.host}:{c.port})</span><CvssBadge info={cveInfo[c.cve]} /></a>
                                ))}
                                {allCves.length > 12 && <span className="more">+{allCves.length - 12} daha</span>}
                              </div>
                            )}
                            {interesting.length > 0 && (
                              <div className="f-svc">İlgi çekici servisler: {[...new Set(interesting.map((p) => `${p.service || p.port}`))].join(', ')}</div>
                            )}
                          </div>
                        )}
                        {(() => {
                          const steps = buildNextSteps(upHosts);
                          if (!steps.length) return null;
                          return (
                            <div className="next-steps">
                              <div className="ns-title">🧭 Önerilen Sonraki Adımlar</div>
                              <div className="ns-list">
                                {steps.map((s, i) => (
                                  <div key={i} className="ns-card">
                                    <div className="ns-ic">{s.icon}</div>
                                    <div className="ns-body">
                                      <div className="ns-head">{s.title}</div>
                                      <div className="ns-detail">{s.detail}</div>
                                    </div>
                                    <button className="ns-run" onClick={() => runNextStep(s.action)}>▶ Çalıştır</button>
                                  </div>
                                ))}
                              </div>
                            </div>
                          );
                        })()}
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
                note={notes[selHost.ip]} onNote={saveNote}
                cveInfo={cveInfo} autoExploit={autoExploit} onAutoExploit={autoMatchExploits}
                autoExpBusy={autoExpBusy} onEnrich={enrichCves} cveBusy={cveBusy}
                arpCut={!!arpCutSet[selHost.ip]} arpBusy={!!arpBusy[selHost.ip]} onCut={toggleCut} />}
            </div>
          </div>
        </div>
      )}

      {/* ---------- ENGAGEMENT VIEW ---------- */}
      {view === 'engagement' && activeWs && (
        <div className="page">
          <div className="eng-top">
            <h2>🎯 {t.engagement}: {activeWs.name}</h2>
            <div>
              <button className="primary report-btn" onClick={async () => {
                const r = await window.api.reportPro(activeWs.id);
                if (r.ok) toast('Profesyonel rapor kaydedildi: ' + r.path, 'success');
                else if (r.error !== 'iptal') toast('Rapor hatası: ' + r.error, 'error');
              }}>📄 PDF</button>
              <button className="export" style={{ marginLeft: 6 }} onClick={async () => {
                const r = await window.api.reportDocx(activeWs.id);
                if (r.ok) toast('Word raporu: ' + r.path, 'success');
                else if (r.error !== 'iptal') toast('Word: ' + r.error, 'error');
              }}>📝 Word (.doc)</button>
            </div>
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
              <label style={{ marginTop: 12 }}>{t.client}</label>
              <input type="text" defaultValue={activeWs.client || ''} placeholder="Acme Corp"
                onBlur={(e) => updateWsField({ client: e.target.value })} />
              <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                <div style={{ flex: 1 }}>
                  <label>{t.startDate}</label>
                  <input type="date" defaultValue={(activeWs.start_date || '').slice(0, 10)}
                    onBlur={(e) => updateWsField({ start_date: e.target.value })} />
                </div>
                <div style={{ flex: 1 }}>
                  <label>{t.endDate}</label>
                  <input type="date" defaultValue={(activeWs.end_date || '').slice(0, 10)}
                    onBlur={(e) => updateWsField({ end_date: e.target.value })} />
                </div>
              </div>
              <label style={{ marginTop: 12 }}>{t.roe}</label>
              <textarea defaultValue={activeWs.roe || ''} placeholder={t.roeHint} rows={4}
                style={{ width: '100%', fontFamily: 'inherit', resize: 'vertical' }}
                onBlur={(e) => updateWsField({ roe: e.target.value })} />
              <p className="muted small">{t.roeHint}</p>
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

          {/* AD Recon paneli (Faz 3) */}
          <div className="eng-card" style={{ marginTop: 14 }}>
            <div className="section-head">
              <h3 className="section-title" style={{ margin: 0 }}>🏰 AD Recon (netexec)</h3>
              {adBusy ? <button onClick={stopAd}>■ Durdur</button> : null}
            </div>
            <p className="muted small" style={{ marginTop: 4 }}>
              Salt-okunur kontroller (null, signing, policy) Lab modunda da çalışır. Saldırgan modüller (kerberoast, asreproast, zerologon) yalnızca Engagement modunda + scope içinde.
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr 1fr', gap: 8 }}>
              <div><label>DC IP / Host</label>
                <input type="text" value={adForm.target} placeholder="10.0.0.10"
                  onChange={(e) => setAdForm({ ...adForm, target: e.target.value })} /></div>
              <div><label>Kullanıcı</label>
                <input type="text" value={adForm.user} placeholder="boş = null"
                  onChange={(e) => setAdForm({ ...adForm, user: e.target.value })} /></div>
              <div><label>Parola</label>
                <input type="password" value={adForm.pass}
                  onChange={(e) => setAdForm({ ...adForm, pass: e.target.value })} /></div>
              <div><label>NTLM Hash</label>
                <input type="text" value={adForm.hash} placeholder="opsiyonel"
                  onChange={(e) => setAdForm({ ...adForm, hash: e.target.value })} /></div>
              <div><label>Domain</label>
                <input type="text" value={adForm.domain} placeholder="corp.local"
                  onChange={(e) => setAdForm({ ...adForm, domain: e.target.value })} /></div>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10 }}>
              {adModules.map((m) => (
                <button key={m.id}
                  className={(adModule === m.id ? 'active ' : '') + (m.aggressive ? 'export' : '')}
                  title={m.desc + ' · MITRE ' + m.mitre}
                  onClick={() => setAdModule(m.id)}
                  style={{ borderColor: m.aggressive ? '#ef4444' : undefined,
                           color: m.aggressive ? '#ef4444' : undefined }}>
                  {m.aggressive ? '🔥' : '🔍'} {m.id}
                  {m.requireAuth && <sup style={{ marginLeft: 3 }}>🔑</sup>}
                </button>
              ))}
            </div>
            <div style={{ marginTop: 10 }}>
              <button className="primary" onClick={runAd} disabled={adBusy}>
                {adBusy ? '⏳ Çalışıyor...' : '▶ Çalıştır'}
              </button>
              {adOut && <button className="export" style={{ marginLeft: 6 }} onClick={() => setAdOut('')}>🗑 Çıktıyı temizle</button>}
            </div>
            {(adBusy || adOut) && (
              <pre className="console-body" style={{ marginTop: 8, maxHeight: 320 }}>{adOut || '— başlatılıyor —'}</pre>
            )}
          </div>

          <h3 className="section-title">📦 {t.assets} ({wsAssets.hosts.length})</h3>
          {wsAssets.hosts.length === 0 ? <p className="muted">Henüz varlık yok. Tarama yapın; sonuçlar bu çalışma alanında birikir.</p> : (
            <table className="results wide"><thead><tr>
              <th>{t.ip}</th><th>{t.netname}</th><th>{t.type}</th><th>{t.mac}</th><th>{t.vendor}</th>
              <th>{t.os}</th><th>{t.totalServices}</th><th>{t.totalVulns}</th><th>📝</th><th>İlk/Son görülme</th></tr></thead>
              <tbody>{wsAssets.hosts.map((h) => {
                const svc = wsAssets.services.filter((s) => s.host_ip === h.ip).length;
                const vl = wsAssets.vulns.filter((v) => v.host_ip === h.ip).length;
                const hasNote = !!hostNotes[h.ip];
                return (<tr key={h.id}>
                  <td><b>{h.ip}</b></td><td className="muted">{h.name || '-'}</td>
                  <td>{DEVICE_ICONS[h.device_type] || ''} {h.device_type}</td>
                  <td className="mono muted">{h.mac || '-'}</td><td className="muted">{h.vendor || '-'}</td>
                  <td className="muted">{h.os || '-'}</td><td>{svc}</td>
                  <td>{vl > 0 ? <span style={{ color: 'var(--red)' }}>{vl}</span> : '0'}</td>
                  <td>
                    <button className="export" onClick={() => openNoteModal(h.ip)}
                      title={hasNote ? hostNotes[h.ip].slice(0, 200) : 'Not ekle'}>
                      {hasNote ? '📝✓' : '📝'}
                    </button>
                  </td>
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

      {/* ---------- FINDINGS VIEW (Faz 1: triyaj) ---------- */}
      {view === 'findings' && activeWs && (() => {
        const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
        const sevColor = SEV_COLORS;
        const STATUS_LABELS = {
          open: t.statusOpen, fixed: t.statusFixed, false_positive: t.statusFp,
          accepted: t.statusAccepted, in_progress: t.statusInProgress,
        };
        const CLOSED = new Set(['fixed', 'false_positive']);
        const filtered = findings.filter((f) => {
          if (findingsSevFilter !== 'all' && (f.severity || 'info') !== findingsSevFilter) return false;
          if (findingsHideClosed && CLOSED.has(f.status)) return false;
          return true;
        });
        const sevCount = SEV_ORDER.reduce((a, s) => { a[s] = findings.filter((f) => (f.severity || 'info') === s).length; return a; }, {});
        return (
          <div className="page">
            <div className="eng-top">
              <h2>🔎 {t.findings} <span className="muted small">({filtered.length}/{findings.length})</span></h2>
              <div>
                <button className="export" onClick={refreshFindings} disabled={findingsBusy}>🔄</button>
                <button className="primary report-btn" onClick={async () => {
                  const r = await window.api.reportPro(activeWs.id);
                  if (r.ok) toast('Rapor: ' + r.path, 'success');
                  else if (r.error !== 'iptal') toast(r.error, 'error');
                }}>📄 {t.exportPdf}</button>
              </div>
            </div>

            <div className="stat-cards">
              {SEV_ORDER.filter((s) => s !== 'unknown').map((s) => (
                <div key={s} className="stat-card" style={{ borderTop: '3px solid ' + sevColor[s] }}>
                  <b style={{ color: sevColor[s] }}>{sevCount[s] || 0}</b>
                  <span>{s.toUpperCase()}</span>
                </div>
              ))}
            </div>

            <div className="tabs" style={{ marginTop: 12 }}>
              <button className={findingsView === 'table' ? 'active' : ''} onClick={() => setFindingsView('table')}>📋 Tablo</button>
              <button className={findingsView === 'graph' ? 'active' : ''} onClick={() => setFindingsView('graph')}>🕸️ Saldırı Grafiği</button>
              <button className={findingsView === 'mitre' ? 'active' : ''} onClick={() => setFindingsView('mitre')}>🎯 MITRE Matris</button>
            </div>

            {findingsView === 'table' && <div className="nuclei-bar" style={{ marginTop: 14 }}>
              <label>{t.severity}:&nbsp;</label>
              <select value={findingsSevFilter} onChange={(e) => setFindingsSevFilter(e.target.value)}>
                <option value="all">all</option>
                {SEV_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              <label style={{ marginLeft: 16 }}>
                <input type="checkbox" checked={findingsHideClosed} onChange={(e) => setFindingsHideClosed(e.target.checked)} />
                &nbsp;{t.hideClosed}
              </label>
            </div>}

            {findingsView === 'table' && filtered.length === 0 ? (
              <p className="muted" style={{ marginTop: 24 }}>{t.noFindings}</p>
            ) : findingsView === 'table' && (
              <table className="results wide" style={{ marginTop: 12 }}>
                <thead><tr>
                  <th>{t.severity}</th><th>{t.ip}</th><th>{t.port}</th><th>CVE / Template</th>
                  <th>{t.status}</th><th>{t.mitre}</th><th>{t.notes}</th><th></th>
                </tr></thead>
                <tbody>
                  {filtered.map((f) => {
                    const sev = f.severity || 'info';
                    return (
                      <tr key={f.id} style={CLOSED.has(f.status) ? { opacity: 0.55 } : null}>
                        <td>
                          <span style={{ background: sevColor[sev] || '#666', color: '#fff',
                                         padding: '2px 8px', borderRadius: 8, fontSize: 11, fontWeight: 700 }}>
                            {sev.toUpperCase()}
                          </span>
                        </td>
                        <td><b>{f.host_ip}</b>{f.host_name ? <div className="muted small">{f.host_name}</div> : null}</td>
                        <td className="mono">{f.port || '-'}</td>
                        <td className="mono small">
                          {f.cve && /^CVE-/i.test(f.cve)
                            ? <a href="#" onClick={(e) => { e.preventDefault(); window.api && window.api.openDownload ? null : null; window.open('https://nvd.nist.gov/vuln/detail/' + f.cve, '_blank'); }}>{f.cve}</a>
                            : (f.cve || '-')}
                          {f.script ? <div className="muted small">{f.script}</div> : null}
                        </td>
                        <td>
                          <select value={f.status || 'open'} onChange={(e) => patchFinding(f.id, { status: e.target.value })}>
                            {Object.entries(STATUS_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                          </select>
                        </td>
                        <td>
                          <input type="text" defaultValue={f.mitre || ''} placeholder="T1190"
                            style={{ width: 90 }}
                            onBlur={(e) => { if (e.target.value !== (f.mitre || '')) patchFinding(f.id, { mitre: e.target.value }); }} />
                        </td>
                        <td>
                          <input type="text" defaultValue={f.notes || ''} placeholder="…"
                            style={{ width: '100%', minWidth: 180 }}
                            onBlur={(e) => { if (e.target.value !== (f.notes || '')) patchFinding(f.id, { notes: e.target.value }); }} />
                        </td>
                        <td><button onClick={() => removeFinding(f.id)} title={t.delete}>✕</button></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}

            {/* SALDIRI GRAFİĞİ (Faz 3) */}
            {findingsView === 'graph' && (() => {
              const hosts = wsAssets.hosts.slice(0, 40);
              if (hosts.length === 0) return <p className="muted" style={{ marginTop: 24 }}>Henüz varlık yok. Önce tarama yapın.</p>;
              const W = 980, H = 560, cx = W / 2, cy = H / 2;
              const R = Math.min(W, H) * 0.38;
              const nodes = hosts.map((h, i) => {
                const a = (i / hosts.length) * Math.PI * 2 - Math.PI / 2;
                const svc = wsAssets.services.filter((s) => s.host_ip === h.ip).length;
                const vl = findings.filter((f) => f.host_ip === h.ip);
                const maxSev = vl.reduce((m, v) => Math.max(m, SEV_ORDER.indexOf(v.severity || 'info') >= 0 ? (5 - SEV_ORDER.indexOf(v.severity || 'info')) : 0), 0);
                return { ip: h.ip, name: h.name, x: cx + R * Math.cos(a), y: cy + R * Math.sin(a),
                         svc, vulnCount: vl.length, maxSev, devType: h.device_type };
              });
              const sevToColor = (s) => [sevColor.unknown, sevColor.info, sevColor.low, sevColor.medium, sevColor.high, sevColor.critical][s] || '#666';
              return (
                <div style={{ marginTop: 14, background: 'var(--panel)', borderRadius: 10, padding: 10 }}>
                  <p className="muted small">Node büyüklüğü = açık servis sayısı · renk = en yüksek bulgu seviyesi · merkez = workspace.</p>
                  <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: 'auto', maxHeight: 600 }}>
                    {nodes.map((n) => (
                      <line key={'l' + n.ip} x1={cx} y1={cy} x2={n.x} y2={n.y}
                        stroke={sevToColor(n.maxSev)} strokeWidth={n.vulnCount ? 1.5 : 0.5} opacity={0.4} />
                    ))}
                    <circle cx={cx} cy={cy} r={28} fill="#1e3a5f" stroke="#fff" strokeWidth={2} />
                    <text x={cx} y={cy + 5} textAnchor="middle" fill="#fff" fontSize={12} fontWeight={700}>{activeWs.name.slice(0, 8)}</text>
                    {nodes.map((n) => {
                      const r = 12 + Math.min(n.svc * 1.5, 18);
                      return (
                        <g key={n.ip} style={{ cursor: 'pointer' }}
                           onClick={() => toast(`${n.ip} · ${n.svc} servis · ${n.vulnCount} bulgu`, 'info')}>
                          <circle cx={n.x} cy={n.y} r={r} fill={sevToColor(n.maxSev)} stroke="#fff" strokeWidth={1.5} opacity={0.9} />
                          <text x={n.x} y={n.y + r + 14} textAnchor="middle" fontSize={10} fill="var(--text)">{n.ip}</text>
                          {n.vulnCount > 0 && <text x={n.x} y={n.y + 4} textAnchor="middle" fontSize={11} fontWeight={700} fill="#fff">{n.vulnCount}</text>}
                        </g>
                      );
                    })}
                  </svg>
                </div>
              );
            })()}

            {/* MITRE MATRIS (Faz 3) */}
            {findingsView === 'mitre' && (() => {
              // Findings.mitre tag'lerini tactic sütunlarına dağıt
              const byT = {};
              findings.forEach((f) => {
                if (!f.mitre) return;
                const base = f.mitre.split('.')[0];
                mitreTactics.forEach((ta) => {
                  if (ta.t.includes(base)) {
                    (byT[ta.id] = byT[ta.id] || []).push({ id: f.mitre, host: f.host_ip, sev: f.severity, name: f.cve || f.script });
                  }
                });
              });
              const all = Object.values(byT).reduce((a, x) => a + x.length, 0);
              return (
                <div style={{ marginTop: 14 }}>
                  <p className="muted small">Bulguların MITRE ATT&CK taktik matrisi ({all} etiketli bulgu).</p>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 8 }}>
                    {mitreTactics.map((ta) => {
                      const list = byT[ta.id] || [];
                      return (
                        <div key={ta.id} className="eng-card" style={{ padding: 10 }}>
                          <div style={{ fontSize: 11, color: 'var(--muted)' }}>{ta.id}</div>
                          <div style={{ fontWeight: 700, fontSize: 13 }}>{ta.name}</div>
                          <div style={{ fontSize: 22, fontWeight: 700, color: list.length ? sevColor.high : 'var(--muted)' }}>{list.length}</div>
                          <div style={{ fontSize: 10, color: 'var(--muted)' }}>
                            {ta.t.slice(0, 4).join(', ')}
                          </div>
                          {list.slice(0, 3).map((x, i) => (
                            <div key={i} style={{ fontSize: 10, marginTop: 4, color: 'var(--text)' }}>
                              <span style={{ color: sevColor[x.sev] || '#888' }}>●</span> {x.id} · {x.host}
                            </div>
                          ))}
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })()}
          </div>
        );
      })()}

      {/* ---------- LOOT VIEW (Faz 2: vault + revshell + listeners) ---------- */}
      {view === 'loot' && activeWs && (() => {
        const tpl = revshellTpl.find((x) => x.id === revshell.tplId);
        const payload = renderPayload();
        const listenerCmd = `nc -lvnp ${revshell.lport || '4444'}`;
        return (
          <div className="page">
            <div className="eng-top">
              <h2>🗝️ {t.loot}</h2>
              <div className="muted small">
                {vaultStatus.encryptionAvailable
                  ? <span style={{ color: '#22c55e' }}>🔐 {t.vaultEnc}</span>
                  : <span style={{ color: '#f59e0b' }}>⚠️ {t.vaultPlain}</span>}
              </div>
            </div>

            <div className="tabs" style={{ marginTop: 10 }}>
              <button className={lootTab === 'creds' ? 'active' : ''} onClick={() => setLootTab('creds')}>🔑 {t.credentials} ({creds.length})</button>
              <button className={lootTab === 'revshell' ? 'active' : ''} onClick={() => setLootTab('revshell')}>🐚 {t.revshell}</button>
              <button className={lootTab === 'listeners' ? 'active' : ''} onClick={() => setLootTab('listeners')}>📡 {t.listeners}</button>
              <button className={lootTab === 'pivot' ? 'active' : ''} onClick={() => setLootTab('pivot')}>🌉 Pivot</button>
            </div>

            {/* CREDENTIALS */}
            {lootTab === 'creds' && (
              <div style={{ marginTop: 16 }}>
                <div className="eng-card" style={{ marginBottom: 14 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
                    <div><label>{t.host}</label><input type="text" value={credForm.host} placeholder="10.0.0.5"
                      onChange={(e) => setCredForm({ ...credForm, host: e.target.value })} /></div>
                    <div><label>{t.service}</label><input type="text" value={credForm.service} placeholder="ssh / smb / web"
                      onChange={(e) => setCredForm({ ...credForm, service: e.target.value })} /></div>
                    <div><label>{t.username}</label><input type="text" value={credForm.username} placeholder="admin"
                      onChange={(e) => setCredForm({ ...credForm, username: e.target.value })} /></div>
                    <div><label>{t.password}</label><input type="password" value={credForm.password} placeholder="••••••"
                      onChange={(e) => setCredForm({ ...credForm, password: e.target.value })} /></div>
                  </div>
                  <label style={{ marginTop: 10 }}>{t.hash}</label>
                  <input type="text" value={credForm.hash} placeholder="$2y$.. veya 32+ karakterlik hex"
                    onChange={(e) => setCredForm({ ...credForm, hash: e.target.value })} style={{ fontFamily: 'monospace' }} />
                  {credForm.hash && hashDetected.type && (
                    <div className="muted small" style={{ marginTop: 4 }}>
                      🔍 Tespit: <b>{hashDetected.type}</b>
                      {hashDetected.mode ? <> &nbsp;·&nbsp; hashcat <code>-m {hashDetected.mode}</code></> : null}
                    </div>
                  )}
                  <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
                    <input type="text" value={credForm.source} placeholder="kaynak (hydra/nuclei/leak)"
                      onChange={(e) => setCredForm({ ...credForm, source: e.target.value })} />
                    <input type="text" value={credForm.notes} placeholder="not"
                      onChange={(e) => setCredForm({ ...credForm, notes: e.target.value })} style={{ flex: 2 }} />
                    <button className="primary" onClick={submitCred}>+ {t.addCred}</button>
                  </div>
                </div>

                {creds.length === 0 ? <p className="muted">{t.noCreds}</p> : (
                  <table className="results wide">
                    <thead><tr>
                      <th>{t.host}</th><th>{t.service}</th><th>{t.username}</th><th>{t.password}</th>
                      <th>{t.hash}</th><th>{t.hashType}</th><th>{t.notes}</th><th></th>
                    </tr></thead>
                    <tbody>
                      {creds.map((c) => (
                        <tr key={c.id}>
                          <td><b>{c.host || '-'}</b></td>
                          <td>{c.service || '-'}</td>
                          <td className="mono">{c.username || '-'}</td>
                          <td>
                            {c.has_pass ? (
                              <span>
                                {revealed[c.id] != null
                                  ? <span className="mono">{revealed[c.id] || '(boş)'}</span>
                                  : <span className="muted">••••••</span>}
                                <button className="export" style={{ marginLeft: 6 }} onClick={() => revealCred(c.id)}>
                                  {revealed[c.id] != null ? '🙈' : '👁'}</button>
                                {revealed[c.id] && <button className="export" onClick={() => copyText(revealed[c.id])}>📋</button>}
                              </span>
                            ) : <span className="muted">-</span>}
                          </td>
                          <td className="mono small" style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                              title={c.hash}>{c.hash ? c.hash.slice(0, 32) + (c.hash.length > 32 ? '…' : '') : '-'}</td>
                          <td>
                            {c.hash_type ? <span className="mini-badge">{c.hash_type}</span> : '-'}
                            {c.hashcat_mode && (
                              <button className="export" style={{ marginLeft: 4 }}
                                onClick={() => copyText(`hashcat -m ${c.hashcat_mode} -a 0 hash.txt /usr/share/wordlists/rockyou.txt`)}
                                title={t.hashcatCmd}>📋hc</button>
                            )}
                          </td>
                          <td className="muted small">{c.notes || ''}</td>
                          <td>
                            <button onClick={() => removeCred(c.id)}>✕</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* REVERSE SHELL */}
            {lootTab === 'revshell' && (
              <div style={{ marginTop: 16 }}>
                <div className="eng-card">
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 2fr', gap: 10 }}>
                    <div><label>LHOST</label>
                      <input type="text" value={revshell.lhost} placeholder="10.10.14.5"
                        onChange={(e) => setRevshell({ ...revshell, lhost: e.target.value })} /></div>
                    <div><label>LPORT</label>
                      <input type="text" value={revshell.lport} placeholder="4444"
                        onChange={(e) => setRevshell({ ...revshell, lport: e.target.value })} /></div>
                    <div><label>{t.payload}</label>
                      <select value={revshell.tplId} onChange={(e) => setRevshell({ ...revshell, tplId: e.target.value })}>
                        {revshellTpl.map((x) => (
                          <option key={x.id} value={x.id}>[{x.os}] {x.name}</option>
                        ))}
                      </select></div>
                  </div>
                </div>
                <div style={{ marginTop: 12 }}>
                  <div className="section-head">
                    <b>{tpl ? tpl.name : ''}</b>
                    <div>
                      <button className="export" onClick={() => copyText(payload)}>📋 {t.copy}</button>
                      <button className="export" onClick={() => copyText(encodeURIComponent(payload))}>📋 URL-encoded</button>
                      <button className="export" onClick={() => copyText(btoa(payload))}>📋 base64</button>
                    </div>
                  </div>
                  <pre className="console-body" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{payload || '— LHOST/LPORT girin —'}</pre>
                </div>
                <div style={{ marginTop: 12 }}>
                  <div className="section-head">
                    <b>{t.listener} ({listenerCmd})</b>
                    <div>
                      <button className="export" onClick={() => copyText(listenerCmd)}>📋 {t.copy}</button>
                      <button className="primary" onClick={() => { setListenerCfg((m) => ({ ...m, nc: { port: revshell.lport || '4444' } })); setLootTab('listeners'); }}>
                        📡 Dahili dinleyici başlat
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* LISTENERS */}
            {lootTab === 'listeners' && (
              <div style={{ marginTop: 16 }}>
                <p className="muted small">{t.listenerHint}</p>

                {/* NC */}
                <div className="eng-card" style={{ marginTop: 12 }}>
                  <div className="section-head">
                    <b>📡 TCP Reverse Shell Catcher (nc)</b>
                    {listenerState.nc && listenerState.nc.running
                      ? <span className="mini-badge ok">çalışıyor :{listenerState.nc.port}</span>
                      : <span className="mini-badge">kapalı</span>}
                  </div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'end', marginTop: 8 }}>
                    <div><label>Port</label>
                      <input type="text" value={listenerCfg.nc.port}
                        onChange={(e) => setListenerCfg((m) => ({ ...m, nc: { port: e.target.value } }))} /></div>
                    {!listenerState.nc || !listenerState.nc.running
                      ? <button className="primary" onClick={() => startListener('nc')}>▶ {t.lStart}</button>
                      : <button onClick={() => stopListener('nc')}>■ {t.lStop}</button>}
                  </div>
                  <pre className="console-body" style={{ marginTop: 8, maxHeight: 260 }}>{listenerOut.nc || '— başlatılmadı —'}</pre>
                  {listenerState.nc && listenerState.nc.running && (
                    <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
                      <input type="text" value={ncInput} placeholder="komut → yakalanan shell'e gönder (whoami, id...)"
                        onChange={(e) => setNcInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && sendNc()} style={{ flex: 1, fontFamily: 'monospace' }} />
                      <button onClick={sendNc}>↵ Gönder</button>
                    </div>
                  )}
                </div>

                {/* HTTP */}
                <div className="eng-card" style={{ marginTop: 12 }}>
                  <div className="section-head">
                    <b>🌐 HTTP File Server</b>
                    {listenerState.http && listenerState.http.running
                      ? <span className="mini-badge ok">çalışıyor :{listenerState.http.port}</span>
                      : <span className="mini-badge">kapalı</span>}
                  </div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'end', marginTop: 8 }}>
                    <div><label>Port</label>
                      <input type="text" value={listenerCfg.http.port}
                        onChange={(e) => setListenerCfg((m) => ({ ...m, http: { ...m.http, port: e.target.value } }))} /></div>
                    <div style={{ flex: 1 }}><label>Dizin</label>
                      <input type="text" readOnly value={listenerCfg.http.dir || '(varsayılan)'} />
                    </div>
                    <button onClick={() => pickShareDir('http')}>📁</button>
                    {!listenerState.http || !listenerState.http.running
                      ? <button className="primary" onClick={() => startListener('http')}>▶ {t.lStart}</button>
                      : <button onClick={() => stopListener('http')}>■ {t.lStop}</button>}
                  </div>
                  <pre className="console-body" style={{ marginTop: 8, maxHeight: 200 }}>{listenerOut.http || '— başlatılmadı —'}</pre>
                </div>

                {/* SMB */}
                <div className="eng-card" style={{ marginTop: 12 }}>
                  <div className="section-head">
                    <b>📂 SMB Share (impacket-smbserver)</b>
                    {listenerState.smb && listenerState.smb.running
                      ? <span className="mini-badge ok">çalışıyor :{listenerState.smb.port}</span>
                      : <span className="mini-badge">kapalı</span>}
                  </div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'end', marginTop: 8 }}>
                    <div style={{ flex: 1 }}><label>Dizin</label>
                      <input type="text" readOnly value={listenerCfg.smb.dir || '(varsayılan)'} />
                    </div>
                    <button onClick={() => pickShareDir('smb')}>📁</button>
                    {!listenerState.smb || !listenerState.smb.running
                      ? <button className="primary" onClick={() => startListener('smb')}>▶ {t.lStart}</button>
                      : <button onClick={() => stopListener('smb')}>■ {t.lStop}</button>}
                  </div>
                  <pre className="console-body" style={{ marginTop: 8, maxHeight: 200 }}>{listenerOut.smb || '— başlatılmadı; impacket-smbserver kurulu olmalı —'}</pre>
                </div>
              </div>
            )}

            {/* PIVOT (Faz 4) */}
            {lootTab === 'pivot' && (
              <div style={{ marginTop: 16 }}>
                <p className="muted small">Tüm komutlar sadece şablon; uygulama hiçbir şey çalıştırmaz. Chisel için portable binary kuruluysa "dahili server" listener'lar sekmesinden başlatılabilir.</p>
                <div className="eng-card">
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
                    <div><label>LHOST (saldırgan)</label>
                      <select value={pivot.lhost} onChange={(e) => setPivot({ ...pivot, lhost: e.target.value })}>
                        {localIps.length === 0 && <option value="">LHOST</option>}
                        {localIps.map((x, i) => <option key={i} value={x.ip}>{x.ip} ({x.iface})</option>)}
                        <option value="LHOST">manuel...</option>
                      </select>
                      {pivot.lhost === 'LHOST' && (
                        <input type="text" placeholder="manuel IP" onBlur={(e) => setPivot({ ...pivot, lhost: e.target.value })} />
                      )}
                    </div>
                    <div><label>LPORT</label>
                      <input type="text" value={pivot.lport} onChange={(e) => setPivot({ ...pivot, lport: e.target.value })} /></div>
                    <div><label>İç hedef IP</label>
                      <input type="text" value={pivot.targetIp} placeholder="10.10.10.5"
                        onChange={(e) => setPivot({ ...pivot, targetIp: e.target.value })} /></div>
                    <div><label>İç hedef port</label>
                      <input type="text" value={pivot.targetPort}
                        onChange={(e) => setPivot({ ...pivot, targetPort: e.target.value })} /></div>
                  </div>
                </div>

                {pivot.tpl && (() => {
                  const Block = ({ title, cmd, use }) => (
                    <div style={{ marginTop: 8 }}>
                      <div className="section-head">
                        <b style={{ fontSize: 12 }}>{title}</b>
                        <button className="export" onClick={() => copyText(cmd)}>📋</button>
                      </div>
                      <pre className="console-body" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{cmd}</pre>
                      {use && <div className="muted small">→ {use}</div>}
                    </div>
                  );
                  const t1 = pivot.tpl;
                  return (
                    <>
                      <div className="eng-card" style={{ marginTop: 12 }}>
                        <h3 className="section-title" style={{ margin: 0 }}>🔁 Chisel — SOCKS</h3>
                        <Block title="Saldırgan (server)" cmd={t1.chisel.socks.server} use={t1.chisel.socks.use} />
                        <Block title="Pivot host (client)" cmd={t1.chisel.socks.client} />
                      </div>
                      <div className="eng-card" style={{ marginTop: 12 }}>
                        <h3 className="section-title" style={{ margin: 0 }}>🔁 Chisel — Port Forward</h3>
                        <Block title="Saldırgan" cmd={t1.chisel.forward.server} use={t1.chisel.forward.use} />
                        <Block title="Pivot host" cmd={t1.chisel.forward.client} />
                      </div>
                      <div className="eng-card" style={{ marginTop: 12 }}>
                        <h3 className="section-title" style={{ margin: 0 }}>🐉 ligolo-ng</h3>
                        <Block title="Saldırgan (proxy)" cmd={t1.ligolo.server} use={t1.ligolo.use} />
                        <Block title="Pivot host (agent)" cmd={t1.ligolo.agent} />
                      </div>
                      <div className="eng-card" style={{ marginTop: 12 }}>
                        <h3 className="section-title" style={{ margin: 0 }}>🔧 SSH varyantları</h3>
                        <Block title="Dynamic SOCKS (-D)" cmd={t1.sshDynamic.cmd} use={t1.sshDynamic.use} />
                        <Block title="Local forward (-L)" cmd={t1.sshLocal.cmd} use={t1.sshLocal.use} />
                        <Block title="Remote forward (-R)" cmd={t1.sshRemote.cmd} use={t1.sshRemote.use} />
                      </div>
                      <div className="eng-card" style={{ marginTop: 12 }}>
                        <h3 className="section-title" style={{ margin: 0 }}>🔗 Proxychains</h3>
                        <Block title="Konfig" cmd={t1.proxychains.conf} use={t1.proxychains.use} />
                      </div>
                    </>
                  );
                })()}
              </div>
            )}
          </div>
        );
      })()}

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
            <button className="export" onClick={runWayback} disabled={osintBusy === 'wayback'}>
              {osintBusy === 'wayback' ? '⏳' : '🕰️ Wayback'}</button>
            <button className="export" onClick={runGhDorks}>🐙 GitHub Dorks</button>
            <button className="export" onClick={runFavicon} disabled={osintBusy === 'fav'}>
              {osintBusy === 'fav' ? '⏳' : '🦄 Favicon Hash'}</button>
            <button className="export" onClick={runMailSec} disabled={osintBusy === 'mail'}>
              {osintBusy === 'mail' ? '⏳' : '✉️ Mail Security'}</button>
            <button className="export" onClick={runGoogleDorks}>🔎 Google Dorks</button>
          </div>
          {/* ASN + bucket: ayrı satır, kendi input'larıyla */}
          <div className="nuclei-bar" style={{ marginTop: 8 }}>
            <input type="text" placeholder="ASN/Reverse IP: IP, ASN# veya domain" value={asnQ}
              onChange={(e) => setAsnQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && runAsn()} />
            <button className="export" onClick={runAsn} disabled={osintBusy === 'asn'}>
              {osintBusy === 'asn' ? '⏳' : '🛰️ ASN / Prefixes'}</button>
            <button className="export" onClick={runReverseIp} disabled={osintBusy === 'rev'}>
              {osintBusy === 'rev' ? '⏳' : '🔁 Reverse IP'}</button>
            <input type="text" placeholder="Bucket: şirket adı (boşsa domain.split)" value={bucketName}
              onChange={(e) => setBucketName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && runBuckets()} />
            <button className="export" onClick={runBuckets} disabled={osintBusy === 'buckets'}>
              {osintBusy === 'buckets' ? '⏳' : '☁️ Cloud Buckets'}</button>
          </div>
          {/* OSINT 2. paket bar */}
          <div className="nuclei-bar" style={{ marginTop: 8 }}>
            <button className="export" onClick={runWhois} disabled={osintBusy === 'whois'}>
              {osintBusy === 'whois' ? '⏳' : '🌐 WHOIS / RDAP'}</button>
            <button className="export" onClick={runTls} disabled={osintBusy === 'tls'}>
              {osintBusy === 'tls' ? '⏳' : '🔐 TLS Cert + SAN'}</button>
            <button className="export" onClick={runTakeover} disabled={osintBusy === 'takeover'}>
              {osintBusy === 'takeover' ? '⏳' : `🪤 Subdomain Takeover${subdomains.length ? ` (${subdomains.length})` : ''}`}</button>
            <button className="export" onClick={runHttpRecon} disabled={osintBusy === 'http'}>
              {osintBusy === 'http' ? '⏳' : '🌐 HTTP Recon Bundle'}</button>
          </div>

          {/* Wayback sonuçları */}
          {waybackUrls.length > 0 && (
            <div className="eng-card" style={{ marginTop: 12 }}>
              <div className="section-head">
                <b>🕰️ Wayback Machine ({waybackUrls.length})</b>
                <button className="export" onClick={() => copyText(waybackUrls.join('\n'))}>📋 Hepsi</button>
              </div>
              <div style={{ maxHeight: 320, overflow: 'auto', fontFamily: 'monospace', fontSize: 12, marginTop: 8 }}>
                {waybackUrls.slice(0, 500).map((u, i) => (
                  <div key={i} style={{ padding: '2px 0', borderBottom: '1px solid var(--border)' }}>
                    <a href="#" onClick={(e) => { e.preventDefault(); window.open(u, '_blank'); }}>{u}</a>
                  </div>
                ))}
                {waybackUrls.length > 500 && <div className="muted small">... +{waybackUrls.length - 500} daha</div>}
              </div>
            </div>
          )}

          {/* GitHub Dork sonuçları */}
          {ghDorks.length > 0 && (
            <div className="eng-card" style={{ marginTop: 12 }}>
              <div className="section-head">
                <b>🐙 GitHub Code Search Dorks</b>
                <span className="muted small">tarayıcıda açılır — login gerekir</span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 8, marginTop: 8 }}>
                {ghDorks.map((d, i) => (
                  <div key={i} style={{ padding: 8, background: 'var(--bg)', borderRadius: 6 }}>
                    <div style={{ fontWeight: 700, fontSize: 12 }}>{d.name}</div>
                    <code style={{ fontSize: 11, color: 'var(--muted)' }}>{d.q}</code>
                    <div style={{ marginTop: 6 }}>
                      <button className="export" onClick={() => window.open(d.url, '_blank')}>🔗 Aç</button>
                      <button className="export" onClick={() => copyText(d.q)}>📋</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ASN / netblock sonucu */}
          {asnRes && (
            <div className="eng-card" style={{ marginTop: 12 }}>
              <div className="section-head">
                <b>🛰️ ASN / Netblock — {asnRes.query}</b>
                {asnRes.asnInfo && <span className="muted small">AS{asnRes.asnInfo.asn} · {asnRes.asnInfo.name} · {asnRes.asnInfo.country}</span>}
              </div>
              <p className="muted small">Şirketin tüm IP aralıkları; engagement scope'a eklemek için altın.</p>
              {asnRes.prefixes.length === 0
                ? <p className="muted">prefix bulunamadı</p>
                : <table className="results wide" style={{ marginTop: 8 }}>
                    <thead><tr><th>Prefix</th><th>Ad</th><th>Açıklama</th><th>ASN</th><th></th></tr></thead>
                    <tbody>{asnRes.prefixes.map((p, i) => (
                      <tr key={i}>
                        <td className="mono"><b>{p.prefix}</b></td>
                        <td>{p.name || '-'}</td>
                        <td className="muted small">{p.desc || '-'}</td>
                        <td className="muted">{p.asn ? `AS${p.asn}` : '-'}</td>
                        <td><button className="export" onClick={() => copyText(p.prefix)}>📋</button></td>
                      </tr>
                    ))}</tbody>
                  </table>}
              {asnRes.prefixes.length > 0 && (
                <button className="primary" style={{ marginTop: 8 }}
                  onClick={() => copyText(asnRes.prefixes.map((p) => p.prefix).join(','))}>
                  📋 Tüm prefix'ler (scope için)
                </button>
              )}
            </div>
          )}

          {/* Favicon hash sonucu */}
          {favRes && (
            <div className="eng-card" style={{ marginTop: 12 }}>
              <div className="section-head">
                <b>🦄 Favicon Hash — {favRes.url.replace('/favicon.ico', '')}</b>
                <span className="muted small">{favRes.size} bayt</span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 8 }}>
                <div style={{ padding: 12, background: 'var(--bg)', borderRadius: 6 }}>
                  <div className="muted small">Shodan mmh3 (signed int32)</div>
                  <div style={{ fontSize: 20, fontFamily: 'monospace', fontWeight: 700 }}>{favRes.hash}</div>
                  <code style={{ fontSize: 11 }}>{favRes.shodan}</code>
                  <div style={{ marginTop: 8 }}>
                    <button className="export" onClick={() => window.open(favRes.shodanUrl, '_blank')}>🔗 Shodan'da ara</button>
                    <button className="export" onClick={() => copyText(favRes.shodan)}>📋</button>
                  </div>
                </div>
                <div style={{ padding: 12, background: 'var(--bg)', borderRadius: 6 }}>
                  <div className="muted small">Censys</div>
                  <button className="export" onClick={() => window.open(favRes.censysUrl, '_blank')}>🔗 Censys'te ara</button>
                  <p className="muted small" style={{ marginTop: 10 }}>
                    Aynı favicon'u çalıştıran tüm internet host'larını bulur — gizli paneller, stage ortamı, kopyalar.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Cloud bucket sonucu */}
          {bucketRes && (
            <div className="eng-card" style={{ marginTop: 12 }}>
              <div className="section-head">
                <b>☁️ Cloud Buckets ({bucketRes.hits.length} / {bucketRes.total} taranmıştı)</b>
                <span className="muted small">200 = açık · 403 = var ama gizli</span>
              </div>
              {bucketRes.hits.length === 0
                ? <p className="muted" style={{ marginTop: 8 }}>Hit yok. Permütasyonlar boş döndü.</p>
                : <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 8, marginTop: 8 }}>
                    {bucketRes.hits.map((h, i) => (
                      <div key={i} style={{ padding: 8, borderRadius: 6,
                        background: h.code === 200 ? 'rgba(34,197,94,0.1)' : 'rgba(245,158,11,0.1)',
                        borderLeft: `4px solid ${h.code === 200 ? '#22c55e' : '#f59e0b'}` }}>
                        <div style={{ fontSize: 11, color: 'var(--muted)' }}>{h.provider.toUpperCase()} · HTTP {h.code}</div>
                        <div style={{ fontWeight: 700, fontFamily: 'monospace', fontSize: 13 }}>{h.bucket}</div>
                        <code style={{ fontSize: 10, color: 'var(--muted)', wordBreak: 'break-all' }}>{h.url}</code>
                        <div style={{ marginTop: 6 }}>
                          <button className="export" onClick={() => window.open(h.url, '_blank')}>🔗 Aç</button>
                          <button className="export" onClick={() => copyText(h.url)}>📋</button>
                        </div>
                      </div>
                    ))}
                  </div>}
            </div>
          )}

          {/* Mail security sonucu */}
          {mailSec && (() => {
            const riskColor = mailSec.risk >= 60 ? '#ef4444' : mailSec.risk >= 30 ? '#f59e0b' : '#22c55e';
            const Badge = ({ ok, label, weak }) => (
              <div style={{ padding: 10, borderRadius: 6, background: 'var(--bg)',
                            borderLeft: `4px solid ${ok && !weak ? '#22c55e' : (ok ? '#f59e0b' : '#ef4444')}` }}>
                <div style={{ fontSize: 11, color: 'var(--muted)' }}>{label}</div>
                <div style={{ fontWeight: 700 }}>{ok ? (weak ? 'Zayıf' : 'Tamam') : 'YOK'}</div>
              </div>
            );
            return (
              <div className="eng-card" style={{ marginTop: 12 }}>
                <div className="section-head">
                  <b>✉️ Mail Security — {mailSec.domain}</b>
                  <span style={{ background: riskColor, color: '#fff', padding: '3px 10px', borderRadius: 12, fontSize: 12, fontWeight: 700 }}>
                    Risk {mailSec.risk}/100 · {mailSec.verdict}
                  </span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginTop: 10 }}>
                  <Badge ok={mailSec.spf.present} weak={mailSec.spf.weak} label="SPF" />
                  <Badge ok={mailSec.dmarc.present} weak={mailSec.dmarc.weak} label="DMARC" />
                  <Badge ok={mailSec.dkim.length > 0} label={`DKIM (${mailSec.dkim.length} selector)`} />
                  <Badge ok={!!mailSec.bimi} label="BIMI" />
                </div>
                <div style={{ marginTop: 12, fontSize: 12 }}>
                  {mailSec.spf.present && (
                    <div style={{ marginBottom: 8 }}>
                      <b>SPF:</b> <code>{mailSec.spf.qualifier || '?'}</code>
                      <span className="muted small"> · {mailSec.spf.lookups} lookup{mailSec.spf.lookups > 10 ? ' ⚠️ RFC limit aşıldı' : ''}</span>
                      <pre className="console-body" style={{ marginTop: 4, fontSize: 11, maxHeight: 80 }}>{mailSec.spf.raw}</pre>
                    </div>
                  )}
                  {mailSec.dmarc.present && (
                    <div style={{ marginBottom: 8 }}>
                      <b>DMARC:</b> p=<code>{mailSec.dmarc.policy}</code>
                      {mailSec.dmarc.subPolicy && <span> · sp=<code>{mailSec.dmarc.subPolicy}</code></span>}
                      <span> · pct={mailSec.dmarc.pct}</span>
                      {mailSec.dmarc.rua && <div className="muted small">rua: {mailSec.dmarc.rua}</div>}
                    </div>
                  )}
                  {mailSec.dkim.length > 0 && (
                    <div style={{ marginBottom: 8 }}>
                      <b>DKIM selector'lar:</b> {mailSec.dkim.map((d) => d.selector).join(', ')}
                    </div>
                  )}
                  {mailSec.mx.length > 0 && (
                    <div className="muted small">MX: {mailSec.mx.map((m) => `${m.pref} ${m.host}`).join(', ')}</div>
                  )}
                  {!mailSec.spf.present && !mailSec.dmarc.present && (
                    <div style={{ color: '#ef4444', marginTop: 8 }}>
                      🚨 SPF/DMARC yok — bu domain'den **spoofing** mümkün. Phishing ROE'sine uygunsa kullanılabilir.
                    </div>
                  )}
                </div>
              </div>
            );
          })()}

          {/* Google dorks sonucu */}
          {googleDorks.length > 0 && (
            <div className="eng-card" style={{ marginTop: 12 }}>
              <div className="section-head">
                <b>🔎 Google Dorks ({googleDorks.length})</b>
                <span className="muted small">tarayıcıda açılır</span>
              </div>
              {Array.from(new Set(googleDorks.map((d) => d.cat))).map((cat) => (
                <div key={cat} style={{ marginTop: 10 }}>
                  <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>{cat}</div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 6 }}>
                    {googleDorks.filter((d) => d.cat === cat).map((d, i) => (
                      <div key={i} style={{ padding: 6, background: 'var(--bg)', borderRadius: 4, fontSize: 12 }}>
                        <div style={{ fontWeight: 700 }}>{d.name}</div>
                        <code style={{ fontSize: 10, color: 'var(--muted)' }}>{d.q}</code>
                        <div style={{ marginTop: 4 }}>
                          <button className="export" onClick={() => window.open(d.url, '_blank')}>🔗</button>
                          <button className="export" onClick={() => copyText(d.q)}>📋</button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* WHOIS / RDAP */}
          {whoisRes && (
            <div className="eng-card" style={{ marginTop: 12 }}>
              <div className="section-head">
                <b>🌐 WHOIS / RDAP — {whoisRes.domain}</b>
                {whoisRes.dnssec && <span className="mini-badge ok">DNSSEC</span>}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10, marginTop: 8, fontSize: 13 }}>
                <div><b>Registrar:</b> {whoisRes.registrar || '-'}</div>
                <div><b>Kayıt:</b> {whoisRes.registered ? new Date(whoisRes.registered).toLocaleDateString() : '-'}</div>
                <div><b>Bitiş:</b> {whoisRes.expires ? new Date(whoisRes.expires).toLocaleDateString() : '-'}</div>
                <div><b>Güncelleme:</b> {whoisRes.updated ? new Date(whoisRes.updated).toLocaleDateString() : '-'}</div>
                {whoisRes.registrant && whoisRes.registrant.org && <div><b>Sahip org:</b> {whoisRes.registrant.org}</div>}
                {whoisRes.registrant && whoisRes.registrant.email && <div><b>Email:</b> {whoisRes.registrant.email}</div>}
              </div>
              {whoisRes.nameservers.length > 0 && (
                <div style={{ marginTop: 8 }}>
                  <b>Nameserver'lar:</b>
                  <div className="mono small" style={{ marginTop: 4 }}>{whoisRes.nameservers.join(', ')}</div>
                </div>
              )}
              {whoisRes.status.length > 0 && (
                <div style={{ marginTop: 8 }} className="muted small">Status: {whoisRes.status.join(', ')}</div>
              )}
            </div>
          )}

          {/* Reverse IP */}
          {revIpRes && (
            <div className="eng-card" style={{ marginTop: 12 }}>
              <div className="section-head">
                <b>🔁 Reverse IP — {revIpRes.ip}</b>
                <span className="muted small">{revIpRes.count} virtual host</span>
              </div>
              <p className="muted small">Aynı IP'de barınan diğer domain'ler — shared hosting komşusu veya CDN arkasındaki origin.</p>
              {revIpRes.count === 0 ? <p className="muted">Sonuç yok</p> : (
                <div style={{ maxHeight: 320, overflow: 'auto', fontFamily: 'monospace', fontSize: 12, marginTop: 8 }}>
                  {revIpRes.hosts.map((h, i) => (
                    <div key={i} style={{ padding: '2px 0', borderBottom: '1px solid var(--border)' }}>
                      <a href="#" onClick={(e) => { e.preventDefault(); setOsintDomain(h); }}>{h}</a>
                    </div>
                  ))}
                </div>
              )}
              {revIpRes.count > 0 && (
                <button className="primary" style={{ marginTop: 8 }}
                  onClick={() => copyText(revIpRes.hosts.join('\n'))}>📋 Hepsi</button>
              )}
            </div>
          )}

          {/* TLS Cert + SAN */}
          {tlsRes && (() => {
            const expiring = tlsRes.daysLeft != null && tlsRes.daysLeft < 30;
            return (
              <div className="eng-card" style={{ marginTop: 12 }}>
                <div className="section-head">
                  <b>🔐 TLS Sertifika — {tlsRes.host}:{tlsRes.port}</b>
                  <span className={'mini-badge ' + (tlsRes.expired ? 'bad' : expiring ? 'warn' : 'ok')}>
                    {tlsRes.expired ? `${-tlsRes.daysLeft} gün önce doldu` : `${tlsRes.daysLeft} gün kaldı`}
                  </span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10, marginTop: 8, fontSize: 13 }}>
                  <div><b>Subject:</b> {tlsRes.subject}</div>
                  <div><b>Issuer:</b> {tlsRes.issuer}</div>
                  <div><b>Protocol:</b> {tlsRes.protocol || '-'} · <b>Cipher:</b> {tlsRes.cipher || '-'}</div>
                  <div><b>Key:</b> {tlsRes.keyType || '-'}</div>
                  <div><b>Geçerli:</b> {tlsRes.validFrom} → {tlsRes.validTo}</div>
                  <div className="mono small"><b>Serial:</b> {tlsRes.serial}</div>
                </div>
                <div style={{ marginTop: 10 }}>
                  <div className="section-head">
                    <b>SAN ({tlsRes.sanCount}) — sertifikadaki tüm isimler</b>
                    <button className="export" onClick={() => copyText(tlsRes.sans.join('\n'))}>📋</button>
                  </div>
                  <p className="muted small">Bunlar sertifikadan çıkar — crt.sh kaçırmış olabileceği subdomain'leri bulur.</p>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
                    {tlsRes.sans.map((s, i) => (
                      <span key={i} className="mini-badge" style={{ fontFamily: 'monospace', fontSize: 11, cursor: 'pointer' }}
                        onClick={() => setOsintDomain(s)}>{s}</span>
                    ))}
                  </div>
                </div>
                {tlsRes.chain && tlsRes.chain.length > 1 && (
                  <details style={{ marginTop: 10 }}>
                    <summary className="muted small">Sertifika zinciri ({tlsRes.chain.length})</summary>
                    {tlsRes.chain.map((c, i) => (
                      <div key={i} style={{ padding: 6, background: 'var(--bg)', borderRadius: 4, marginTop: 4, fontSize: 11 }}>
                        <div><b>{c.subject}</b> ← {c.issuer}</div>
                        <div className="muted">{c.validFrom} → {c.validTo}</div>
                        <div className="muted mono">{c.fingerprint256}</div>
                      </div>
                    ))}
                  </details>
                )}
              </div>
            );
          })()}

          {/* Subdomain takeover */}
          {takeoverRes && (
            <div className="eng-card" style={{ marginTop: 12 }}>
              <div className="section-head">
                <b>🪤 Subdomain Takeover ({takeoverRes.hits.length}/{takeoverRes.total})</b>
                <span className="muted small">CNAME + body fingerprint</span>
              </div>
              {takeoverRes.hits.length === 0 ? (
                <p className="muted" style={{ marginTop: 6 }}>Olası takeover yok — tüm subdomain'ler sağlıklı veya provider eşleşmedi.</p>
              ) : (
                <table className="results wide" style={{ marginTop: 8 }}>
                  <thead><tr><th>Subdomain</th><th>Provider</th><th>CNAME</th><th>Durum</th><th>Severity</th></tr></thead>
                  <tbody>{takeoverRes.hits.map((h, i) => (
                    <tr key={i}>
                      <td><b>{h.sub}</b></td>
                      <td>{h.provider}</td>
                      <td className="mono small">{h.cname || '-'}</td>
                      <td>
                        <span className={'mini-badge ' + (h.takeover === 'confirmed' ? 'bad' : 'warn')}>
                          {h.takeover === 'confirmed' ? '🎯 onaylı' : '⚠ olası'}
                        </span>
                        {h.resolves ? '' : ' · A yok'}
                      </td>
                      <td>
                        <span style={{ background: SEV_COLORS[h.severity] || '#666', color: '#fff', padding: '2px 8px', borderRadius: 8, fontSize: 11, fontWeight: 700 }}>
                          {(h.severity || '').toUpperCase()}
                        </span>
                      </td>
                    </tr>
                  ))}</tbody>
                </table>
              )}
              <details style={{ marginTop: 8 }}>
                <summary className="muted small">Tüm taranan ({takeoverRes.all.length})</summary>
                <div style={{ maxHeight: 200, overflow: 'auto', fontSize: 11, fontFamily: 'monospace', marginTop: 6 }}>
                  {takeoverRes.all.map((r, i) => (
                    <div key={i} style={{ opacity: r.takeover ? 1 : 0.6 }}>
                      {r.takeover === 'confirmed' ? '🎯' : r.takeover === 'likely' ? '⚠' : r.resolves ? '○' : '·'} {r.sub}
                      {r.cname && <span className="muted"> → {r.cname}</span>}
                    </div>
                  ))}
                </div>
              </details>
            </div>
          )}

          {/* HTTP Recon Bundle */}
          {httpRecon && (() => {
            const sec = httpRecon.secHeaders;
            const gradeColor = { A: '#22c55e', B: '#84cc16', C: '#f59e0b', D: '#f97316', F: '#ef4444' }[sec.grade];
            return (
              <div className="eng-card" style={{ marginTop: 12 }}>
                <div className="section-head">
                  <b>🌐 HTTP Recon — {httpRecon.origin}</b>
                  <div>
                    <span className="mini-badge">HTTP {httpRecon.status}</span>
                    {httpRecon.waf.map((w) => <span key={w} className="mini-badge ok" style={{ marginLeft: 4 }}>🛡️ {w}</span>)}
                    <span style={{ background: gradeColor, color: '#fff', padding: '3px 10px', borderRadius: 12, fontSize: 12, fontWeight: 700, marginLeft: 6 }}>
                      Sec {sec.grade} ({sec.score})
                    </span>
                  </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 10 }}>
                  <div>
                    {httpRecon.tech.length > 0 && (
                      <div style={{ marginBottom: 8 }}>
                        <b>Tech ipuçları:</b>
                        <div>{httpRecon.tech.map((t, i) => <span key={i} className="mini-badge" style={{ marginRight: 4 }}>{t}</span>)}</div>
                      </div>
                    )}
                    {sec.reasons.length > 0 && (
                      <div style={{ marginBottom: 8 }}>
                        <b>Güvenlik header eksikleri:</b>
                        <ul style={{ marginTop: 4, paddingLeft: 18 }}>
                          {sec.reasons.map((r, i) => <li key={i} style={{ fontSize: 12 }}>{r}</li>)}
                        </ul>
                      </div>
                    )}
                  </div>
                  <div>
                    <details>
                      <summary><b>Response headers</b></summary>
                      <pre style={{ fontSize: 11, maxHeight: 200, overflow: 'auto', background: 'var(--bg)', padding: 8, borderRadius: 4 }}>{httpRecon.headerText}</pre>
                    </details>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginTop: 10 }}>
                  {/* robots.txt */}
                  <div style={{ padding: 8, background: 'var(--bg)', borderRadius: 6 }}>
                    <div className="section-head">
                      <b>robots.txt {httpRecon.robots.present ? '✓' : '✕'}</b>
                      {httpRecon.robots.present && <span className="muted small">{httpRecon.robots.disallows.length} Disallow</span>}
                    </div>
                    {httpRecon.robots.disallows.length > 0 && (
                      <div style={{ maxHeight: 140, overflow: 'auto', fontSize: 11, fontFamily: 'monospace', marginTop: 6 }}>
                        {httpRecon.robots.disallows.slice(0, 50).map((p, i) => <div key={i}>{p}</div>)}
                      </div>
                    )}
                  </div>
                  {/* sitemap.xml */}
                  <div style={{ padding: 8, background: 'var(--bg)', borderRadius: 6 }}>
                    <div className="section-head">
                      <b>sitemap.xml {httpRecon.sitemap.present ? '✓' : '✕'}</b>
                      {httpRecon.sitemap.present && <span className="muted small">{httpRecon.sitemap.urls.length} URL</span>}
                    </div>
                    {httpRecon.sitemap.urls.length > 0 && (
                      <div style={{ maxHeight: 140, overflow: 'auto', fontSize: 10, fontFamily: 'monospace', marginTop: 6 }}>
                        {httpRecon.sitemap.urls.slice(0, 30).map((u, i) => <div key={i}>{u}</div>)}
                      </div>
                    )}
                  </div>
                  {/* security.txt */}
                  <div style={{ padding: 8, background: 'var(--bg)', borderRadius: 6 }}>
                    <div className="section-head">
                      <b>security.txt {httpRecon.securityTxt.present ? '✓' : '✕'}</b>
                    </div>
                    {httpRecon.securityTxt.present && (
                      <div style={{ fontSize: 11, marginTop: 6 }}>
                        {Object.entries(httpRecon.securityTxt.parsed).map(([k, v], i) => (
                          <div key={i}><b>{k}:</b> {Array.isArray(v) ? v.join(', ') : String(v)}</div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })()}

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
        <div className="page tools-page">
          {/* Web Pipeline orkestratörü (Faz 3) */}
          <div className="eng-card" style={{ marginBottom: 16 }}>
            <div className="section-head">
              <h3 className="section-title" style={{ margin: 0 }}>🚀 Web Recon Pipeline</h3>
              {webBusy ? <button onClick={stopWeb}>■ Durdur</button> : null}
            </div>
            <p className="muted small">httpx fingerprint → tech tespiti → akıllı nuclei `-tags` türetimi → opsiyonel subfinder → live alt-host taraması. Sonuçlar workspace'e yazılır.</p>
            <div style={{ display: 'flex', gap: 8, alignItems: 'end' }}>
              <div style={{ flex: 2 }}><label>Hedef (URL veya domain)</label>
                <input type="text" value={web.target} placeholder="example.com veya https://example.com"
                  onChange={(e) => setWeb({ ...web, target: e.target.value })} /></div>
              <label style={{ marginBottom: 8 }}>
                <input type="checkbox" checked={web.subdomains} onChange={(e) => setWeb({ ...web, subdomains: e.target.checked })} /> Subdomain
              </label>
              <label style={{ marginBottom: 8 }}>
                <input type="checkbox" checked={web.nuclei} onChange={(e) => setWeb({ ...web, nuclei: e.target.checked })} /> nuclei
              </label>
              <button className="primary" onClick={runWeb} disabled={webBusy}>{webBusy ? '⏳' : '▶ Başlat'}</button>
            </div>
            {webSteps.length > 0 && (
              <div style={{ marginTop: 10, maxHeight: 260, overflow: 'auto', background: 'var(--bg)', padding: 10, borderRadius: 6 }}>
                {webSteps.map((s, i) => (
                  <div key={i} style={{ fontSize: 12, marginBottom: 4, fontFamily: 'monospace' }}>
                    <span style={{ color: 'var(--muted)' }}>[{s.step}]</span>{' '}
                    {s.step === 'start' && <span>başlatıldı: {s.data.target}</span>}
                    {s.step === 'httpx' && <span>httpx → {s.data.count} canlı host{s.data.results && s.data.results[0] ? `, server: ${s.data.results[0].server || '?'}` : ''}</span>}
                    {s.step === 'tech' && <span>tech: <b>{s.data.tech.join(', ') || '-'}</b> · nuclei tags: <b style={{ color: 'var(--red)' }}>{s.data.nucleiTags.join(',')}</b></span>}
                    {s.step === 'subfinder' && <span>subfinder: {s.data.status || (s.data.count + ' subdomain')}</span>}
                    {s.step === 'subhttpx' && <span>live subdomain: {s.data.count}</span>}
                    {s.step === 'nuclei' && <span>nuclei {s.data.status}{s.data.count ? ` · ${s.data.count} bulgu` : ''}</span>}
                    {s.step === 'finding' && <span style={{ color: sevColorMap[s.data.severity] || 'var(--text)' }}>● [{s.data.severity}] {s.data.host}:{s.data.port || '-'} {s.data.name}</span>}
                    {s.step === 'done' && <span style={{ color: 'var(--green)' }}>✓ pipeline {s.data.stopped ? 'durduruldu' : 'tamamlandı'}</span>}
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="tools-head">
            <h2>🧰 {t.tools}</h2>
            <div className="tools-head-actions">
              <button className="primary" disabled={portableBusy} onClick={installAllPortable}>
                {portableBusy ? '⏳ İndiriliyor...' : '⚡ Tüm portable\'ları kur'}</button>
              {isWin && toolStatus.wsl && (
                <button className="export" disabled={installingTool} onClick={() => installTool('all')}>
                  {installingTool === 'all' ? 'WSL kuruluyor...' : '🐧 WSL araçları'}</button>
              )}
              <button className="export" onClick={() => { refreshTools(); refreshPortable(); }}>↻</button>
            </div>
          </div>

          {/* Runtime durum şeridi (kompakt) */}
          <div className="runtime-bar">
            <span className={'rt-chip ' + (nmap.installed ? 'ok' : 'no')}>nmap {nmap.installed ? '✓' : '✕'}</span>
            <span className={'rt-chip ok'}>portable {Object.values(portableStatus).filter((s) => s.installed).length}/{Object.values(portableStatus).filter((s) => s.supported).length}</span>
            {isWin && <span className={'rt-chip ' + (toolStatus.wsl ? 'ok' : 'no')}>WSL {toolStatus.wsl ? '✓' : '✕'}</span>}
            {isWin && !toolStatus.wsl && (
              <button className="rt-act" onClick={installWsl}>⬇ WSL kur</button>
            )}
          </div>

          {/* ============== KILL-CHAIN KANBAN ============== */}
          <div className="kanban">
            {KILL_CHAIN.map((col) => {
              const colTools = toolCatalog.filter((tl) => tl.phase === col.id);
              return (
                <div key={col.id} className="kb-col">
                  <div className="kb-head" style={{ background: col.color }}>
                    <div className="kb-h-left">
                      <span className="kb-h-ic">{col.icon}</span>
                      <div>
                        <div className="kb-h-title">{col.title}</div>
                        <div className="kb-h-desc">{col.desc}</div>
                      </div>
                    </div>
                    <span className="kb-h-count">{colTools.length}</span>
                  </div>
                  <div className="kb-body">
                    {colTools.map((tl) => {
                      const found = toolStatus.tools[tl.id] || tl.builtIn;
                      const isPortable = toolStatus.portable && toolStatus.portable[tl.id];
                      const portableSupported = portableStatus[tl.id] && portableStatus[tl.id].supported;
                      const prog = portableProg[tl.id];
                      const portableInstalling = prog && prog.phase !== 'done' && (prog.pct || 0) < 100 && !(portableStatus[tl.id] && portableStatus[tl.id].installed);
                      const wslInstalling = installingTool === tl.id;
                      const busy = portableInstalling || wslInstalling;
                      const stateLabel = tl.builtIn ? 'Dahili' : (isPortable ? 'Portable' : (found ? 'WSL' : 'Yok'));
                      const stateClass = found ? 'ok' : 'no';
                      const smartInstall = () => {
                        if (busy || tl.builtIn) return;
                        if (portableSupported) return installPortable(tl.id);
                        if (toolStatus.wsl) return installTool(tl.id);
                        toast('Bu araç WSL gerektirir.', 'warn');
                        installWsl();
                      };
                      const btnLabel = (() => {
                        if (portableInstalling) return `⬇ %${prog.pct || 0}`;
                        if (wslInstalling) return '...';
                        if (portableSupported) return '⬇ Portable';
                        if (toolStatus.wsl) return '⬇ WSL';
                        return '⬇ Kur';
                      })();
                      return (
                        <div key={tl.id} className={'kb-card ' + (found ? 'on' : 'off')}>
                          <div className="kb-c-bar" style={{ background: found ? '#22c55e' : '#3a3a40' }}></div>
                          <div className="kb-c-main">
                            <div className="kb-c-head">
                              <b>{tl.name}</b>
                              <span className={'kb-c-st ' + stateClass}>{stateLabel}</span>
                            </div>
                            <div className="kb-c-desc">{tl.desc}</div>
                            {portableInstalling && (
                              <div className="pc-bar"><div className="pc-bar-fill" style={{ width: (prog.pct || 0) + '%' }}></div></div>
                            )}
                            {!found && !tl.builtIn && (
                              <button className="kb-c-btn" disabled={busy} onClick={smartInstall}>{btnLabel}</button>
                            )}
                            {(found || tl.builtIn) && TOOL_LAUNCHERS[tl.id] && (
                              <button className="kb-c-run" onClick={() => openLauncher(tl.id)}>▶ Çalıştır</button>
                            )}
                            {found && !tl.builtIn && portableSupported && (
                              <div className="kb-c-actions">
                                <button className="kb-c-mini" title="Güncelle" onClick={() => installPortable(tl.id)}>↻</button>
                                <button className="kb-c-mini" title="Kaldır" onClick={() => uninstallPortable(tl.id)}>🗑</button>
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
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
              {diffResult.verChanges && diffResult.verChanges.length > 0 && (
                <div className="diff-vers">
                  <b>🔧 Sürüm değişiklikleri ({diffResult.verChanges.length})</b>
                  {diffResult.verChanges.map((v, i) => (
                    <div key={i} className="diff-ver-row"><span className="mono">{v.key}</span>
                      <span className="muted">{v.from}</span> → <b>{v.to}</b></div>
                  ))}
                </div>
              )}
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
          <div className="set-row"><label>{t.autoEvidence}</label>
            <input type="checkbox" checked={settings.autoEvidence !== false} onChange={(e) => saveSettings({ ...settings, autoEvidence: e.target.checked })} /></div>
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
