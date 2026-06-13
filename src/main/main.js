const { app, BrowserWindow, ipcMain, shell, dialog, Notification, desktopCapturer, Menu, Tray, nativeImage } = require('electron');
const dns = require('dns').promises;
const path = require('path');
const fs = require('fs');
const os = require('os');
const https = require('https');
const { spawn, execFile, exec } = require('child_process');
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
    backgroundColor: '#0e0e11',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  // Pencereli tam ekran (maximized) — ekran sınırlarına kadar, ama yine sürüklenebilir.
  mainWindow.once('ready-to-show', () => { mainWindow.maximize(); mainWindow.show(); });

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

app.whenReady().then(async () => {
  ensureDirs();
  portable.init(dataDir());
  try { await db.initDb(dataDir()); log('Veritabanı hazır.'); }
  catch (e) { log('DB init hatası: ' + e); }
  log('Uygulama başlatıldı.');
  createWindow();
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

  currentScan.stdout.on('data', (d) => mainWindow.webContents.send('scan:stdout', d.toString()));
  currentScan.stderr.on('data', (d) => {
    const s = d.toString();
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

// ---------------- Workspace / Engagement ----------------
ipcMain.handle('ws:list', async () => db.listWorkspaces());
ipcMain.handle('ws:active', async () => db.getActiveWorkspace());
ipcMain.handle('ws:create', async (e, { name, mode, scope }) => db.createWorkspace(name, mode, scope));
ipcMain.handle('ws:setActive', async (e, id) => db.setActiveWorkspace(id));
ipcMain.handle('ws:update', async (e, { id, fields }) => db.updateWorkspace(id, fields));
ipcMain.handle('ws:delete', async (e, id) => db.deleteWorkspace(id));
ipcMain.handle('ws:assets', async (e, id) => db.workspaceAssets(id));
ipcMain.handle('ws:audit', async (e, id) => db.listAudit(id));
ipcMain.handle('ws:logAudit', async (e, { ws, action, detail }) => { db.addAudit(ws, action, detail); return true; });

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
  { id: 'enum4linux', name: 'enum4linux', desc: 'SMB/Samba enumerasyonu', cat: 'Enum', phase: 'enum',
    install: 'apt-get update && apt-get install -y enum4linux' },

  // EXPLOIT
  { id: 'searchsploit', name: 'SearchSploit', desc: 'ExploitDB exploit araması (salt-okunur)', cat: 'Exploit', phase: 'exploit',
    install: 'apt-get update && apt-get install -y exploitdb' },
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
    install: 'apt-get update && apt-get install -y python3-pip && pipx install netexec' },
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
    // Tüm araçları tek komutta kur (apt olanlar + nuclei).
    const aptTools = TOOL_CATALOG.filter((x) => x.id !== 'nuclei').map((x) => x.id).join(' ');
    const script = `apt-get update && apt-get install -y ${aptTools} curl unzip; ${NUCLEI_INSTALL}`;
    return runInstall(script, 'Tüm araçlar');
  }
  const tdef = TOOL_CATALOG.find((x) => x.id === toolId);
  if (!tdef) return { ok: false, error: 'Bilinmeyen araç' };
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
  currentNuclei.stdout.on('data', (d) => {
    buf += d.toString();
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
  currentNuclei.stderr.on('data', (d) => mainWindow.webContents.send('nuclei:out', d.toString()));
  currentNuclei.on('close', (code) => {
    try {
      const ws = db.getActiveWorkspace();
      if (ws && findings.length) db.addNucleiFindings(ws.id, findings);
    } catch (err) { log('nuclei persist hatası: ' + err); }
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
  mainWindow.webContents.send('tool:out', `=== ${tool} ${target} ===\n`);
  currentTool.stdout.on('data', (d) => {
    const s = d.toString();
    mainWindow.webContents.send('tool:out', s);
    if (tool === 'masscan') {
      // "Discovered open port 80/tcp on 192.168.0.1"
      const re = /Discovered open port (\d+)\/(tcp|udp) on ([\d.]+)/g; let m;
      while ((m = re.exec(s))) masscanPorts.push({ port: m[1], proto: m[2], ip: m[3] });
    }
  });
  currentTool.stderr.on('data', (d) => mainWindow.webContents.send('tool:out', d.toString()));
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
  const vulns = (a.vulns || []).slice().sort((x, y) => (sevRank[y.severity] || 0) - (sevRank[x.severity] || 0));
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
    return `<tr><td><span style="background:${c};color:#fff;padding:2px 8px;border-radius:8px;font-size:11px">${esc((v.severity || 'info').toUpperCase())}</span></td>
      <td>${esc(v.host_ip)}</td><td>${esc(v.port || '-')}</td><td>${esc(v.cve)}</td><td>${esc(v.script || '')}</td></tr>`;
  }).join('');

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
      <div class="sub">Çalışma Alanı: <b>${esc(ws.name)}</b> · Kapsam: ${esc(ws.scope || '-')}<br>
      Tarih: ${new Date().toLocaleString('tr-TR')} · Mod: ${esc(ws.mode)}</div>
      <div class="risk">Genel Risk: ${riskLevel}</div>
    </div>
    <div class="content">
      <h2>Yönetici Özeti</h2>
      <p>Bu değerlendirmede <b>${a.hosts.length}</b> canlı varlık, <b>${a.services.length}</b> açık servis ve
      <b>${a.vulns.length}</b> zafiyet bulgusu tespit edilmiştir. Toplam ${a.scans.length} tarama yürütülmüştür.
      Genel risk seviyesi <b style="color:${riskColor}">${riskLevel}</b> olarak değerlendirilmiştir.</p>
      <div class="stats">
        <div class="stat"><b>${a.hosts.length}</b><span>Varlık</span></div>
        <div class="stat"><b>${a.services.length}</b><span>Servis</span></div>
        <div class="stat"><b style="color:#b91c1c">${a.vulns.length}</b><span>Zafiyet</span></div>
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
