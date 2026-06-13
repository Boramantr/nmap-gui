// Portable pentest araçları — Windows native binary'leri GitHub release'lerden indirir.
// WSL gereksinimini kaldırır. Indirilen exe'ler userData/bin/<tool>/ altına yerleşir.
//
// Kayıt formatı:
//   id       : araç id'si (TOOL_CATALOG ile aynı)
//   platforms: { win32: { repo, assetPattern, binInZip } }
//     repo:         GitHub "owner/name"
//     assetPattern: hangi release asset'i (regex)
//     binInZip:     zip içinde aranacak exe'nin adı

const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const { exec } = require('child_process');

const REGISTRY = {
  nuclei: {
    name: 'Nuclei',
    platforms: {
      win32: { repo: 'projectdiscovery/nuclei', assetPattern: /nuclei_.*_windows_amd64\.zip$/i, binInZip: 'nuclei.exe' },
      linux: { repo: 'projectdiscovery/nuclei', assetPattern: /nuclei_.*_linux_amd64\.zip$/i, binInZip: 'nuclei' },
      darwin: { repo: 'projectdiscovery/nuclei', assetPattern: /nuclei_.*_macOS_(arm64|amd64)\.zip$/i, binInZip: 'nuclei' },
    },
  },
  gobuster: {
    name: 'Gobuster',
    platforms: {
      win32: { repo: 'OJ/gobuster', assetPattern: /gobuster_Windows_x86_64\.zip$/i, binInZip: 'gobuster.exe' },
      linux: { repo: 'OJ/gobuster', assetPattern: /gobuster_Linux_x86_64\.tar\.gz$/i, binInZip: 'gobuster' },
      darwin: { repo: 'OJ/gobuster', assetPattern: /gobuster_Darwin_(arm64|x86_64)\.tar\.gz$/i, binInZip: 'gobuster' },
    },
  },
  httpx: {
    name: 'httpx',
    platforms: {
      win32: { repo: 'projectdiscovery/httpx', assetPattern: /httpx_.*_windows_amd64\.zip$/i, binInZip: 'httpx.exe' },
      linux: { repo: 'projectdiscovery/httpx', assetPattern: /httpx_.*_linux_amd64\.zip$/i, binInZip: 'httpx' },
      darwin: { repo: 'projectdiscovery/httpx', assetPattern: /httpx_.*_macOS_(arm64|amd64)\.zip$/i, binInZip: 'httpx' },
    },
  },
  subfinder: {
    name: 'Subfinder',
    platforms: {
      win32: { repo: 'projectdiscovery/subfinder', assetPattern: /subfinder_.*_windows_amd64\.zip$/i, binInZip: 'subfinder.exe' },
      linux: { repo: 'projectdiscovery/subfinder', assetPattern: /subfinder_.*_linux_amd64\.zip$/i, binInZip: 'subfinder' },
      darwin: { repo: 'projectdiscovery/subfinder', assetPattern: /subfinder_.*_macOS_(arm64|amd64)\.zip$/i, binInZip: 'subfinder' },
    },
  },
};

let binRoot = null;
function init(userDataDir) { binRoot = path.join(userDataDir, 'bin'); fs.mkdirSync(binRoot, { recursive: true }); }

// Bir aracın portable olarak desteklenip desteklenmediği.
function isSupported(id) { return !!(REGISTRY[id] && REGISTRY[id].platforms[process.platform]); }
function listSupported() { return Object.keys(REGISTRY).filter(isSupported); }

// Kurulu portable binary yolu (yoksa null).
function binPath(id) {
  if (!binRoot || !REGISTRY[id]) return null;
  const meta = REGISTRY[id].platforms[process.platform];
  if (!meta) return null;
  const p = path.join(binRoot, id, meta.binInZip);
  return fs.existsSync(p) ? p : null;
}

function statusAll() {
  const out = {};
  Object.keys(REGISTRY).forEach((id) => {
    out[id] = { supported: isSupported(id), installed: !!binPath(id), path: binPath(id) || '' };
  });
  return out;
}

// GitHub release API — en son sürümün asset URL'si.
function fetchLatestAsset(repo, pattern) {
  return new Promise((resolve, reject) => {
    const opts = { headers: { 'User-Agent': 'NmapGUI', Accept: 'application/vnd.github+json' } };
    https.get(`https://api.github.com/repos/${repo}/releases/latest`, opts, (res) => {
      if (res.statusCode === 403) return reject(new Error('GitHub API limiti (403). Birkaç dakika sonra deneyin.'));
      if (res.statusCode !== 200) return reject(new Error('GitHub HTTP ' + res.statusCode));
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        try {
          const j = JSON.parse(body);
          const asset = (j.assets || []).find((a) => pattern.test(a.name || ''));
          if (!asset) return reject(new Error(`Eşleşen asset bulunamadı (${pattern}).`));
          resolve({ url: asset.browser_download_url, name: asset.name, version: j.tag_name });
        } catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

// HTTPS indirici — yönlendirmeleri (302) takip eder, ilerleme bildirir.
function downloadFile(url, dest, onProgress, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 6) return reject(new Error('Çok fazla yönlendirme'));
    const file = fs.createWriteStream(dest);
    https.get(url, { headers: { 'User-Agent': 'NmapGUI' } }, (res) => {
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

// .zip -> PowerShell Expand-Archive (Windows built-in)
// .tar.gz -> tar (Linux/macOS built-in; Windows 10+ tar.exe da var)
function extractArchive(archivePath, destDir) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(destDir, { recursive: true });
    const isTar = /\.tar\.gz$|\.tgz$/i.test(archivePath);
    if (isTar) {
      exec(`tar -xzf "${archivePath}" -C "${destDir}"`, { windowsHide: true }, (err) => err ? reject(err) : resolve());
    } else {
      // Expand-Archive PS 5+'ta her zaman var; Linux/macOS'ta unzip
      const cmd = process.platform === 'win32'
        ? `powershell -NoProfile -Command "Expand-Archive -Path '${archivePath}' -DestinationPath '${destDir}' -Force"`
        : `unzip -o "${archivePath}" -d "${destDir}"`;
      exec(cmd, { windowsHide: true, maxBuffer: 8 * 1024 * 1024 }, (err) => err ? reject(err) : resolve());
    }
  });
}

// Dizin ağacında belirli adı bul (zip/tar içeriği iç içe klasörlü olabilir).
function findBin(rootDir, name) {
  let hit = null;
  const walk = (dir) => {
    if (hit) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (hit) return;
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (entry.name === name) hit = p;
    }
  };
  walk(rootDir);
  return hit;
}

// Bir aracı portable kur. onProgress({phase, pct, msg}) — UI canlı durum için.
async function install(id, onProgress = () => {}) {
  if (!REGISTRY[id]) throw new Error('Bilinmeyen araç: ' + id);
  const meta = REGISTRY[id].platforms[process.platform];
  if (!meta) throw new Error(`Bu platformda (${process.platform}) portable desteklenmiyor: ${id}`);
  if (!binRoot) throw new Error('binRoot başlatılmadı');

  const toolDir = path.join(binRoot, id);
  fs.mkdirSync(toolDir, { recursive: true });

  onProgress({ phase: 'resolve', pct: 0, msg: 'En son sürüm sorgulanıyor...' });
  const asset = await fetchLatestAsset(meta.repo, meta.assetPattern);
  onProgress({ phase: 'resolve', pct: 5, msg: `Bulundu: ${asset.name} (${asset.version})` });

  const archive = path.join(os.tmpdir(), `nmapgui-${id}-${Date.now()}-${asset.name}`);
  onProgress({ phase: 'download', pct: 0, msg: 'İndiriliyor...' });
  await downloadFile(asset.url, archive, (pct) => onProgress({ phase: 'download', pct, msg: `İndiriliyor... %${pct}` }));

  onProgress({ phase: 'extract', pct: 0, msg: 'Açılıyor...' });
  const stageDir = path.join(toolDir, '_stage');
  try { fs.rmSync(stageDir, { recursive: true, force: true }); } catch (e) {}
  await extractArchive(archive, stageDir);
  fs.unlink(archive, () => {});

  const found = findBin(stageDir, meta.binInZip);
  if (!found) throw new Error(`Binary bulunamadı: ${meta.binInZip}`);

  const dest = path.join(toolDir, meta.binInZip);
  try { fs.unlinkSync(dest); } catch (e) {}
  fs.copyFileSync(found, dest);
  // Linux/macOS'ta çalıştırma izni
  if (process.platform !== 'win32') { try { fs.chmodSync(dest, 0o755); } catch (e) {} }
  try { fs.rmSync(stageDir, { recursive: true, force: true }); } catch (e) {}

  onProgress({ phase: 'done', pct: 100, msg: `Kuruldu: ${dest}` });
  return { ok: true, path: dest, version: asset.version };
}

function uninstall(id) {
  if (!binRoot) return false;
  const dir = path.join(binRoot, id);
  try { fs.rmSync(dir, { recursive: true, force: true }); return true; } catch (e) { return false; }
}

module.exports = { init, isSupported, listSupported, binPath, statusAll, install, uninstall, REGISTRY };
