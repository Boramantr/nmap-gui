const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  platform: process.platform,
  // nmap
  checkNmap: () => ipcRenderer.invoke('nmap:check'),
  openDownload: () => ipcRenderer.invoke('nmap:openDownload'),
  installNmap: () => ipcRenderer.invoke('nmap:install'),
  // ağ / yetki
  localRange: () => ipcRenderer.invoke('net:localRange'),
  checkAdmin: () => ipcRenderer.invoke('admin:check'),
  relaunchAdmin: () => ipcRenderer.invoke('admin:relaunch'),
  // tarama
  startScan: (args) => ipcRenderer.invoke('scan:start', args),
  stopScan: () => ipcRenderer.invoke('scan:stop'),
  // rapor
  savePdf: (html) => ipcRenderer.invoke('report:savePdf', html),
  // geçmiş
  historySave: (rec) => ipcRenderer.invoke('history:save', rec),
  historyList: () => ipcRenderer.invoke('history:list'),
  historyGet: (id) => ipcRenderer.invoke('history:get', id),
  historyDelete: (id) => ipcRenderer.invoke('history:delete', id),
  // ayarlar
  getSettings: () => ipcRenderer.invoke('settings:get'),
  saveSettings: (s) => ipcRenderer.invoke('settings:save', s),
  // bildirim
  notify: (n) => ipcRenderer.invoke('notify', n),
  // pencere kontrolleri
  winMinimize: () => ipcRenderer.invoke('win:minimize'),
  winMaximize: () => ipcRenderer.invoke('win:maximize'),
  winClose: () => ipcRenderer.invoke('win:close'),
  winIsMaximized: () => ipcRenderer.invoke('win:isMaximized'),
  // workspace / engagement
  wsList: () => ipcRenderer.invoke('ws:list'),
  wsActive: () => ipcRenderer.invoke('ws:active'),
  wsCreate: (data) => ipcRenderer.invoke('ws:create', data),
  wsSetActive: (id) => ipcRenderer.invoke('ws:setActive', id),
  wsUpdate: (id, fields) => ipcRenderer.invoke('ws:update', { id, fields }),
  wsDelete: (id) => ipcRenderer.invoke('ws:delete', id),
  wsAssets: (id) => ipcRenderer.invoke('ws:assets', id),
  wsAudit: (id) => ipcRenderer.invoke('ws:audit', id),
  wsLogAudit: (ws, action, detail) => ipcRenderer.invoke('ws:logAudit', { ws, action, detail }),
  // findings (triyaj)
  findingsList: (wsId) => ipcRenderer.invoke('findings:list', wsId),
  findingsUpdate: (id, fields) => ipcRenderer.invoke('findings:update', { id, fields }),
  findingsDelete: (id) => ipcRenderer.invoke('findings:delete', id),
  findingsStatuses: () => ipcRenderer.invoke('findings:statuses'),
  // Faz 2: credential vault
  credsList: (wsId) => ipcRenderer.invoke('creds:list', wsId),
  credsAdd: (c) => ipcRenderer.invoke('creds:add', c),
  credsUpdate: (id, fields) => ipcRenderer.invoke('creds:update', { id, fields }),
  credsReveal: (id) => ipcRenderer.invoke('creds:reveal', id),
  credsDelete: (id) => ipcRenderer.invoke('creds:delete', id),
  credsDetectHash: (h) => ipcRenderer.invoke('creds:detectHash', h),
  credsVaultStatus: () => ipcRenderer.invoke('creds:vaultStatus'),
  // Faz 2: reverse shell + listener
  revshellTemplates: () => ipcRenderer.invoke('revshell:templates'),
  listenerStart: (opts) => ipcRenderer.invoke('listener:start', opts),
  listenerStop: (type) => ipcRenderer.invoke('listener:stop', type),
  listenerList: () => ipcRenderer.invoke('listener:list'),
  listenerSend: (opts) => ipcRenderer.invoke('listener:send', opts),
  listenerPickDir: () => ipcRenderer.invoke('listener:pickDir'),
  onListenerOut: (cb) => ipcRenderer.on('listener:out', (_e, d) => cb(d)),
  onListenerState: (cb) => ipcRenderer.on('listener:state', (_e, d) => cb(d)),
  // Faz 2: DOCX
  reportDocx: (wsId) => ipcRenderer.invoke('report:docx', wsId),
  // Faz 3: AD recon
  adModules: () => ipcRenderer.invoke('ad:modules'),
  adRun: (opts) => ipcRenderer.invoke('ad:run', opts),
  adStop: () => ipcRenderer.invoke('ad:stop'),
  onAdOut: (cb) => ipcRenderer.on('ad:out', (_e, d) => cb(d)),
  onAdDone: (cb) => ipcRenderer.on('ad:done', (_e, d) => cb(d)),
  // Faz 3: web pipeline
  webPipeline: (opts) => ipcRenderer.invoke('web:pipeline', opts),
  webStop: () => ipcRenderer.invoke('web:stop'),
  onWebStep: (cb) => ipcRenderer.on('web:step', (_e, d) => cb(d)),
  // Faz 3: MITRE
  mitreToolMap: () => ipcRenderer.invoke('mitre:toolMap'),
  mitreTactics: () => ipcRenderer.invoke('mitre:tactics'),
  // Faz 4: stealth + pivot + notes + extra OSINT
  scanProfiles: () => ipcRenderer.invoke('scan:profiles'),
  pivotTemplates: (opts) => ipcRenderer.invoke('pivot:templates', opts || {}),
  localIps: () => ipcRenderer.invoke('net:localIps'),
  noteGet: (ws, host) => ipcRenderer.invoke('notes:get', { ws, host }),
  noteSet: (ws, host, content) => ipcRenderer.invoke('notes:set', { ws, host, content }),
  notesList: (wsId) => ipcRenderer.invoke('notes:list', wsId),
  wayback: (domain) => ipcRenderer.invoke('osint:wayback', domain),
  ghDorks: (target) => ipcRenderer.invoke('osint:ghDorks', target),
  // OSINT genişletme (5)
  osintAsn: (q) => ipcRenderer.invoke('osint:asn', q),
  osintFavicon: (target) => ipcRenderer.invoke('osint:faviconHash', target),
  osintBuckets: (name) => ipcRenderer.invoke('osint:buckets', name),
  osintMailSec: (domain) => ipcRenderer.invoke('osint:mailSec', domain),
  osintGoogleDorks: (target) => ipcRenderer.invoke('osint:googleDorks', target),
  // OSINT 2. paket
  osintWhois: (d) => ipcRenderer.invoke('osint:whois', d),
  osintReverseIp: (ip) => ipcRenderer.invoke('osint:reverseIp', ip),
  osintTlsCert: (host) => ipcRenderer.invoke('osint:tlsCert', host),
  osintSubTakeover: (subs) => ipcRenderer.invoke('osint:subTakeover', subs),
  osintHttpRecon: (target) => ipcRenderer.invoke('osint:httpRecon', target),
  // wsl / araçlar
  wslCheck: () => ipcRenderer.invoke('wsl:check'),
  wslInstall: () => ipcRenderer.invoke('wsl:install'),
  wslPrepareRoot: () => ipcRenderer.invoke('wsl:prepareRoot'),
  wslTool: (tool) => ipcRenderer.invoke('wsl:tool', tool),
  toolsCatalog: () => ipcRenderer.invoke('tools:catalog'),
  toolsCheck: () => ipcRenderer.invoke('tools:check'),
  toolsInstall: (id) => ipcRenderer.invoke('tools:install', id),
  // portable (WSL'siz native binary'ler)
  portableStatus: () => ipcRenderer.invoke('portable:status'),
  portableInstall: (id) => ipcRenderer.invoke('portable:install', id),
  portableInstallAll: () => ipcRenderer.invoke('portable:installAll'),
  portableUninstall: (id) => ipcRenderer.invoke('portable:uninstall', id),
  onPortableProgress: (cb) => ipcRenderer.on('portable:progress', (_e, d) => cb(d)),
  onPortableDone: (cb) => ipcRenderer.on('portable:done', (_e, d) => cb(d)),
  onPortableAllDone: (cb) => ipcRenderer.on('portable:allDone', (_e, d) => cb(d)),
  // nuclei
  nucleiRun: (opts) => ipcRenderer.invoke('nuclei:run', opts),
  nucleiStop: () => ipcRenderer.invoke('nuclei:stop'),
  // genel araç çalıştırıcı + rapor
  toolRun: (opts) => ipcRenderer.invoke('tool:run', opts),
  toolStop: () => ipcRenderer.invoke('tool:stop'),
  onToolOut: (cb) => ipcRenderer.on('tool:out', (_e, d) => cb(d)),
  onToolDone: (cb) => ipcRenderer.on('tool:done', (_e, d) => cb(d)),
  reportPro: (wsId) => ipcRenderer.invoke('report:professional', wsId),
  // exploit / saldırgan
  exploitSearch: (term) => ipcRenderer.invoke('exploit:search', term),
  exploitAuto: (terms) => ipcRenderer.invoke('exploit:auto', terms),
  // CVE zenginleştirme (NVD)
  enrichCve: (ids) => ipcRenderer.invoke('cve:enrich', ids),
  hydraRun: (opts) => ipcRenderer.invoke('attack:hydra', opts),
  hydraStop: () => ipcRenderer.invoke('attack:hydraStop'),
  // metasploit
  msfSearch: (term) => ipcRenderer.invoke('msf:search', term),
  msfInfo: (module) => ipcRenderer.invoke('msf:info', module),
  msfRun: (opts) => ipcRenderer.invoke('msf:run', opts),
  msfStop: () => ipcRenderer.invoke('msf:stop'),
  // OSINT
  shodan: (ip) => ipcRenderer.invoke('osint:shodan', ip),
  subdomains: (domain) => ipcRenderer.invoke('osint:subdomains', domain),
  dnsRecords: (domain) => ipcRenderer.invoke('osint:dns', domain),
  // kanıt
  evidenceAdd: (data) => ipcRenderer.invoke('evidence:add', data),
  evidenceShot: (data) => ipcRenderer.invoke('evidence:screenshot', data),
  evidenceList: (wsId) => ipcRenderer.invoke('evidence:list', wsId),
  evidenceDelete: (id) => ipcRenderer.invoke('evidence:delete', id),
  evidenceOpen: (p) => ipcRenderer.invoke('evidence:open', p),
  onNucleiFinding: (cb) => ipcRenderer.on('nuclei:finding', (_e, d) => cb(d)),
  onNucleiOut: (cb) => ipcRenderer.on('nuclei:out', (_e, d) => cb(d)),
  onNucleiDone: (cb) => ipcRenderer.on('nuclei:done', (_e, d) => cb(d)),
  onToolsInstallOut: (cb) => ipcRenderer.on('tools:installOut', (_e, d) => cb(d)),
  onToolsInstallDone: (cb) => ipcRenderer.on('tools:installDone', (_e, d) => cb(d)),

  // olaylar
  onStdout: (cb) => ipcRenderer.on('scan:stdout', (_e, d) => cb(d)),
  onStderr: (cb) => ipcRenderer.on('scan:stderr', (_e, d) => cb(d)),
  onProgress: (cb) => ipcRenderer.on('scan:progress', (_e, d) => cb(d)),
  onDone: (cb) => ipcRenderer.on('scan:done', (_e, d) => cb(d)),
  onError: (cb) => ipcRenderer.on('scan:error', (_e, d) => cb(d)),
  onDownloadProgress: (cb) => ipcRenderer.on('nmap:downloadProgress', (_e, d) => cb(d)),
});
