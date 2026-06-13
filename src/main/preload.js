const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
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
  // wsl / araçlar
  wslCheck: () => ipcRenderer.invoke('wsl:check'),
  wslInstall: () => ipcRenderer.invoke('wsl:install'),
  wslPrepareRoot: () => ipcRenderer.invoke('wsl:prepareRoot'),
  wslTool: (tool) => ipcRenderer.invoke('wsl:tool', tool),
  toolsCatalog: () => ipcRenderer.invoke('tools:catalog'),
  toolsCheck: () => ipcRenderer.invoke('tools:check'),
  toolsInstall: (id) => ipcRenderer.invoke('tools:install', id),
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
