// Kalıcı veri katmanı — sql.js (WASM SQLite). Native derleme gerektirmez.
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

let SQL = null;
let db = null;
let dbPath = null;

async function initDb(userDataDir) {
  dbPath = path.join(userDataDir, 'nmapgui.db');
  const wasm = path.join(require.resolve('sql.js'), '..', 'sql-wasm.wasm');
  SQL = await initSqlJs({ locateFile: () => wasm });
  if (fs.existsSync(dbPath)) {
    db = new SQL.Database(fs.readFileSync(dbPath));
  } else {
    db = new SQL.Database();
  }
  db.run(`
    CREATE TABLE IF NOT EXISTS workspaces (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, mode TEXT DEFAULT 'lab',
      scope TEXT DEFAULT '', created TEXT, active INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS hosts (
      id INTEGER PRIMARY KEY AUTOINCREMENT, ws INTEGER, ip TEXT, mac TEXT, vendor TEXT,
      name TEXT, device_type TEXT, os TEXT, status TEXT, first_seen TEXT, last_seen TEXT,
      UNIQUE(ws, ip));
    CREATE TABLE IF NOT EXISTS services (
      id INTEGER PRIMARY KEY AUTOINCREMENT, ws INTEGER, host_ip TEXT, port TEXT, proto TEXT,
      state TEXT, service TEXT, version TEXT, last_seen TEXT, UNIQUE(ws, host_ip, port, proto));
    CREATE TABLE IF NOT EXISTS vulns (
      id INTEGER PRIMARY KEY AUTOINCREMENT, ws INTEGER, host_ip TEXT, port TEXT, cve TEXT,
      script TEXT, last_seen TEXT, UNIQUE(ws, host_ip, cve));
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT, ws INTEGER, date TEXT, target TEXT, command TEXT,
      device_count INTEGER, port_count INTEGER);
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT, ws INTEGER, date TEXT, action TEXT, detail TEXT);
    CREATE TABLE IF NOT EXISTS evidence (
      id INTEGER PRIMARY KEY AUTOINCREMENT, ws INTEGER, host_ip TEXT, type TEXT, label TEXT,
      path TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT, ws INTEGER, host_ip TEXT,
      content TEXT DEFAULT '', updated TEXT, UNIQUE(ws, host_ip));
    CREATE TABLE IF NOT EXISTS creds (
      id INTEGER PRIMARY KEY AUTOINCREMENT, ws INTEGER, host TEXT DEFAULT '',
      service TEXT DEFAULT '', username TEXT DEFAULT '',
      pass_enc TEXT DEFAULT '', hash TEXT DEFAULT '', hash_type TEXT DEFAULT '',
      hashcat_mode TEXT DEFAULT '', source TEXT DEFAULT '', notes TEXT DEFAULT '',
      captured_at TEXT);
  `);
  // Şema göçü: nuclei için severity sütunu
  try { db.run("ALTER TABLE vulns ADD COLUMN severity TEXT DEFAULT ''"); } catch (e) {}
  try { db.run("ALTER TABLE vulns ADD COLUMN source TEXT DEFAULT 'nmap'"); } catch (e) {}
  // Faz 1: finding triyaj sütunları
  try { db.run("ALTER TABLE vulns ADD COLUMN status TEXT DEFAULT 'open'"); } catch (e) {}
  try { db.run("ALTER TABLE vulns ADD COLUMN notes TEXT DEFAULT ''"); } catch (e) {}
  try { db.run("ALTER TABLE vulns ADD COLUMN mitre TEXT DEFAULT ''"); } catch (e) {}
  // Faz 1: workspace engagement metadata
  try { db.run("ALTER TABLE workspaces ADD COLUMN client TEXT DEFAULT ''"); } catch (e) {}
  try { db.run("ALTER TABLE workspaces ADD COLUMN start_date TEXT DEFAULT ''"); } catch (e) {}
  try { db.run("ALTER TABLE workspaces ADD COLUMN end_date TEXT DEFAULT ''"); } catch (e) {}
  try { db.run("ALTER TABLE workspaces ADD COLUMN roe TEXT DEFAULT ''"); } catch (e) {}
  save();
  // İlk açılışta varsayılan workspace
  if (rows('SELECT COUNT(*) c FROM workspaces')[0].c === 0) {
    createWorkspace('Varsayılan Lab', 'lab', '192.168.0.0/24');
  }
  return true;
}

function save() {
  if (db && dbPath) fs.writeFileSync(dbPath, Buffer.from(db.export()));
}

// Yardımcı: SELECT -> nesne dizisi
function rows(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const out = [];
  while (stmt.step()) out.push(stmt.getAsObject());
  stmt.free();
  return out;
}
function run(sql, params = []) { db.run(sql, params); }

/* ---------- Workspaces ---------- */
function createWorkspace(name, mode = 'lab', scope = '') {
  run('UPDATE workspaces SET active = 0');
  run('INSERT INTO workspaces (name, mode, scope, created, active) VALUES (?,?,?,?,1)',
    [name, mode, scope, new Date().toISOString()]);
  save();
  return rows('SELECT * FROM workspaces ORDER BY id DESC LIMIT 1')[0];
}
function listWorkspaces() { return rows('SELECT * FROM workspaces ORDER BY id DESC'); }
function getActiveWorkspace() {
  const r = rows('SELECT * FROM workspaces WHERE active = 1');
  return r[0] || rows('SELECT * FROM workspaces ORDER BY id DESC LIMIT 1')[0] || null;
}
function setActiveWorkspace(id) {
  run('UPDATE workspaces SET active = 0');
  run('UPDATE workspaces SET active = 1 WHERE id = ?', [id]);
  save();
  return getActiveWorkspace();
}
function updateWorkspace(id, fields) {
  const allowed = ['mode', 'scope', 'name', 'client', 'start_date', 'end_date', 'roe'];
  allowed.forEach((k) => {
    if (k in fields) run(`UPDATE workspaces SET ${k} = ? WHERE id = ?`, [fields[k] ?? '', id]);
  });
  save();
  return rows('SELECT * FROM workspaces WHERE id = ?', [id])[0];
}
function deleteWorkspace(id) {
  ['hosts','services','vulns','scans','audit','evidence','creds','notes'].forEach((t) => {
    try { run(`DELETE FROM ${t} WHERE ws = ?`, [id]); } catch (e) {}
  });
  run('DELETE FROM workspaces WHERE id = ?', [id]);
  if (!getActiveWorkspace()) { const w = listWorkspaces()[0]; if (w) setActiveWorkspace(w.id); }
  save();
  return true;
}

/* ---------- Tarama sonucunu asset graph'a yaz ---------- */
function persistScan(ws, record) {
  const now = new Date().toISOString();
  const up = (record.parsed.hosts || []).filter((h) => h.status === 'up');
  let portCount = 0;
  up.forEach((h) => {
    run(`INSERT INTO hosts (ws, ip, mac, vendor, name, device_type, os, status, first_seen, last_seen)
         VALUES (?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(ws, ip) DO UPDATE SET
           mac=COALESCE(NULLIF(excluded.mac,''), hosts.mac),
           vendor=COALESCE(NULLIF(excluded.vendor,''), hosts.vendor),
           name=COALESCE(NULLIF(excluded.name,''), hosts.name),
           device_type=excluded.device_type, os=COALESCE(NULLIF(excluded.os,''), hosts.os),
           status=excluded.status, last_seen=excluded.last_seen`,
      [ws, h.ip, h.mac || '', h.vendor || '', h.name || '', h.deviceType || 'unknown',
       h.osGuess || '', h.status, now, now]);
    (h.ports || []).forEach((p) => {
      portCount++;
      run(`INSERT INTO services (ws, host_ip, port, proto, state, service, version, last_seen)
           VALUES (?,?,?,?,?,?,?,?)
           ON CONFLICT(ws, host_ip, port, proto) DO UPDATE SET
             state=excluded.state, service=excluded.service, version=excluded.version, last_seen=excluded.last_seen`,
        [ws, h.ip, p.port, p.proto, p.state, p.service || '', p.version || '', now]);
    });
    (h.vulns || []).forEach((v) => {
      run(`INSERT OR IGNORE INTO vulns (ws, host_ip, port, cve, script, last_seen)
           VALUES (?,?,?,?,?,?)`, [ws, h.ip, v.port, v.cve, v.script || '', now]);
    });
  });
  run('INSERT INTO scans (ws, date, target, command, device_count, port_count) VALUES (?,?,?,?,?,?)',
    [ws, now, record.target || '', record.command || '', up.length, portCount]);
  addAudit(ws, 'scan', `${record.command || ''} → ${up.length} host, ${portCount} port`);
  save();
}

function workspaceAssets(ws) {
  return {
    hosts: rows('SELECT * FROM hosts WHERE ws = ? ORDER BY ip', [ws]),
    services: rows('SELECT * FROM services WHERE ws = ? ORDER BY host_ip, CAST(port AS INTEGER)', [ws]),
    vulns: rows('SELECT * FROM vulns WHERE ws = ?', [ws]),
    scans: rows('SELECT * FROM scans WHERE ws = ? ORDER BY id DESC', [ws]),
  };
}

/* ---------- nuclei bulgularını yaz ---------- */
function addNucleiFindings(ws, findings) {
  const now = new Date().toISOString();
  let added = 0;
  findings.forEach((f) => {
    const ident = f.cve || f.templateId;
    // Host kaydı yoksa minimal oluştur
    run(`INSERT OR IGNORE INTO hosts (ws, ip, status, first_seen, last_seen, device_type)
         VALUES (?,?,?,?,?,?)`, [ws, f.host, 'up', now, now, 'unknown']);
    run(`INSERT OR IGNORE INTO vulns (ws, host_ip, port, cve, script, last_seen, severity, source)
         VALUES (?,?,?,?,?,?,?,?)`,
      [ws, f.host, f.port || '', ident, f.name || f.templateId, now, f.severity || 'info', 'nuclei']);
    added++;
  });
  addAudit(ws, 'nuclei', `${findings.length} bulgu eklendi`);
  save();
  return added;
}

/* ---------- CVE severity güncelle (NVD zenginleştirme) ---------- */
function setVulnSeverity(ws, cve, severity) {
  run('UPDATE vulns SET severity = ? WHERE ws = ? AND cve = ?', [severity, ws, cve]);
  save();
}

/* ---------- Finding triyaj (Faz 1) ---------- */
const FINDING_STATUSES = ['open', 'fixed', 'false_positive', 'accepted', 'in_progress'];
function listFindings(ws) {
  // vulns + host name/vendor join
  return rows(`SELECT v.id, v.host_ip, v.port, v.cve, v.script, v.severity, v.source,
                      COALESCE(v.status,'open') AS status, COALESCE(v.notes,'') AS notes,
                      COALESCE(v.mitre,'') AS mitre, v.last_seen,
                      COALESCE(h.name,'') AS host_name, COALESCE(h.vendor,'') AS host_vendor
               FROM vulns v LEFT JOIN hosts h ON h.ws = v.ws AND h.ip = v.host_ip
               WHERE v.ws = ? ORDER BY
                 CASE COALESCE(v.severity,'info')
                   WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                   WHEN 'low' THEN 2 ELSE 1 END DESC, v.host_ip`, [ws]);
}
function updateFinding(id, fields) {
  if ('status' in fields) {
    const s = FINDING_STATUSES.includes(fields.status) ? fields.status : 'open';
    run('UPDATE vulns SET status = ? WHERE id = ?', [s, id]);
  }
  if ('notes' in fields) run('UPDATE vulns SET notes = ? WHERE id = ?', [String(fields.notes || ''), id]);
  if ('mitre' in fields) run('UPDATE vulns SET mitre = ? WHERE id = ?', [String(fields.mitre || ''), id]);
  if ('severity' in fields) run('UPDATE vulns SET severity = ? WHERE id = ?', [String(fields.severity || 'info'), id]);
  save();
  return rows('SELECT * FROM vulns WHERE id = ?', [id])[0];
}
function deleteFinding(id) { run('DELETE FROM vulns WHERE id = ?', [id]); save(); return true; }
// Belirtilen host listesindeki etiketsiz vulns'lara toplu MITRE tag uygula.
function bulkTagMitre(ws, hosts, mitre) {
  const uniq = [...new Set((hosts || []).filter(Boolean))];
  if (!uniq.length || !mitre) return 0;
  let n = 0;
  uniq.forEach((h) => {
    run("UPDATE vulns SET mitre = ? WHERE ws = ? AND host_ip = ? AND (mitre IS NULL OR mitre = '')",
      [mitre, ws, h]);
    n++;
  });
  save();
  return n;
}

/* ---------- Credentials / Loot vault (Faz 2) ---------- */
// pass_enc, main.js içinde safeStorage ile şifrelenmiş base64 string'tir.
// DB sadece taşıyıcı; deşifreleme yalnızca main process'te (renderer'a düz parola asla gitmez).
function addCred(ws, c) {
  const now = new Date().toISOString();
  run(`INSERT INTO creds (ws, host, service, username, pass_enc, hash, hash_type, hashcat_mode, source, notes, captured_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [ws, c.host || '', c.service || '', c.username || '', c.pass_enc || '',
     c.hash || '', c.hash_type || '', c.hashcat_mode || '', c.source || '', c.notes || '', now]);
  save();
  return rows('SELECT * FROM creds ORDER BY id DESC LIMIT 1')[0];
}
function listCreds(ws) {
  // pass_enc'i listede DÖNDÜRMEYİZ — yalnızca getCredEnc() ile reveal akışında okunur
  return rows(`SELECT id, ws, host, service, username, hash, hash_type, hashcat_mode,
                      source, notes, captured_at,
                      CASE WHEN pass_enc IS NULL OR pass_enc='' THEN 0 ELSE 1 END AS has_pass
               FROM creds WHERE ws = ? ORDER BY id DESC`, [ws]);
}
function getCredEnc(id) {
  const r = rows('SELECT pass_enc FROM creds WHERE id = ?', [id])[0];
  return r ? (r.pass_enc || '') : '';
}
function updateCred(id, fields) {
  const allowed = ['host', 'service', 'username', 'hash', 'hash_type', 'hashcat_mode', 'source', 'notes', 'pass_enc'];
  allowed.forEach((k) => {
    if (k in fields) run(`UPDATE creds SET ${k} = ? WHERE id = ?`, [String(fields[k] == null ? '' : fields[k]), id]);
  });
  save();
  return rows('SELECT id, host, service, username, hash, hash_type, source, captured_at FROM creds WHERE id = ?', [id])[0];
}
function deleteCred(id) { run('DELETE FROM creds WHERE id = ?', [id]); save(); return true; }

/* ---------- Host notes (Faz 4) ---------- */
function setNote(ws, hostIp, content) {
  const now = new Date().toISOString();
  run(`INSERT INTO notes (ws, host_ip, content, updated) VALUES (?,?,?,?)
       ON CONFLICT(ws, host_ip) DO UPDATE SET content = excluded.content, updated = excluded.updated`,
    [ws, hostIp, String(content || ''), now]);
  save();
  return rows('SELECT * FROM notes WHERE ws = ? AND host_ip = ?', [ws, hostIp])[0];
}
function getNote(ws, hostIp) {
  const r = rows('SELECT * FROM notes WHERE ws = ? AND host_ip = ?', [ws, hostIp])[0];
  return r || null;
}
function listNotes(ws) {
  return rows('SELECT host_ip, content, updated FROM notes WHERE ws = ? AND content != ""', [ws]);
}
function deleteNote(ws, hostIp) {
  run('DELETE FROM notes WHERE ws = ? AND host_ip = ?', [ws, hostIp]); save(); return true;
}

/* ---------- Hash tipi otomatik tespiti (Faz 2) ---------- */
// hashcat -m mod numarasıyla birlikte döner.
const HASH_PATTERNS = [
  { re: /^\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}$/, type: 'bcrypt', mode: '3200' },
  { re: /^\$argon2(id|i|d)\$/i, type: 'argon2', mode: '' },
  { re: /^\$1\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}$/, type: 'md5crypt', mode: '500' },
  { re: /^\$5\$/, type: 'sha256crypt', mode: '7400' },
  { re: /^\$6\$/, type: 'sha512crypt', mode: '1800' },
  { re: /^\$y\$/, type: 'yescrypt', mode: '' },
  // NTLMv2 (Responder format): user::domain:challenge:hash:blob
  { re: /^[^:]+::[^:]*:[A-Fa-f0-9]{16}:[A-Fa-f0-9]{32}:[A-Fa-f0-9]+$/, type: 'NetNTLMv2', mode: '5600' },
  // NTLMv1
  { re: /^[^:]+::[^:]*:[A-Fa-f0-9]{48}:[A-Fa-f0-9]{48}:[A-Fa-f0-9]{16}$/, type: 'NetNTLMv1', mode: '5500' },
  // LM:NTLM (pwdump format) — son alanı NTLM say
  { re: /^[^:]+:\d+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::$/, type: 'NTLM (pwdump)', mode: '1000' },
  // Kerberoast TGS-REP
  { re: /^\$krb5tgs\$23\$/i, type: 'Kerberoast (RC4)', mode: '13100' },
  { re: /^\$krb5tgs\$(17|18)\$/i, type: 'Kerberoast (AES)', mode: '19700' },
  // ASREProast
  { re: /^\$krb5asrep\$23\$/i, type: 'AS-REP roast', mode: '18200' },
  // MySQL
  { re: /^\*[A-Fa-f0-9]{40}$/, type: 'MySQL4.1+', mode: '300' },
  // PostgreSQL md5
  { re: /^md5[a-f0-9]{32}$/, type: 'PostgreSQL md5', mode: '12' },
  // Cisco
  { re: /^\$8\$[A-Za-z0-9./]{14}\$/, type: 'Cisco IOS PBKDF2', mode: '9200' },
  { re: /^\$9\$[A-Za-z0-9./]{14}\$/, type: 'Cisco IOS scrypt', mode: '9300' },
  // Düz hex hash'ler (uzunluk bazlı)
  { re: /^[A-Fa-f0-9]{32}$/, type: 'MD5 / NTLM', mode: '0/1000' },
  { re: /^[A-Fa-f0-9]{40}$/, type: 'SHA1', mode: '100' },
  { re: /^[A-Fa-f0-9]{56}$/, type: 'SHA224', mode: '1300' },
  { re: /^[A-Fa-f0-9]{64}$/, type: 'SHA256', mode: '1400' },
  { re: /^[A-Fa-f0-9]{96}$/, type: 'SHA384', mode: '10800' },
  { re: /^[A-Fa-f0-9]{128}$/, type: 'SHA512', mode: '1700' },
];
function detectHash(h) {
  const s = (h || '').trim();
  if (!s) return { type: '', mode: '' };
  for (const p of HASH_PATTERNS) if (p.re.test(s)) return { type: p.type, mode: p.mode };
  return { type: 'bilinmiyor', mode: '' };
}

/* ---------- Audit log ---------- */
function addAudit(ws, action, detail) {
  run('INSERT INTO audit (ws, date, action, detail) VALUES (?,?,?,?)',
    [ws, new Date().toISOString(), action, detail || '']);
  save();
}
function listAudit(ws) { return rows('SELECT * FROM audit WHERE ws = ? ORDER BY id DESC LIMIT 200', [ws]); }

/* ---------- Kanıt (evidence) ---------- */
function addEvidence(ws, hostIp, type, label, p) {
  run('INSERT INTO evidence (ws, host_ip, type, label, path, created) VALUES (?,?,?,?,?,?)',
    [ws, hostIp || '', type, label || '', p, new Date().toISOString()]);
  addAudit(ws, 'evidence', `Kanıt eklendi: ${label || type}`);
  save();
  return rows('SELECT * FROM evidence ORDER BY id DESC LIMIT 1')[0];
}
function listEvidence(ws) { return rows('SELECT * FROM evidence WHERE ws = ? ORDER BY id DESC', [ws]); }
function deleteEvidence(id) { run('DELETE FROM evidence WHERE id = ?', [id]); save(); return true; }

module.exports = {
  initDb, createWorkspace, listWorkspaces, getActiveWorkspace, setActiveWorkspace,
  updateWorkspace, deleteWorkspace, persistScan, workspaceAssets, addAudit, listAudit,
  addNucleiFindings, addEvidence, listEvidence, deleteEvidence, setVulnSeverity,
  listFindings, updateFinding, deleteFinding, FINDING_STATUSES, bulkTagMitre,
  addCred, listCreds, getCredEnc, updateCred, deleteCred, detectHash,
  setNote, getNote, listNotes, deleteNote,
};
