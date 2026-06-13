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
  `);
  // Şema göçü: nuclei için severity sütunu
  try { db.run("ALTER TABLE vulns ADD COLUMN severity TEXT DEFAULT ''"); } catch (e) {}
  try { db.run("ALTER TABLE vulns ADD COLUMN source TEXT DEFAULT 'nmap'"); } catch (e) {}
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
  if ('mode' in fields) run('UPDATE workspaces SET mode = ? WHERE id = ?', [fields.mode, id]);
  if ('scope' in fields) run('UPDATE workspaces SET scope = ? WHERE id = ?', [fields.scope, id]);
  if ('name' in fields) run('UPDATE workspaces SET name = ? WHERE id = ?', [fields.name, id]);
  save();
  return rows('SELECT * FROM workspaces WHERE id = ?', [id])[0];
}
function deleteWorkspace(id) {
  ['hosts','services','vulns','scans','audit'].forEach((t) => run(`DELETE FROM ${t} WHERE ws = ?`, [id]));
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
  addNucleiFindings, addEvidence, listEvidence, deleteEvidence,
};
