# NmapGUI — Pentest Orchestrator

<p align="center">
  <img src="assets/icon.png" alt="NmapGUI" width="96"/>
</p>

<p align="center">
  <b>Not a nmap GUI.</b><br>
  An engagement-based, asset-graph-powered, kill-chain-focused <b>pentest IDE</b>.<br>
  <sub>Recon · Enum · Exploit · Post · Reporting — in a single window, fully auditable.</sub>
</p>

<p align="center">
  <img alt="platform" src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue">
  <img alt="electron" src="https://img.shields.io/badge/electron-31-47848F">
  <img alt="react" src="https://img.shields.io/badge/react-18-61DAFB">
  <img alt="sqlite" src="https://img.shields.io/badge/sqlite-sql.js-003B57">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="status" src="https://img.shields.io/badge/status-active%20development-orange">
</p>

<p align="center">
  <a href="README.md">🇹🇷 Türkçe</a> · <a href="README.en.md">🇬🇧 English</a>
</p>

---

## 🎯 What is this?

NmapGUI is a pentest station built around **scope and engagement mode**. Every scan, every tool invocation, every offensive module writes to the **active workspace** — hosts accumulate as an asset graph, findings land in a triage queue, outputs are auto-archived as **evidence**, the MITRE ATT&CK matrix populates automatically, and a **PDF/Word report** is generated with a single click.

Goal: let the pentester stop living across 20 tabs, 5 separate tools, and 3 different notepads — and move to a **single window + single workspace + single report** flow.

> **This is not a GUI for nmap.** nmap is just one of its engines (nuclei, netexec, sqlmap, hydra, httpx, subfinder, masscan, ffuf, gobuster... all at the same level).

---

## 🗺️ At a glance — Kill-chain ↔ Feature map

```
┌───────────────┐   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│  🔍 Recon     │   │  🧪 Enum      │   │  💥 Exploit   │   │  🚀 Post      │   │  📄 Report    │
├───────────────┤   ├───────────────┤   ├───────────────┤   ├───────────────┤   ├───────────────┤
│ Shodan        │   │ Nuclei        │   │ SearchSploit  │   │ Cred Vault    │   │ PDF (rich)    │
│ crt.sh        │ → │ Web Pipeline  │ → │ Metasploit    │ → │ Hash → Hashcat│ → │ Word (.doc)   │
│ Wayback       │   │ HTTPx + Tech  │   │ Hydra         │   │ Reverse Shell │   │ MITRE Matrix  │
│ ASN/Netblock  │   │ Gobuster/FFUF │   │ SQLMap        │   │ TCP Catcher   │   │ Risk Matrix   │
│ Favicon Pivot │   │ AD: Null/Sig  │   │ Kerberoast    │   │ HTTP/SMB Share│   │ Asset Graph   │
│ TLS SAN       │   │ AD: Policy    │   │ AS-REP roast  │   │ Pivot Wizard  │   │ Auto Evidence │
│ WHOIS/RDAP    │   │ Bloodhound    │   │ Zerologon     │   │ Chisel/Ligolo │   │ Finding Notes │
│ Reverse IP    │   │ HTTP Recon    │   │ NetExec       │   │ Host Notes    │   │ ROE/Client    │
│ Cloud Buckets │   │ Sub Takeover  │   │ MSF Run       │   │ MITRE Auto    │   │ DOCX Export   │
│ Mail Security │   │ NVD CVSS      │   │ AD Offensive  │   │               │   │               │
│ Google Dorks  │   │ Auto Exploit  │   │               │   │               │   │               │
│ GitHub Dorks  │   │ MITRE Mapping │   │               │   │               │   │               │
└───────────────┘   └───────────────┘   └───────────────┘   └───────────────┘   └───────────────┘
        ▲                                                                              │
        └──────────────────── Workspace + Scope + Audit ─────────────────────────────┘
```

---

## ⭐ Highlights

### 🏗️ Engagement Workspace
- **Workspaces**: separate workspace per job (lab / engagement mode)
- **Scope guard**: in engagement mode, scanning/attacking out-of-scope IPs is **blocked + audited**
- **ROE field**: permissions, restrictions, contact — shown on the report cover
- **Client / start-end** metadata appears in the report
- **Audit log**: blocked attempts, credential reveals, report generations, listener starts — timestamped

### 📎 Automatic Evidence
- Every `nmap`, `nuclei`, `tool:run`, `netexec` output is buffered → written as `.log` to `evidence/ws-{id}/` in the workspace
- Transcript with command + timestamp + exit code header
- Manual screenshot + file attachment also available
- Embedded image/file reference in the report

### 🔎 Finding Triage
- nmap NSE / nuclei / AD modules → all findings in a single table
- Severity filter, "hide closed" toggle
- **Status**: open / in_progress / fixed / false_positive / accepted
- Inline MITRE technique tag + notes (auto-saved on blur)
- NVD CVSS enrichment (real score + severity)
- ExploitDB / searchsploit auto-mapping

### 🗝️ Loot (Phase 2)
| Module | Description |
|---|---|
| **Credential Vault** | Encrypted storage via DPAPI / Keychain / libsecret. Plaintext passwords never reach the renderer. Reveal action is explicitly audited. |
| **Hash Detection** | bcrypt, argon2, NTLM, NetNTLMv1/v2, Kerberoast (RC4+AES), AS-REP, MySQL, PostgreSQL, Cisco PBKDF2/scrypt + hex (MD5/SHA1/256/384/512) — 22 patterns with hashcat `-m` mode |
| **Reverse Shell** | 14 payloads: bash TCP/UDP, mkfifo nc, python 2/3, php, perl, ruby, PowerShell (long + IEX), msfvenom (ELF/EXE/ASPX). URL-encoded + base64 variants. |
| **Listener Manager** | TCP catcher (send commands to caught shell), HTTP file server (path traversal protection), SMB share (impacket). Each single-instance, port-validated. |
| **Pivot Wizard** | Chisel SOCKS + port forward, ligolo-ng (proxy + agent + tun setup), SSH -D/-L/-R, proxychains config. LHOST auto-detected. |

### 🏰 AD Recon (netexec / nxc)
13 ready modules, split into two groups:

| Read-only (🔍) | Offensive (🔥, requires engagement + scope) |
|---|---|
| `null` — null session | `kerberoast` — TGS-REP hash |
| `signing` — SMB signing | `asreproast` — AS-REP hash |
| `users` — AD user enum | `zerologon` — CVE-2020-1472 |
| `policy` — password policy | `petitpotam` — coerce |
| `shares` — SMB shares | |
| `loggedon` — logged-on users | |
| `sessions` — active SMB | |
| `bloodhound` — All collection | |
| `ntlmrelay` — relay list | |

Each module's **MITRE technique ID** is automatically tagged to the relevant host's findings. Patterns like `$krb5tgs$`, `$krb5asrep$`, `Signing: False`, zerologon `VULNERABLE` are **auto-converted to findings**.

### 🚀 Web Recon Pipeline
Chained flow with a single click:
```
httpx fingerprint
  ↓
Tech detection (Wappalyzer-style)
  ↓
Smart nuclei -tags derivation
  (wordpress → wp, jenkins → jenkins, weblogic → weblogic, ...)
  ↓
Subfinder (optional)
  ↓
First 50 subdomains → httpx
  ↓
Top 10 live hosts → nuclei
  ↓
Findings → DB + auto MITRE T1595.002
```

Live event stream in UI: each step as a colored line + stop button.

### 🌐 OSINT (15 modules — all passive, most API-key-free)

| Category | Module | API |
|---|---|---|
| **Host intel** | Shodan | key |
| | crt.sh subdomain | — |
| | DNS (A/AAAA/MX/NS/TXT/CNAME) | system DNS |
| | Wayback Machine URL list | — |
| | Reverse IP / virtual host | hackertarget |
| | ASN / netblock | bgpview.io |
| **Cert intel** | TLS Cert + SAN extraction | — (built-in tls) |
| **Target profiling** | Favicon hash pivot | — (pure JS mmh3) |
| | HTTP Recon Bundle | — |
| | WHOIS / RDAP | rdap.org |
| **Attack surface** | Cloud Buckets (S3/Azure/GCS) | — (3rd party HEAD) |
| | Subdomain takeover heuristic | — |
| | Mail Security (SPF/DMARC/DKIM) | system DNS |
| **Leak hunting** | Google Dorks (25 dorks, 7 categories) | URL builder |
| | GitHub Code Dorks (12 dorks) | URL builder |

#### 🔐 TLS Cert + SAN
Gold for subdomains that **crt.sh misses**. Click SANs in the certificate to change your main target → other panels work on the new target. Chained flow.

#### 🪤 Subdomain Takeover
13 provider fingerprints (GitHub Pages, Heroku, AWS S3, Azure cloudapp/azurewebsites/blob, Shopify, Tumblr, Bitbucket, Fastly, Pantheon, Tilda, Unbounce, Helpjuice, Zendesk). CNAME + body fingerprint → **confirmed / likely / safe** classification.

#### 🦄 Favicon Hash Pivot
Pure JS MurmurHash3 (Shodan format: base64 + 76-char wrap + trailing `\n`). One click to find **all internet** hosts running the same favicon on Shodan and Censys.

#### ☁️ Cloud Buckets
38 permutations × 3 providers = 114 targets, 16 parallel HEADs. 200 (open) green, 403 (exists but private) yellow.

#### ✉️ Mail Security
SPF qualifier + lookup count (RFC 7208 limit), DMARC p/sp/pct/rua, 13 DKIM selector attempts, BIMI. **Risk score 0–100** (higher = easier to spoof).

#### 🌐 HTTP Recon Bundle
One click: headers + 13 WAF/CDN fingerprints + robots.txt Disallow + sitemap.xml URLs + security.txt + Mozilla Observatory-style **security header score (A–F)**.

### 🥷 Stealth Profiles
| Profile | Flags |
|---|---|
| 📢 Loud | `-T5 --min-rate 5000` |
| ⚖️ Normal | `-T4` |
| 🌒 Stealth | `-T2 -f --source-port 53 --data-length 24 --randomize-hosts` |
| 👻 Paranoid | `-T0 -f --source-port 53 --data-length 32 --randomize-hosts --scan-delay 5s` |

If the user manually sets `-T*`, **user preference wins** — profile flags don't conflict.

### 🕸️ Attack Graph & MITRE Matrix
- **Attack graph**: radial SVG, node size = open service count, color = highest severity
- **MITRE matrix**: 11 tactic columns (TA0043 → TA0011), each with finding count + top 3 example findings

### 📝 Host Notes
Markdown notes per host (workspace-based UPSERT, **intentionally hidden from reports** — pentester's internal workspace).

### 📄 Reporting
- **PDF report**: rich cover (client, ROE, date, risk level), executive summary, risk matrix (critical/high/medium/low/info), findings table (severity + MITRE + notes), asset inventory, embedded evidence
- **DOCX export**: Word-compatible HTML wrapper, editable by client
- **fixed / false_positive** findings are auto-excluded from reports; the count is noted in the executive summary

---

## 🏛️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Renderer (React + Babel)                       │
│       app.jsx — tabs, panels, state, IPC consumption                │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ contextBridge (preload.js)
                               │ ~80 IPC endpoints
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                Main Process (Electron / Node)                       │
│  main.js                                                            │
│  ├─ spawn(nmap, nuclei, netexec, ...) — pentest engine orchestration│
│  ├─ httpsGetJson — Shodan, NVD, bgpview, rdap                       │
│  ├─ tls.connect — certificate analysis                              │
│  ├─ safeStorage — credential vault encryption                       │
│  ├─ scope guard — gate for engagement offensive modules             │
│  ├─ auto-evidence — stdout buffer → workspace evidence/             │
│  └─ listener manager — TCP/HTTP/SMB single-instance processes       │
│                                                                     │
│  db.js (sql.js — WASM SQLite, no native compilation)                │
│  ├─ workspaces (client, scope, mode, ROE, dates)                    │
│  ├─ hosts / services / vulns — asset graph                          │
│  ├─ creds (pass_enc TEXT, hash, hash_type, hashcat_mode)            │
│  ├─ evidence (path, label, type)                                    │
│  ├─ notes (host_ip → markdown)                                      │
│  ├─ audit (action, detail, date)                                    │
│  └─ scans (command + target + count)                                │
│                                                                     │
│  portable.js — official binaries for Go-based pentest tools         │
│                (nuclei, httpx, gobuster, ffuf, subfinder, ...)      │
│                Downloads and installs from GitHub releases. No WSL. │
└─────────────────────────────────────────────────────────────────────┘
```

**Zero native compilation**: `sql.js` WASM SQLite. Pure Node + Electron 31.  
**Pure JS**: mmh3 (favicon hash), Murmur3 algorithm — no npm dependency.  
**Built-in**: `tls`, `crypto`, `dns.promises`, `https`, `child_process.spawn` — Node standard library.

---

## 📦 Installation

### Prerequisites
| | Windows | Linux | macOS |
|---|---|---|---|
| **Node.js 18+** | ✓ (for development) | ✓ | ✓ |
| **nmap** | auto-detect + install guide | `apt install nmap` | `brew install nmap` |
| **WSL2** | optional (for full toolset) | — | — |

On Windows, **portable** mode (no WSL) is the default: nuclei, httpx, subfinder, gobuster, ffuf, dnsx, katana, chisel, amass GitHub release binaries are downloaded with a single click.

### Development
```bash
git clone https://github.com/Boramantr/nmap-gui.git
cd nmap-gui
npm install
npm start
```

### Windows .exe
```bash
npm run dist
```
Output: NSIS installer under `dist/`.

---

## ⚡ Quick Start (engagement in 10 minutes)

1. **Create a workspace**: `🗂️ Workspace` tab → "+ Create"
   - Client name, scope (CIDR/IP list, comma-separated), ROE, start/end dates
   - Mode: **Engagement** (unlocks offensive modules)

2. **Passive recon**: `🌐 OSINT` tab → enter domain
   - WHOIS → learn company ranges
   - ASN → get all netblocks, add to scope
   - TLS SAN → forgotten subdomains
   - crt.sh + Subdomain takeover → quick wins
   - Mail Security → phishing surface (if ROE permits)

3. **Active recon**: `🎯 Scan` → select target + stealth profile → ▶
   - Profile flags mix automatically
   - XML parser writes hosts to workspace asset graph
   - New devices appear in audit

4. **Enum**: `🧰 Tools` → 🚀 **Web Recon Pipeline** → target → ▶
   - Auto nuclei tags based on tech stack
   - Findings appear in `🔎 Findings` tab

5. **Triage**: `🔎 Findings`
   - Filter by severity, hide closed
   - Status + MITRE + notes per finding
   - 🕸️ Attack graph · 🎯 MITRE matrix

6. **AD mode** (if applicable): `🏰 AD Recon` → DC IP + creds → preset buttons
   - Start with read-only (null, signing, policy)
   - kerberoast / asreproast / zerologon unlock in engagement mode

7. **Loot**: `🗝️ Loot`
   - Captured creds → vault (encrypted)
   - Found a hash → auto type detection + copy hashcat command
   - Generate reverse shell payload → start internal TCP catcher
   - Need pivot → Pivot tab (chisel/ligolo templates)

8. **Report**: `🗂️ Workspace` → 📄 PDF / 📝 Word
   - Cover: client, ROE, risk level
   - Finding table sorted by severity, status-filtered
   - Embedded evidence
   - Asset inventory

---

## 🔐 Security principles (internal to the app)

### 1. Three-layer offensive gate
Hydra, Metasploit run, AD kerberoast/asreproast/zerologon all pass through **the same 3 gates**:
- **Confirmation** flag (UI explicitly prompts)
- **Engagement mode** check
- **In scope** check
Every rejected attempt is written to the `audit` table with a `blocked` action.

### 2. Credential vault
- Plaintext passwords are **never sent to the renderer** — only via `creds:reveal` IPC, with auditing
- `safeStorage`: Windows DPAPI · macOS Keychain · Linux libsecret
- If no keychain is available, marked with `PLAIN:` prefix and a UI warning is shown

### 3. Command injection protection
All user inputs pass regex validation:
- Targets: `/^[a-zA-Z0-9._:\/\-]+$/`
- Usernames: `/^[A-Za-z0-9._\\\/@-]{1,80}$/`
- NTLM hash: `/^[A-Fa-f0-9:]{16,200}$/`
- MSF/searchsploit search: letters + digits + limited symbols
- Spawn arguments are passed as arrays, not shell strings

### 4. Listener security
- Single-instance per type
- Port 1–65535 validation
- HTTP server path traversal protection (`path.resolve` + prefix check)
- Automatic cleanup on app close (`before-quit`)

### 5. OSINT passivity
Cloud bucket probes go to 3rd-party endpoints; no packets are sent to the target's infrastructure. If you don't want this, don't click the button.

---

## ⚠️ Ethics & Legal

**This tool is for authorized security testing only.**

- Use only on your own networks, systems you have explicit written permission to test, CTF / lab environments, registered bug bounty programs, or under an authorized pentest contract.
- Engagement mode is **not automatic legal protection** — it's a design gate that prevents accidentally scanning out of scope.
- Offensive modules (Metasploit run, hydra, kerberoast, zerologon, AS-REP roast, NTLM relay list) **have real impact**. The responsibility for running them lies with the user.
- The developer(s) accept no liability for misuse.

> If in doubt: get written authorization first. Verbal "go ahead" is not authorization.

---

## 🗂️ Folder structure

```
nmap-gui/
├── src/
│   ├── main/
│   │   ├── main.js          # Electron main process, ~80 IPCs, engine orchestration
│   │   ├── preload.js       # contextBridge — secure IPC bridge
│   │   ├── db.js            # sql.js — workspaces/hosts/services/vulns/creds/notes/...
│   │   └── portable.js      # Portable binary downloader for Go tools
│   └── renderer/
│       ├── app.jsx          # All UI: tabs, panels, state (~250 KB)
│       ├── app.js           # Built JS (not gitignored — needed at runtime)
│       ├── styles.css       # Theme, tables, cards, kanban design
│       └── index.html
├── assets/                  # Icons, logo
├── build-renderer.js        # JSX → JS Babel compiler (build step)
├── build-logos.js           # Bundles vendor logo SVGs
├── build-icon.js            # Platform icons
└── package.json
```

---

## 🛠️ Developer notes

### Adding a new IPC endpoint
1. `main.js` — `ipcMain.handle('your:thing', async (e, args) => {...})`
2. `preload.js` — `yourThing: (args) => ipcRenderer.invoke('your:thing', args)`
3. `app.jsx` — `await window.api.yourThing(args)`

### Adding a new offensive module
Follow the scope guard pattern:
```js
const ws = db.getActiveWorkspace();
if (!ws || ws.mode !== 'engagement') {
  if (ws) db.addAudit(ws.id, 'blocked', `rejected: ${reason}`);
  return { ok: false, error: 'Engagement mode required' };
}
if (inScopeMain(target, ws.scope) !== true) {
  db.addAudit(ws.id, 'blocked', `out of scope: ${target}`);
  return { ok: false, error: 'Out of scope' };
}
```

### DB migration
In `db.js` → `initDb()`, add `try { db.run("ALTER TABLE ... ADD COLUMN ...") } catch(e) {}`. `sql.js` doesn't make ALTER idempotent — use the try/catch migration pattern.

### Build
```bash
npm start                    # build + electron
node build-renderer.js       # JSX → JS only
npm run dist                 # NSIS .exe
```

---

## 🗺️ Roadmap

- [ ] **Vite + real React bundle** — prod build instead of JSX runtime
- [ ] **Code signing certificate** — for Windows SmartScreen warning
- [ ] **Mobile app panel** (apk decompile + manifest analysis + Frida hook bash)
- [ ] **API testing module** (Postman-style, OpenAPI import)
- [ ] **CVE feed automation** — daily NVD diff
- [ ] **BloodHound CE integration** — bulk import + cypher query
- [ ] **Multi-user / team sync** (shared workspace export/import)
- [ ] **DefectDojo / Jira issue push** — CSV/JSON from findings
- [ ] **Threat model export** (STRIDE / PASTA template)
- [ ] **Web fuzzing wordlist management** (SecLists auto-clone)
- [ ] **Weak cipher detection in cert analysis** (inline sslscan-like)
- [ ] **Email format guesser + breach search** (HIBP integration, key-based)

---

## 🤝 Contributing

PRs and issues are open. Opening an issue to discuss before a large change saves everyone time.

### Commit style
- English or Turkish, **what** + **why**
- One commit = one context (report change + AD module + UI theme → 3 commits)
- If adding a new offensive module, **do not bypass the scope guard**

---

## 📜 License

MIT — use freely, but responsibility is yours. See [LICENSE](LICENSE).

---

## 🙏 Credits

- [nmap](https://nmap.org) · [nuclei](https://github.com/projectdiscovery/nuclei) · [netexec](https://github.com/Pennyw0rth/NetExec) · [impacket](https://github.com/fortra/impacket) · [chisel](https://github.com/jpillora/chisel) · [ligolo-ng](https://github.com/nicocha30/ligolo-ng) · [searchsploit](https://gitlab.com/exploit-database/exploitdb)
- [bgpview.io](https://bgpview.io) · [crt.sh](https://crt.sh) · [Wayback Machine](https://web.archive.org) · [rdap.org](https://rdap.org) · [hackertarget.com](https://hackertarget.com)
- MITRE ATT&CK · Mozilla Observatory · MurmurHash3 (Austin Appleby)

---

<p align="center">
  <sub>For authorized security testing only. Re-read the <a href="#%EF%B8%8F-ethics--legal">Ethics section</a>.</sub>
</p>
