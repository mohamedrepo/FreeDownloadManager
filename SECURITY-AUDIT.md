# Flow Download Manager — Security & Malware Audit

**Audited:** 2026-10-30
**Scope:** Full tracked tree (363 files), version 2.7.1, commit `81e7eed`
**Type:** Electron desktop app + local HTTP API + Chromium extension + vendored `aria2c`/`yt-dlp`

---

## 1. Verdict

**No malware found.** No cryptocurrency miner, no ransomware capability, no
credential stealer, no exfiltration channel, no obfuscated payload, no
unauthorised persistence.

The three committed Windows executables were verified **byte-for-byte against
their official upstream releases** — this is the strongest possible result for
bundled binaries, because it rules out a tampered or trojanised build rather
than merely failing to spot one.

The security engineering is well above average for a hobby-scale project. The
findings below are **hardening items, not compromises**. There is no evidence
that any user is currently at risk from this code.

---

## 2. Binary provenance verification

| File | Size | SHA-256 | Verdict |
|---|---|---|---|
| `vendor/yt-dlp.exe` | 17,880,111 | `33121d19…d9f555` | **Matches upstream** `yt-dlp 2026.10.21` `SHA2-256SUMS` published by the yt-dlp project |
| `vendor/aria2/aria2c.exe` | 5,649,408 | `be2099c2…9d70c2` | **Matches upstream**: extracted from the official `aria2-1.37.0-win-64bit-build1.zip` release asset |
| `native/FlowNativeHost.exe` | 10,752 | `c2803306…e6a66b` | First-party 10 KB .NET assembly; behaviour matches `native/FlowNativeHost.cs` |

### Why the native host is trusted

`FlowNativeHost.exe` imports `CreateProcess`, `HttpWebRequest` and Base64 —
a pattern that also appears in droppers, so it was verified against its source
line by line. It is a legitimate Chrome native-messaging host:

- HTTP target is hard-pinned: the address must parse as absolute, use the
  `http` scheme **and** have host exactly `127.0.0.1`, otherwise it throws.
- The caller must be the configured extension: `argv[0]` is compared to
  `chrome-extension://<extensionId>` derived from the repo's manifest key.
- Only two commands exist: `ping` and `download`. Anything else is rejected.
- The shared secret is stored with Windows DPAPI (`ProtectedData.Protect`,
  `CurrentUser` scope), not in plaintext.
- Responses are capped at 1 MB; inbound messages at 512 KB.
- `CreateProcess` passes a fixed executable from config, **not** attacker input,
  and the child is detached so it cannot inherit the browser's stdio pipes.

### Install-time hooks

`postinstall` runs `scripts/setup.cjs`, which only executes Electron's own
`node_modules/electron/install.js`. `scripts/verify-source.cjs` only runs
`node --check`. **No install-time network fetch or remote code execution.**

### Committed secrets

Scanned every tracked file for PEM private keys, GitHub/Slack/AWS/OpenAI token
formats and `.env` files: **none present.**

---

## 3. Malware indicator sweep — negative results

Searched all `.cjs/.js/.cs/.ps1/.nsh/.nsi/.cmd/.json/.yml` plus `ui/` and
`extension/` for the indicators below. Every category returned zero hits unless
noted.

| Category | Indicators searched | Result |
|---|---|---|
| Cryptomining | `stratum`, `xmrig`, `monero`, `coinhive`, `cryptonight`, `randomx`, `nicehash`, `hashrate` | **None** |
| Ransomware | `ransom`, `.locked`, file-walk + encrypt loops, ransom notes, BTC addresses | **None** — the `encrypt`/`decrypt` hits are the legitimate Realm key and AES store (see below) |
| Exfiltration | Discord webhooks, Telegram bot API, Pastebin, ngrok, requestbin, webhook.site, transfer.sh | **None** |
| Obfuscation | `eval(`, `new Function(`, `document.write(`, large base64 blobs | **None.** The `Buffer.from(...,'base64')` hits are manifest-key hashing, engine keys and DPAPI blobs |
| C2 / hardcoded infrastructure | Non-loopback IP literals, `.onion`, raw-IP URLs | **None.** Every absolute URL is a known vendor: `nodejs.org`, `api.nuget.org`, `raw.githubusercontent.com`, `api.github.com`, `timestamp.digicert.com`, Microsoft docs |
| Credential theft | Chrome `Login Data`, `Cookies` DB, `wallet.dat`, `.ssh`, `id_rsa`, `lsass`, `mimikatz` | **None.** The only `cookies` reference is the extension forwarding cookies for a download the user initiated |
| Unauthorised persistence | `schtasks`, `reg add`, `Run` keys, Startup folder, LaunchAgents, systemd | **None.** Registry writes are limited to the app's own uninstall keys and the *browser native-messaging host registration* the feature requires (`HKCU\Software\...\NativeMessagingHosts\local.flow.companion`) |

### The encryption code is legitimate

Two patterns look alarming in isolation and are not:

- `src/store.cjs:100` — AES-256-GCM used to encrypt saved FTP credentials and
  the library; `logins()` strips the password before returning, so plaintext
  never reaches the renderer or the API.
- `src/native-protection.cjs` / `src/electron.cjs:76` — the Realm database key is
  wrapped with the OS keyring (DPAPI / safeStorage), not a hardcoded key. The
  library key is 64 random bytes from `crypto.randomBytes`.

There is **no file-encryption routine** anywhere in the tree, which is the
defining capability of ransomware.

---

## 4. Vulnerabilities & hardening findings

### F1 — Remote Control binds to all interfaces over plain HTTP (Medium)

`src/remote.cjs:6` — `.listen(0, this.listenHost || '0.0.0.0')`. `listenHost` is
never assigned anywhere, so enabling Remote Control exposes an HTTP server on
**every network interface**, including Wi-Fi and public networks.

Pairing uses a 6-digit PIN (`crypto.randomInt(100000,1000000)`) and issues a
bearer token valid for 12 hours (`now + 12*3600000`). All of it travels in
**cleartext**; there is no TLS. Anyone able to observe the LAN (shared Wi-Fi,
hotel/airport network, ARP spoofing) can capture a token and then add downloads
and read download names/statuses for 12 hours.

Mitigations already present: 5 pairing attempts per IP per minute, PIN expires
after 10 minutes, max 5 devices, Host-header allowlist, exact-Origin +
JSON-content-type requirement on POST (blocks browser CSRF), and the remote API
is limited to `add`/`pause`/`resume`.

**Fix:** bind to a specific interface the user selects (or default to loopback),
warn when enabling on an untrusted network, lengthen the PIN, and use
`crypto.timingSafeEqual` for the PIN comparison instead of `String(data.pin)!==this.pin`.

### F2 — Linux without a keyring stores the library key unencrypted (Medium)

`src/electron.cjs:76` treats Linux `basic_text` as "no encryption available",
and `src/store.cjs:44-58` then falls back to writing the 64-byte Realm key to
`realm-key.local` as raw bytes (`mode: 0o600`).

On a Linux box with no Secret Service (headless, minimal WM, some containers),
`flow.realm` is still encrypted, but **the key sits next to it in plaintext**.
That key decrypts the database, which contains saved FTP passwords. Mode `0600`
protects against other users but not against backups, sync folders, or any
process running as that user.

**Fix:** refuse to start on `basic_text` unless the user explicitly opts in with
a warning, or derive the key from a user passphrase with `scrypt`/`argon2`.

### F3 — Local API token is unauthenticated on loopback (Low–Medium)

`src/server.cjs:28` — `GET /api/session` returns the process API token with no
authentication, only Host/Origin checks. DNS rebinding and browser CSRF are
correctly blocked (Host allowlist + exact `sec-fetch-site`/Origin checks +
`timingSafeEqual` on the token), so **a web page cannot exploit this**.

However, the token is not bound to a user or process: **any local process, and
on a multi-user Linux host any other logged-in user, can read the token and then
call `/api/state` and `/api/action`** with full privileges.

`src/service.cjs:56` compounds this — `snapshot()` returns `extensionToken` and
the complete `settings` object, where `proxy` may contain `user:password@host`
(proxy URLs are not checked for embedded credentials, unlike `validateURL`).

**Fix:** write the token to a `0600` file in the user's data directory and read
it from there instead of serving it over HTTP; omit `extensionToken` and
`proxy` credentials from `snapshot()`.

### F4 — Configurable scanner is an arbitrary-execution primitive (Low)

`src/service.cjs:20` (`validateSettings`) accepts any key present in `DEFAULTS`,
which includes `scanner` and `scannerArgs`. `src/engine.cjs:227-232` then runs
`spawn(settings.scanner, args)` on every completed download. Arguments use an
argv array with **no shell**, so there is no command injection — but the path is
an arbitrary executable.

Two things already limit this well: config import deliberately deletes
`scanner`, `scannerArgs`, `proxy`, `downloadDir`, `tempDir` and the sound paths
(`src/library.cjs:22`) so a malicious config file cannot set them, and reaching
`settings` requires an already-authenticated caller. The residual risk is that a
compromised renderer (e.g. an XSS in a future UI change) escalates to native code
execution, and that a malicious "AV" path can be set directly in settings.

**Fix:** select the scanner through a native file dialog only, require it to be
an absolute path to an existing file, and consider an allowlist of known AV
binaries.

### F5 — Internal error strings returned to clients (Low)

`src/server.cjs` responds with `send(400,{error:e.message})`. Local API callers
receive raw exception text (paths, filesystem state). Low impact because callers
are already privileged.

**Fix:** map to generic messages and keep details in `desktop.log`.

### F6 — Extension holds broad host and cookie permissions (Low / by design)

`extension/manifest.json` requests `cookies`, `webRequest`, `tabs`, `scripting`,
`nativeMessaging` and `host_permissions: http://*/*, https://*/*`, with a content
script on every frame of every site.

This is genuinely required to intercept downloads and hand off an authorised
session, and the code only uses cookies for a download the user explicitly
initiates (`extension/background.js:25`). Still, it means the extension **can**
read cookies for any site — users installing it should understand that.

**Fix:** document it in `BROWSER-INTEGRATION.md`, and consider
`optional_host_permissions` so users grant site access on demand.

---

## 5. Controls that are already strong

Worth recording, because these are what make the posture good and should not be
regressed while adding features:

- **Process isolation:** `contextIsolation: true`, `nodeIntegration: false`,
  `sandbox: true` on the main window, drop basket **and** every tool window.
- **IPC:** every `flow:action`/`flow:state` call is checked by `trusted(event)`
  (sender must be a known window *and* `senderFrame` origin must equal the app
  origin), plus a preload allowlist of ~120 action names. The drop basket can
  only add downloads.
- **Navigation:** `setWindowOpenHandler` denies all, `will-navigate` blocks
  off-origin, and all permission requests are denied.
- **Local HTTP server:** loopback-only bind, Host allowlist (defeats DNS
  rebinding), `timingSafeEqual` token compare, strict CSP, `nosniff`, `DENY`
  framing, 4 MB body cap, and path-traversal-safe static serving
  (`resolve` + `startsWith(ui + sep)`).
- **Crypto-integrity before execution:** `aria2c.exe` SHA-256 is checked against
  `PROVENANCE.json` before every launch (`src/peers.cjs:21`), and `yt-dlp` is
  version/URL/hash-pinned with the downloaded file verified **before**
  `chmod`/`rename` into place (`src/video-tools.cjs`). A failed digest means no
  binary is installed.
- **Updates:** never auto-install. Release JSON is strictly validated (tag
  format, `draft`/`prerelease` false, asset URL must equal the expected GitHub
  download prefix), `redirect: 'error'`, 512 KB response cap, and only the
  release *page* is opened.
- **ZIP extraction:** blocks `..`, absolute paths, drive letters, `:` segments,
  symlinks and encrypted entries; flattens to `basename`; verifies CRC-32 and
  size; writes with `flag: 'wx'`, `mode: 0o600`; caps entries at 128 MB.
- **Command execution:** no `shell: true` anywhere. PowerShell is invoked with
  `-EncodedCommand` over base64 and receives config as JSON on **stdin**;
  `reg.exe` receives an argv array. Redirects strip `authorization`, `cookie`,
  `referer` and `origin` on cross-origin hops (`src/network.cjs`).
- **Credentials:** FTP passwords AES-256-GCM encrypted at rest and stripped from
  `logins()`; the browser handoff token is 32 random bytes compared in constant
  time; cookies travel as a `0600` Netscape temp cookie file that is removed
  after use.
- **Filename handling:** `fileName()` strips `<>:"/\|?*` and control characters,
  trims trailing dots/spaces, caps at 180 chars and prefixes Windows reserved
  names (`con`, `nul`, `com1`…), so server-supplied names cannot traverse paths.

---

## 6. Prioritised recommendations

1. **F1** — default Remote Control to loopback or a chosen interface; add a
   plaintext-LAN warning; constant-time PIN compare.
2. **F2** — do not fall back to a plaintext key on Linux `basic_text`.
3. **F3** — stop serving the API token over HTTP; strip `extensionToken` and
   proxy credentials from `snapshot()`.
4. **F4** — constrain `scanner`/`scannerArgs` to a chosen, absolute executable.
5. **F5/F6** — generic error responses; document extension permissions.

## 7. Method & limitations

- Static analysis by reading every entry point, the three binaries and the
  build/install scripts; pattern sweep over the whole tree; upstream hash
  verification via the yt-dlp `SHA2-256SUMS` release asset and the official
  aria2 1.37.0 Windows archive.
- `aria2c.exe` and `yt-dlp.exe` were verified by **hash equality with upstream**,
  not by disassembly. `FlowNativeHost.exe` was reviewed via its source and
  imported-symbol/string inspection, **not** by full IL decompilation.
- No dynamic/runtime analysis was performed: the app was not executed, and no
  `npm install` was run (Realm and Electron are large native downloads).
- Dependency CVEs were not enumerated; `realm 20.2.0`, `electron 45.0.0`,
  `cheerio 1.2.0`, `basic-ftp 6.2.3`, `proxy-agent 6.5.0` and
  `http2-wrapper 2.2.1` are pinned, but no audit database was consulted. Run
  `npm audit` after installing to cover that gap.
