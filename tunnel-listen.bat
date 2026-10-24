@echo off
rem Listener side: run on winhigh-01 (or keep this DSH session running) while
rem the MacBook opens the outbound Tailscale connection.
rem
rem Usage: tunnel-listen.bat [LOCAL_PORT] [REMOTE_HOST:PORT]
rem   LOCAL_PORT     - port on 127.0.0.1:82 to expose to the exploit
rem   REMOTE_HOST:PORT - MacBook's Tailscale IP:port, default 100.81.175.61:8082

setlocal
set LOCAL_PORT=%1
set REMOTE=%2
if "%LOCAL_PORT%"=="" set LOCAL_PORT=82
if "%REMOTE%"=="" set REMOTE=100.81.175.61:8082

for /f "tokens=1,2 delims=:" %%a in ("%REMOTE%") do (
    set REMOTE_HOST=%%a
    set REMOTE_PORT=%%b
)

echo [*] Listening on 127.0.0.1:%LOCAL_PORT%, forwarding to %REMOTE_HOST%:%REMOTE_PORT%

:loop
netstat -ano | findstr "127.0.0.1:%LOCAL_PORT%.*LISTENING" >nul
if errorlevel 1 (
    echo [*] Starting listener...
    start /b netsh interface portproxy add v4tov4 listenport=%LOCAL_PORT% listenaddress=127.0.0.1 connectport=%REMOTE_PORT% connectaddress=%REMOTE_HOST%
    netsh interface portproxy show v4tov4
)
echo [*] Listener active. Press Ctrl+C to stop.
:wait
timeout /t 5 >nul
goto wait
