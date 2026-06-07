@echo off
setlocal
echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║   Minifra Hub — First-Time Setup                 ║
echo  ║   Hub Machine:  192.168.1.109                    ║
echo  ║   Endpoints:    192.168.1.134 / .141 / .142/.143 ║
echo  ╚══════════════════════════════════════════════════╝
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3.11+ required.
    echo         Download from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/5] Creating data + certs directories ...
if not exist data   mkdir data
if not exist certs  mkdir certs

echo [2/5] Installing dependencies ...
pip install -r requirements.txt --quiet
if errorlevel 1 ( echo [ERROR] pip install failed & pause & exit /b 1 )
pip install -r requirements-agent.txt --quiet

echo [3/5] Generating self-signed TLS certificate ...
python generate-cert.py
if errorlevel 1 (
    echo [WARN] Cert generation failed — Hub will run HTTP only.
    echo        Install pyopenssl:  pip install pyopenssl
)

echo [4/5] Building EXEs (this takes 1-3 minutes) ...
call build\build.bat
if errorlevel 1 ( echo [ERROR] Build failed & pause & exit /b 1 )

echo [5/5] Setup complete!
echo.
echo  ┌─ NEXT STEPS ──────────────────────────────────────────────┐
echo  │                                                            │
echo  │  1. Edit config\hub-config.json                           │
echo  │     • Set "password" for each endpoint (WinRM creds)      │
echo  │     • Set "auth_token" to a strong secret                 │
echo  │                                                            │
echo  │  2. Start the Hub:                                         │
echo  │       dist\minifra-hub.exe                                 │
echo  │                                                            │
echo  │  3. Deploy agents to the 4 VMs:                           │
echo  │       python build\deploy.py                               │
echo  │                                                            │
echo  │  4. Open Minifra Secure Console in your browser           │
echo  │       Config → Hub tab                                     │
echo  │       URL:   https://192.168.1.109:8080                   │
echo  │       Token: (the auth_token you set above)               │
echo  │                                                            │
echo  │  5. Accept the self-signed cert warning once in browser   │
echo  │       https://192.168.1.109:8080/health                   │
echo  │       (you should see {"status":"ok",...})                 │
echo  │                                                            │
echo  └────────────────────────────────────────────────────────────┘
echo.
pause
