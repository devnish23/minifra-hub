@echo off
setlocal
echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║   Minifra Hub — EXE Build Script             ║
echo  ║   Produces: dist\minifra-hub.exe             ║
echo  ║             dist\minifra-agent.exe           ║
echo  ╚══════════════════════════════════════════════╝
echo.

cd /d "%~dp0.."

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.11+ from https://python.org
    pause
    exit /b 1
)

echo [1/4] Installing Hub dependencies...
pip install -r requirements.txt --quiet
if errorlevel 1 ( echo [ERROR] pip install failed & pause & exit /b 1 )

echo [2/4] Installing Agent dependencies...
pip install -r requirements-agent.txt --quiet
if errorlevel 1 ( echo [ERROR] pip install (agent) failed & pause & exit /b 1 )

echo [3/4] Building minifra-hub.exe ...
pyinstaller build\hub.spec --noconfirm --clean
if errorlevel 1 ( echo [ERROR] PyInstaller (hub) failed & pause & exit /b 1 )

echo [4/4] Building minifra-agent.exe ...
pyinstaller build\agent.spec --noconfirm --clean
if errorlevel 1 ( echo [ERROR] PyInstaller (agent) failed & pause & exit /b 1 )

echo.
echo  ✓  dist\minifra-hub.exe
echo  ✓  dist\minifra-agent.exe
echo.
echo  Next steps:
echo    1. Edit config\hub-config.json  (set WinRM credentials + auth_token)
echo    2. Run generate-cert.bat        (enable HTTPS — recommended)
echo    3. Run dist\minifra-hub.exe     (starts Hub on port 8080)
echo    4. Run build\deploy.py          (push agent to all 4 endpoints)
echo.
pause
