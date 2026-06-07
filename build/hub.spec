# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for minifra-hub.exe
import os

block_cipher = None
ROOT = os.path.abspath(os.path.join(SPECPATH, '..'))
SRC  = os.path.join(ROOT, 'src', 'hub')

a = Analysis(
    [os.path.join(SRC, 'main.py')],
    pathex=[SRC],
    binaries=[],
    datas=[
        (os.path.join(ROOT, 'config'), 'config'),
        (os.path.join(ROOT, 'certs'), 'certs') if os.path.exists(os.path.join(ROOT, 'certs')) else ([], '.'),
    ],
    hiddenimports=[
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'fastapi',
        'pydantic',
        'winrm',
        'winrm.protocol',
        'winrm.exceptions',
        'requests_ntlm',
        'ntlm_auth',
        'requests_credssp',
        'cryptography',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.backends',
        'sqlite3',
        'db',
        'models',
        'collector',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='minifra-hub',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
