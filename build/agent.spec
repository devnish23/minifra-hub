# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for minifra-agent.exe
import os

block_cipher = None
ROOT = os.path.abspath(os.path.join(SPECPATH, '..'))
SRC  = os.path.join(ROOT, 'src', 'agent')

a = Analysis(
    [os.path.join(SRC, 'service.py')],
    pathex=[SRC],
    binaries=[],
    datas=[],
    hiddenimports=[
        'agent',
        'psutil',
        'requests',
        'requests.adapters',
        'urllib3',
        'win32service',
        'win32serviceutil',
        'win32event',
        'servicemanager',
        'win32api',
        'win32con',
        'pywintypes',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy'],
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
    name='minifra-agent',
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
