# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置。

重新生成 exe：双击 打包exe.bat，或执行
    .build-venv\\Scripts\\python.exe -m PyInstaller --noconfirm --clean wireguard-manager.spec
"""
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ["paramiko"] + collect_submodules("paramiko")

a = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "pytest",
        "numpy",
        "pandas",
        "matplotlib",
        "PIL",
        "setuptools",
        "pip",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="WireGuard密钥管理工具",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="build_assets/app.ico",
    version="build_assets/version_info.txt",
)
