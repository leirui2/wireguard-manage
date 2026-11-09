# -*- mode: python ; coding: utf-8 -*-
"""目录版（onedir）打包配置 —— 免解压，启动快。

和单文件版（wireguard-manager.spec）的区别只有一个：不把依赖塞进 exe，
而是摊在 `WireGuard管理台\\_internal\\` 里。好处是启动时**不需要解压**：

    单文件版  双击 → 解压 49 MB / 1028 个文件到 %TEMP% → 启动   ≈ 5.0 秒
    目录版    双击 → 直接启动                                  ≈ 1.2 秒

代价是分发：得给一个文件夹（我们打成 zip），用户解压一次以后就有这个速度。
两版共用同一份代码和同一套数据文件，`gui.app_dir()` 取 exe 所在目录，
所以配置（connections.json / tunnels.json）在哪个版里都能读到。

重新生成：打包exe.bat（会先出单文件版，再出目录版并 zip）
"""
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = (
    ["paramiko", "segno", "PIL", "PIL.Image", "PIL.ImageDraw", "PIL.ImageFont"]
    + ["pystray", "pystray._win32", "pystray._base"]
    + collect_submodules("paramiko")
    + collect_submodules("segno")
)

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
        "PIL.ImageQt",
        "PIL.ImageTk",
        "PIL.ImageShow",
        "PIL.AvifImagePlugin",
        "PIL.WebPImagePlugin",
        "setuptools",
        "pip",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

# 目录版**不要**启动画面：启动只 1.2 秒，splash 闪一下反而像界面抖动。
# main.py 里的 pyi_splash.close() 有 try/except 兜着，没有 splash 也不报错。
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="WireGuard管理台",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="build_assets/app.ico",
    version="build_assets/version_info.txt",
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="WireGuard管理台",
)
