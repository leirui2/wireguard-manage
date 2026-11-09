# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置。

重新生成 exe：双击 打包exe.bat，或执行
    .build-venv\\Scripts\\python.exe -m PyInstaller --noconfirm --clean wireguard-manager.spec
"""
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = (
    # card.py 里 PIL 是函数内延迟导入（只有点「生成卡片」才加载），
    # 静态分析容易漏掉，这里显式声明
    ["paramiko", "segno", "PIL", "PIL.Image", "PIL.ImageDraw", "PIL.ImageFont"]
    # pystray 按平台动态挑后端（Windows 是 pystray._win32），静态分析看不到
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
        # Pillow 的可选后端：ImageQt 要 PyQt、ImageTk 走 tkinter PhotoImage、
        # ImageShow 是调试用的系统看图器，三样都用不上，留着白占十几 MB
        "PIL.ImageQt",
        "PIL.ImageTk",
        "PIL.ImageShow",
        # 我们只读 PNG（二维码）和写 PNG（卡片），AVIF/WebP 解码器用不到
        "PIL.AvifImagePlugin",
        "PIL.WebPImagePlugin",
        "setuptools",
        "pip",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

# 启动画面。onefile 每次启动要先把 49 MB 解到 %TEMP%，这期间窗口还不存在；
# splash 由引导程序画，解压开始前就显示，双击后立刻有反馈。
# 图片由 build_assets/make_splash.py 生成（版本号写在图里，打包前重跑）。
splash = Splash(
    "build_assets/splash.png",
    binaries=a.binaries,
    datas=a.datas,
    always_on_top=True,
)

exe = EXE(
    pyz,
    a.scripts,
    splash,
    splash.binaries,
    a.binaries,
    a.datas,
    [],
    name="WireGuard管理台",
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
