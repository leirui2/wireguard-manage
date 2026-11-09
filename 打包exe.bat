@echo off
setlocal
chcp 65001 >nul 2>&1
set "ROOT=%~dp0"
set "PY=%ROOT%.build-venv\Scripts\python.exe"

if not exist "%PY%" (
  echo [ERROR] Build environment not found:
  echo   %PY%
  echo.
  echo Create it once with these two commands:
  echo   "E:\JAVA\Python3.13.5\python.exe" -m venv .build-venv
  echo   .build-venv\Scripts\python.exe -m pip install pyinstaller paramiko==5.1.0
  pause
  exit /b 1
)

if not "%~1"=="" (
  echo Stamping version %~1 ...
  "%PY%" "%ROOT%build_assets\stamp_version.py" "%~1"
  if errorlevel 1 (
    echo.
    echo [ERROR] Bad version. Use something like 1.0.12
    pause
    exit /b 1
  )
) else (
  echo Resolving version from the published release...
  "%PY%" "%ROOT%build_assets\resolve_version.py"
  if errorlevel 1 (
    echo.
    echo [ERROR] Failed to resolve version.
    pause
    exit /b 1
  )
)

REM Splash must be generated AFTER stamping: the version is printed on the image.
echo Generating splash image...
"%PY%" "%ROOT%build_assets\make_splash.py"
if errorlevel 1 (
  echo.
  echo [ERROR] Failed to build splash image.
  pause
  exit /b 1
)

echo Building single-file exe, please wait...

"%PY%" -m PyInstaller --noconfirm --clean "%ROOT%wireguard-manager.spec"
if errorlevel 1 (
  echo.
  echo [ERROR] Build failed. See messages above.
  pause
  exit /b 1
)

REM The installer payload is the onedir layout (fast start after install).
REM It is NOT a product anymore: it goes to build\installer-src and is never shipped.
echo Building installer payload (onedir), please wait...
"%PY%" -m PyInstaller --noconfirm --clean --distpath "%ROOT%build\installer-src" "%ROOT%wireguard-manager-onedir.spec"
if errorlevel 1 (
  echo.
  echo [ERROR] Installer payload build failed. Single-file exe is still available.
  pause
  exit /b 1
)

REM Installer needs Inno Setup 6; skip gracefully when it is not installed.
echo Building installer...
"%PY%" "%ROOT%build_assets\make_installer.py" "%~1"
if errorlevel 2 (
  echo [WARN] Installer skipped. Install Inno Setup 6 once:
  echo        winget install JRSoftware.InnoSetup
  goto summary
)
if errorlevel 1 (
  echo.
  echo [ERROR] Installer build failed. Single-file exe is still available.
  pause
  exit /b 1
)

:summary
echo.
echo Build OK. Output:
dir /b "%ROOT%dist\*.exe"
echo Folder: %ROOT%dist
pause
