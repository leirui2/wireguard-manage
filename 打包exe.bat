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

echo Building, please wait...

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

"%PY%" -m PyInstaller --noconfirm --clean "%ROOT%wireguard-manager.spec"
if errorlevel 1 (
  echo.
  echo [ERROR] Build failed. See messages above.
  pause
  exit /b 1
)

echo.
echo Build OK. Output:
dir /b "%ROOT%dist\*.exe"
echo Folder: %ROOT%dist
pause
