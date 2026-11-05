@echo off
setlocal
chcp 65001 >nul 2>&1
set "ROOT=%~dp0"

rem ---- find a Python that ships tkinter ----
rem 1) 本机常用的固定路径（不存在会自动跳过，换机器不影响）
set "PYEXE=E:\JAVA\Python3.13.5\python.exe"
if not exist "%PYEXE%" set "PYEXE="
rem 2) 官方 py 启动器
if not defined PYEXE (
  for /f "delims=" %%i in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do if not defined PYEXE set "PYEXE=%%i"
)
rem 3) PATH 里的 python.exe
if not defined PYEXE (
  for /f "delims=" %%i in ('where python.exe 2^>nul') do if not defined PYEXE set "PYEXE=%%i"
)
if not defined PYEXE (
  echo [ERROR] Python not found. Please install Python 3.10+ with tkinter.
  pause
  exit /b 1
)

set "PYTHONPATH=%ROOT%;%ROOT%vendor"
set "PYTHONIOENCODING=utf-8"

rem ---- install dependencies into local vendor folder if missing ----
"%PYEXE%" -c "import tkinter, paramiko" >nul 2>&1
if errorlevel 1 (
  echo Installing dependencies into vendor\ ...
  "%PYEXE%" -m pip install --disable-pip-version-check --target "%ROOT%vendor" -r "%ROOT%requirements.txt"
  if errorlevel 1 (
    echo [ERROR] Failed to install dependencies. Check network connection.
    pause
    exit /b 1
  )
)

rem ---- prefer pythonw.exe so no console window stays behind ----
set "PYW=%PYEXE:python.exe=pythonw.exe%"
if not exist "%PYW%" set "PYW=%PYEXE%"
start "" "%PYW%" "%ROOT%main.py"
endlocal
