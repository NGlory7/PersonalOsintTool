@echo off
chcp 65001 >nul
title OSINT Detective Web Dashboard
cd /d "%~dp0"

echo ===================================================
echo     OSINT DETECTIVE WEB PANELİ BAŞLATILIYOR
echo ===================================================
echo.

set PYTHON_CMD=python
if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" (
    set "PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
)

"%PYTHON_CMD%" web_app.py

echo.
pause
