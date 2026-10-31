@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
set "QUIET="
if /I "%~1"=="/quiet" set "QUIET=1"
if defined QUIET (
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup-engines.ps1"
) else (
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup-engines.ps1" %*
)
set "EXIT_CODE=%ERRORLEVEL%"
echo.
if not defined QUIET pause
endlocal & exit /b %EXIT_CODE%
