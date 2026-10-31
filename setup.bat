@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
set "PYTHONUTF8=1"

echo.
echo                    .-=============-.
echo                   /   .--------.    \
echo                  ^|   /  o  o   \    ^|
echo                  ^|  ^|    ^    ^|     ^|
echo                   \   \ '----' /    /
echo                .---'----\____/----'---.
echo               /       SITEAUDIT SETUP   \
echo               '-------------------------'

if not exist ".venv\Scripts\python.exe" (
    where py >nul 2>nul
    if not errorlevel 1 (
        py -3.11 -m venv .venv
        if not errorlevel 1 goto install
    )
    python -c "import sys; raise SystemExit(sys.version_info < (3, 11))" >nul 2>nul
    if errorlevel 1 goto no_python
    python -m venv .venv
    if errorlevel 1 goto setup_failed
)

:install
".venv\Scripts\python.exe" -c "import sys; raise SystemExit(sys.version_info < (3, 11))"
if errorlevel 1 goto no_python
".venv\Scripts\python.exe" -m pip install --editable ".[yaml]"
if errorlevel 1 goto setup_failed
echo.
echo SiteAudit is installed. Run start.bat to choose a scan mode.
if /I "%~1"=="/quiet" goto setup_done
echo.
echo.
echo   1. Finish with SiteAudit core only
echo   2. Set up available upstream engines
choice /C 12 /N /M "Choose setup option: "
if errorlevel 2 goto setup_engines
goto setup_done
:setup_engines
call "%~dp0setup-engines.bat" /quiet
if errorlevel 1 echo Upstream setup was incomplete. Run siteaudit --doctor for details.
:setup_done
if /I not "%~1"=="/quiet" pause
exit /b 0

:no_python
echo Python 3.11 or newer is required. Install it from https://www.python.org/downloads/windows/
if /I not "%~1"=="/quiet" pause
exit /b 1

:setup_failed
echo Setup failed. Check the Python installation and internet connection, then run setup.bat again.
if /I not "%~1"=="/quiet" pause
exit /b 1
