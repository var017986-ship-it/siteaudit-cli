@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

echo.
echo      .---------------------------------.
echo      ^|        SITEAUDIT SETUP          ^|
echo      ^|   Safe, scoped web assessment   ^|
echo      '---------------------------------'

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
echo Optional: setup-engines.bat downloads Nuclei templates, installs Wapiti locally,
echo and pulls the official Nikto and ZAP Docker images when Docker is available.
choice /C YN /N /M "Set up supported upstream engines now? [Y/N] "
if errorlevel 2 goto setup_done
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
