@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
set "PYTHONUTF8=1"
if not defined SITEAUDIT_ENGINE_HOME set "SITEAUDIT_ENGINE_HOME=%LOCALAPPDATA%\SiteAudit\engines"
set "PATH=%SITEAUDIT_ENGINE_HOME%\bin;%SITEAUDIT_ENGINE_HOME%\wapiti\Scripts;%PATH%"

if not exist ".venv\Scripts\python.exe" (
    echo First run: setting up SiteAudit...
    call "%~dp0setup.bat" /quiet
    if errorlevel 1 goto failed
)
set "PATH=%~dp0.venv\Scripts;%PATH%"

:menu
cls
set "SCAN_ARGS="
set "RUN_ENGINE_DOCTOR="
echo                    .-=========-.
echo                   /  .-------.  \\
echo                  ^|  /  o o  \\  ^|
echo                  ^| ^|    ^    ^| ^|
echo                  ^|  \\  '-'  /  ^|
echo                   \\  '-----'  /
echo                    '---.____.---'
echo                 .---'  SITEAUDIT  '---.
echo                      .----.   .----.
echo                     /      \ /      \
echo                    /        ^|        \
echo                   ^|         ^|         ^|
echo                  /          ^|          \
echo                 /_____      ^|      _____\
echo                       \     ^|     /
echo                        \   .-.   /
echo                         \ ( O ) /
echo                          '-------'
echo.
echo   1. Quick passive scan     ^(10 built-in pages, no active probes^)
echo   2. Standard scan          ^(built-in checks, 50 pages^)
echo   3. Deep SiteAudit scan    ^(up to 200 built-in pages, SQLi/GraphQL^)
echo   4. Full combined scan    ^(SiteAudit + active ZAP, if installed^)
echo   5. Upstream engines only ^(ZAP active, if installed^)
echo   6. Focused Nuclei scan    ^(misconfig/exposure, up to 15 min^)
echo   7. Check engine readiness
echo   8. Exit
echo.
choice /C 12345678 /N /M "Choose a mode: "
if errorlevel 8 goto end
if errorlevel 7 (
    ".venv\Scripts\python.exe" -m siteaudit --doctor
    echo.
    pause
    goto menu
)
if errorlevel 6 if not errorlevel 7 set "SCAN_ARGS=--external-only --max-pages 50 --max-depth 2 --delay 1 --engine nuclei --nuclei-tags misconfig,exposure --engine-timeout 900"
if errorlevel 5 if not errorlevel 6 (
    set "SCAN_ARGS=--external-only --max-pages 100 --max-depth 3 --delay 1 --engine all --engine-timeout 300 --zap-active"
    set "RUN_ENGINE_DOCTOR=1"
)
if errorlevel 4 if not errorlevel 5 (
    set "SCAN_ARGS=--max-pages 100 --max-depth 3 --delay 1 --engine all --engine-timeout 300 --zap-active"
    set "RUN_ENGINE_DOCTOR=1"
)
if errorlevel 3 if not errorlevel 4 set "SCAN_ARGS=--max-pages 200 --max-depth 4 --delay 0.75 --sqli-probes --graphql-probe"
if errorlevel 2 if not errorlevel 3 set "SCAN_ARGS=--max-pages 50 --max-depth 2 --delay 0.5"
if errorlevel 1 if not errorlevel 2 set "SCAN_ARGS=--passive --max-pages 10 --max-depth 1 --delay 1"

echo.
if defined RUN_ENGINE_DOCTOR (
    ".venv\Scripts\python.exe" -m siteaudit --doctor
    if errorlevel 1 (
        echo.
        echo Some requested engines are missing or unsupported here.
        choice /C YN /N /M "Continue with available engines only? [Y/N] "
        if errorlevel 2 goto menu
    )
    echo.
)
set "SITEAUDIT_TARGET="
set /p "SITEAUDIT_TARGET=Enter the URL you are authorized to scan: "
if not defined SITEAUDIT_TARGET goto menu
set "REPORT=reports\scan-%RANDOM%-%RANDOM%.json"
echo.
".venv\Scripts\python.exe" -m siteaudit "%SITEAUDIT_TARGET%" %SCAN_ARGS% --output "%REPORT%"
set "SITEAUDIT_TARGET="
set "RUN_ENGINE_DOCTOR="
echo.
echo Report: %REPORT%
echo.
pause
goto menu

:failed
set "EXIT_CODE=1"
echo Could not set up SiteAudit. Run setup.bat and check the error.
pause
goto end

:end
if not defined EXIT_CODE set "EXIT_CODE=0"
endlocal & exit /b %EXIT_CODE%
