@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
set "PYTHONUTF8=1"

if not exist ".venv\Scripts\python.exe" (
    echo First run: setting up SiteAudit...
    call "%~dp0setup.bat" /quiet
    if errorlevel 1 goto failed
)

:menu
cls
echo    .---------------------------------------.
echo   /              SITEAUDIT                  \
echo  ^|          .---------------.                ^|
echo  ^|       .-'   .-------.     '-.              ^|
echo  ^|      /     /  .---.  \      \             ^|
echo  ^|     ^|     ^|  ^(  o  ^)  ^|      ^|             ^|
echo  ^|      \     \  '---'  /      /             ^|
echo  ^|       '-.   '-------'    .-'              ^|
echo   \          '-------------'               /
echo    '---------------------------------------'
echo.
echo   1. Quick passive scan   ^(10 pages, no active probes^)
echo   2. Standard scan        ^(built-in checks, 50 pages^)
echo   3. Deep SiteAudit scan  ^(up to 200 pages, SQLi/GraphQL checks^)
echo   4. Full scan            ^(all installed engines; ZAP active^)
echo   5. Exit
echo.
choice /C 12345 /N /M "Choose a mode: "
if errorlevel 5 goto end
if errorlevel 4 set "SCAN_ARGS=--max-pages 100 --max-depth 3 --delay 1 --engine all --engine-timeout 300 --zap-active"
if errorlevel 3 if not errorlevel 4 set "SCAN_ARGS=--max-pages 200 --max-depth 4 --delay 0.75 --sqli-probes --graphql-probe"
if errorlevel 2 if not errorlevel 3 set "SCAN_ARGS=--max-pages 50 --max-depth 2 --delay 0.5"
if errorlevel 1 if not errorlevel 2 set "SCAN_ARGS=--passive --max-pages 10 --max-depth 1 --delay 1"

echo.
set "SITEAUDIT_TARGET="
set /p "SITEAUDIT_TARGET=Enter the URL you are authorized to scan: "
if not defined SITEAUDIT_TARGET goto menu
set "REPORT=reports\scan-%RANDOM%-%RANDOM%.json"
echo.
".venv\Scripts\python.exe" -m siteaudit %SCAN_ARGS% --output "%REPORT%"
set "SITEAUDIT_TARGET="
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
