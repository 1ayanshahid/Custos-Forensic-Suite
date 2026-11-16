@echo off
setlocal
if defined CUSTOS_ELEVATED_LAUNCH (
    powershell.exe -NoProfile -Command "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $principal = New-Object Security.Principal.WindowsPrincipal($identity); if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 }; exit 1" >nul 2>&1
    if not errorlevel 1 goto :custos_preflight_done_20261105
)
set "CUSTOS_LAUNCHER=%~f0"
set "CUSTOS_ARGUMENTS=%*"
set "CUSTOS_ELEVATION_RESULT=%TEMP%\custos-elevation-%RANDOM%-%RANDOM%.txt"
if exist "%CUSTOS_ELEVATION_RESULT%" del /q "%CUSTOS_ELEVATION_RESULT%" >nul 2>&1
powershell.exe -NoProfile -Command "$ErrorActionPreference = 'Stop'; $identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $principal = New-Object Security.Principal.WindowsPrincipal($identity); if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 }; try { Write-Host 'Administrator approval is required. Requesting Windows UAC...'; $arguments = $env:CUSTOS_ARGUMENTS; $quote = [char]34; $command = '/d /s /c ' + $quote + 'set CUSTOS_ELEVATED_LAUNCH=1 & call ' + $quote + $env:CUSTOS_LAUNCHER + $quote; if (-not [string]::IsNullOrWhiteSpace($arguments)) { $command += ' ' + $arguments }; $command += $quote; $process = Start-Process -FilePath $env:ComSpec -ArgumentList $command -Verb RunAs -Wait -PassThru; [IO.File]::WriteAllText($env:CUSTOS_ELEVATION_RESULT, [string]$process.ExitCode); exit 0 } catch { Write-Error ('UAC approval was cancelled or elevation failed. No collection was started. ' + $_.Exception.Message); exit 1223 }"
if exist "%CUSTOS_ELEVATION_RESULT%" goto :custos_elevated_child_finished_20261105
if errorlevel 1 goto :custos_elevation_failed_20261105
goto :custos_preflight_done_20261105
:custos_elevated_child_finished_20261105
set "CUSTOS_CHILD_EXIT=2"
for /f "usebackq delims=" %%A in ("%CUSTOS_ELEVATION_RESULT%") do set "CUSTOS_CHILD_EXIT=%%A"
del /q "%CUSTOS_ELEVATION_RESULT%" >nul 2>&1
exit /b %CUSTOS_CHILD_EXIT%
:custos_elevation_failed_20261105
echo UAC approval was cancelled or failed. No collection was started.
if "%~1"=="" pause
exit /b 1223
:custos_preflight_done_20261105
set "CUSTOS_LAUNCHER_OUTPUT_PROMPT=1"

set "PYTHON=%~dp0..\..\.venv\Scripts\python.exe"
set "COLLECTOR=%~dp0collector.py"

if not exist "%PYTHON%" (
    echo Required project Python was not found:
    echo "%PYTHON%"
    echo Run setup_environment.bat from the project root to prepare the shared environment.
    goto failed
)

if not exist "%COLLECTOR%" (
    echo A23 collector was not found:
    echo "%COLLECTOR%"
    goto failed
)

"%PYTHON%" -c "import win32api, win32security, win32service" >nul 2>nul
if errorlevel 1 (
    echo Required pywin32 modules are unavailable in the existing project environment.
    echo Run setup_environment.bat from the project root to prepare the shared environment.
    echo Run setup_environment.bat from the project root to prepare the shared environment.
    goto failed
)

powershell.exe -NoProfile -Command "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $principal = New-Object Security.Principal.WindowsPrincipal($identity); if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 }; exit 1" >nul 2>&1
if not errorlevel 1 goto administrator

echo Administrator permission is required for the fullest driver inventory.
echo Approve the standard Windows UAC prompt to continue.
set "CUSTOS_PYTHON=%PYTHON%"
set "CUSTOS_COLLECTOR=%COLLECTOR%"
set "CUSTOS_ARGUMENTS=%*"
powershell.exe -NoProfile -Command "try { $python = $env:CUSTOS_PYTHON; $collector = $env:CUSTOS_COLLECTOR; $arguments = '""' + $collector + '""'; if (-not [string]::IsNullOrWhiteSpace($env:CUSTOS_ARGUMENTS)) { $arguments += ' ' + $env:CUSTOS_ARGUMENTS }; $process = Start-Process -FilePath $python -ArgumentList $arguments -Verb RunAs -Wait -PassThru; exit $process.ExitCode } catch { Write-Error ('Administrator elevation was cancelled or failed; collection was not started. ' + $_.Exception.Message); exit 1223 }"
set "COLLECTOR_EXIT=%ERRORLEVEL%"
if "%COLLECTOR_EXIT%"=="1223" echo UAC was cancelled or elevation failed. No collection was started.
if not "%COLLECTOR_EXIT%"=="1223" echo A23 collector exit code: %COLLECTOR_EXIT%
pause
exit /b %COLLECTOR_EXIT%

:administrator
if "%~1"=="" (
    "%PYTHON%" "%COLLECTOR%"
) else (
    "%PYTHON%" "%COLLECTOR%" %*
)
set "COLLECTOR_EXIT=%ERRORLEVEL%"
if "%COLLECTOR_EXIT%"=="1" echo A23 collection was partial. Review the output JSON.
if "%COLLECTOR_EXIT%"=="2" echo A23 collection failed. Review the error above.
echo A23 collector exit code: %COLLECTOR_EXIT%
pause
exit /b %COLLECTOR_EXIT%

:failed
echo A23 launcher exit code: 2
pause
exit /b 2
