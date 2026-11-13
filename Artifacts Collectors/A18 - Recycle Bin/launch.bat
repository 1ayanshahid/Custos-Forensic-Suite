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
set "COLLECTOR_EXIT="

powershell.exe -NoProfile -Command "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $principal = New-Object Security.Principal.WindowsPrincipal($identity); if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 }; exit 1" >nul 2>&1
if not errorlevel 1 goto administrator

echo Administrator permission is required. Approve the Windows UAC prompt to continue.
set "CUSTOS_LAUNCHER=%~f0"
set "CUSTOS_ARGUMENTS=%*"
powershell.exe -NoProfile -Command "try { $launcher = $env:CUSTOS_LAUNCHER; $arguments = $env:CUSTOS_ARGUMENTS; $quote = [char]34; $command = '/d /s /c ' + $quote + 'set CUSTOS_ELEVATED_LAUNCH=1 & call ' + $quote + $launcher + $quote; if (-not [string]::IsNullOrWhiteSpace($arguments)) { $command += ' ' + $arguments }; $command += $quote; $process = Start-Process -FilePath $env:ComSpec -ArgumentList $command -Verb RunAs -Wait -PassThru; exit (100 + $process.ExitCode) } catch { Write-Error ('Elevation was cancelled or failed: ' + $_.Exception.Message); exit 1223 }"
set "ELEVATION_EXIT=%ERRORLEVEL%"
if "%ELEVATION_EXIT%"=="100" set "COLLECTOR_EXIT=0"
if "%ELEVATION_EXIT%"=="101" set "COLLECTOR_EXIT=1"
if "%ELEVATION_EXIT%"=="102" set "COLLECTOR_EXIT=2"
if defined COLLECTOR_EXIT goto elevated_result
echo Collection did not start because elevation was cancelled or failed.
pause
exit /b 2

:administrator
set "SCRIPT_DIR=%~dp0"
set "PYTHON=%~dp0..\..\.venv\Scripts\python.exe"
set "COLLECTOR=%SCRIPT_DIR%collector.py"

if not exist "%PYTHON%" (
    echo Required project Python was not found:
    echo "%PYTHON%"
    echo Run setup_environment.bat from the project root to prepare the shared environment.
    goto failed
)

if not exist "%COLLECTOR%" (
    echo A18 collector is missing:
    echo "%COLLECTOR%"
    goto failed
)

"%PYTHON%" "%COLLECTOR%" %*
set "COLLECTOR_EXIT=%ERRORLEVEL%"
if "%COLLECTOR_EXIT%"=="1" echo Collection was partial. Review the result JSON errors and limitations.
if "%COLLECTOR_EXIT%"=="2" echo Collection failed.
echo A18 collector exit code: %COLLECTOR_EXIT%
pause
exit /b %COLLECTOR_EXIT%

:failed
echo A18 launcher exit code: 2
pause
exit /b 2

:elevated_result
if "%COLLECTOR_EXIT%"=="1" echo Collection was partial. Review the result JSON errors and limitations.
if "%COLLECTOR_EXIT%"=="2" echo Collection failed.
echo A18 collector exit code: %COLLECTOR_EXIT%
pause
exit /b %COLLECTOR_EXIT%
