@echo off
setlocal EnableExtensions DisableDelayedExpansion
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

set "A40_DIR=%~dp0"
set "A40_PYTHON=%~dp0..\..\.venv\Scripts\python.exe"
set "A40_COLLECTOR=%A40_DIR%collector.py"

set "A40_ELEVATED="
if /i "%~1"=="--elevated" (
    set "A40_ELEVATED=1"
    shift
    goto :check_requirements
)

set "A40_OUTPUT="
set "A40_OVERWRITE_ARG="

:parse_arguments
if "%~1"=="" goto :check_requirements
if /i "%~1"=="--output" (
    if "%~2"=="" (
        echo ERROR: --output requires a destination file path.
        goto :failed
    )
    set "A40_OUTPUT=%~2"
    shift
    shift
    goto :parse_arguments
)
if /i "%~1"=="--overwrite" (
    set "A40_OVERWRITE_ARG=--overwrite"
    shift
    goto :parse_arguments
)
echo ERROR: Unsupported launcher argument.
echo Use: launch.bat [--output "C:\path\Local Users.json"] [--overwrite]
goto :failed

:check_requirements
if not exist "%A40_PYTHON%" (
    echo ERROR: Required Python executable was not found:
    echo "%A40_PYTHON%"
    echo Run setup_environment.bat from the project root to prepare the shared environment.
    goto :failed
)

"%A40_PYTHON%" -c "import win32api, win32net, win32security" >nul 2>&1
if errorlevel 1 (
    echo ERROR: pywin32 is missing or unusable in the required project environment.
    echo Run setup_environment.bat from the project root to prepare the shared environment.
    echo Run setup_environment.bat from the project root to prepare the shared environment.
    goto :failed
)

fltmc >nul 2>&1
if not errorlevel 1 goto :run_collector

if defined A40_ELEVATED (
    echo ERROR: The elevated launcher did not receive administrator access.
    goto :failed
)

echo Administrator access is required for A40 local-account inventory.
echo Approve the standard Windows UAC prompt to continue.
set "A40_LAUNCHER=%~f0"
set "A40_ELEVATION_REQUESTED=1"
powershell.exe -NoProfile -NonInteractive -Command ^
  "try { $q = [char]34; $a = '/d /c ' + $q + $q + $env:A40_LAUNCHER + $q + ' --elevated' + $q; $p = Start-Process -FilePath $env:ComSpec -ArgumentList $a -Verb RunAs -Wait -PassThru; if ($null -eq $p.ExitCode) { exit 125 }; exit $p.ExitCode } catch { if (($_.Exception.HResult -band 65535) -eq 1223) { [Console]::Error.WriteLine('UAC was cancelled. No collection was started.'); exit 1223 } [Console]::Error.WriteLine(('Elevation failed: ' + $_.Exception.Message)); exit 125 }"
set "A40_ELEVATION_RESULT=%ERRORLEVEL%"
if "%A40_ELEVATION_RESULT%"=="1223" (
    set "A40_KEEP_VISIBLE=1"
    set "A40_EXIT=2"
    goto :finish
)
if "%A40_ELEVATION_RESULT%"=="125" (
    echo Elevated launcher could not be started.
    set "A40_KEEP_VISIBLE=1"
    set "A40_EXIT=2"
    goto :finish
)
if not "%A40_ELEVATION_RESULT%"=="0" if not "%A40_ELEVATION_RESULT%"=="1" if not "%A40_ELEVATION_RESULT%"=="2" (
    echo Elevation request failed with code %A40_ELEVATION_RESULT%.
    set "A40_KEEP_VISIBLE=1"
    set "A40_EXIT=2"
    goto :finish
)
set "A40_EXIT=%A40_ELEVATION_RESULT%"
if "%A40_EXIT%"=="2" echo Elevated A40 collection failed with exit code 2.
goto :finish

:run_collector
if not exist "%A40_COLLECTOR%" (
    echo ERROR: Collector file was not found:
    echo "%A40_COLLECTOR%"
    goto :failed
)

if defined A40_OUTPUT (
    "%A40_PYTHON%" "%A40_COLLECTOR%" --output "%A40_OUTPUT%" %A40_OVERWRITE_ARG%
) else (
    "%A40_PYTHON%" "%A40_COLLECTOR%" %A40_OVERWRITE_ARG%
)
set "A40_EXIT=%ERRORLEVEL%"
goto :finish

:failed
set "A40_EXIT=2"

:finish
if "%A40_EXIT%"=="1" echo PARTIAL: A40 output is retained but incomplete. Review the report errors; exit code 1 is nonzero.
if not "%A40_EXIT%"=="0" echo A40 launcher exit code: %A40_EXIT%
if "%A40_EXIT%"=="0" echo A40 collection finished successfully.
echo.
if defined A40_ELEVATED pause
if not defined A40_ELEVATED if not defined A40_ELEVATION_REQUESTED pause
if defined A40_KEEP_VISIBLE pause
exit /b %A40_EXIT%
