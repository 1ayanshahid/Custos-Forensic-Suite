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

set "A42_DIR=%~dp0"
set "A42_PYTHON=%~dp0..\..\.venv\Scripts\python.exe"
set "A42_COLLECTOR=%A42_DIR%collector.py"
set "A42_ELEVATED="
set "A42_OUTPUT="
set "A42_OVERWRITE_ARG="

if /i "%~1"=="--elevated" (
    set "A42_ELEVATED=1"
    goto :check_requirements
)

:parse_arguments
if "%~1"=="" goto :check_requirements
if /i "%~1"=="--output" (
    if "%~2"=="" (
        echo ERROR: --output requires a destination JSON file or existing directory.
        goto :failed
    )
    set "A42_OUTPUT=%~2"
    shift
    shift
    goto :parse_arguments
)
if /i "%~1"=="--overwrite" (
    set "A42_OVERWRITE_ARG=--overwrite"
    shift
    goto :parse_arguments
)
if /i "%~1"=="--help" (
    echo Usage: launch.bat [--output "C:\path\Logon Sessions.json"] [--overwrite]
    set "A42_HELP=1"
    set "A42_EXIT=0"
    goto :finish
)
echo ERROR: Unsupported launcher argument.
echo Usage: launch.bat [--output "C:\path\Logon Sessions.json"] [--overwrite]
goto :failed

:check_requirements
if not exist "%A42_PYTHON%" (
    echo ERROR: Required Python executable was not found:
    echo "%A42_PYTHON%"
    echo Run setup_environment.bat from the project root to prepare the shared environment.
    goto :failed
)

"%A42_PYTHON%" -c "import win32ts, win32security"
if errorlevel 1 (
    echo ERROR: Required pywin32 WTS or LSA modules are missing or unusable.
    echo Run setup_environment.bat from the project root to prepare the shared environment.
    echo Run setup_environment.bat from the project root to prepare the shared environment.
    goto :failed
)

"%SystemRoot%\System32\fltmc.exe" >nul 2>&1
if not errorlevel 1 goto :run_collector

if defined A42_ELEVATED (
    echo ERROR: The elevated launcher did not receive administrator access.
    goto :failed
)

echo Administrator access is requested for A42 WTS, LSA, and Security-log collection.
echo Approve the standard Windows UAC prompt to continue.
set "A42_LAUNCHER=%~f0"
set "A42_ELEVATION_REQUESTED=1"
powershell.exe -NoProfile -NonInteractive -Command ^
  "try { $q = [char]34; $a = '/d /c ' + $q + $q + $env:A42_LAUNCHER + $q + ' --elevated' + $q; $p = Start-Process -FilePath $env:ComSpec -ArgumentList $a -Verb RunAs -Wait -PassThru; if ($null -eq $p.ExitCode) { exit 125 }; exit $p.ExitCode } catch { if (($_.Exception.HResult -band 65535) -eq 1223) { [Console]::Error.WriteLine('UAC was cancelled. No collection was started.'); exit 1223 } [Console]::Error.WriteLine(('Elevation failed: ' + $_.Exception.Message)); exit 125 }"
set "A42_ELEVATION_RESULT=%ERRORLEVEL%"
if "%A42_ELEVATION_RESULT%"=="1223" (
    echo UAC was cancelled. No collection was started.
    set "A42_KEEP_VISIBLE=1"
    set "A42_EXIT=2"
    goto :finish
)
if "%A42_ELEVATION_RESULT%"=="125" (
    echo Elevated launcher could not be started.
    set "A42_KEEP_VISIBLE=1"
    set "A42_EXIT=2"
    goto :finish
)
if not "%A42_ELEVATION_RESULT%"=="0" if not "%A42_ELEVATION_RESULT%"=="1" if not "%A42_ELEVATION_RESULT%"=="2" (
    echo Elevation request failed with code %A42_ELEVATION_RESULT%.
    set "A42_KEEP_VISIBLE=1"
    set "A42_EXIT=2"
    goto :finish
)
set "A42_EXIT=%A42_ELEVATION_RESULT%"
goto :finish

:run_collector
if not exist "%A42_COLLECTOR%" (
    echo ERROR: Collector file was not found:
    echo "%A42_COLLECTOR%"
    goto :failed
)

if defined A42_OUTPUT (
    "%A42_PYTHON%" "%A42_COLLECTOR%" --output "%A42_OUTPUT%" %A42_OVERWRITE_ARG%
) else (
    "%A42_PYTHON%" "%A42_COLLECTOR%" %A42_OVERWRITE_ARG%
)
set "A42_EXIT=%ERRORLEVEL%"
goto :finish

:failed
set "A42_EXIT=2"

:finish
if "%A42_EXIT%"=="1" echo PARTIAL: A42 output is retained but incomplete. Review the report errors; exit code 1 is nonzero.
if not "%A42_EXIT%"=="0" echo A42 launcher exit code: %A42_EXIT%
if "%A42_EXIT%"=="0" if not defined A42_HELP echo A42 collection finished successfully.
echo.
if defined A42_ELEVATED pause
if not defined A42_ELEVATED if not defined A42_ELEVATION_REQUESTED pause
if defined A42_KEEP_VISIBLE pause
exit /b %A42_EXIT%
