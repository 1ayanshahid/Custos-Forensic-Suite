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

powershell.exe -NoProfile -Command "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $principal = New-Object Security.Principal.WindowsPrincipal($identity); if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 }; exit 1" >nul 2>&1
if not errorlevel 1 goto administrator

echo Administrator permission is required. Approve the Windows UAC prompt to continue.
set "CUSTOS_LAUNCHER=%~f0"
set "CUSTOS_ARGUMENTS=%*"
powershell.exe -NoProfile -Command "try { $launcher = $env:CUSTOS_LAUNCHER; $arguments = $env:CUSTOS_ARGUMENTS; $quote = [char]34; $command = '/d /s /c ' + $quote + 'set CUSTOS_ELEVATED_LAUNCH=1 & call ' + $quote + $launcher + $quote; if (-not [string]::IsNullOrWhiteSpace($arguments)) { $command += ' ' + $arguments }; $command += $quote; $process = Start-Process -FilePath $env:ComSpec -ArgumentList $command -Verb RunAs -Wait -PassThru; exit $process.ExitCode } catch { Write-Error ('Elevation was cancelled or failed: ' + $_.Exception.Message); exit 1223 }"
set "ELEVATION_EXIT=%ERRORLEVEL%"
if not "%ELEVATION_EXIT%"=="0" echo Collector did not run because administrator elevation was cancelled or failed.
if not "%ELEVATION_EXIT%"=="0" pause
exit /b %ELEVATION_EXIT%

:administrator
set "PYTHON=%~dp0..\..\.venv\Scripts\python.exe"
set "COLLECTOR=%~dp0collector.py"

if not exist "%PYTHON%" (
    echo Required project Python was not found:
    echo "%PYTHON%"
    echo Restore that interpreter or update this launcher to the approved Python path.
    goto failed
)

if not exist "%COLLECTOR%" (
    echo A06 collector is missing: "%COLLECTOR%"
    goto failed
)

"%PYTHON%" -c "import win32service, win32security" >nul 2>nul
if errorlevel 1 (
    echo Required pywin32 modules are unavailable in the existing project environment.
    echo Run setup_environment.bat from the project root to prepare the shared environment.
    echo Run setup_environment.bat from the project root to prepare the shared environment.
    goto failed
)

if "%~1"=="" goto prompt_output
"%PYTHON%" "%COLLECTOR%" %*
set "COLLECTOR_EXIT=%ERRORLEVEL%"
goto finish

:prompt_output
set "OUTPUT_PATH="
set /p "OUTPUT_PATH=Enter an output folder or JSON file path (leave blank for the Services_Output folder): "
if not defined OUTPUT_PATH set "OUTPUT_PATH=%~dp0Services_Output"
if "%OUTPUT_PATH%"=="%~dp0Services_Output" (
    set "A06_DEFAULT_OUTPUT=%OUTPUT_PATH%"
    powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference = 'Stop'; try { [IO.Directory]::CreateDirectory($env:A06_DEFAULT_OUTPUT) | Out-Null } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"
    if errorlevel 1 (
        echo Could not prepare the default output folder "%OUTPUT_PATH%".
        goto failed
    )
)
"%PYTHON%" "%COLLECTOR%" --output "%OUTPUT_PATH%"
set "COLLECTOR_EXIT=%ERRORLEVEL%"

:finish
if "%COLLECTOR_EXIT%"=="1" echo Collection completed with partial results; check the JSON errors and limitations.
if "%COLLECTOR_EXIT%"=="2" echo Collection failed.
echo A06 launcher exit code: %COLLECTOR_EXIT%
pause
exit /b %COLLECTOR_EXIT%

:failed
echo A06 launcher exit code: 2
pause
exit /b 2
