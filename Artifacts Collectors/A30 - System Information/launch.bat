@echo off
setlocal DisableDelayedExpansion
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
set "A30_SCRIPT=%~dp0collector.py"
set "A30_PYTHON=%~dp0..\..\.venv\Scripts\python.exe"
set "A30_RAW_ARGS=%*"
set "A30_EXIT=0"

if not exist "%A30_PYTHON%" (
    echo Required Python interpreter was not found:
    echo %A30_PYTHON%
    echo Restore the existing project virtual environment; this launcher does not install dependencies.
    set "A30_EXIT=2"
    goto finish
)

if not exist "%A30_SCRIPT%" (
    echo A30 collector was not found:
    echo %A30_SCRIPT%
    set "A30_EXIT=2"
    goto finish
)

"%SystemRoot%\System32\fltmc.exe" >nul 2>&1
if not errorlevel 1 goto run_collector
goto request_elevation

:run_collector
"%A30_PYTHON%" "%A30_SCRIPT%" %*
set "A30_EXIT=%ERRORLEVEL%"
goto finish

:request_elevation
echo Administrator permission is required. Approve the Windows UAC prompt to continue.
where powershell.exe >nul 2>&1
if errorlevel 1 (
    echo Windows PowerShell was not found. No collection was started.
    set "A30_EXIT=2"
    goto finish
)
powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand JABFAHIAcgBvAHIAQQBjAHQAaQBvAG4AUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAdABvAHAAJwAKAHQAcgB5ACAAewAKACAAIAAgACAAJABhAHIAZwB1AG0AZQBuAHQATABpAG4AZQAgAD0AIAAnACIAJwAgACsAIAAkAGUAbgB2ADoAQQAzADAAXwBTAEMAUgBJAFAAVAAgACsAIAAnACIAJwAKACAAIAAgACAAaQBmACAAKAAtAG4AbwB0ACAAWwBzAHQAcgBpAG4AZwBdADoAOgBJAHMATgB1AGwAbABPAHIARQBtAHAAdAB5ACgAJABlAG4AdgA6AEEAMwAwAF8AUgBBAFcAXwBBAFIARwBTACkAKQAgAHsACgAgACAAIAAgACAAIAAgACAAJABhAHIAZwB1AG0AZQBuAHQATABpAG4AZQAgACsAPQAgACcAIAAnACAAKwAgACQAZQBuAHYAOgBBADMAMABfAFIAQQBXAF8AQQBSAEcAUwAKACAAIAAgACAAfQAKACAAIAAgACAAJABwAHIAbwBjAGUAcwBzACAAPQAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEYAaQBsAGUAUABhAHQAaAAgACQAZQBuAHYAOgBBADMAMABfAFAAWQBUAEgATwBOACAALQBBAHIAZwB1AG0AZQBuAHQATABpAHMAdAAgACQAYQByAGcAdQBtAGUAbgB0AEwAaQBuAGUAIAAtAFYAZQByAGIAIABSAHUAbgBBAHMAIAAtAFcAYQBpAHQAIAAtAFAAYQBzAHMAVABoAHIAdQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAAKACAAIAAgACAAZQB4AGkAdAAgAFsAaQBuAHQAXQAkAHAAcgBvAGMAZQBzAHMALgBFAHgAaQB0AEMAbwBkAGUACgB9ACAAYwBhAHQAYwBoACAAewAKACAAIAAgACAAWwBDAG8AbgBzAG8AbABlAF0AOgA6AEUAcgByAG8AcgAuAFcAcgBpAHQAZQBMAGkAbgBlACgAJwBFAGwAZQB2AGEAdABpAG8AbgAgAHcAYQBzACAAYwBhAG4AYwBlAGwAbABlAGQAIABvAHIAIABmAGEAaQBsAGUAZAAuACAATgBvACAAYwBvAGwAbABlAGMAdABpAG8AbgAgAHcAYQBzACAAcwB0AGEAcgB0AGUAZAAuACcAKQAKACAAIAAgACAAZQB4AGkAdAAgADEAMgAyADMACgB9AA==
set "A30_EXIT=%ERRORLEVEL%"
if "%A30_EXIT%"=="1223" echo UAC elevation was cancelled or failed. No collection was started.

:finish
if "%A30_EXIT%"=="0" echo A30 collection completed successfully. Exit code: 0
if "%A30_EXIT%"=="1" echo A30 collection completed with partial results. Exit code: 1
if "%A30_EXIT%"=="2" echo A30 collection failed. Exit code: 2
if "%A30_EXIT%"=="1223" echo A30 collection was cancelled because UAC elevation was cancelled or failed. Exit code: 1223. No collection was started.
if "%~1"=="" pause
exit /b %A30_EXIT%
