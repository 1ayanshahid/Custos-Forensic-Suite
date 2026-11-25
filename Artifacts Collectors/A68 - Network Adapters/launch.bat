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
set "A68_PYTHON=%~dp0..\..\.venv\Scripts\python.exe"
set "A68_COLLECTOR=%~dp0collector.py"
set "A68_DIRECTORY=%~dp0Network Adapters_Output"
set "A68_PROMPT=Enter a custom save folder, or press Enter to save in the Network Adapters_Output folder."
set "A68_WORKING_DIRECTORY=%CD%"
set "A68_INTERACTIVE=0"
if "%~1"=="" set "A68_INTERACTIVE=1"

if not exist "%A68_PYTHON%" (
    echo A68 cannot start: the project Python interpreter was not found:
    echo "%A68_PYTHON%"
    echo Run setup_environment.bat from the project root to prepare the shared environment.
    goto :failed
)
if not exist "%A68_COLLECTOR%" (
    echo A68 cannot start: the network adapter collector was not found:
    echo "%A68_COLLECTOR%"
    goto :failed
)

powershell.exe -NoProfile -Command "try { $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 } } catch { exit 2 }" >nul 2>&1
if errorlevel 2 (
    echo A68 could not determine administrator status. No collection was started.
    goto :failed
)
if not errorlevel 1 goto :run_elevated

echo Requesting administrator approval through Windows UAC...
set "A68_ARGUMENTS_FILE=%TEMP%\A68-arguments-%RANDOM%-%RANDOM%.txt"
set "A68_LOG_FILE=%TEMP%\Network Adapters-output-%RANDOM%-%RANDOM%.txt"
"%A68_PYTHON%" -c "import base64,json,sys; print(base64.b64encode(json.dumps(sys.argv[1:],ensure_ascii=False).encode('utf-8')).decode('ascii'))" %* > "%A68_ARGUMENTS_FILE%"
if errorlevel 1 goto :argument_encoding_failed

powershell.exe -NoProfile -Command "$ErrorActionPreference = 'Stop'; try { $argumentFile = $env:A68_ARGUMENTS_FILE; $encodedArguments = [IO.File]::ReadAllText($argumentFile).Trim(); $arguments = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedArguments)) | ConvertFrom-Json; Remove-Item -LiteralPath $argumentFile -Force; $payloadData = @{ arguments = @($arguments); python = $env:A68_PYTHON; collector = $env:A68_COLLECTOR; defaultOutput = $env:A68_DIRECTORY; prompt = $env:A68_PROMPT; log = $env:A68_LOG_FILE; workingDirectory = $env:A68_WORKING_DIRECTORY }; $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $payloadData -Compress))); $elevatedScript = '$ErrorActionPreference = ''Stop''; $logPath = $null; try { $data = ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''' + $payload + '''))); $logPath = $data.log; $arguments = @($data.arguments); $hasOutput = @($arguments | Where-Object { $_ -eq ''--output-dir'' -or $_.StartsWith(''--output-dir='') }).Count -gt 0; if (-not $hasOutput) { $folder = Read-Host $data.prompt; if ([string]::IsNullOrWhiteSpace($folder)) { $folder = $data.defaultOutput; [IO.Directory]::CreateDirectory($folder) | Out-Null }; $arguments += @(''--output-dir'', $folder) }; Set-Location -LiteralPath $data.workingDirectory; $pythonArgs = @($data.collector) + $arguments; $output = & $data.python @pythonArgs 2>&1; $exitCode = $LASTEXITCODE; [IO.File]::WriteAllText($logPath, (($output | Out-String)), [Text.Encoding]::UTF8); exit $exitCode } catch { if ($logPath) { [IO.File]::WriteAllText($logPath, ($_ | Out-String), [Text.Encoding]::UTF8) }; exit 2 }'; $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($elevatedScript)); $process = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-EncodedCommand', $encodedCommand) -Verb RunAs -PassThru -Wait; if (Test-Path -LiteralPath $payloadData.log) { [Console]::Write([IO.File]::ReadAllText($payloadData.log)) } else { Write-Host 'A68 elevated process exited without producing its output log.'; exit 2 }; exit $process.ExitCode } catch { $nativeCode = $_.Exception.NativeErrorCode; if ($_.Exception.HResult -eq -2147023673 -or $nativeCode -eq 1223) { Write-Host 'UAC approval was cancelled. No collection was started.' } else { Write-Host ('A68 could not start elevated collection: ' + $_.Exception.Message + '. No collection was started.') }; exit 2 }"
set "A68_EXIT=%ERRORLEVEL%"
if exist "%A68_ARGUMENTS_FILE%" del /q "%A68_ARGUMENTS_FILE%" >nul 2>&1
if exist "%A68_LOG_FILE%" del /q "%A68_LOG_FILE%" >nul 2>&1
goto :report_result

:argument_encoding_failed
if exist "%A68_ARGUMENTS_FILE%" del /q "%A68_ARGUMENTS_FILE%" >nul 2>&1
echo A68 could not safely prepare arguments for elevation.
goto :failed

:run_elevated
set "A68_ARGUMENTS_FILE=%TEMP%\A68-arguments-%RANDOM%-%RANDOM%.txt"
"%A68_PYTHON%" -c "import base64,json,sys; print(base64.b64encode(json.dumps(sys.argv[1:],ensure_ascii=False).encode('utf-8')).decode('ascii'))" %* > "%A68_ARGUMENTS_FILE%"
if errorlevel 1 goto :argument_encoding_failed
powershell.exe -NoProfile -Command "$ErrorActionPreference = 'Stop'; try { $argumentFile = $env:A68_ARGUMENTS_FILE; $encoded = [IO.File]::ReadAllText($argumentFile).Trim(); $arguments = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded)) | ConvertFrom-Json; Remove-Item -LiteralPath $argumentFile -Force; $arguments = @($arguments); $hasOutput = @($arguments | Where-Object { $_ -eq '--output-dir' -or $_.StartsWith('--output-dir=') }).Count -gt 0; if (-not $hasOutput) { $folder = Read-Host $env:A68_PROMPT; if ([string]::IsNullOrWhiteSpace($folder)) { $folder = $env:A68_DIRECTORY; [IO.Directory]::CreateDirectory($folder) | Out-Null }; $arguments += @('--output-dir', $folder) }; Set-Location -LiteralPath $env:A68_WORKING_DIRECTORY; & $env:A68_PYTHON $env:A68_COLLECTOR @arguments; exit $LASTEXITCODE } catch { Write-Host ('A68 could not start collection: ' + $_.Exception.Message); exit 2 }"
set "A68_EXIT=%ERRORLEVEL%"
if exist "%A68_ARGUMENTS_FILE%" del /q "%A68_ARGUMENTS_FILE%" >nul 2>&1

:report_result
if "%A68_EXIT%"=="0" echo A68 network adapter collection completed successfully.
if "%A68_EXIT%"=="1" echo A68 completed with partial provider coverage. Review the output above.
if "%A68_EXIT%"=="2" echo A68 collection failed or elevation was cancelled. Review the message above.
if not "%A68_EXIT%"=="0" if not "%A68_EXIT%"=="1" if not "%A68_EXIT%"=="2" echo A68 collector exited with code %A68_EXIT%.
if "%A68_INTERACTIVE%"=="1" pause
exit /b %A68_EXIT%

:failed
set "A68_EXIT=2"
if "%A68_INTERACTIVE%"=="1" pause
exit /b %A68_EXIT%
