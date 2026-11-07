@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "CUSTOS_LAUNCHER_OUTPUT_PROMPT=1"
set "A01_DIRECTORY=%~dp0RAM_Output"
for %%I in ("%~dp0..\..") do set "A01_PROJECT_ROOT=%%~fI"
set "A01_PYTHON=%A01_PROJECT_ROOT%\.venv\Scripts\python.exe"
set "A01_COLLECTOR=%~dp0collector.py"
set "A01_TOOL=%~dp0go-winpmem_amd64_1.0-rc2_signed.exe"
set "A01_WORKING_DIRECTORY=%CD%"
set "A01_INTERACTIVE=0"
if "%~1"=="" set "A01_INTERACTIVE=1"

if not exist "%A01_PYTHON%" (
    echo A01 project Python was not found:
    echo "%A01_PYTHON%"
    goto :failed
)
if not exist "%A01_COLLECTOR%" (
    echo A01 collector was not found:
    echo "%A01_COLLECTOR%"
    goto :failed
)
if not exist "%A01_TOOL%" (
    echo A01 WinPmem executable was not found:
    echo "%A01_TOOL%"
    goto :failed
)

"%A01_PYTHON%" -c "import sys; print('A01 collector Python: ' + str(sys.version_info.major) + '.' + str(sys.version_info.minor) + '.')"
if errorlevel 1 (
    echo A01 could not verify the project Python interpreter.
    goto :failed
)

set "A01_ARGUMENTS_FILE=%TEMP%\A01-arguments-%RANDOM%-%RANDOM%.txt"
set "A01_LOG_FILE=%TEMP%\RAM-output-%RANDOM%-%RANDOM%.txt"
"%A01_PYTHON%" -c "import base64,json,sys; print(base64.b64encode(json.dumps(sys.argv[1:],ensure_ascii=True).encode('utf-8')).decode('ascii'))" %* > "%A01_ARGUMENTS_FILE%"
if errorlevel 1 goto :argument_encoding_failed

powershell.exe -NoProfile -Command "$ErrorActionPreference = 'Stop'; try { $encoded = [IO.File]::ReadAllText($env:A01_ARGUMENTS_FILE).Trim(); $arguments = ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))); if ($null -eq $arguments) { $arguments = @() } elseif ($arguments -isnot [array]) { $arguments = @($arguments) }; $arguments = [string[]]$arguments; Remove-Item -LiteralPath $env:A01_ARGUMENTS_FILE -Force; $payloadData = @{ arguments = $arguments; python = $env:A01_PYTHON; collector = $env:A01_COLLECTOR; workingDirectory = $env:A01_WORKING_DIRECTORY; defaultOutput = $env:A01_DIRECTORY }; $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $payloadData -Compress))); $elevatedScript = '$ErrorActionPreference = ''Stop''; try { $data = ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''' + $payload + '''))); $arguments = [string[]]@($data.arguments); Set-Location -LiteralPath $data.workingDirectory; $hasOutput = @($arguments | Where-Object { $_ -eq ''--output-dir'' -or $_.StartsWith(''--output-dir='') }).Count -gt 0; if (-not $hasOutput) { $folder = (Read-Host ''Enter a custom output folder, or press Enter for the RAM_Output folder'').Trim().Trim([char]34); if ([string]::IsNullOrWhiteSpace($folder)) { $folder = $data.defaultOutput } else { [IO.Directory]::CreateDirectory($folder) | Out-Null }; $arguments += @(''--output-dir'', $folder) }; & $data.python $data.collector @arguments; exit $LASTEXITCODE } catch { [Console]::Error.WriteLine(($_ | Out-String)); exit 2 }'; $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($elevatedScript)); $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Invoke-Expression $elevatedScript; exit $LASTEXITCODE }; Write-Host 'Administrator approval is required. Requesting Windows UAC...'; $process = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-EncodedCommand', $encodedCommand) -Verb RunAs -Wait -PassThru; exit $process.ExitCode } catch { Write-Error ('Administrator approval or A01 startup failed: ' + $_.Exception.Message); exit 2 } finally { if (Test-Path -LiteralPath $env:A01_ARGUMENTS_FILE) { Remove-Item -LiteralPath $env:A01_ARGUMENTS_FILE -Force } }"
set "A01_EXIT=%ERRORLEVEL%"
if exist "%A01_ARGUMENTS_FILE%" del /q "%A01_ARGUMENTS_FILE%" >nul 2>&1
if exist "%A01_LOG_FILE%" del /q "%A01_LOG_FILE%" >nul 2>&1
if "%A01_EXIT%"=="0" echo A01 RAM acquisition completed. Review the image and collection-result JSON paths above.
if "%A01_EXIT%"=="1" echo A01 acquisition was partial or cancelled. Keep the output only as an incomplete capture.
if "%A01_EXIT%"=="2" echo A01 acquisition failed. Review the reported diagnostics.
if not "%A01_EXIT%"=="0" if not "%A01_EXIT%"=="1" if not "%A01_EXIT%"=="2" echo A01 collector exited with code %A01_EXIT%.
if "%A01_INTERACTIVE%"=="1" pause
exit /b %A01_EXIT%

:argument_encoding_failed
if exist "%A01_ARGUMENTS_FILE%" del /q "%A01_ARGUMENTS_FILE%" >nul 2>&1
echo A01 could not safely prepare arguments for elevation.

:failed
set "A01_EXIT=2"
if "%A01_INTERACTIVE%"=="1" pause
exit /b %A01_EXIT%
