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
set "RAWCOPY=%~dp0RawCopy64.exe"

powershell.exe -NoProfile -Command "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $principal = New-Object Security.Principal.WindowsPrincipal($identity); if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 }; exit 1" >nul 2>&1
if not errorlevel 1 goto administrator

echo Administrator permission is required. Approve the Windows UAC prompt to continue.
set "CUSTOS_LAUNCHER=%~f0"
set "CUSTOS_ARGUMENTS=%*"
powershell.exe -NoProfile -Command "try { $launcher = $env:CUSTOS_LAUNCHER; $arguments = $env:CUSTOS_ARGUMENTS; $quote = [char]34; $command = '/d /s /c ' + $quote + 'set CUSTOS_ELEVATED_LAUNCH=1 & call ' + $quote + $launcher + $quote; if (-not [string]::IsNullOrWhiteSpace($arguments)) { $command += ' ' + $arguments }; $command += $quote; $process = Start-Process -FilePath $env:ComSpec -ArgumentList $command -Verb RunAs -Wait -PassThru; exit $process.ExitCode } catch { Write-Error ('Elevation was cancelled or failed: ' + $_.Exception.Message); exit 1223 }"
set "ELEVATION_EXIT=%ERRORLEVEL%"
if not "%ELEVATION_EXIT%"=="0" echo Acquisition did not run because administrator elevation was cancelled or failed.
if not "%ELEVATION_EXIT%"=="0" pause
if not "%ELEVATION_EXIT%"=="0" exit /b 2
exit /b 0

:administrator
if not exist "%PYTHON%" (
    echo Required project Python was not found:
    echo "%PYTHON%"
    pause
    exit /b 2
)
if not exist "%COLLECTOR%" (
    echo A17 collector is missing: "%COLLECTOR%"
    pause
    exit /b 2
)
if not exist "%RAWCOPY%" (
    echo RawCopy64.exe is required but was not found:
    echo "%RAWCOPY%"
    echo Obtain it manually from https://github.com/jschicht/RawCopy
    echo Verify the source and place RawCopy64.exe in this A17 folder.
    pause
    exit /b 2
)

if "%~1"=="" goto prompt_output
"%PYTHON%" "%COLLECTOR%" --tool "%RAWCOPY%" %*
set "RESULT=%ERRORLEVEL%"
goto collection_finished

:prompt_output
set "OUTPUT_DIR="
set /p "OUTPUT_DIR=Enter a custom output folder, or press Enter for the MFT_Output folder [%~dp0MFT_Output]: "
if not defined OUTPUT_DIR set "OUTPUT_DIR=%~dp0MFT_Output"
set "A17_OUTPUT_ROOT=%OUTPUT_DIR%"
powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference = 'Stop'; try { [IO.Directory]::CreateDirectory($env:A17_OUTPUT_ROOT) | Out-Null } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 2 }"
if errorlevel 1 (
    echo Could not prepare the output folder "%OUTPUT_DIR%".
    goto output_folder_failed
)
set "A17_PYTHON=%PYTHON%"
set "A17_COLLECTOR=%COLLECTOR%"
set "A17_TOOL=%RAWCOPY%"
powershell.exe -NoProfile -NonInteractive -Command "$volumes = @(); $enumerationFailed = $false; try { $drives = [IO.DriveInfo]::GetDrives() } catch { [Console]::Error.WriteLine(('Could not enumerate local drives: ' + $_.Exception.Message)); exit 2 }; foreach ($drive in $drives) { try { if ($drive.IsReady -and ($drive.DriveType -eq [IO.DriveType]::Fixed -or $drive.DriveType -eq [IO.DriveType]::Removable) -and $drive.DriveFormat -eq 'NTFS') { $volumes += $drive } } catch { [Console]::Error.WriteLine(('Could not inspect drive ' + $drive.Name + ': ' + $_.Exception.Message)); $enumerationFailed = $true } }; if ($volumes.Count -eq 0) { Write-Error 'No ready local NTFS drive-letter volumes were found.'; exit 2 }; $overallExit = if ($enumerationFailed) { 1 } else { 0 }; foreach ($volume in $volumes) { $letter = $volume.Name.Substring(0, 1); $volumeOutput = Join-Path $env:A17_OUTPUT_ROOT $letter; try { [IO.Directory]::CreateDirectory($volumeOutput) | Out-Null } catch { [Console]::Error.WriteLine(('Could not create output folder for ' + $letter + ': ' + $_.Exception.Message)); $overallExit = 2; continue }; Write-Host ('Collecting $MFT from ' + $letter + ': into ' + $volumeOutput); $volumeExit = 2; try { & $env:A17_PYTHON $env:A17_COLLECTOR --source ($letter + ':') --output-dir $volumeOutput --tool $env:A17_TOOL; $volumeExit = $LASTEXITCODE } catch { [Console]::Error.WriteLine(('Could not run the collector for ' + $letter + ': ' + $_.Exception.Message)); $overallExit = 2; continue }; if ($volumeExit -eq 1) { if ($overallExit -eq 0) { $overallExit = 1 } } elseif ($volumeExit -ne 0) { $overallExit = 2 } }; exit $overallExit"
set "RESULT=%ERRORLEVEL%"
goto collection_finished

:output_folder_failed
set "RESULT=2"
echo A17 launcher exit code: %RESULT%
pause
exit /b %RESULT%

:collection_finished
if "%RESULT%"=="0" echo A17 completed for all discovered local NTFS volumes.
if "%RESULT%"=="1" echo A17 completed with partial coverage. Review each volume's collection-result JSON.
if "%RESULT%"=="2" echo A17 failed or one or more volumes could not be collected. Review the errors and per-volume result JSON files.
if "%RESULT%"=="1" echo Acquisition is partial; inspect the collection-result JSON.
if "%RESULT%"=="2" echo Acquisition failed; check the error output above.
echo A17 launcher exit code: %RESULT%
pause
exit /b %RESULT%
