@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Custos Artifact Collector
set "ARTIFACT_DIR=%~dp0"
for %%I in ("%ARTIFACT_DIR%..") do set "PROJECT_ROOT=%%~fI"
for %%I in ("%PROJECT_ROOT%\..") do set "SUITE_ROOT=%%~fI"
set "VENV_PYTHON=%SUITE_ROOT%\.venv\Scripts\python.exe"
set "DOTNET_ROOT=%SUITE_ROOT%\.dotnet"
set "DOTNET_ROOT_X64=%DOTNET_ROOT%"
set "DOTNET_MULTILEVEL_LOOKUP=0"
set "PATH=%DOTNET_ROOT%;%PATH%"
set "COLLECTOR=%ARTIFACT_DIR%collector.py"
set "CUSTOS_USERPROFILE=%USERPROFILE%"
if not exist "%COLLECTOR%" (
    echo ERROR: This artifact's collector.py was not found:
    echo "%COLLECTOR%"
    goto launcher_error
)
if not exist "%VENV_PYTHON%" (
    echo ERROR: The shared project environment is missing.
    echo Run "%SUITE_ROOT%\setup_environment.bat" first.
    goto launcher_error
)
if not exist "%DOTNET_ROOT%\dotnet.exe" (
    echo ERROR: The shared project .NET runtime is missing.
    echo Run "%SUITE_ROOT%\setup_environment.bat" first.
    goto launcher_error
)
set "CUSTOS_PROJECT_ROOT=%PROJECT_ROOT%"
set "CUSTOS_SUITE_ROOT=%SUITE_ROOT%"
set "CUSTOS_ARTIFACT_DIR=%ARTIFACT_DIR%"
set "CUSTOS_COLLECTOR=%COLLECTOR%"
set "CUSTOS_VENV_PYTHON=%VENV_PYTHON%"
set "CUSTOS_SELF=%~f0"
set "CUSTOS_ARG_COUNT=0"
:collect_arguments
if "%~1"=="" goto arguments_collected
set /a CUSTOS_ARG_COUNT+=1
set "CUSTOS_ARG_%CUSTOS_ARG_COUNT%=%~1"
shift
goto collect_arguments
:arguments_collected
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if(-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 1}"
if not errorlevel 1 goto elevated
echo Administrator approval is required. Requesting standard Windows UAC elevation...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; function Quote-WinArg([string]$value) { $builder=New-Object System.Text.StringBuilder; [void]$builder.Append([char]34); $slashes=0; foreach($ch in $value.ToCharArray()) { if($ch -eq [char]92) { $slashes++; continue }; if($ch -eq [char]34) { if($slashes) { [void]$builder.Append(('\' * (2*$slashes+1))) }; [void]$builder.Append([char]34); $slashes=0; continue }; if($slashes) { [void]$builder.Append(('\' * $slashes)); $slashes=0 }; [void]$builder.Append($ch) }; if($slashes) { [void]$builder.Append(('\' * (2*$slashes))) }; [void]$builder.Append([char]34); $builder.ToString() }; $argsList=New-Object 'System.Collections.Generic.List[string]'; for($i=1; $i -le [int]$env:CUSTOS_ARG_COUNT; $i++) { $argsList.Add([Environment]::GetEnvironmentVariable('CUSTOS_ARG_'+$i)) }; $argumentLine=(($argsList | ForEach-Object { Quote-WinArg $_ }) -join ' '); try { if($argumentLine) { $p=Start-Process -FilePath $env:CUSTOS_SELF -ArgumentList $argumentLine -Verb RunAs -Wait -PassThru -ErrorAction Stop } else { $p=Start-Process -FilePath $env:CUSTOS_SELF -Verb RunAs -Wait -PassThru -ErrorAction Stop }; exit $p.ExitCode } catch { if($_.Exception.NativeErrorCode -eq 1223) { Write-Host 'UAC approval was cancelled or denied. No collection was started.'; exit 1223 }; throw }"
set "ELEV_RESULT=%ERRORLEVEL%"
if not "%ELEV_RESULT%"=="0" (
    echo.
    echo Elevated run exited with code %ELEV_RESULT%.
    pause
)
exit /b %ELEV_RESULT%
:elevated
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; try { $artifactName=Split-Path -Leaf ($env:CUSTOS_ARTIFACT_DIR).TrimEnd([char]92); $code=$artifactName.Split('-')[0].Trim(); $displayName=$artifactName.Substring($artifactName.IndexOf(' - ')+3); if ($code -eq 'A08') {$displayName='Registry Hive'}; $default=[IO.Path]::GetFullPath((Join-Path $env:CUSTOS_ARTIFACT_DIR ($displayName + '_Output'))); Write-Host ('Custom output folder, or press Enter for the default: '+$default); $requested=Read-Host 'Output folder'; if ([string]::IsNullOrWhiteSpace($requested)) { $output=$default } else { if ($requested.Length -ge 2 -and $requested[0] -eq [char]34 -and $requested[$requested.Length-1] -eq [char]34) { $requested=$requested.Substring(1,$requested.Length-2) }; if ([IO.Path]::IsPathRooted($requested)) { $output=[IO.Path]::GetFullPath($requested) } else { $output=[IO.Path]::GetFullPath((Join-Path $env:CUSTOS_ARTIFACT_DIR $requested)) } }; Write-Host ('Resolved output folder: '+$output); $env:CUSTOS_OUTPUT_DIR=$output; $arguments=New-Object 'System.Collections.Generic.List[string]'; $arguments.Add($env:CUSTOS_COLLECTOR); for($i=1; $i -le [int]$env:CUSTOS_ARG_COUNT; $i++) { $argName='CUSTOS_ARG_'+$i; $arguments.Add([Environment]::GetEnvironmentVariable($argName)) }; function Quote-WinArg([string]$value) { $builder=New-Object System.Text.StringBuilder; [void]$builder.Append([char]34); $slashes=0; foreach($ch in $value.ToCharArray()) { if($ch -eq [char]92) { $slashes++; continue }; if($ch -eq [char]34) { if($slashes) { [void]$builder.Append(('\' * (2*$slashes+1))) }; [void]$builder.Append([char]34); $slashes=0; continue }; if($slashes) { [void]$builder.Append(('\' * $slashes)); $slashes=0 }; [void]$builder.Append($ch) }; if($slashes) { [void]$builder.Append(('\' * (2*$slashes))) }; [void]$builder.Append([char]34); $builder.ToString() }; $argumentLine=(($arguments | ForEach-Object { Quote-WinArg $_ }) -join ' '); $process=Start-Process -FilePath $env:CUSTOS_VENV_PYTHON -ArgumentList $argumentLine -WorkingDirectory $env:CUSTOS_ARTIFACT_DIR -Wait -PassThru -NoNewWindow -ErrorAction Stop; Write-Host ('Collector exit code: '+$process.ExitCode); exit $process.ExitCode } catch { Write-Error ('Launcher failed: '+$_.Exception.Message); exit 1 }"
set "COLLECTOR_RESULT=%ERRORLEVEL%"
pause
exit /b %COLLECTOR_RESULT%
:launcher_error
echo.
pause
exit /b 1
