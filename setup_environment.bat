@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Custos Forensic Suite Environment Setup

set "PROJECT_ROOT=%~dp0"
for %%I in ("%PROJECT_ROOT%.") do set "PROJECT_ROOT=%%~fI"
set "VENV_DIR=%PROJECT_ROOT%\.venv"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "REQUIREMENTS_FILE=%PROJECT_ROOT%\requirements-dev-lock.txt"
set "RUNTIME_DIR=%PROJECT_ROOT%\.custos-runtime"
set "TOOLS_DIR=%PROJECT_ROOT%\_tools"
set "DOTNET_DIR=%PROJECT_ROOT%\.dotnet"
set "LOG_FILE=%PROJECT_ROOT%\setup_environment.log"
set "PYTHON_EXE="
set "SETUP_BLOCKED=0"

>"%LOG_FILE%" echo Custos Forensic Suite setup log - %DATE% %TIME%
call :log "Project root resolved relative to setup_environment.bat."

set "INSTALL_TYPE="
set "WINDOWS_BUILD="
set "OS_ARCH=%PROCESSOR_ARCHITEW6432%"
if not defined OS_ARCH set "OS_ARCH=%PROCESSOR_ARCHITECTURE%"
for /f "tokens=3" %%V in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v InstallationType 2^>nul ^| findstr /i "InstallationType"') do set "INSTALL_TYPE=%%V"
for /f "tokens=3" %%V in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber 2^>nul ^| findstr /i "CurrentBuildNumber"') do set "WINDOWS_BUILD=%%V"
if /i not "%INSTALL_TYPE%"=="Client" (
    call :log "ERROR: This setup supports Windows 10/11 client systems only."
    goto failed
)
if /i not "%OS_ARCH%"=="AMD64" (
    call :log "ERROR: This setup requires 64-bit AMD64 Windows."
    goto failed
)
if not defined WINDOWS_BUILD (
    call :log "ERROR: Could not determine the Windows build from the system registry."
    goto failed
)
if %WINDOWS_BUILD% LSS 17763 (
    call :log "ERROR: Windows 10 build 17763 or later is required."
    goto failed
)
for %%T in (wevtutil.exe schtasks.exe netsh.exe reg.exe) do (
    if not exist "%SystemRoot%\System32\%%T" (
        call :log "ERROR: Required Windows tool is missing: %SystemRoot%\System32\%%T"
        goto failed
    )
)

if not exist "%REQUIREMENTS_FILE%" (
    call :log "ERROR: requirements-dev-lock.txt is missing."
    goto failed
)

call :find_python
if not defined PYTHON_EXE goto install_python
goto python_found

:install_python
call :log "64-bit Python 3.12 was not found. Downloading the official Python 3.12.10 x64 installer."
set "PYTHON_INSTALL_LOG=%TEMP%\custos-python-installer-%RANDOM%-%RANDOM%.log"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; $file=Join-Path $env:TEMP ('custos-python-3.12.10-' + [guid]::NewGuid().ToString('N') + '.exe'); try { for ($i=1; $i -le 3; $i++) { try { Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe' -OutFile $file -UseBasicParsing -TimeoutSec 60; break } catch { if ($i -eq 3) { throw }; Start-Sleep -Seconds $i } }; $sig=Get-AuthenticodeSignature -FilePath $file; if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Python Software Foundation') { throw 'Python installer signature is invalid or is not issued to the Python Software Foundation.' }; $target=Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312'; $args='/quiet InstallAllUsers=0 PrependPath=0 Include_launcher=1 Include_test=0 TargetDir=' + [char]34 + $target + [char]34; $proc=Start-Process -FilePath $file -ArgumentList $args -Wait -PassThru; if ($proc.ExitCode -ne 0) { throw ('Python installer exited with code ' + $proc.ExitCode) }; $exe=Join-Path $target 'python.exe'; if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Python installer completed but python.exe is missing.' }; [Console]::WriteLine($exe) } finally { if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force } }" >"%PYTHON_INSTALL_LOG%" 2>&1
if errorlevel 1 (
    type "%PYTHON_INSTALL_LOG%"
    type "%PYTHON_INSTALL_LOG%" >>"%LOG_FILE%"
    del "%PYTHON_INSTALL_LOG%" >nul 2>nul
    call :log "ERROR: Python could not be located or installed."
    goto failed
)
for /f "usebackq delims=" %%P in ("%PYTHON_INSTALL_LOG%") do set "PYTHON_EXE=%%P"
del "%PYTHON_INSTALL_LOG%" >nul 2>nul
if not exist "%PYTHON_EXE%" (
    call :log "ERROR: The selected Python executable does not exist: %PYTHON_EXE%"
    goto failed
)

:python_found
"%PYTHON_EXE%" -c "import struct,sys; print('Selected Python: ' + sys.version.split()[0] + ' (' + str(struct.calcsize('P')*8) + '-bit)'); raise SystemExit(0 if sys.version_info[:2] == (3,12) and struct.calcsize('P')*8 == 64 else 1)"
if errorlevel 1 (
    call :log "ERROR: Custos requires 64-bit Python 3.12."
    goto failed
)

if exist "%VENV_DIR%\" goto validate_venv
goto create_venv

:validate_venv
if not exist "%VENV_PYTHON%" goto replace_venv
"%VENV_PYTHON%" -c "import os,struct,sys; expected=os.path.normcase(os.path.abspath(sys.argv[1])); actual=os.path.normcase(os.path.abspath(sys.prefix)); raise SystemExit(0 if sys.version_info[:2] == (3,12) and struct.calcsize('P')*8 == 64 and actual == expected else 1)" "%VENV_DIR%" >nul 2>nul
if errorlevel 1 goto replace_venv
call :log "Reusing the valid project .venv."
goto install_dependencies

:replace_venv
call :log "The existing .venv is broken, moved, or incompatible."
set "REPLACE_VENV="
set /p "REPLACE_VENV=Type Y to preserve it under a backup name and create a fresh .venv, or any other key to stop: "
if /I not "%REPLACE_VENV%"=="Y" (
    call :log "Setup stopped. The existing .venv was left untouched."
    goto failed
)
move "%VENV_DIR%" "%PROJECT_ROOT%\.venv.backup-%RANDOM%-%RANDOM%" >nul
if errorlevel 1 (
    call :log "ERROR: Could not preserve the existing .venv as a backup."
    goto failed
)

:create_venv
call :log "Creating .venv with the selected Python interpreter."
"%PYTHON_EXE%" -m venv "%VENV_DIR%"
if errorlevel 1 (
    call :log "ERROR: Python could not create .venv. The partial environment, if any, was preserved."
    goto failed
)
if not exist "%VENV_PYTHON%" (
    call :log "ERROR: .venv creation returned success but Scripts\python.exe is missing."
    goto failed
)

:install_dependencies
"%VENV_PYTHON%" -m pip --version >nul 2>nul
if errorlevel 1 (
    call :log "Bootstrapping pip in .venv."
    "%VENV_PYTHON%" -m ensurepip --upgrade
    if errorlevel 1 (
        call :log "ERROR: pip could not be bootstrapped."
        goto failed
    )
)

rem ------------------------------------------------------------------
rem Network hardening for pip.
rem
rem unicodecsv==0.14.1 ships only as a source tarball, so pip must build
rem it. That triggers an isolated build-environment subprocess which
rem downloads setuptools from files.pythonhosted.org. If that download
rem exceeds pip's default 15s read timeout, the inner subprocess dies
rem with ReadTimeoutError and the whole install aborts.
rem
rem PIP_DEFAULT_TIMEOUT / PIP_RETRIES are environment variables, so they
rem are inherited by the inner build-dependency subprocess - unlike
rem --timeout / --retries which only affect the outer command. We set
rem both, belt-and-braces, then pre-install build tooling so a dead or
rem very slow connection fails fast (and warms pip's HTTP cache) before
rem the full pinned install runs.
rem ------------------------------------------------------------------
set "PIP_DEFAULT_TIMEOUT=120"
set "PIP_RETRIES=10"

call :log "Pre-installing build tooling (setuptools/wheel) with extended network timeout."
"%VENV_PYTHON%" -m pip install --disable-pip-version-check --timeout 120 --retries 10 "setuptools>=40.8.0" wheel
if errorlevel 1 (
    call :log "ERROR: Could not pre-install build tooling. Check the network and pip output."
    goto failed
)

call :log "Installing pinned dependencies from requirements-dev-lock.txt."
"%VENV_PYTHON%" -m pip install --disable-pip-version-check --timeout 120 --retries 10 --requirement "%REQUIREMENTS_FILE%"
if errorlevel 1 (
    call :log "ERROR: Dependency installation failed. Check the network and pip output."
    goto failed
)

call :log "Running pip check."
"%VENV_PYTHON%" -m pip check
if errorlevel 1 (
    call :log "ERROR: pip check reported missing or incompatible dependencies."
    goto failed
)

call :log "Checking locked package and collector dependency imports."
"%VENV_PYTHON%" -c "import importlib.metadata, Registry, colorama, iniconfig, packaging, pefile, pluggy, psutil, pygments, pytest, unicodecsv, win32api, win32net, win32security, win32service, win32ts, win32wnet; assert importlib.metadata.version('enum-compat') == '0.0.3'; print('Required dependency imports succeeded.')"
if errorlevel 1 (
    call :log "ERROR: A required dependency import failed."
    goto failed
)

set "CUSTOS_PROJECT_ROOT=%PROJECT_ROOT%"
set "RUNTIME_LOG=%TEMP%\custos-runtime-%RANDOM%-%RANDOM%.log"
call :log "Preparing the project-local .NET 10.0.14 x64 runtime."
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; $ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; $root=$env:CUSTOS_PROJECT_ROOT; $version='10.0.14'; $target=Join-Path $root '.dotnet'; $expected='A176095F1DB69B42C81ACC60940744078D6BF2D2AC643E418342AA9C81889F4BD13E42F4621B131F9E77E4BC781AD46E375956219DF9A4F979031D2A5A8D93CD'; $stage=Join-Path $root ('.dotnet.stage-'+[guid]::NewGuid().ToString('N')); $zip=Join-Path $env:TEMP ('custos-dotnet-'+[guid]::NewGuid().ToString('N')+'.zip'); function Test-Runtime([string]$path) { $runtime=Join-Path $path ('shared\Microsoft.NETCore.App\'+$version); if(-not (Test-Path -LiteralPath (Join-Path $path 'dotnet.exe') -PathType Leaf) -or -not (Test-Path -LiteralPath $runtime -PathType Container)) { return $false }; $env:DOTNET_ROOT=$path; $env:DOTNET_ROOT_X64=$path; $env:DOTNET_MULTILEVEL_LOOKUP='0'; $list=& (Join-Path $path 'dotnet.exe') --list-runtimes 2>&1; return ($LASTEXITCODE -eq 0 -and (($list -join \"`n\") -match [regex]::Escape('Microsoft.NETCore.App '+$version))) }; try { if(Test-Runtime $target) { Write-Output 'Reusing verified project-local .NET runtime 10.0.14 x64.' } else { $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($root)); if($drive.AvailableFreeSpace -lt 250MB) { throw 'Insufficient free space for the .NET runtime and tool packages (need at least 250 MB).' }; for($i=1;$i -le 3;$i++){try{Invoke-WebRequest -Uri 'https://builds.dotnet.microsoft.com/dotnet/Runtime/10.0.14/dotnet-runtime-10.0.14-win-x64.zip' -OutFile $zip -UseBasicParsing -TimeoutSec 120;break}catch{if($i -eq 3){throw};Start-Sleep -Seconds $i}}; $hash=(Get-FileHash -LiteralPath $zip -Algorithm SHA512).Hash; if($hash -ne $expected){throw 'The .NET runtime ZIP SHA-512 does not match the official .NET 10.0.14 release metadata.'}; New-Item -ItemType Directory -Path $stage | Out-Null; [IO.Compression.ZipFile]::ExtractToDirectory($zip,$stage); if(-not (Test-Runtime $stage)){throw 'The extracted .NET runtime did not report Microsoft.NETCore.App 10.0.14.'}; if(Test-Path -LiteralPath $target){$backup=Join-Path $root ('.dotnet.backup-'+[guid]::NewGuid().ToString('N')); Move-Item -LiteralPath $target -Destination $backup; Write-Output ('Preserved previous .dotnet at '+$backup)}; Move-Item -LiteralPath $stage -Destination $target; if(-not (Test-Runtime $target)){throw 'Installed project-local .NET runtime failed its post-install check.'}; Write-Output 'Installed verified project-local .NET runtime 10.0.14 x64.' } } finally { if(Test-Path -LiteralPath $zip){Remove-Item -LiteralPath $zip -Force}; if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Recurse -Force} }" >"%RUNTIME_LOG%" 2>&1
set "RUNTIME_EXIT=%ERRORLEVEL%"
if exist "%RUNTIME_LOG%" (
    type "%RUNTIME_LOG%"
    type "%RUNTIME_LOG%" >>"%LOG_FILE%"
    del "%RUNTIME_LOG%" >nul 2>nul
)
if not "%RUNTIME_EXIT%"=="0" (
    call :log "ERROR: The project-local .NET runtime could not be verified or installed."
    goto failed
)

set "TOOL_LOG=%TEMP%\custos-tools-%RANDOM%-%RANDOM%.log"
call :log "Preparing fixed-version publisher tools and checking safe help output."
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; $ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; $root=$env:CUSTOS_PROJECT_ROOT; $tools=Join-Path $root '_tools'; New-Item -ItemType Directory -Force -Path $tools | Out-Null; $env:DOTNET_ROOT=Join-Path $root '.dotnet'; $env:DOTNET_ROOT_X64=$env:DOTNET_ROOT; $env:DOTNET_MULTILEVEL_LOOKUP='0'; $env:PATH=$env:DOTNET_ROOT+';'+$env:PATH; $specs=@(@{Name='PECmd';Version='2026.10.3';Exe='PECmd.exe';Files=@('PECmd.exe','PECmd.dll','PECmd.runtimeconfig.json');Artifacts=@('A11 - Prefetch Files');Flags=@('-d','--csv','--csvf','-q')},@{Name='AppCompatCacheParser';Version='2026.10.1';Exe='AppCompatCacheParser.exe';Files=@('AppCompatCacheParser.exe','AppCompatCacheParser.dll','AppCompatCacheParser.runtimeconfig.json');Artifacts=@('A12 - Shimcache and AppCompatCache');Flags=@('-f','--csv','-t')},@{Name='JLECmd';Version='2026.10.6';Exe='JLECmd.exe';Files=@('JLECmd.exe','JLECmd.dll','JLECmd.runtimeconfig.json');Artifacts=@('A15 - Jump Lists');Flags=@('-d','--csv','-q')},@{Name='LECmd';Version='2026.10.4';Exe='LECmd.exe';Files=@('LECmd.exe','LECmd.dll','LECmd.runtimeconfig.json');Artifacts=@('A19 - LNK Files');Flags=@('-d','--csv','--csvf','-q')},@{Name='RECmd';Version='2026.10.3';Exe='RECmd\\RECmd.exe';Files=@('RECmd\\RECmd.exe','RECmd\\RECmd.dll','RECmd\\RECmd.runtimeconfig.json','RECmd\\BatchExamples\\UserActivity.reb');Artifacts=@('A32 - UserAssist','A34 - RecentDocs','A35 - OpenSaveMRU');Flags=@('-d','--bn','--csv','--nl')},@{Name='SBECmd';Version='2026.10.3';Exe='SBECmd.exe';Files=@('SBECmd.exe','SBECmd.dll','SBECmd.runtimeconfig.json');Artifacts=@('A33 - ShellBags');Flags=@('-d','--csv','--nl')},@{Name='SrumECmd';Version='2026.10.1';Exe='SrumECmd.exe';Files=@('SrumECmd.exe','SrumECmd.dll','SrumECmd.runtimeconfig.json');Artifacts=@('A16 - SRUM Database');Flags=@('-f','-r','--csv')}); $states=@{}; foreach($s in $specs){foreach($a in $s.Artifacts){$states[$a]=$false}}; $stageRoot=Join-Path $tools ('.custos-stage-'+[guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $stageRoot | Out-Null; function Test-Tool($spec,[string]$dir){foreach($rel in $spec.Files){if(-not (Test-Path -LiteralPath (Join-Path $dir $rel) -PathType Leaf)){throw ('Missing required publisher file: '+$rel)}}; $exe=Join-Path $dir $spec.Exe; $product=[Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion; if(-not $product.StartsWith($spec.Version+'+',[StringComparison]::Ordinal)){throw ('Expected '+$spec.Version+' but found '+$product)}; $bytes=[IO.File]::ReadAllBytes($exe); if($bytes.Length -lt 64){throw 'Executable is too short to be a valid PE file'}; $pe=[BitConverter]::ToInt32($bytes,0x3c); if($pe -lt 0 -or $pe+6 -gt $bytes.Length -or $bytes[$pe] -ne 0x50 -or $bytes[$pe+1] -ne 0x45 -or [BitConverter]::ToUInt16($bytes,$pe+4) -ne 0x8664){throw 'Tool executable is not a valid Windows x64 PE'}; $runtime=Get-ChildItem -LiteralPath (Split-Path -Parent $exe) -File -Filter '*.runtimeconfig.json' | Select-Object -First 1; if(-not $runtime -or (Get-Content -Raw -LiteralPath $runtime.FullName | ConvertFrom-Json).runtimeOptions.tfm -ne 'net10.0'){throw 'Tool runtimeconfig is not a .NET 10 build'}; $pes=Get-ChildItem -LiteralPath $dir -Recurse -File | Where-Object {$_.Extension -in '.exe','.dll'}; if(-not $pes){throw 'No signed tool binaries found'}; foreach($p in $pes){$sig=Get-AuthenticodeSignature -FilePath $p.FullName; if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'ZimTech LLC'){throw ('Publisher signature validation failed: '+$p.FullName+' ('+$sig.Status+')')}}; $help=& $exe '-?' 2>&1; $code=$LASTEXITCODE; $text=$help -join \"`n\"; if($code -ne 0){throw ('Safe -? help check exited with '+$code)}; foreach($flag in $spec.Flags){if($text -notmatch [regex]::Escape($flag)){throw ('The '+$spec.Name+' help output does not document required flag '+$flag)}}; return $product }; try { foreach($s in $specs){$target=Join-Path $tools $s.Name; $valid=$false; if(Test-Path -LiteralPath $target -PathType Container){try{$product=Test-Tool $s $target;$valid=$true;Write-Output ($s.Name+' '+$product+' already present, Authenticode verified, and help flags checked.')}catch{Write-Output ($s.Name+' existing copy will be preserved and replaced: '+$_.Exception.Message)}}; if(-not $valid){$zip=Join-Path $stageRoot ($s.Name+'.zip');$dest=Join-Path $stageRoot $s.Name;$url='https://download.ericzimmermanstools.com/net/'+$s.Name+'.zip';for($i=1;$i -le 3;$i++){try{Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -TimeoutSec 120;break}catch{if($i -eq 3){throw ('Download failed for '+$s.Name+': '+$_.Exception.Message)};Start-Sleep -Seconds $i}}; $archive=[IO.Compression.ZipFile]::OpenRead($zip);try{foreach($entry in $archive.Entries){$path=[IO.Path]::GetFullPath((Join-Path $dest $entry.FullName));$prefix=[IO.Path]::GetFullPath($dest)+[IO.Path]::DirectorySeparatorChar;if(-not $path.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw ('Unsafe path in '+$s.Name+' archive: '+$entry.FullName)}}}finally{$archive.Dispose()}; [IO.Compression.ZipFile]::ExtractToDirectory($zip,$dest); $product=Test-Tool $s $dest; if(Test-Path -LiteralPath $target){$backup=Join-Path $tools ($s.Name+'.backup-'+[guid]::NewGuid().ToString('N'));Move-Item -LiteralPath $target -Destination $backup;Write-Output ('Preserved previous '+$s.Name+' at '+$backup)};Move-Item -LiteralPath $dest -Destination $target;$product=Test-Tool $s $target;Write-Output ('Installed '+$s.Name+' '+$product+'; signed publisher files and required command flags verified.')}; foreach($a in $s.Artifacts){$states[$a]=$true}}; foreach($a in ($states.Keys | Sort-Object)){if($states[$a]){Write-Output ('READY: '+$a+' (verified external tool installed)')}else{Write-Output ('BLOCKED: '+$a+' (external tool unavailable)')}}; Write-Output 'Tool ZIPs are downloaded only from the official publisher HTTPS host at fixed release endpoints; no publisher ZIP checksum is published. Extracted executables and DLLs are checked for valid ZimTech LLC Authenticode signatures and exact product versions.'; if(@($states.Values | Where-Object {-not $_}).Count -gt 0){exit 1} } finally {if(Test-Path -LiteralPath $stageRoot){Remove-Item -LiteralPath $stageRoot -Recurse -Force}} " >"%TOOL_LOG%" 2>&1
set "TOOL_EXIT=%ERRORLEVEL%"
if exist "%TOOL_LOG%" (
    type "%TOOL_LOG%"
    type "%TOOL_LOG%" >>"%LOG_FILE%"
    del "%TOOL_LOG%" >nul 2>nul
)
if not "%TOOL_EXIT%"=="0" set "SETUP_BLOCKED=1"

call :log "Checking collector source syntax without running acquisition."
set "SYNTAX_LOG=%TEMP%\custos-syntax-%RANDOM%-%RANDOM%.log"
"%VENV_PYTHON%" -c "import ast,pathlib,sys; root=pathlib.Path(sys.argv[1]); excluded={'.venv','venv','evidence','output & validation','__pycache__'}; files=sorted(p for p in root.rglob('collector.py') if (p.parent/'launch.bat').is_file() and any(p.parent.glob('*_Guide.md')) and not any(part.casefold() in excluded for part in p.relative_to(root).parts)); [ast.parse(p.read_text(encoding='utf-8-sig'), filename=str(p)) for p in files]; print('Parsed ' + str(len(files)) + ' collector entry points without running acquisition.')" "%PROJECT_ROOT%" >"%SYNTAX_LOG%" 2>&1
set "SYNTAX_EXIT=%ERRORLEVEL%"
if exist "%SYNTAX_LOG%" (
    type "%SYNTAX_LOG%"
    type "%SYNTAX_LOG%" >>"%LOG_FILE%"
    del "%SYNTAX_LOG%" >nul 2>nul
)
if not "%SYNTAX_EXIT%"=="0" (
    call :log "BLOCKED: One or more collector entry points contain syntax errors."
    set "SETUP_BLOCKED=1"
)

set "WINDOWS_LOG=%TEMP%\custos-windows-%RANDOM%-%RANDOM%.log"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$root=$env:CUSTOS_PROJECT_ROOT; $blocked=0; $checks=@(@{Artifact='A08 - Registry Hives';Commands=@('reg.exe','powershell.exe');Cmdlets=@('Get-CimInstance');Probe='Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Select-Object -First 1 | Out-Null'},@{Artifact='A76 - Windows Security Log';Commands=@('wevtutil.exe')},@{Artifact='A09 - Windows Event Logs';Commands=@('wevtutil.exe')},@{Artifact='A28 - RDP History from Events and Server Context';Commands=@('wevtutil.exe')},@{Artifact='A77 - Windows System Log';Commands=@('wevtutil.exe')},@{Artifact='A78 - Windows Application Log';Commands=@('wevtutil.exe')},@{Artifact='A81 - Bluetooth Device Metadata';Commands=@('powershell.exe','reg.exe');Cmdlets=@('Get-PnpDevice');Module='PnpDevice'},@{Artifact='A87 - SMB Sessions and Open Network Files';Commands=@('powershell.exe','net.exe');Cmdlets=@('Get-SmbSession','Get-SmbOpenFile');Module='SmbShare'},@{Artifact='A93 - Firewall Rules and Profiles';Commands=@('powershell.exe');Cmdlets=@('Get-NetFirewallRule');Module='NetSecurity'},@{Artifact='A61 - Volume Shadow Copies';Commands=@('powershell.exe')},@{Artifact='A62 - Restore Points';Commands=@('powershell.exe')},@{Artifact='A85 - Clipboard Content and Metadata';Commands=@('powershell.exe')},@{Artifact='A51 - Network Shares';Commands=@('powershell.exe')},@{Artifact='A95 - Historical Network Profiles';Commands=@('powershell.exe')},@{Artifact='A98 - OpenSSH Configuration Metadata';Commands=@('powershell.exe')},@{Artifact='A01 - RAM';Files=@('go-winpmem_amd64_1.0-rc2_signed.exe')},@{Artifact='A17 - MFT';Files=@('RawCopy64.exe')},@{Artifact='A83 - Handle Inventory';Files=@('Sysinternals Handle\handle64.exe')}); foreach($c in $checks){$candidatePaths=@((Join-Path $root ($c.Artifact+'\collector.py')),(Join-Path $root ('artifacts\'+$c.Artifact+'\collector.py')));foreach($owner in Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue){$candidatePaths+=Join-Path $owner.FullName ($c.Artifact+'\collector.py');$candidatePaths+=Join-Path $owner.FullName ('artifacts\'+$c.Artifact+'\collector.py')};if(-not (@($candidatePaths|Where-Object {Test-Path -LiteralPath $_ -PathType Leaf}).Count)){Write-Output ('SKIPPED: '+$c.Artifact+' (collector not present in this workspace)');continue};$ok=$true;foreach($n in $c.Commands){if(-not (Get-Command $n -ErrorAction SilentlyContinue)){$ok=$false;Write-Output ('BLOCKED: '+$c.Artifact+' requires Windows command '+$n)}};foreach($n in $c.Cmdlets){if(-not (Get-Command $n -ErrorAction SilentlyContinue)){$ok=$false;Write-Output ('BLOCKED: '+$c.Artifact+' requires PowerShell cmdlet '+$n)}};foreach($relativeFile in $c.Files){$foundFile=$false;foreach($candidate in $candidatePaths){$filePath=Join-Path (Split-Path -Parent $candidate) $relativeFile;if(Test-Path -LiteralPath $filePath -PathType Leaf){$foundFile=$true;break}};if(-not $foundFile){$ok=$false;Write-Output ('BLOCKED: '+$c.Artifact+' requires bundled tool '+$relativeFile)}};if($c.Module -and -not (Get-Module -ListAvailable -Name $c.Module)){$ok=$false;Write-Output ('BLOCKED: '+$c.Artifact+' requires built-in Windows PowerShell module '+$c.Module)};if($c.Probe){try{Invoke-Expression $c.Probe}catch{$ok=$false;Write-Output ('BLOCKED: '+$c.Artifact+' Windows profile API probe failed: '+$_.Exception.Message)}};if($ok){if($c.Artifact -eq 'A01 - RAM'){Write-Output 'READY: A01 - RAM (bundled WinPmem is present; its guide documents that it is unsigned and Windows may block its driver)'}elseif($c.Artifact -eq 'A17 - MFT'){Write-Output 'READY: A17 - MFT (bundled RawCopy is present; the collector verifies its pinned upstream identity before execution)'}elseif($c.Artifact -eq 'A83 - Handle Inventory'){Write-Output 'READY: A83 - Handle Inventory (bundled x64 Handle file is present; manual Sysinternals license acceptance may be required)'}else{Write-Output ('READY: '+$c.Artifact+' (required Windows components available)')}}else{$blocked++}}; exit ([Math]::Min($blocked,255))" >"%WINDOWS_LOG%" 2>&1
set "WINDOWS_EXIT=%ERRORLEVEL%"
if exist "%WINDOWS_LOG%" (
    type "%WINDOWS_LOG%"
    type "%WINDOWS_LOG%" >>"%LOG_FILE%"
    del "%WINDOWS_LOG%" >nul 2>nul
)
if not "%WINDOWS_EXIT%"=="0" set "SETUP_BLOCKED=1"

if "%SETUP_BLOCKED%"=="1" goto blocked

call :log "Writing the shared runtime verification record."
"%VENV_PYTHON%" -c "import hashlib,json,os,platform,sys; p=os.path.abspath(sys.executable); os.makedirs(sys.argv[1],exist_ok=True); f=open(os.path.join(sys.argv[1],'setup.json'),'w',encoding='utf-8'); json.dump({'setup_version':2,'python_version':platform.python_version(),'python_executable':p,'python_architecture':'64-bit','python_executable_sha256':hashlib.sha256(open(p,'rb').read()).hexdigest(),'dependency_policy':'Pinned packages from requirements-dev-lock.txt.'},f,indent=2); f.write('\n'); f.close()" "%RUNTIME_DIR%"
if errorlevel 1 (
    call :log "ERROR: Could not write the shared runtime verification record."
    goto failed
)
"%VENV_PYTHON%" -c "import hashlib,json,os,platform,sys; d=json.load(open(os.path.join(sys.argv[1],'setup.json'),encoding='utf-8')); p=os.path.abspath(sys.executable); raise SystemExit(0 if d['setup_version']==2 and d['python_version']==platform.python_version() and os.path.normcase(os.path.abspath(d['python_executable']))==os.path.normcase(p) and d['python_architecture']=='64-bit' and d['python_executable_sha256']==hashlib.sha256(open(p,'rb').read()).hexdigest() else 1)" "%RUNTIME_DIR%" >nul 2>nul
if errorlevel 1 (
    call :log "ERROR: The shared runtime verification record failed validation."
    goto failed
)

call :log "Environment setup completed. Shared Python, Windows components, .NET runtime, and fixed-version tools are ready."
call :log "Ayan bundled acquisition utilities are checked for presence; their collectors retain their own verification and license behavior."
call :log "Project .venv: .venv"
call :log "Project .NET runtime: .dotnet"
call :log "Setup log: setup_environment.log"
echo.
echo Environment setup completed successfully. No artifact collection was run.
echo Review setup_environment.log for verified components and tool versions.
pause
exit /b 0

:find_python
set "PYTHON_EXE="
where py.exe >nul 2>nul
if not errorlevel 1 (
    for /f "delims=" %%P in ('py -3.12-64 -c "import sys; print(sys.executable)" 2^>nul') do set "PYTHON_EXE=%%P"
)
if defined PYTHON_EXE exit /b 0
for /f "delims=" %%P in ('where python.exe 2^>nul') do (
    if not defined PYTHON_EXE (
        "%%P" -c "import struct,sys; raise SystemExit(0 if sys.version_info[:2] == (3,12) and struct.calcsize('P')*8 == 64 else 1)" >nul 2>nul
        if not errorlevel 1 set "PYTHON_EXE=%%P"
    )
)
exit /b 0

:log
echo %*
>>"%LOG_FILE%" echo %*
exit /b 0

:blocked
call :log "Setup is incomplete. Review BLOCKED items above and setup_environment.log."
echo.
echo Environment setup is incomplete. No collector was run.
pause
exit /b 1

:failed
call :log "Environment setup failed. Review the error above and setup_environment.log."
echo.
echo Environment setup did not complete.
pause
exit /b 1