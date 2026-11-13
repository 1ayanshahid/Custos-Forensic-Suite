@echo off
setlocal DisableDelayedExpansion
set "CUSTOS_LAUNCH_FILE=%~f0"
set "CUSTOS_ARTIFACT=%~dp0"
set "CUSTOS_COLLECTOR=collector.py"
set "POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if defined PROCESSOR_ARCHITEW6432 set "POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%POWERSHELL%" -NoLogo -NoProfile -Command "$lines=Get-Content -LiteralPath $env:CUSTOS_LAUNCH_FILE; $markerIndex=[Array]::IndexOf($lines, '#--CUSTOS-POWERSHELL-CODE--'); if($markerIndex -lt 0){throw 'Embedded launch logic is missing.'}; $code=$lines[($markerIndex+1)..($lines.Length-1)] -join [Environment]::NewLine; & ([scriptblock]::Create($code)) -ArtifactFolder $env:CUSTOS_ARTIFACT -Collector $env:CUSTOS_COLLECTOR"
set "RESULT=%ERRORLEVEL%"
exit /b %RESULT%
#--CUSTOS-POWERSHELL-CODE--
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactFolder,
    [Parameter(Mandatory = $true)]
    [string]$Collector,
    [switch]$ElevatedRetry,
    [string]$OriginalProfile,
    [string]$OriginalSid
)

$ErrorActionPreference = 'Stop'
$runtimeVersion = '3.12'

function Write-Failure([string]$Message, [int]$Code = 1) {
    [Console]::Error.WriteLine("ERROR: $Message")
    [void](Read-Host 'Press Enter to close this window')
    exit $Code
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-QuotedScriptLiteral([string]$Value) {
    if ($null -eq $Value) { return "''" }
    return "'" + $Value.Replace("'", "''") + "'"
}
function Test-IsStandaloneHashOutput([IO.FileInfo]$File) {
    return ($File.Extension -ieq '.sha256' -or $File.Name -match '(?i)(?:hash(?:es)?|sha-?256)')
}

try {

    $artifactPath = [IO.Path]::GetFullPath($ArtifactFolder)
    if (-not (Test-Path -LiteralPath $artifactPath -PathType Container)) {
        Write-Failure "Artifact folder does not exist: $artifactPath"
    }
    $workspacePath = (Get-Item -LiteralPath $artifactPath).Parent.Parent.FullName
    $collectorPath = [IO.Path]::GetFullPath((Join-Path $artifactPath $Collector))
    $runtimeRoot = Join-Path $workspacePath '.custos-runtime'
    $pythonPath = $null
    $markerPath = Join-Path $runtimeRoot 'setup.json'

    if (-not (Test-Path -LiteralPath $collectorPath -PathType Leaf)) {
        Write-Failure "Collector entry point does not exist: $collectorPath"
    }
    $folderLabel = (Get-Item -LiteralPath $artifactPath).Name
    $artifactDisplayName = [regex]::Replace($folderLabel, '^[AX]\d{2,3}\s*-\s*', '').Trim()
    $guideIds = @(
        Get-ChildItem -LiteralPath $artifactPath -Filter '*_Guide.md' -File |
            ForEach-Object { $_.BaseName -replace '_Guide$', '' }
    )
    $folderId = [regex]::Match($folderLabel, '^[AX]\d{2,3}')
    $artifactId = $null
    if ($folderId.Success) {
        $artifactId = $folderId.Value
    }
    elseif ($guideIds.Count -eq 1) {
        $artifactId = $guideIds[0]
    }
    if (-not $artifactId) { $artifactId = 'Unmapped' }

    if (-not (Test-IsAdministrator)) {
        if ($ElevatedRetry) {
            Write-Failure 'The elevated relaunch did not receive an administrator token. Collection was not started.'
        }
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $OriginalSid = $currentIdentity.User.Value
        $OriginalProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
        if (-not $OriginalProfile) { $OriginalProfile = $env:USERPROFILE }

        $launcherPath = $env:CUSTOS_LAUNCH_FILE
        if (-not $launcherPath -or -not (Test-Path -LiteralPath $launcherPath -PathType Leaf)) {
            Write-Failure 'The artifact launcher could not be located for elevation. Collection was not started.'
        }
        $artifactLiteral = Get-QuotedScriptLiteral $artifactPath
        $collectorLiteral = Get-QuotedScriptLiteral $Collector
        $profileLiteral = Get-QuotedScriptLiteral $OriginalProfile
        $sidLiteral = Get-QuotedScriptLiteral $OriginalSid
        $launcherLiteral = Get-QuotedScriptLiteral $launcherPath
        $elevatedCommand = "`$env:CUSTOS_LAUNCH_FILE = $launcherLiteral; `$lines = Get-Content -LiteralPath `$env:CUSTOS_LAUNCH_FILE; `$markerIndex = [Array]::IndexOf(`$lines, '#--CUSTOS-POWERSHELL-CODE--'); if (`$markerIndex -lt 0) { throw 'Embedded launch logic is missing.' }; `$code = `$lines[(`$markerIndex + 1)..(`$lines.Length - 1)] -join [Environment]::NewLine; & ([scriptblock]::Create(`$code)) -ArtifactFolder $artifactLiteral -Collector $collectorLiteral -OriginalProfile $profileLiteral -OriginalSid $sidLiteral -ElevatedRetry"
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($elevatedCommand))
        $powerShellExe = Join-Path $PSHOME 'powershell.exe'
        try {
            $child = Start-Process -FilePath $powerShellExe -Verb RunAs -ArgumentList @('-NoLogo', '-NoProfile', '-EncodedCommand', $encodedCommand) -PassThru -Wait
            exit $child.ExitCode
        }
        catch {
            if ($_.Exception.NativeErrorCode -eq 1223) {
                Write-Failure 'UAC elevation was canceled. No collection was performed.'
            }
            Write-Failure "Could not request UAC elevation: $($_.Exception.Message). No collection was performed."
        }
    }

    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        Write-Failure 'Workspace setup is missing or incomplete. Run setup_environment.bat from the workspace root, then launch this artifact again.'
    }
    try {
        $setup = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    }
    catch {
        Write-Failure 'Workspace setup verification data is unreadable. Run setup_environment.bat again.'
    }
    if ($setup.setup_version -ne 2 -or $setup.python_version -notmatch '^3\.12\.\d+$' -or -not $setup.python_executable) {
        Write-Failure 'Workspace setup verification data does not match the required runtime. Run setup_environment.bat again.'
    }
    $runtimeVersion = $setup.python_version
    $pythonPath = [IO.Path]::GetFullPath([string]$setup.python_executable)
    if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
        Write-Failure "The prepared Python interpreter is missing: $pythonPath. Run setup_environment.bat again."
    }

    $currentOs = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $currentArchitecture = $env:PROCESSOR_ARCHITEW6432
    if (-not $currentArchitecture) { $currentArchitecture = $env:PROCESSOR_ARCHITECTURE }
    if (
        [version]$currentOs.Version -lt [version]'10.0.17763' -or
        [int]$currentOs.ProductType -ne 1 -or
        $currentOs.Caption -notmatch 'Windows 10|Windows 11' -or
        -not [Environment]::Is64BitOperatingSystem -or
        $currentArchitecture -ne 'AMD64' -or
        $PSVersionTable.PSVersion -lt [version]'5.1'
    ) {
        Write-Failure "Unsupported or changed host platform: $($currentOs.Caption), build $($currentOs.BuildNumber), architecture $currentArchitecture. Setup supports Windows 10 build 17763 or later/Windows 11 x64 with Windows PowerShell 5.1+."
    }

    if (-not $setup.python_executable_sha256) {
        Write-Failure 'Workspace setup verification data does not include the Python integrity value. Run setup_environment.bat again.'
    }
    $currentPythonHash = (Get-FileHash -LiteralPath $pythonPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($currentPythonHash -ne $setup.python_executable_sha256) {
        Write-Failure 'The prepared Python runtime no longer matches the setup integrity value. Run setup_environment.bat again.'
    }

    $pythonProbe = & $pythonPath -E -s -c "import platform,sys; print(platform.python_version()); print(int(sys.maxsize > 2**32))" 2>$null
    if ($LASTEXITCODE -ne 0 -or $pythonProbe.Count -lt 2 -or $pythonProbe[0] -ne $runtimeVersion -or $pythonProbe[1] -ne '1') {
        Write-Failure 'The prepared workspace Python runtime failed verification. Run setup_environment.bat again.'
    }
    $moduleCheck = "import importlib; [importlib.import_module(m) for m in 'argparse,base64,ctypes,datetime,hashlib,json,os,pathlib,platform,shutil,socket,sqlite3,struct,subprocess,sys,tempfile,time,traceback,typing,uuid,winreg,xml.etree.ElementTree'.split(',')]"
    & $pythonPath -E -s -c $moduleCheck 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Failure 'A required Python standard-library module is unavailable. Run setup_environment.bat again.'
    }

    $windowsTools = @(
        (Join-Path $env:SystemRoot 'System32\wevtutil.exe'),
        (Join-Path $env:SystemRoot 'System32\schtasks.exe'),
        (Join-Path $env:SystemRoot 'System32\netsh.exe'),
        (Join-Path $env:SystemRoot 'System32\reg.exe')
    )
    $missingWindowsTools = @($windowsTools | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) })
    if ($missingWindowsTools.Count -gt 0) {
        Write-Failure ("Required built-in Windows capabilities are unavailable: " + ($missingWindowsTools -join ', ') + '. Repair/enable the Windows components; setup does not install third-party replacements.')
    }
    $unversionedWindowsTools = @(
        foreach ($toolPath in $windowsTools) {
            if (-not (Get-Item -LiteralPath $toolPath).VersionInfo.FileVersion) { $toolPath }
        }
    )
    if ($unversionedWindowsTools.Count -gt 0) {
        Write-Failure ("Could not verify the file version of required Windows tools: " + ($unversionedWindowsTools -join ', ') + '.')
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($OriginalSid -and $identity.User.Value -ne $OriginalSid) {
        Write-Warning "UAC used a different administrator account. The original profile path will be passed to the collector; access to that profile and its registry hive may still be restricted."
    }
    if ($OriginalProfile) {
        if (-not (Test-Path -LiteralPath $OriginalProfile -PathType Container)) {
            Write-Warning "The original user profile path is not accessible: $OriginalProfile. User-scoped collection may be partial or denied."
        }
        $env:CUSTOS_ORIGINAL_PROFILE = $OriginalProfile
        $env:CUSTOS_ORIGINAL_SID = $OriginalSid
        $env:USERPROFILE = $OriginalProfile
        $env:HOME = $OriginalProfile
        $profileRoot = [IO.Path]::GetPathRoot($OriginalProfile)
        if ($profileRoot) {
            $env:HOMEDRIVE = $profileRoot.TrimEnd('\')
            $env:HOMEPATH = $OriginalProfile.Substring($profileRoot.Length - 1)
        }
    }
    $trustedPathEntries = @(
        (Join-Path $env:SystemRoot 'System32'),
        $env:SystemRoot,
        (Join-Path $env:SystemRoot 'System32\Wbem'),
        (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0')
    )
    $env:PATH = (($trustedPathEntries -join ';') + ';' + $env:PATH)

    Write-Host "Artifact ID: $artifactId"
    Write-Host "Artifact folder: $folderLabel"
    Write-Host 'Enter a custom output folder, or press Enter to save in the artifact-specific output folder.'
    Write-Host 'Relative paths are resolved from this artifact folder.'

    $destination = $null
    while (-not $destination) {
        $inputPath = Read-Host 'Output folder'
        if ([string]::IsNullOrWhiteSpace($inputPath)) {
            $candidate = Join-Path $artifactPath ($artifactDisplayName + '_Output')
        }
        else {
            $candidate = $inputPath.Trim()
            if ($candidate.Length -ge 2 -and $candidate.StartsWith('"') -and $candidate.EndsWith('"')) {
                $candidate = $candidate.Substring(1, $candidate.Length - 2)
            }
            if ([string]::IsNullOrWhiteSpace($candidate)) {
                $candidate = Join-Path $artifactPath ($artifactDisplayName + '_Output')
            }
            $isDriveAbsolute = $candidate -match '^[A-Za-z]:[\\/]'
            $isUncAbsolute = $candidate.StartsWith('\\')
            if (-not $isDriveAbsolute -and -not $isUncAbsolute) {
                $candidate = Join-Path $artifactPath $candidate
            }
        }

        try {
            $candidate = [IO.Path]::GetFullPath($candidate)
            $runtimeFullPath = [IO.Path]::GetFullPath($runtimeRoot).TrimEnd('\') + '\'
            $candidateFullPath = $candidate.TrimEnd('\') + '\'
            if ($candidateFullPath.StartsWith($runtimeFullPath, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'The workspace-managed runtime folder cannot be used as an output destination.'
            }
            [IO.Directory]::CreateDirectory($candidate) | Out-Null
            $probePath = Join-Path $candidate ('.custos-write-test-' + [guid]::NewGuid().ToString('N'))
            try {
                [IO.File]::WriteAllText($probePath, 'write test')
            }
            finally {
                if (Test-Path -LiteralPath $probePath -PathType Leaf) {
                    Remove-Item -LiteralPath $probePath -Force -ErrorAction Stop
                }
            }
            if ($artifactId -eq 'A45') {
                $a45Conflicts = @(
                    Get-ChildItem -LiteralPath $candidate -Force |
                        Where-Object {
                            $_.Name -in @('Files', 'ToolOutput', 'Recent Items.json', 'Recent Items.json.tmp') -or
                            $_.Name -like 'Recent Items_*.json' -or
                            $_.Name -like 'Recent Items_*.json.tmp' -or
                            $_.Name -like 'acquisition_manifest_*.json' -or
                            $_.Name -like 'acquisition_manifest_*.json.tmp' -or
                            $_.Name -like 'verification_*.json' -or
                            $_.Name -like 'verification_*.json.tmp'
                        } |
                        ForEach-Object { $_.FullName }
                )
                if ($a45Conflicts.Count -gt 0) {
                    [Console]::Error.WriteLine(
                        "A45 output already exists and will not be overwritten: " +
                        ($a45Conflicts -join ', ')
                    )
                    $retry = Read-Host 'Enter another folder, or type Q to exit'
                    if ($retry -match '^(?i:q)$') {
                        Write-Failure 'No unused A45 destination was selected. No collection was performed.'
                    }
                    continue
                }
            }
            $destination = $candidate
        }
        catch {
            $leftoverProbe = if ($probePath -and (Test-Path -LiteralPath $probePath -PathType Leaf)) { " Temporary write-test file remains at '$probePath'." } else { '' }
            [Console]::Error.WriteLine("Cannot use output folder '$candidate': $($_.Exception.Message)$leftoverProbe")
            $retry = Read-Host 'Enter another folder, or type Q to exit'
            if ($retry -match '^(?i:q)$') {
                Write-Failure 'No valid output destination was selected. No collection was performed.'
            }
        }
    }

    $hashReportPath = Join-Path $destination ($artifactDisplayName + '_Hash & Timestamp Report.json')
    $existingHashOutputs = @(
        Get-ChildItem -LiteralPath $destination -File -Force -ErrorAction Stop |
            Where-Object { Test-IsStandaloneHashOutput $_ }
    )
    if ($existingHashOutputs.Count -gt 0) {
        Write-Failure ("The selected output already contains previous standalone hash/report files: " + ($existingHashOutputs.Name -join ', ') + ". Existing files were preserved; choose a fresh output folder.") 4
    }

    $destinationIsArtifactFolder = $destination.TrimEnd('\') -eq $artifactPath.TrimEnd('\')
    if (-not $destinationIsArtifactFolder) {
        $protectedNames = @('launch.bat', $Collector, 'setup_environment.bat', 'requirement_dev_log.txt')
        foreach ($protectedName in $protectedNames) {
            $protectedPath = Join-Path $destination $protectedName
            if (Test-Path -LiteralPath $protectedPath -PathType Leaf) {
                Write-Failure "The selected destination contains protected project file '$protectedName'. Choose a different destination; project files will not be overwritten."
            }
        }
    }

    $collectorDestination = $destination.TrimEnd('\', '/')
    $destinationRoot = [IO.Path]::GetPathRoot($destination)
    if (
        $destinationRoot -and
        $collectorDestination -eq $destinationRoot.TrimEnd('\', '/')
    ) {
        $collectorDestination = $destinationRoot + '.'
    }

    Write-Host "Starting collection. Destination: $destination"
    $previousErrorPreference = $ErrorActionPreference
    $previousCollectorPath = $env:CUSTOS_LAUNCH_COLLECTOR
    $previousOutputPath = $env:CUSTOS_LAUNCH_OUTPUT_DIR
    $ErrorActionPreference = 'Continue'
    try {
        $env:CUSTOS_LAUNCH_COLLECTOR = $collectorPath
        $env:CUSTOS_LAUNCH_OUTPUT_DIR = $collectorDestination
        $collectorRunner = "import os,runpy,sys; p=os.environ['CUSTOS_LAUNCH_COLLECTOR']; sys.path.insert(0,os.path.dirname(p)); sys.argv=[p,'--output-dir',os.environ['CUSTOS_LAUNCH_OUTPUT_DIR']]; runpy.run_path(p,run_name='__main__')"
        $collectorOutput = @(& $pythonPath -E -s -c $collectorRunner 2>&1)
        $collectorExitCode = $LASTEXITCODE
    }
    finally {
        if ($null -eq $previousCollectorPath) {
            Remove-Item Env:\CUSTOS_LAUNCH_COLLECTOR -ErrorAction SilentlyContinue
        }
        else {
            $env:CUSTOS_LAUNCH_COLLECTOR = $previousCollectorPath
        }
        if ($null -eq $previousOutputPath) {
            Remove-Item Env:\CUSTOS_LAUNCH_OUTPUT_DIR -ErrorAction SilentlyContinue
        }
        else {
            $env:CUSTOS_LAUNCH_OUTPUT_DIR = $previousOutputPath
        }
        $ErrorActionPreference = $previousErrorPreference
    }
    try {
        if (-not (Test-Path -LiteralPath $hashReportPath -PathType Leaf)) {
            throw "Collector did not produce its canonical report."
        }
        Write-Host "Hash and timestamp report: $hashReportPath"
    }
    catch {
        [Console]::Error.WriteLine("ERROR: Could not create the hash and timestamp report '$hashReportPath': $($_.Exception.Message)")
        if ($collectorExitCode -eq 0) { $collectorExitCode = 1 }
    }
    foreach ($outputLine in $collectorOutput) {
        if ($collectorExitCode -ne 0 -or $outputLine -is [Management.Automation.ErrorRecord]) {
            [Console]::Error.WriteLine([string]$outputLine)
        }
    }
    if ($collectorExitCode -eq 0) {
        Write-Host "Collection process completed with exit code 0. Output destination: $destination"
    }
    else {
        [Console]::Error.WriteLine("Collection process ended with exit code $collectorExitCode. Review the error details above. Output destination: $destination")
    }
    [void](Read-Host 'Press Enter to close this window')
    exit $collectorExitCode
}
catch {
    Write-Failure "Launcher failed: $($_.Exception.Message)"
}

