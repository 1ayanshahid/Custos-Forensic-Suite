"""Read-only A30 Windows system-information snapshot collector."""

from __future__ import annotations

import argparse
import base64
import ctypes
import json
import os
import platform
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

ARTIFACT_ID = "A30"
EXIT_SUCCESS = 0
EXIT_PARTIAL = 1
EXIT_FAILURE = 2
DEFAULT_TIMEOUT_SECONDS = 120
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
COMPUTER_NAME_FORMATS = {
    "netbios_name": 0,
    "dns_hostname": 1,
    "dns_domain": 2,
    "dns_fqdn": 3,
    "physical_netbios_name": 4,
    "physical_dns_hostname": 5,
    "physical_dns_domain": 6,
    "physical_dns_fqdn": 7,
}

QUERY_PROPERTIES: dict[str, tuple[str, ...]] = {
    "operating_system": (
        "Caption", "Description", "Version", "BuildNumber", "BuildType",
        "CSDVersion", "OSArchitecture", "InstallDate", "LastBootUpTime",
        "WindowsDirectory", "SystemDirectory", "SystemDrive", "OSLanguage",
        "Locale", "MUILanguages", "CountryCode", "CodeSet", "OSType",
        "OperatingSystemSKU", "ProductType", "SuiteMask",
        "PortableOperatingSystem", "Primary", "DataExecutionPrevention_Available",
        "DataExecutionPrevention_32BitApplications", "DataExecutionPrevention_Drivers",
        "DataExecutionPrevention_SupportPolicy", "TotalVisibleMemorySize",
        "FreePhysicalMemory", "TotalVirtualMemorySize", "FreeVirtualMemory",
        "SizeStoredInPagingFiles", "FreeSpaceInPagingFiles",
    ),
    "computer_system": (
        "Name", "DNSHostName", "Domain", "Workgroup", "PartOfDomain",
        "DomainRole", "Manufacturer", "Model", "SystemType", "PCSystemType",
        "PCSystemTypeEx", "SystemFamily", "SystemSKUNumber", "ChassisSKUNumber",
        "HypervisorPresent", "NumberOfProcessors", "NumberOfLogicalProcessors",
        "TotalPhysicalMemory", "NetworkServerModeEnabled",
    ),
    "computer_product": (
        "Vendor", "Name", "Version", "IdentifyingNumber", "SKUNumber", "UUID",
    ),
    "bios": (
        "Manufacturer", "Name", "Version", "SMBIOSBIOSVersion", "BIOSVersion",
        "ReleaseDate", "SerialNumber", "SMBIOSMajorVersion", "SMBIOSMinorVersion",
        "SMBIOSPresent", "SystemBiosMajorVersion", "SystemBiosMinorVersion",
        "CurrentLanguage", "ListOfLanguages", "PrimaryBIOS",
    ),
    "baseboard": (
        "Manufacturer", "Model", "Product", "Version", "SerialNumber",
        "PartNumber", "SKU", "HostingBoard",
    ),
    "processors": (
        "Name", "Manufacturer", "Architecture", "AddressWidth", "DataWidth",
        "ProcessorId", "SocketDesignation", "NumberOfCores",
        "NumberOfEnabledCore", "NumberOfLogicalProcessors", "CurrentClockSpeed",
        "MaxClockSpeed", "ExtClock", "VirtualizationFirmwareEnabled",
        "VMMonitorModeExtensions", "SecondLevelAddressTranslationExtensions",
        "Characteristics", "ThreadCount",
    ),
    "physical_memory": (
        "Capacity", "Speed", "ConfiguredClockSpeed", "Manufacturer",
        "PartNumber", "SerialNumber", "DeviceLocator", "BankLabel",
        "DataWidth", "TotalWidth", "FormFactor", "MemoryType", "SMBIOSMemoryType",
        "Attributes", "ConfiguredVoltage", "MinVoltage", "MaxVoltage",
    ),
    "physical_memory_arrays": (
        "Location", "Manufacturer", "Model", "Name", "MaxCapacity",
        "MaxCapacityEx", "MemoryDevices", "MemoryErrorCorrection", "Use",
    ),
    "logical_disks": (
        "DeviceID", "DriveType", "FileSystem", "VolumeName", "VolumeSerialNumber",
        "Size", "FreeSpace", "ProviderName", "Compressed", "VolumeDirty",
    ),
    "volumes": (
        "DeviceID", "DriveLetter", "Name", "Label", "FileSystem", "Capacity",
        "FreeSpace", "DriveType", "BootVolume", "SystemVolume",
    ),
    "physical_disks": (
        "DeviceID", "Index", "Model", "Manufacturer", "SerialNumber", "Size",
        "InterfaceType", "MediaType", "FirmwareRevision", "PNPDeviceID",
        "BytesPerSector", "Partitions", "Signature",
    ),
    "partitions": (
        "DeviceID", "DiskIndex", "Index", "Name", "Type", "Size",
        "StartingOffset", "NumberOfBlocks", "BlockSize", "Bootable",
        "BootPartition", "PrimaryPartition", "HiddenSectors",
    ),
    "display_adapters": (
        "Name", "Description", "AdapterCompatibility", "AdapterRAM",
        "VideoProcessor", "PNPDeviceID", "DriverVersion", "DriverDate",
        "MinRefreshRate", "MaxRefreshRate", "CurrentNumberOfColors",
        "CurrentScanMode", "VideoMode",
        "CurrentHorizontalResolution", "CurrentVerticalResolution",
        "CurrentRefreshRate", "CurrentBitsPerPixel", "VideoModeDescription",
    ),
    "quick_fixes": (
        "HotFixID", "Description", "InstalledBy", "InstalledOn", "InstallDate",
        "ServicePackInEffect", "FixComments", "Name", "Status",
    ),
    "disk_to_partition": ("Antecedent", "Dependent"),
    "partition_to_logical_disk": ("Antecedent", "Dependent"),
    "mount_points": ("Directory", "Volume"),
}

QUERY_CLASSES = {
    "operating_system": "Win32_OperatingSystem",
    "computer_system": "Win32_ComputerSystem",
    "computer_product": "Win32_ComputerSystemProduct",
    "bios": "Win32_BIOS",
    "baseboard": "Win32_BaseBoard",
    "processors": "Win32_Processor",
    "physical_memory": "Win32_PhysicalMemory",
    "physical_memory_arrays": "Win32_PhysicalMemoryArray",
    "logical_disks": "Win32_LogicalDisk",
    "volumes": "Win32_Volume",
    "physical_disks": "Win32_DiskDrive",
    "partitions": "Win32_DiskPartition",
    "display_adapters": "Win32_VideoController",
    "quick_fixes": "Win32_QuickFixEngineering",
    "disk_to_partition": "Win32_DiskDriveToDiskPartition",
    "partition_to_logical_disk": "Win32_LogicalDiskToPartition",
    "mount_points": "Win32_MountPoint",
}

REGISTRY_PROPERTIES = (
    "ProductName", "EditionID", "DisplayVersion", "ReleaseId", "CurrentBuild",
    "CurrentBuildNumber", "UBR", "BuildLabEx", "InstallationType", "ProductId",
)

CIM_DATE_FIELDS: dict[str, tuple[str, ...]] = {
    "operating_system": ("InstallDate", "LastBootUpTime"),
    "bios": ("ReleaseDate",),
    "display_adapters": ("DriverDate",),
    "quick_fixes": ("InstallDate",),
}

FIELD_STATUS_REASONS = {
    "available": "Provider returned a non-null value.",
    "blank_value": "Provider returned a blank string; the original string is preserved.",
    "null_value": "Provider exposed this property but returned null.",
    "not_exposed": "Provider instance did not expose this selected property.",
    "not_returned": "Structured provider response omitted this selected property.",
    "malformed_value": "Provider returned a value with an unexpected type or format.",
}

FIELD_UNITS: dict[str, dict[str, str]] = {
    "operating_system": {
        "TotalVisibleMemorySize": "KB (provider-reported)",
        "FreePhysicalMemory": "KB (provider-reported)",
        "TotalVirtualMemorySize": "KB (provider-reported)",
        "FreeVirtualMemory": "KB (provider-reported)",
        "SizeStoredInPagingFiles": "KB (provider-reported)",
        "FreeSpaceInPagingFiles": "KB (provider-reported)",
        "InstallDate": "CIM DateTime wrapper; provider round-trip value, .NET ticks, and normalized UTC",
        "LastBootUpTime": "CIM DateTime wrapper; provider round-trip value, .NET ticks, and normalized UTC",
    },
    "computer_system": {
        "TotalPhysicalMemory": "bytes",
    },
    "bios": {
        "ReleaseDate": "CIM DateTime wrapper; provider round-trip value, .NET ticks, and normalized UTC",
    },
    "processors": {
        "CurrentClockSpeed": "MHz",
        "MaxClockSpeed": "MHz",
        "ExtClock": "MHz",
    },
    "physical_memory": {
        "Capacity": "bytes",
        "Speed": "MHz",
        "ConfiguredClockSpeed": "MHz",
        "ConfiguredVoltage": "millivolts",
        "MinVoltage": "millivolts",
        "MaxVoltage": "millivolts",
    },
    "physical_memory_arrays": {
        "MaxCapacity": "KB (provider-reported)",
        "MaxCapacityEx": "KB (provider-reported)",
    },
    "logical_disks": {
        "Size": "bytes",
        "FreeSpace": "bytes",
    },
    "volumes": {
        "Capacity": "bytes",
        "FreeSpace": "bytes",
    },
    "physical_disks": {
        "Size": "bytes",
        "BytesPerSector": "bytes",
    },
    "partitions": {
        "Size": "bytes",
        "StartingOffset": "bytes",
        "NumberOfBlocks": "blocks",
        "BlockSize": "bytes",
        "HiddenSectors": "sectors",
    },
    "display_adapters": {
        "AdapterRAM": (
            "bytes (Win32_VideoController uint32 provider-reported adapter "
            "memory; not verified dedicated graphics memory)"
        ),
        "DriverDate": "CIM DateTime wrapper; provider round-trip value, .NET ticks, and normalized UTC",
        "CurrentHorizontalResolution": "pixels",
        "CurrentVerticalResolution": "pixels",
        "CurrentRefreshRate": "Hz",
        "MinRefreshRate": "Hz",
        "MaxRefreshRate": "Hz",
        "CurrentNumberOfColors": "colors",
        "CurrentBitsPerPixel": "bits per pixel",
    },
    "quick_fixes": {
        "InstallDate": "CIM DateTime wrapper; provider round-trip value, .NET ticks, and normalized UTC",
        "InstalledOn": "provider string; ambiguous date preserved without parsing",
    },
}

POWER_SHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$spec = $payload.specification
function Get-Category($ErrorRecord) {
    if ($ErrorRecord.CategoryInfo.Category -eq 'PermissionDenied') {
        return 'access_denied'
    }
    $match = [regex]::Match(
        [string]$ErrorRecord.FullyQualifiedErrorId,
        'HRESULT 0x([0-9A-Fa-f]{8})'
    )
    if ($match.Success) {
        $code = [uint32]::Parse(
            $match.Groups[1].Value,
            [Globalization.NumberStyles]::HexNumber,
            [Globalization.CultureInfo]::InvariantCulture
        )
        if ($code -eq 0x80070005 -or $code -eq 0x80041003) { return 'access_denied' }
        if ($code -eq 0x8004100e -or $code -eq 0x80041010 -or $code -eq 0x80041002) { return 'unsupported' }
    }
    return 'provider_failure'
}
function Get-QueryResult([string]$ClassName, [string[]]$Properties) {
    $referenceFields = @{
        Win32_DiskDriveToDiskPartition = @('Antecedent', 'Dependent')
        Win32_LogicalDiskToPartition = @('Antecedent', 'Dependent')
        Win32_MountPoint = @('Directory', 'Volume')
    }
    try {
        $instances = @(Get-CimInstance -Namespace 'root\cimv2' -ClassName $ClassName `
            -Property $Properties -ErrorAction Stop)
        $records = @()
        foreach ($instance in $instances) {
            $values = [ordered]@{}
            $fieldStatus = [ordered]@{}
            foreach ($property in $Properties) {
                $cimProperty = $instance.CimInstanceProperties[$property]
                if ($null -eq $cimProperty) {
                    $values[$property] = $null
                    $fieldStatus[$property] = 'not_exposed'
                } elseif ($null -eq $cimProperty.Value) {
                    $values[$property] = $null
                    $fieldStatus[$property] = 'null_value'
                } elseif ($referenceFields.ContainsKey($ClassName) -and
                    $property -in $referenceFields[$ClassName]) {
                    if ($cimProperty.Value -isnot [Microsoft.Management.Infrastructure.CimInstance]) {
                        $values[$property] = $null
                        $fieldStatus[$property] = 'malformed_value'
                        continue
                    }
                    $reference = $cimProperty.Value
                    $keys = [ordered]@{}
                    foreach ($classProperty in $reference.CimClass.CimClassProperties) {
                        $isKey = $false
                        foreach ($qualifier in $classProperty.Qualifiers) {
                            if ($qualifier.Name -eq 'Key' -and $qualifier.Value -eq $true) {
                                $isKey = $true
                                break
                            }
                        }
                        if ($isKey) {
                            $keyProperty = $reference.CimInstanceProperties[$classProperty.Name]
                            if ($null -ne $keyProperty) {
                                $keys[$classProperty.Name] = $keyProperty.Value
                            }
                        }
                    }
                    $values[$property] = [pscustomobject]@{
                        class_name = $reference.CimSystemProperties.ClassName
                        keys = $keys
                    }
                    $fieldStatus[$property] = 'available'
                } elseif ($cimProperty.Value -is [datetime]) {
                    $dateValue = $cimProperty.Value
                    $values[$property] = [ordered]@{
                        provider_datetime = $dateValue.ToString(
                            'o',
                            [Globalization.CultureInfo]::InvariantCulture
                        )
                        date_time_kind = $dateValue.Kind.ToString()
                        ticks = $dateValue.Ticks
                    }
                    $fieldStatus[$property] = 'available'
                } else {
                    $values[$property] = $cimProperty.Value
                    $fieldStatus[$property] = 'available'
                }
            }
            $records += [pscustomobject]@{ values = $values; field_status = $fieldStatus }
        }
        return @{ status = 'success'; error_category = $null; records_returned = $records.Count; records = @($records) }
    } catch {
        $category = Get-Category $_
        $hresult = $null
        if ($null -ne $_.Exception) {
            $hresult = '0x{0:X8}' -f [uint32]$_.Exception.HResult
        }
        return @{ status = $category; error_category = $category; native_hresult = $hresult; records_returned = 0; records = @() }
    }
}
$results = [ordered]@{}
foreach ($name in $spec.queries.PSObject.Properties.Name) {
    $query = $spec.queries.PSObject.Properties[$name].Value
    $results[$name] = Get-QueryResult ([string]$query.class_name) @($query.properties)
}
try {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $item = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
    $values = [ordered]@{}
    $fieldStatus = [ordered]@{}
    foreach ($property in $spec.registry_properties) {
        $member = $item.PSObject.Properties[$property]
        if ($null -eq $member) {
            $values[$property] = $null
            $fieldStatus[$property] = 'not_exposed'
        } elseif ($null -eq $member.Value) {
            $values[$property] = $null
            $fieldStatus[$property] = 'null_value'
        } else {
            $values[$property] = $member.Value
            $fieldStatus[$property] = 'available'
        }
    }
    $results['windows_registry_identity'] = @{
        status = 'success'; error_category = $null; records_returned = 1
        records = @(@{ values = $values; field_status = $fieldStatus })
    }
} catch {
    $category = Get-Category $_
    $hresult = $null
    if ($null -ne $_.Exception) {
        $hresult = '0x{0:X8}' -f [uint32]$_.Exception.HResult
    }
    $results['windows_registry_identity'] = @{
        status = $category; error_category = $category; native_hresult = $hresult
        records_returned = 0; records = @()
    }
}
$results | ConvertTo-Json -Depth 16 -Compress
"""

POWER_SHELL_BOOTSTRAP = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
Invoke-Expression ([string]$payload.script)
"""


def _canonical_integrity_report(report):
    # Isolated embedded implementation: collector globals cannot shadow its imports.
    _inline_namespace = {}
    exec('"""Canonical post-save integrity reports; never evidence of acquisition-time hashing."""\nimport hashlib\nfrom datetime import datetime, timezone\nfrom pathlib import Path\n\n\ndef _now():\n    return datetime.now(timezone.utc).isoformat()\n\n\ndef _metadata(info):\n    return (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_dev, info.st_ino)\n\n\ndef _read_hash(path):\n    digest = hashlib.sha256()\n    with path.open(\'rb\') as stream:\n        for chunk in iter(lambda: stream.read(1024 * 1024), b\'\'):\n            digest.update(chunk)\n    return digest.hexdigest()\n\n\ndef canonical_report(source):\n    root = Path(source[\'output_directory\']).resolve()\n    outputs = []\n    for original in source.get(\'outputs\', []):\n        entry = dict.fromkeys((\'path\', \'size_bytes\', \'sha256\', \'verification_sha256\',\n                              \'last_modified_utc\', \'hash_timestamp_utc\',\n                              \'verification_timestamp_utc\', \'verification_status\', \'error\'))\n        entry[\'path\'] = original[\'path\']\n        entry[\'verification_status\'] = \'failed\'\n        try:\n            path = (root / original[\'path\']).resolve()\n            path.relative_to(root)\n            before = path.stat()\n            metadata = _metadata(before)\n            entry[\'size_bytes\'] = before.st_size\n            entry[\'last_modified_utc\'] = datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat()\n            entry[\'sha256\'] = _read_hash(path)\n            entry[\'hash_timestamp_utc\'] = _now()\n            if _metadata(path.stat()) != metadata:\n                raise RuntimeError(\'Saved file metadata changed during first read\')\n            entry[\'verification_sha256\'] = _read_hash(path)\n            entry[\'verification_timestamp_utc\'] = _now()\n            if _metadata(path.stat()) != metadata:\n                raise RuntimeError(\'Saved file metadata changed during independent verification read\')\n            if entry[\'sha256\'] != entry[\'verification_sha256\']:\n                raise RuntimeError(\'Saved-file SHA-256 mismatch between independent reads\')\n            entry[\'verification_status\'] = \'verified\'\n        except (OSError, ValueError, RuntimeError) as exc:\n            entry[\'error\'] = str(exc)\n        outputs.append(entry)\n    failed = any(item[\'verification_status\'] == \'failed\' for item in outputs)\n    return {\n        \'schema_version\': 1,\n        \'artifact_id\': source.get(\'artifact_id\'),\n        \'artifact_name\': source.get(\'artifact_name\') or root.name.removesuffix(\'_Output\'),\n        \'collector\': source.get(\'collector\', \'collector.py\'),\n        \'hash_algorithm\': \'SHA-256\',\n        \'verification_status\': \'failed\' if failed else \'verified\' if outputs else \'not_run\',\n        \'verification_method\': \'Two independent reads of saved output files; SHA-256 comparison and size, mtime, ctime, device and file identity stability checks. Not acquisition-time hashing.\',\n        \'collection_started_at_utc\': source.get(\'collection_started_at_utc\'),\n        \'collection_ended_at_utc\': source.get(\'collection_ended_at_utc\'),\n        \'collection_status\': \'partial\' if failed and source.get(\'collection_exit_code\') == 0 else source.get(\'collection_status\'),\n        \'collection_exit_code\': 1 if failed and source.get(\'collection_exit_code\') == 0 else source.get(\'collection_exit_code\'),\n        \'output_directory\': str(root),\n        \'outputs\': sorted(outputs, key=lambda item: item[\'path\'].casefold()),\n        \'manifest\': source.get(\'consolidated_reports\', source.get(\'manifest\', {})),\n        \'error\': source.get(\'error\'),\n        \'errors\': source.get(\'errors\', []),\n        \'generated_at_utc\': _now(),\n        \'generated_at_local\': datetime.now().astimezone().isoformat(),\n    }\n', _inline_namespace)
    report.setdefault('artifact_name', _inline_namespace['Path'](__file__).resolve().parent.name.split(' - ', 1)[1])
    canonical = _inline_namespace['canonical_report'](report)
    manifest = report.get('consolidated_reports', report.get('manifest', {}))
    if manifest == {}:
        canonical.pop('manifest', None)
    else:
        canonical['manifest'] = manifest
    return canonical


def _filetime_to_iso(value: int) -> str:
    return (FILETIME_EPOCH + timedelta(microseconds=value // 10)).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _read_system_utc_detail() -> tuple[str, str, int | None]:
    if os.name == "nt":
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            class FileTime(ctypes.Structure):
                _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

            precise = getattr(kernel32, "GetSystemTimePreciseAsFileTime", None)
            if precise is not None:
                precise.argtypes = [ctypes.POINTER(FileTime)]
                precise.restype = None
                file_time = FileTime()
                precise(ctypes.byref(file_time))
                ticks = (file_time.high << 32) | file_time.low
                return (
                    _filetime_to_iso(ticks),
                    "GetSystemTimePreciseAsFileTime",
                    ticks,
                )

            fallback = kernel32.GetSystemTimeAsFileTime
            fallback.argtypes = [ctypes.POINTER(FileTime)]
            fallback.restype = None
            file_time = FileTime()
            fallback(ctypes.byref(file_time))
            ticks = (file_time.high << 32) | file_time.low
            return _filetime_to_iso(ticks), "GetSystemTimeAsFileTime", ticks
        except (AttributeError, OSError, OverflowError, ValueError):
            pass
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    ), "Python datetime UTC fallback", None


def _read_system_utc() -> tuple[str, str]:
    value, source, _filetime = _read_system_utc_detail()
    return value, source


def _status_record(value: Any, source: str, status: str = "available") -> dict[str, Any]:
    return {"value": value, "source": source, "status": status}


def _windows_api_snapshot() -> dict[str, Any]:
    source = "Windows documented API via Python ctypes"
    outcomes: dict[str, dict[str, Any]] = {}
    names: dict[str, Any] = {}
    architecture: dict[str, Any] = {}
    memory: dict[str, Any] = {}
    clock: dict[str, Any] = {}
    api_errors: list[dict[str, Any]] = []

    if os.name != "nt":
        unsupported = {"status": "unsupported", "error_category": "unsupported"}
        return {
            "computer_names": names,
            "architecture": architecture,
            "memory_status": memory,
            "clock": clock,
            "providers": {
                "windows_names_api": unsupported,
                "native_system_info_api": unsupported,
                "global_memory_status_api": unsupported,
                "clock_apis": unsupported,
            },
        }

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError) as exc:
        failure = {
            "status": "provider_failure",
            "error_category": type(exc).__name__,
        }
        return {
            "computer_names": names,
            "architecture": architecture,
            "memory_status": memory,
            "clock": clock,
            "providers": {
                "windows_names_api": failure,
                "native_system_info_api": failure,
                "global_memory_status_api": failure,
                "clock_apis": failure,
            },
        }

    def win_error_status() -> dict[str, Any]:
        code = ctypes.get_last_error()
        return {
            "status": "access_denied" if code == 5 else "provider_failure",
            "error_category": "win32_error",
            "win32_error_code": code,
        }

    try:
        get_computer_name_ex = kernel32.GetComputerNameExW
        get_computer_name_ex.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_wchar),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        get_computer_name_ex.restype = ctypes.c_int
        for key, name_type in COMPUTER_NAME_FORMATS.items():
            size = ctypes.c_uint32(0)
            get_computer_name_ex(name_type, None, ctypes.byref(size))
            if size.value == 0:
                names[key] = _status_record(None, "GetComputerNameExW", "unavailable")
                continue
            buffer = ctypes.create_unicode_buffer(size.value)
            if get_computer_name_ex(name_type, buffer, ctypes.byref(size)):
                names[key] = _status_record(buffer.value, "GetComputerNameExW")
            else:
                error_code = ctypes.get_last_error()
                names[key] = {
                    **_status_record(None, "GetComputerNameExW", "provider_failure"),
                    "win32_error_code": error_code,
                }
                api_errors.append(
                    {
                        "provider": "GetComputerNameExW",
                        "field": key,
                        "category": (
                            "access_denied" if error_code == 5 else "provider_failure"
                        ),
                        "win32_error_code": error_code,
                    }
                )
        outcomes["windows_names_api"] = {"status": "success"}
    except (AttributeError, OSError, ValueError):
        outcomes["windows_names_api"] = win_error_status()

    try:
        class ProcessorArchitecture(ctypes.Structure):
            _fields_ = [
                ("wProcessorArchitecture", ctypes.c_uint16),
                ("wReserved", ctypes.c_uint16),
            ]

        class ProcessorInfo(ctypes.Union):
            _anonymous_ = ("architecture",)
            _fields_ = [
                ("dwOemId", ctypes.c_uint32),
                ("architecture", ProcessorArchitecture),
            ]

        class SystemInfo(ctypes.Structure):
            _anonymous_ = ("processor_info",)
            _fields_ = [
                ("processor_info", ProcessorInfo),
                ("dwPageSize", ctypes.c_uint32),
                ("lpMinimumApplicationAddress", ctypes.c_void_p),
                ("lpMaximumApplicationAddress", ctypes.c_void_p),
                ("dwActiveProcessorMask", ctypes.c_size_t),
                ("dwNumberOfProcessors", ctypes.c_uint32),
                ("dwProcessorType", ctypes.c_uint32),
                ("dwAllocationGranularity", ctypes.c_uint32),
                ("wProcessorLevel", ctypes.c_uint16),
                ("wProcessorRevision", ctypes.c_uint16),
            ]

        get_native = kernel32.GetNativeSystemInfo
        get_native.argtypes = [ctypes.POINTER(SystemInfo)]
        get_native.restype = None
        info = SystemInfo()
        get_native(ctypes.byref(info))
        architecture_codes = {
            0: "x86", 5: "ARM", 9: "x64", 12: "ARM64", 6: "Intel Itanium",
        }
        architecture["native_system_architecture"] = _status_record(
            architecture_codes.get(info.wProcessorArchitecture, "unknown"),
            "GetNativeSystemInfo",
        )
        architecture["native_processor_architecture_code"] = _status_record(
            info.wProcessorArchitecture, "GetNativeSystemInfo"
        )
        architecture["native_logical_processor_count"] = _status_record(
            info.dwNumberOfProcessors, "GetNativeSystemInfo", "available"
        )
        architecture["page_size_bytes"] = _status_record(
            info.dwPageSize, "GetNativeSystemInfo"
        )
        architecture["allocation_granularity_bytes"] = _status_record(
            info.dwAllocationGranularity, "GetNativeSystemInfo"
        )
        architecture["python_process_architecture"] = _status_record(
            f"{platform.machine()} ({ctypes.sizeof(ctypes.c_void_p) * 8}-bit)",
            "Python platform.machine and pointer size",
        )
        outcomes["native_system_info_api"] = {"status": "success"}
    except (AttributeError, OSError, ValueError):
        outcomes["native_system_info_api"] = win_error_status()

    try:
        class MemoryStatusEx(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_uint32),
                ("dwMemoryLoad", ctypes.c_uint32),
                ("ullTotalPhys", ctypes.c_uint64),
                ("ullAvailPhys", ctypes.c_uint64),
                ("ullTotalPageFile", ctypes.c_uint64),
                ("ullAvailPageFile", ctypes.c_uint64),
                ("ullTotalVirtual", ctypes.c_uint64),
                ("ullAvailVirtual", ctypes.c_uint64),
                ("ullAvailExtendedVirtual", ctypes.c_uint64),
            ]

        get_memory = kernel32.GlobalMemoryStatusEx
        get_memory.argtypes = [ctypes.POINTER(MemoryStatusEx)]
        get_memory.restype = ctypes.c_int
        status = MemoryStatusEx()
        status.dwLength = ctypes.sizeof(MemoryStatusEx)
        if get_memory(ctypes.byref(status)):
            for key, value, unit in (
                ("memory_load_percent", status.dwMemoryLoad, "percent"),
                ("os_visible_physical_total", status.ullTotalPhys, "bytes"),
                ("available_physical", status.ullAvailPhys, "bytes"),
                ("commit_limit", status.ullTotalPageFile, "bytes"),
                ("commit_available", status.ullAvailPageFile, "bytes"),
                ("user_mode_virtual_address_space", status.ullTotalVirtual, "bytes"),
                ("available_user_mode_virtual_address_space", status.ullAvailVirtual, "bytes"),
                ("available_extended_virtual", status.ullAvailExtendedVirtual, "bytes"),
            ):
                memory[key] = {
                    **_status_record(value, "GlobalMemoryStatusEx"),
                    "unit": unit,
                }
            outcomes["global_memory_status_api"] = {"status": "success"}
        else:
            outcomes["global_memory_status_api"] = win_error_status()
    except (AttributeError, OSError, ValueError):
        outcomes["global_memory_status_api"] = win_error_status()

    try:
        get_tick_count = kernel32.GetTickCount64
        get_tick_count.argtypes = []
        get_tick_count.restype = ctypes.c_uint64
        milliseconds = int(get_tick_count())
        clock["uptime_milliseconds"] = _status_record(
            milliseconds, "GetTickCount64"
        )
        clock["uptime_seconds"] = _status_record(
            milliseconds / 1000, "GetTickCount64"
        )
        clock["uptime_observation_method"] = _status_record(
            "elapsed time since system start; includes sleep time",
            "GetTickCount64",
        )

        class SystemTime(ctypes.Structure):
            _fields_ = [
                ("year", ctypes.c_uint16), ("month", ctypes.c_uint16),
                ("day_of_week", ctypes.c_uint16), ("day", ctypes.c_uint16),
                ("hour", ctypes.c_uint16), ("minute", ctypes.c_uint16),
                ("second", ctypes.c_uint16), ("milliseconds", ctypes.c_uint16),
            ]

        class DynamicTimeZoneInformation(ctypes.Structure):
            _fields_ = [
                ("Bias", ctypes.c_int32),
                ("StandardName", ctypes.c_wchar * 32),
                ("StandardDate", SystemTime),
                ("StandardBias", ctypes.c_int32),
                ("DaylightName", ctypes.c_wchar * 32),
                ("DaylightDate", SystemTime),
                ("DaylightBias", ctypes.c_int32),
                ("TimeZoneKeyName", ctypes.c_wchar * 128),
                ("DynamicDaylightTimeDisabled", ctypes.c_uint8),
            ]

        get_timezone = kernel32.GetDynamicTimeZoneInformation
        get_timezone.argtypes = [ctypes.POINTER(DynamicTimeZoneInformation)]
        get_timezone.restype = ctypes.c_uint32
        zone = DynamicTimeZoneInformation()
        zone_result = int(get_timezone(ctypes.byref(zone)))
        if zone_result == 0xFFFFFFFF:
            outcomes["clock_apis"] = win_error_status()
        else:
            clock["windows_time_zone_id"] = _status_record(
                zone.TimeZoneKeyName, "GetDynamicTimeZoneInformation"
            )
            clock["standard_name"] = _status_record(
                zone.StandardName, "GetDynamicTimeZoneInformation"
            )
            clock["daylight_name"] = _status_record(
                zone.DaylightName, "GetDynamicTimeZoneInformation"
            )
            clock["standard_transition_rule"] = _status_record(
                {
                    "year": zone.StandardDate.year,
                    "month": zone.StandardDate.month,
                    "day_of_week": zone.StandardDate.day_of_week,
                    "day": zone.StandardDate.day,
                    "hour": zone.StandardDate.hour,
                    "minute": zone.StandardDate.minute,
                    "second": zone.StandardDate.second,
                    "milliseconds": zone.StandardDate.milliseconds,
                },
                "GetDynamicTimeZoneInformation",
            )
            clock["daylight_transition_rule"] = _status_record(
                {
                    "year": zone.DaylightDate.year,
                    "month": zone.DaylightDate.month,
                    "day_of_week": zone.DaylightDate.day_of_week,
                    "day": zone.DaylightDate.day,
                    "hour": zone.DaylightDate.hour,
                    "minute": zone.DaylightDate.minute,
                    "second": zone.DaylightDate.second,
                    "milliseconds": zone.DaylightDate.milliseconds,
                },
                "GetDynamicTimeZoneInformation",
            )
            clock["bias_minutes"] = _status_record(
                zone.Bias, "GetDynamicTimeZoneInformation"
            )
            clock["standard_bias_minutes"] = _status_record(
                zone.StandardBias, "GetDynamicTimeZoneInformation"
            )
            clock["daylight_bias_minutes"] = _status_record(
                zone.DaylightBias, "GetDynamicTimeZoneInformation"
            )
            clock["dynamic_daylight_time_disabled"] = _status_record(
                bool(zone.DynamicDaylightTimeDisabled),
                "GetDynamicTimeZoneInformation",
            )
            clock["time_zone_api_return_code"] = _status_record(
                zone_result, "GetDynamicTimeZoneInformation"
            )
            outcomes["clock_apis"] = {"status": "success"}

        precise = getattr(kernel32, "GetSystemTimePreciseAsFileTime", None)
        observed_utc, utc_source, filetime_ticks = _read_system_utc_detail()
        clock["observed_utc"] = _status_record(
            observed_utc, utc_source
        )
        clock["observed_utc_filetime_100ns"] = _status_record(
            filetime_ticks,
            "FILETIME from GetSystemTimePreciseAsFileTime or fallback",
            "available" if filetime_ticks is not None else "unavailable",
        )
        clock["utc_clock_source"] = _status_record(
            utc_source,
            "GetSystemTimePreciseAsFileTime or documented FILETIME fallback",
        )
        local = datetime.now().astimezone()
        clock["observed_local_time"] = _status_record(
            local.isoformat(timespec="microseconds"),
            "Python local datetime observation",
        )
        offset = local.utcoffset()
        clock["current_utc_offset_seconds"] = _status_record(
            int(offset.total_seconds()) if offset is not None else None,
            "Python local datetime UTC offset",
        )
        clock["precise_utc_api_available"] = _status_record(
            precise is not None, "GetSystemTimePreciseAsFileTime availability"
        )
    except (AttributeError, OSError, OverflowError, ValueError):
        outcomes.setdefault("clock_apis", win_error_status())

    return {
        "computer_names": names,
        "architecture": architecture,
        "memory_status": memory,
        "clock": clock,
        "providers": outcomes,
        "errors": api_errors,
    }


def _query_specification() -> dict[str, Any]:
    queries = {
        name: {"class_name": QUERY_CLASSES[name], "properties": list(properties)}
        for name, properties in QUERY_PROPERTIES.items()
    }
    return {"queries": queries, "registry_properties": list(REGISTRY_PROPERTIES)}


def run_powershell(
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    bootstrap = base64.b64encode(
        POWER_SHELL_BOOTSTRAP.encode("utf-16le")
    ).decode("ascii")
    payload = json.dumps(
        {
            "script": POWER_SHELL_SCRIPT,
            "specification": _query_specification(),
        },
        ensure_ascii=True,
    )
    executable = (
        os.environ.get("WINDIR", r"C:\Windows")
        + r"\System32\WindowsPowerShell\v1.0\powershell.exe"
    )
    try:
        completed = runner(
            [
                executable,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                bootstrap,
            ],
            input=payload,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"provider_failure": {"category": "timeout"}}
    except OSError as exc:
        return {
            "provider_failure": {
                "category": "provider_unavailable",
                "exception_type": type(exc).__name__,
            }
        }
    if completed.returncode != 0:
        return {
            "provider_failure": {
                "category": "powershell_failed",
                "exit_code": completed.returncode,
            }
        }
    try:
        parsed = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        return {"provider_failure": {"category": "malformed_json"}}
    if not isinstance(parsed, dict):
        return {"provider_failure": {"category": "malformed_json"}}
    return parsed


def _normalize_cim_datetime(value: Any) -> tuple[dict[str, Any], str]:
    if not isinstance(value, dict):
        return (
            {
                "provider_serialized_value": value,
                "normalized_utc": None,
                "normalization_status": "malformed_value",
            },
            "malformed_value",
        )
    provider_datetime = value.get("provider_datetime")
    date_time_kind = value.get("date_time_kind")
    ticks = value.get("ticks")
    if (
        not isinstance(provider_datetime, str)
        or date_time_kind not in {"Utc", "Local", "Unspecified"}
        or not isinstance(ticks, int)
        or isinstance(ticks, bool)
    ):
        return (
            {
                "provider_serialized_value": value,
                "normalized_utc": None,
                "normalization_status": "malformed_value",
            },
            "malformed_value",
        )
    try:
        parsed = datetime.fromisoformat(
            provider_datetime.replace("Z", "+00:00")
        )
    except ValueError:
        return (
            {
                "provider_datetime": provider_datetime,
                "date_time_kind": date_time_kind,
                "ticks": ticks,
                "normalized_utc": None,
                "normalization_status": "malformed_value",
            },
            "malformed_value",
        )
    if parsed.tzinfo is None:
        if date_time_kind != "Utc":
            return (
                {
                    "provider_datetime": provider_datetime,
                    "date_time_kind": date_time_kind,
                    "ticks": ticks,
                    "normalized_utc": None,
                    "normalization_status": "timezone_unspecified",
                },
                "available",
            )
        parsed = parsed.replace(tzinfo=timezone.utc)
    normalized = parsed.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    return (
        {
            "provider_datetime": provider_datetime,
            "date_time_kind": date_time_kind,
            "ticks": ticks,
            "normalized_utc": normalized,
            "normalization_status": "normalized",
        },
        "available",
    )


def _safe_provider_results(raw: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, dict):
        raw = {}
    results: dict[str, dict[str, Any]] = {}
    for name in (*QUERY_PROPERTIES, "windows_registry_identity"):
        provider = raw.get(name)
        if not isinstance(provider, dict):
            results[name] = {
                "source": (
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
                    if name == "windows_registry_identity"
                    else QUERY_CLASSES[name]
                ),
                "status": "not_returned",
                "error_category": "not_returned",
                "records_returned": 0,
                "records": [],
            }
            continue
        props = (
            REGISTRY_PROPERTIES
            if name == "windows_registry_identity"
            else QUERY_PROPERTIES[name]
        )
        records = provider.get("records")
        if not isinstance(records, list):
            records = []
        safe_records = []
        for record in records:
            if not isinstance(record, dict):
                continue
            values = record.get("values")
            field_status = record.get("field_status")
            if not isinstance(values, dict):
                values = {}
            if not isinstance(field_status, dict):
                field_status = {}
            safe_values = {key: values.get(key) for key in props}
            safe_field_status = {
                key: field_status.get(key, "not_returned") for key in props
            }
            for key in props:
                value = safe_values[key]
                if (
                    safe_field_status[key] == "available"
                    and isinstance(value, str)
                    and not value.strip()
                ):
                    safe_field_status[key] = "blank_value"
            for field in CIM_DATE_FIELDS.get(name, ()):
                if safe_field_status[field] == "available":
                    normalized, date_status = _normalize_cim_datetime(
                        safe_values[field]
                    )
                    safe_values[field] = normalized
                    if date_status == "malformed_value":
                        safe_field_status[field] = date_status
            safe_records.append(
                {
                    "values": safe_values,
                    "field_units": FIELD_UNITS.get(name, {}).copy(),
                    "field_details": {
                        key: {
                            "value": safe_values[key],
                            "status": safe_field_status[key],
                            "status_reason": FIELD_STATUS_REASONS.get(
                                safe_field_status[key],
                                "No defined status explanation is available.",
                            ),
                            "unit": FIELD_UNITS.get(name, {}).get(key),
                        }
                        for key in props
                    },
                }
            )
        results[name] = {
            "source": (
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
                if name == "windows_registry_identity"
                else QUERY_CLASSES[name]
            ),
            "status": provider.get("status", "provider_failure"),
            "error_category": provider.get("error_category"),
            "native_hresult": provider.get("native_hresult"),
            "records_returned": len(safe_records),
            "records": safe_records,
        }
    return results


def _format_json(value: Any, level: int = 0, records_array: bool = False) -> str:
    indent = "  " * level
    child_indent = "  " * (level + 1)
    if isinstance(value, dict):
        if not value:
            return "{}"
        entries = [
            f"{child_indent}{json.dumps(key, ensure_ascii=False)}: "
            f"{_format_json(item, level + 1, key == 'records')}"
            for key, item in value.items()
        ]
        return "{\n" + ",\n".join(entries) + f"\n{indent}}}"
    if isinstance(value, list):
        if not value:
            return "[]"
        separator = ",\n\n" if records_array else ",\n"
        entries = [
            f"{child_indent}{_format_json(item, level + 1)}"
            for item in value
        ]
        return "[\n" + separator.join(entries) + f"\n{indent}]"
    return json.dumps(value, ensure_ascii=False)


def _api_provider_results(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    allowed = {
        "computer_names": (
            "netbios_name", "dns_hostname", "dns_domain", "dns_fqdn",
            "physical_netbios_name", "physical_dns_hostname",
            "physical_dns_domain", "physical_dns_fqdn",
        ),
        "architecture": (
            "native_system_architecture", "native_processor_architecture_code",
            "native_logical_processor_count", "page_size_bytes",
            "allocation_granularity_bytes", "python_process_architecture",
        ),
        "memory_status": (
            "memory_load_percent", "os_visible_physical_total",
            "available_physical", "commit_limit", "commit_available",
            "user_mode_virtual_address_space",
            "available_user_mode_virtual_address_space",
            "available_extended_virtual",
        ),
        "clock": (
            "uptime_milliseconds", "uptime_seconds",
            "uptime_observation_method", "windows_time_zone_id",
            "standard_name", "daylight_name", "bias_minutes",
            "standard_transition_rule", "daylight_transition_rule",
            "standard_bias_minutes", "daylight_bias_minutes",
            "dynamic_daylight_time_disabled", "time_zone_api_return_code",
            "observed_utc", "utc_clock_source", "observed_local_time",
            "observed_utc_filetime_100ns",
            "current_utc_offset_seconds", "precise_utc_api_available",
        ),
    }
    result: dict[str, Any] = {}
    for section, fields in allowed.items():
        values = raw.get(section)
        if not isinstance(values, dict):
            values = {}
        result[section] = {
            key: values[key]
            for key in fields
            if key in values and isinstance(values[key], dict)
        }
    providers = raw.get("providers")
    result["providers"] = {}
    if isinstance(providers, dict):
        for key, value in providers.items():
            if key in {
                "windows_names_api", "native_system_info_api",
                "global_memory_status_api", "clock_apis",
            } and isinstance(value, dict):
                result["providers"][key] = {
                    field: value[field]
                    for field in ("status", "error_category", "win32_error_code")
                    if field in value
                }
    raw_errors = raw.get("errors")
    result["errors"] = []
    if isinstance(raw_errors, list):
        for error in raw_errors:
            if isinstance(error, dict):
                result["errors"].append(
                    {
                        field: error[field]
                        for field in (
                            "provider", "field", "category", "win32_error_code"
                        )
                        if field in error
                    }
                )
    return result


def _limitations() -> list[str]:
    return [
        "This is a live snapshot; independently queried providers may observe different moments.",
        "Hardware serials, UUIDs, firmware dates and model strings are firmware/provider supplied, may be blank, duplicated or placeholders, and are not guaranteed unique.",
        "Win32_VideoController.AdapterRAM is preserved as the provider-reported uint32 byte value; it is not verified dedicated graphics memory and may differ from graphics memory shown by Windows Settings, especially for integrated graphics.",
        "Win32_ComputerSystemProduct.UUID is a firmware/provider product UUID and is not asserted to equal the Windows Settings About Device ID or the registry ProductId; these identifiers remain separate.",
        "Win32_OperatingSystem.Caption and the selected CurrentVersion registry ProductName are preserved as independent source values and can conflict; use the operating-system provider Caption for the OS edition reported by this collector, without rewriting the registry value.",
        "Win32_DiskDrive.Size is physical disk capacity; logical drive and volume Size/FreeSpace are separate provider observations. No derived aggregate used-space or capacity value is calculated, and summing overlapping logical-disk and volume views can double-count storage.",
        "Windows Feature Experience Pack version and the Settings About Pen and Touch summary are not collected; their values cannot be validated or inferred from the selected A30 providers.",
        "HypervisorPresent is one virtualization indicator and does not identify a definitive virtualization platform.",
        "Installed module capacity, OS-visible physical memory, and currently available memory are distinct values.",
        "GlobalMemoryStatusEx commit limit/available values describe system commit accounting, not the size or contents of pagefile.sys.",
        "Win32_QuickFixEngineering lists Component Based Servicing updates only; it is not a complete Windows Update inventory.",
        "Win32_QuickFixEngineering.InstalledOn is preserved as a provider string because its date format can be ambiguous.",
        "The current UTC offset and daylight configuration must not be applied blindly to historical timestamps; historic time-zone rules can differ.",
        "Processor counts are provider observations; this collector does not claim exhaustive enumeration across all Windows processor groups.",
        "Obtaining a timestamp does not establish that the machine clock is accurate or synchronized.",
        "WMI disk, partition and volume relationships are provider associations and are not necessarily one-to-one.",
        "No product keys, activation secrets, RAM/pagefile contents, TPM secrets, driver inventory, software inventory, users, groups, network adapters, BitLocker state, or event logs are collected.",
    ]


def collect_system_information(
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    provider: Callable[[int], dict[str, Any]] = run_powershell,
    api_provider: Callable[[], dict[str, Any]] = _windows_api_snapshot,
) -> dict[str, Any]:
    started, start_source, start_filetime = _read_system_utc_detail()
    api_raw = api_provider()
    api = _api_provider_results(api_raw)
    raw = provider(timeout_seconds)
    errors: list[dict[str, Any]] = []
    if not isinstance(raw, dict):
        raw = {"provider_failure": {"category": "malformed_json"}}
    if raw.get("provider_failure"):
        failure = raw["provider_failure"]
        category = (
            failure.get("category", "provider_failure")
            if isinstance(failure, dict)
            else "provider_failure"
        )
        for name in (*QUERY_PROPERTIES, "windows_registry_identity"):
            raw[name] = {
                "status": category,
                "error_category": category,
                "records": [],
            }
        errors.append(
            {
                "provider": "PowerShell",
                "category": category,
                "message": "PowerShell returned no usable structured provider result.",
            }
        )
    queries = _safe_provider_results(raw)
    provider_outcomes = {
        name: {
            "source": value["source"],
            "status": value["status"],
            "error_category": value["error_category"],
            "native_hresult": value["native_hresult"],
            "records_returned": value["records_returned"],
        }
        for name, value in queries.items()
    }
    for name, outcome in provider_outcomes.items():
        if outcome["status"] not in {"success", "unsupported"}:
            errors.append(
                {
                    "provider": outcome["source"],
                    "category": outcome["error_category"] or outcome["status"],
                    "native_hresult": outcome["native_hresult"],
                }
            )
    for api_name, outcome in api.get("providers", {}).items():
        if outcome.get("status") != "success":
            errors.append(
                {
                    "provider": api_name,
                    "category": outcome.get("error_category") or outcome.get("status"),
                    "win32_error_code": outcome.get("win32_error_code"),
                }
            )
    errors.extend(api.get("errors", []))
    field_errors = []
    for result in queries.values():
        for index, record in enumerate(result["records"]):
            for field, details in record["field_details"].items():
                status = details["status"]
                if status in {
                    "not_exposed", "not_returned", "malformed_value"
                }:
                    field_errors.append(
                        {
                            "provider": result["source"],
                            "record_index": index,
                            "field": field,
                            "category": status,
                        }
                    )
    core_failed = all(
        provider_outcomes[name]["status"] != "success"
        for name in ("operating_system", "computer_system")
    )
    partial = bool(errors) or any(
        issue["category"] in {"not_returned", "malformed_value"}
        for issue in field_errors
    )
    status = EXIT_FAILURE if core_failed else (
        EXIT_PARTIAL if partial else EXIT_SUCCESS
    )
    end, end_source, end_filetime = _read_system_utc_detail()
    started_datetime = datetime.fromisoformat(started.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )
    observed_end_datetime = datetime.fromisoformat(
        end.replace("Z", "+00:00")
    ).astimezone(timezone.utc)
    collection_clock_adjusted = observed_end_datetime < started_datetime
    if collection_clock_adjusted:
        end = started
        end_source = start_source
        end_filetime = start_filetime
        observed_end_datetime = started_datetime
    timezone_record = api.get("clock", {}).get("windows_time_zone_id")
    timezone_id = (
        timezone_record.get("value")
        if isinstance(timezone_record, dict)
        and timezone_record.get("status") == "available"
        and isinstance(timezone_record.get("value"), str)
        and timezone_record.get("value").strip()
        else None
    )
    architecture = api.get("architecture", {})
    return {
        "artifact_id": ARTIFACT_ID,
        "collection_started_at_utc": {
            "value": started,
            "source": start_source,
            "filetime_100ns_since_1601": start_filetime,
        },
        "collection_ended_at_utc": {
            "value": end,
            "source": end_source,
            "filetime_100ns_since_1601": end_filetime,
        },
        "collection_started_at_local": {
            "value": started_datetime.astimezone().isoformat(),
            "source": "Converted from collection_started_at_utc using the local system time zone",
        },
        "collection_ended_at_local": {
            "value": observed_end_datetime.astimezone().isoformat(),
            "source": "Converted from collection_ended_at_utc using the local system time zone",
        },
        "collection_time_zone_id": {
            "value": timezone_id,
            "source": (
                timezone_record.get("source", "GetDynamicTimeZoneInformation")
                if isinstance(timezone_record, dict)
                else "GetDynamicTimeZoneInformation"
            ),
            "status": "available" if timezone_id is not None else "unavailable",
        },
        "collection_clock_adjusted": collection_clock_adjusted,
        "status": {
            EXIT_SUCCESS: "success",
            EXIT_PARTIAL: "partial",
            EXIT_FAILURE: "failed",
        }[status],
        "providers": provider_outcomes,
        "computer_identity": {
            "computer_system": queries["computer_system"],
            "system_product": queries["computer_product"],
            "computer_names": api.get("computer_names", {}),
        },
        "windows_identity": {
            "operating_system": queries["operating_system"],
            "version_registry": queries["windows_registry_identity"],
            "architecture": architecture,
        },
        "firmware_and_motherboard": {
            "bios": queries["bios"],
            "baseboard": queries["baseboard"],
        },
        "processors": queries["processors"],
        "memory": {
            "physical_memory_modules": queries["physical_memory"],
            "memory_arrays": queries["physical_memory_arrays"],
            "os_memory_counters": {
                "source": "Win32_OperatingSystem",
                "records": queries["operating_system"]["records"],
            },
            "observed_memory_status": api.get("memory_status", {}),
        },
        "storage": {
            "physical_disks": queries["physical_disks"],
            "partitions": queries["partitions"],
            "logical_disks": queries["logical_disks"],
            "volumes": queries["volumes"],
            "disk_to_partition_relationships": queries["disk_to_partition"],
            "partition_to_logical_disk_relationships": queries[
                "partition_to_logical_disk"
            ],
            "mount_points": queries["mount_points"],
        },
        "display_hardware": queries["display_adapters"],
        "update_overview": {
            **queries["quick_fixes"],
            "coverage_limitation": (
                "Win32_QuickFixEngineering reports Component Based Servicing "
                "updates only, not all Windows updates."
            ),
        },
        "clock_and_time_zone": api.get("clock", {}),
        "field_errors": field_errors,
        "errors": errors,
        "limitations": _limitations(),
    }


def write_json(
    path: str | Path,
    document: dict[str, Any],
    overwrite: bool = False,
) -> Path:
    destination = Path(path).expanduser().resolve()
    if destination.is_dir():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
        destination = destination / f"System Information-{stamp}.json"
    if not destination.parent.is_dir():
        raise FileNotFoundError(
            f"Output directory does not exist: {destination.parent}"
        )
    payload = (_format_json(document) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temporary, destination)
        else:
            os.link(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return destination


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only Windows system-information snapshot."
    )
    parser.add_argument(
        "--output",
        help="Output JSON path or an existing output folder.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly permit replacing an existing output file.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"PowerShell provider timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS}).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    raw_args = list(sys.argv[1:] if argv is None else argv)
    try:
        args = parser.parse_args(raw_args)
        if args.timeout <= 0:
            print("--timeout must be greater than zero.", file=sys.stderr)
            return EXIT_FAILURE
        output_value = args.output or os.environ.get("CUSTOS_A30_OUTPUT")
        if not output_value and sys.stdin.isatty():
            entered = input(
                "Enter an output JSON path or existing folder "
                    "(press Enter for the System Information_Output folder): "
            ).strip()
            output_value = entered or None
        document = collect_system_information(args.timeout)
        destination = output_value or (
            Path(__file__).resolve().parent / "System Information_Output"
        )
        if not output_value:
            Path(destination).mkdir(parents=True, exist_ok=True)
        written = write_json(
            destination, document, overwrite=args.overwrite
        )
    except KeyboardInterrupt:
        print("A30 collection cancelled.", file=sys.stderr)
        return EXIT_FAILURE
    except FileExistsError as exc:
        print(
            f"Output already exists; use --overwrite to replace it: {exc}",
            file=sys.stderr,
        )
        return EXIT_FAILURE
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"A30 collection/output failure: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    exit_code = {
        "success": EXIT_SUCCESS,
        "partial": EXIT_PARTIAL,
        "failed": EXIT_FAILURE,
    }[document["status"]]
    summary = {
        EXIT_SUCCESS: "completed successfully",
        EXIT_PARTIAL: "completed with partial results",
        EXIT_FAILURE: "failed",
    }[exit_code]
    print(
        f"A30 collection {summary} (exit code {exit_code}): "
        f"system snapshot written to {written}"
    )
    return exit_code


def _run_with_integrity_manifest(main):
    import builtins
    import datetime as _integrity_datetime
    import hashlib as _integrity_hashlib
    import json as _integrity_json
    import os as _integrity_os
    import secrets as _integrity_secrets
    import sys as _integrity_sys
    from pathlib import Path as _IntegrityPath

    arguments = _integrity_sys.argv[1:]
    if any(argument in {"-h", "--help"} for argument in arguments):
        return main()

    launcher_output_response = None
    launcher_output_directory = None
    collector_directory = _IntegrityPath(_integrity_sys.argv[0]).resolve().parent
    artifact_id = collector_directory.name.split(" ", 1)[0]
    artifact_display_name = collector_directory.name.split(" - ", 1)[1]
    default_output_directory = collector_directory / f"{artifact_display_name}_Output"
    output_option_by_id = {
        "A01": "--output-dir", "A02": "--output", "A03": "--output",
        "A04": "--output", "A05": "--output", "A06": "--output",
        "A17": "--output-dir", "A18": "--output-dir", "A23": "--output",
        "A25": "--output", "A30": "--output", "A31": "--output",
        "A40": "--output", "A41": "--output", "A42": "--output",
        "A46": "--output", "A47": "--output", "A48": "--output",
        "A51": "--output-dir", "A52": "--output-dir",
        "A59": "--output-dir", "A66": "--output-dir",
        "A68": "--output-dir", "X14": "--output-dir",
        "X15": "--output-dir", "X16": "--output-dir",
        "X18": "--output-dir", "X20": "--output-dir",
        "X22": "--output-dir", "X23": "--output-dir",
        "X26": "--output-dir", "X29": "--output-dir",
        "X32": "--output-dir",
    }
    has_output = any(
        argument.partition("=")[0] in {
            "-o", "--out", "--output", "--output-dir", "--output-directory"
        }
        for argument in arguments
    )
    if not has_output:
        output_option = output_option_by_id.get(artifact_id)
        if output_option is None:
            raise RuntimeError(f"No launcher output option is configured for {artifact_id}.")
        selected_folder = ""
        if _integrity_os.environ.get("CUSTOS_LAUNCHER_OUTPUT_PROMPT") == "1":
            selected_folder = input(
                f"Enter a custom output folder, or press Enter for the default [{default_output_directory}]: "
            ).strip().strip("\"'")
        output_directory = _IntegrityPath(
            _integrity_os.path.expandvars(
                _integrity_os.path.expanduser(selected_folder)
            )
        ) if selected_folder else default_output_directory
        output_directory = output_directory.resolve()
        output_directory.mkdir(parents=True, exist_ok=True)
        launcher_output_directory = output_directory
        if artifact_id in {
            "A01", "A17", "A18", "A23", "A25", "A30", "A31",
            "A40", "A41", "A42", "A46", "A47", "A48", "A51",
            "A52", "A59", "A66", "A68",
        }:
            launcher_output_response = str(output_directory)
        else:
            arguments.extend((output_option, str(output_directory)))
            _integrity_sys.argv[:] = [_integrity_sys.argv[0], *arguments]

    def utc_now():
        return _integrity_datetime.datetime.now(
            _integrity_datetime.timezone.utc
        ).isoformat(timespec="microseconds").replace("+00:00", "Z")

    def snapshot(directory):
        if not directory.is_dir():
            return {}
        result = {}
        skipped = {".git", ".venv", "venv", "__pycache__", "output & validation"}
        def raise_walk_error(error):
            raise error
        for current, folders, filenames in _integrity_os.walk(
            directory, onerror=raise_walk_error
        ):
            folders[:] = [name for name in folders if name.casefold() not in skipped]
            for filename in filenames:
                path = _IntegrityPath(current) / filename
                if path.is_symlink():
                    continue
                info = path.stat()
                result[path] = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        return result

    collector_directory = _IntegrityPath(_integrity_sys.argv[0]).resolve().parent
    output_options = {
        "-o": False, "--out": False, "--output": False,
        "--output-dir": True, "--output-directory": True,
        "--destination": True, "--dest": True,
    }
    selected = None
    for index, argument in enumerate(arguments):
        option, separator, value = argument.partition("=")
        if option in output_options:
            if separator:
                selected = (value, output_options[option])
            elif index + 1 < len(arguments) and not arguments[index + 1].startswith("-"):
                selected = (arguments[index + 1], output_options[option])
    if selected is None:
        configured = next((
            value for name, value in _integrity_os.environ.items()
            if name.startswith("CUSTOS_") and "OUTPUT" in name and value.strip()
        ), None)
        if configured:
            selected = (configured, False)
    if selected is None or not selected[0].strip():
        output_root = default_output_directory
    else:
        value, is_directory = selected
        output_root = _IntegrityPath(
            _integrity_os.path.expandvars(
                _integrity_os.path.expanduser(value.strip().strip("\"'"))
            )
        )
        if not output_root.is_absolute():
            output_root = _IntegrityPath.cwd() / output_root
        if not is_directory and output_root.suffix and not output_root.is_dir():
            output_root = output_root.parent
        output_root = output_root.resolve()

    if launcher_output_directory is not None:
        output_root = launcher_output_directory

    before = snapshot(output_root)
    started_at = utc_now()
    original_input = builtins.input

    def tracked_input(prompt=""):
        nonlocal output_root, before, launcher_output_response
        is_output_prompt = any(
            word in prompt.casefold() for word in ("output", "destination", "save")
        )
        if is_output_prompt and launcher_output_response is not None:
            response = launcher_output_response
            launcher_output_response = None
        elif is_output_prompt and not _integrity_sys.stdin.isatty():
            response = str(default_output_directory)
        else:
            response = original_input(prompt)
            if is_output_prompt and not response.strip():
                response = str(default_output_directory)
        if is_output_prompt:
            value = response.strip().strip("\"'")
            if value:
                output_root = _IntegrityPath(
                    _integrity_os.path.expandvars(
                        _integrity_os.path.expanduser(value)
                    )
                )
                if not output_root.is_absolute():
                    output_root = _IntegrityPath.cwd() / output_root
                output_root = output_root.resolve()
                before = snapshot(output_root)
        return response

    result = 0
    failure = None
    builtins.input = tracked_input
    try:
        result = main()
    except BaseException as error:
        failure = error
        result = error.code if isinstance(error, SystemExit) and isinstance(error.code, int) else 1
    finally:
        builtins.input = original_input

    ended_at = utc_now()
    artifact_id = collector_directory.name.split(" ", 1)[0]
    artifact_display_name = collector_directory.name.split(" - ", 1)[1]
    run_timestamp = _integrity_datetime.datetime.now(
        _integrity_datetime.timezone.utc
    ).strftime("%Y%m%dT%H%M%S.%fZ")
    manifest_path = output_root / f"{artifact_display_name}_Hash & Timestamp Report.json"
    outputs = []
    verification_errors = 0
    for path, metadata in snapshot(output_root).items():
        if path == manifest_path or before.get(path) == metadata:
            continue
        try:
            info = path.stat()
            current = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if current != metadata:
                raise RuntimeError(f"Output changed before SHA-256 calculation: {path}")
            digest = _integrity_hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            info = path.stat()
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != current:
                raise RuntimeError(f"Output changed during SHA-256 calculation: {path}")
        except (OSError, RuntimeError) as error:
            verification_errors += 1
            print(f"SHA-256 verification failed for {path}: {error}", file=_integrity_sys.stderr)
            outputs.append({
                "path": path.relative_to(output_root).as_posix(),
                "size_bytes": metadata[0],
                "sha256": None,
                "verification_status": "failed",
                "error": str(error),
            })
            continue
        outputs.append({
            "path": path.relative_to(output_root).as_posix(),
            "size_bytes": metadata[0],
            "sha256": digest.hexdigest(),
            "verification_status": "verified",
        })
    outputs.sort(key=lambda item: item["path"].casefold())
    verification_status = "failed" if verification_errors else "verified" if outputs else "not_run"
    if verification_errors and result == 0:
        result = 1
    report = {
        "artifact_id": artifact_id,
        "collector": _IntegrityPath(_integrity_sys.argv[0]).name,
        "hash_algorithm": "SHA-256",
        "verification_status": verification_status,
        "verification_method": "File size, modification time, and creation time remained unchanged during SHA-256 calculation.",
        "collection_started_at_utc": started_at,
        "collection_ended_at_utc": ended_at,
        "collection_status": "partial" if result == 1 else "completed" if result == 0 else "failed",
        "collection_exit_code": result,
        "output_directory": str(output_root),
        "outputs": outputs,
    }
    if failure is not None and not isinstance(failure, SystemExit):
        report["error"] = {"type": type(failure).__name__, "message": str(failure)}

    if not output_root.is_dir() and result != 0:
        output_root = default_output_directory
        output_root.mkdir(parents=True, exist_ok=True)
        manifest_path = output_root / manifest_path.name
        report["output_directory"] = str(output_root)
        report["outputs"] = []
    else:
        output_root.mkdir(parents=True, exist_ok=True)
    temporary_path = manifest_path.with_name(
        f".{manifest_path.name}.{_integrity_secrets.token_hex(4)}.tmp"
    )
    report = _canonical_integrity_report(report)
    result = report["collection_exit_code"]
    try:
        with temporary_path.open("x", encoding="utf-8", newline="\n") as stream:
            _integrity_json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            _integrity_os.fsync(stream.fileno())
        _integrity_os.replace(temporary_path, manifest_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    if failure is not None:
        raise failure.with_traceback(failure.__traceback__)
    return result


if __name__ == "__main__":
    raise SystemExit(_run_with_integrity_manifest(main))
