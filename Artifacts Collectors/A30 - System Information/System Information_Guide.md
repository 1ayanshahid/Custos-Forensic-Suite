# A30 — System Information

A30 takes a read-only, point-in-time snapshot of Windows identity, computer and
hardware information, storage topology, selected update metadata, and current
clock/time-zone context. It does not acquire files, memory, pagefile contents,
or disk images.

## 1. Collection and providers

The collector is [`collector.py`](./collector.py).
Its reusable entry point is `collect_system_information()`. The command-line
interface writes one UTF-8 JSON document to a destination selected by the
operator. CIM classes and the narrow Windows version registry query are run as
independent PowerShell queries. A missing class or denied query is recorded
without discarding successful categories. PowerShell is started with
`-NoProfile`, `-NonInteractive`, a fixed embedded script, UTF-8 input/output,
structured JSON, and a 120-second default timeout. It receives no output path
or other user-controlled expression.

The Python portion uses only the standard library. It uses documented
`kernel32` APIs through `ctypes` for native architecture, computer-name forms,
memory observations, uptime, time-zone configuration, and UTC clock
observations. No Python packages need to be installed.

### Microsoft references

The property selections and API meanings are based on these Microsoft
references:

| Provider or API | Official reference |
|---|---|
| `Win32_OperatingSystem` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem) |
| `Win32_ComputerSystem` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem) |
| `Win32_ComputerSystemProduct` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystemproduct) |
| `Win32_BIOS` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-bios) |
| `Win32_BaseBoard` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-baseboard) |
| `Win32_Processor` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-processor) |
| `Win32_PhysicalMemory` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-physicalmemory) |
| `Win32_PhysicalMemoryArray` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-physicalmemoryarray) |
| `Win32_LogicalDisk` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisk) |
| `Win32_Volume` | [Microsoft Learn, archived VDS WMI reference](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/vdswmi/win32-volume) |
| `Win32_DiskDrive` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-diskdrive) |
| `Win32_DiskPartition` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-diskpartition) |
| `Win32_DiskDriveToDiskPartition` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-diskdrivetodiskpartition) |
| `Win32_LogicalDiskToPartition` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisktopartition) |
| `Win32_MountPoint` | [Microsoft Learn, archived VDS WMI reference](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/vdswmi/win32-mountpoint) |
| `Win32_VideoController` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-videocontroller) |
| `Win32_QuickFixEngineering` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering) |
| `GetNativeSystemInfo` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getnativesysteminfo) |
| `GlobalMemoryStatusEx` / `MEMORYSTATUSEX` | [function](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex), [structure](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex) |
| `GetComputerNameExW` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexw) |
| `GetDynamicTimeZoneInformation` and its structure | [Function](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-getdynamictimezoneinformation), [structure](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-dynamic_time_zone_information) |
| `GetSystemTimePreciseAsFileTime` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimepreciseasfiletime) |
| `GetSystemTimeAsFileTime` fallback | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime) |
| `GetTickCount64` | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64) |

The registry supplement reads only these named values from
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`: `ProductName`,
`EditionID`, `DisplayVersion`, `ReleaseId`, `CurrentBuild`,
`CurrentBuildNumber`, `UBR`, `BuildLabEx`, `InstallationType`, and `ProductId`.
It does not query product keys, activation secrets, or entire registry
branches. Registry values supplement, rather than overwrite, CIM fields.

## 2. Requirements and elevation

- Windows with Windows PowerShell 5.1, CIM/WMI providers, and the selected
  classes available. The VDS WMI volume/mount-point classes may be absent on
  some systems; their result will be reported as unsupported.
- The existing interpreter at
  `E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe`.
- Python standard library only; no dependency installation is required.
- Use `launch.bat` for supported collection. It checks elevation and requests
  administrator consent through Windows UAC before starting Python. Cancelling
  or failing elevation does not start collection. The Python collector itself
  does not silently self-elevate; a direct Python invocation runs with the
  caller's current token and can therefore produce partial results.
- Administrator rights improve access to providers, but do not guarantee that
  every provider/property is present or readable.

The collector performs read-only CIM queries, reads a narrow registry value
set, and calls read-only system-information APIs. It does not modify Windows,
the registry, time, time zone, firmware, Secure Boot, TPM, or storage settings.
It does not install anything, restart services, contact external services, or
run hardware diagnostics.

## 3. Launching

### Double-click

Double-click `launch.bat`. If the process is not already elevated, approve the
Windows UAC prompt first; only after elevation succeeds does the collector
prompt for a JSON path or existing output folder. Press Enter to use the A30
folder. The window remains open for the result or an error. Cancelling UAC
does not start collection or ask for an output location.

### Command Prompt

```bat
"E:\FYP Custos Forensic Suite\artifacts\A30 - System Information\launch.bat" --output "E:\System Information_Output\System Information.json"
```

Use `--overwrite` only when intentionally replacing the exact named file:

```bat
"E:\FYP Custos Forensic Suite\artifacts\A30 - System Information\launch.bat" --output "E:\System Information_Output\System Information.json" --overwrite
```

An existing directory can be supplied instead of a filename; A30 creates a
timestamped `System Information-*.json` file there.

### Direct Python / future caller

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" "E:\FYP Custos Forensic Suite\artifacts\A30 - System Information\collector.py" --output "E:\System Information_Output\System Information.json"
```

The callable API is `collect_system_information(timeout_seconds=120)`;
`write_json(path, document, overwrite=False)` writes a returned document.
Neither function needs a fixed evidence destination. The CLI options are:

| Option | Meaning |
|---|---|
| `--output PATH` | JSON filename or existing directory. If omitted, an interactive terminal asks for a destination; a non-interactive caller defaults to this artifact folder. |
| `--overwrite` | Explicitly replace an existing named file. It is not needed for a new file or when writing into an existing directory. |
| `--timeout SECONDS` | Positive timeout for the PowerShell collection process; default 120 seconds. |

The output is UTF-8 JSON. A named output is created without replacement by
default. A collision prints an error and leaves the existing file unchanged.
Output is written to a temporary file in the same directory and then linked or
atomically replaced. The output parent directory must already exist.

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | `success`: required OS and computer identity queries succeeded; no provider error was reported. Unsupported optional providers and explicitly unexposed fields are documented, not treated as collection failures. |
| `1` | `partial`: at least one provider/API failed, was denied, timed out, or returned an incomplete field result while useful data was collected. |
| `2` | `failed`: both core `Win32_OperatingSystem` and `Win32_ComputerSystem` queries failed, or the collector could not complete/write the output. Argument parsing also follows `argparse` failure behavior. |

Provider failures may produce a JSON document with `"status": "failed"` and
exit code 2 when output writing remains possible. A write failure is printed
to stderr and cannot itself be recorded in the file that could not be written.
The collector and launcher print an explicit terminal summary: exit code `0`
means collection completed successfully, `1` means collection completed with
partial results, and `2` means collection failed. A UAC cancellation is
reported separately and no collection is started.

## 4. Generated file and JSON shape

Each invocation writes exactly one snapshot JSON document; it does not create
per-provider JSON files, logs, manifests, or temporary sidecar files.

Every CIM section contains:

| Field | Meaning |
|---|---|
| `source` | The exact CIM class or registry path that produced the records. |
| `status` | `success`, `unsupported`, `access_denied`, `provider_failure`, `timeout`, `malformed_json`, `powershell_failed`, `provider_unavailable`, or `not_returned`, as applicable. A successful query with no instances is still `success` with an empty `records` array. |
| `error_category` | Failure category, or JSON `null` when there was no provider failure. |
| `native_hresult` | HRESULT string when PowerShell exposed one; otherwise JSON `null`. |
| `records_returned` | Count of normalized records. |
| `records` | Always an array, including when exactly one object is returned. |

Each record has `values` (the selected provider fields), `field_units`
(unit/format descriptions for fields where units or date semantics matter),
and `field_details`, where every field name directly contains its exact
`value`, `status`, `status_reason`, and `unit`. There is no separate
`field_status` object in generated reports. For example,
`field_details.CurrentClockSpeed.value` is the clock speed value; its sibling
`status` identifies availability, `status_reason` states why, and `unit` is
`MHz`. The original `values` and `field_units` maps remain available alongside
the exact per-field details. Thus `"available"` is never a replacement for
the answer: it means a non-null answer is in that same field's `value` (and in
the corresponding `values` property).

A field status is:

- `available`: provider returned a non-null value. Zero and `false` remain
  valid values.
- `blank_value`: provider returned an empty or whitespace-only string. The
  original string remains in `value`; this may indicate a blank firmware or
  provider field and is not treated as a query failure.
- `null_value`: the provider exposed the field but returned null.
- `not_exposed`: the selected provider instance did not expose that property.
  This is also listed in `field_errors`.
- `not_returned`: the wrapper could not find a selected property in its
  structured provider response. This is reported as incomplete collection.
- `malformed_value` means an association reference or CIM date wrapper had an
  unexpected type/format. The raw provider serialization is retained where
  available; the condition is listed in `field_errors` and makes the result
  partial.
- A class-level `unsupported` outcome means that class/query could not be
  obtained; it is not proof that corresponding hardware or a feature is absent.

API observations are field objects with `value`, `source`, and `status`.
Memory API fields also include `unit`. Start/end timestamps have `value` and
`source`. For CIM records, `source` at the containing section applies to each
field; it is not repeated for every property. Status explanations are stored
in `field_details.<name>` rather than in a separate status map.
`field_details.<name>.unit` is
the exact documented unit when one is defined in the collector. It is `null`
for text, identifiers, Boolean flags, provider-native enumerations, or fields
without a verified unit; the collector does not guess units.

Records in a `records` array are separated by a blank line for readability.
This is legal JSON whitespace and does not change how JSON parsers read the
document.

CIM `DateTime` values use a value object with `provider_datetime` (the
invariant .NET round-trip value produced from the CIM `DateTime`),
`date_time_kind`, `ticks` (original .NET 100-nanosecond ticks), `normalized_utc`
(ISO 8601 UTC with `Z` when a time-zone offset is available), and
`normalization_status`. `timezone_unspecified` preserves the original value
without guessing an offset; malformed wrappers retain
`provider_serialized_value` and have a null normalized value. The normalized
string has microsecond precision; the original round-trip string and ticks
preserve any additional 100-nanosecond precision. `InstalledOn` from QFE
remains the exact ambiguous provider string and is not parsed.

### Root fields and sections

| JSON path | Contents |
|---|---|
| `artifact_id` | Literal artifact identifier `A30`. |
| `collection_started_at_utc`, `collection_ended_at_utc` | UTC timestamp objects with ISO `value`, clock `source`, and original `filetime_100ns_since_1601` when available. The original tick is retained because ISO text has microsecond precision. Collection is not atomic. |
| `collection_started_at_local`, `collection_ended_at_local` | Objects with local ISO 8601 `value` including the UTC offset, converted from the corresponding UTC boundary instant, plus conversion `source`. |
| `collection_time_zone_id` | `value`, `source`, and `status` for the Windows time-zone key returned by `GetDynamicTimeZoneInformation`; the value is null if unavailable. |
| `collection_clock_adjusted` | Boolean; true if the end UTC observation was earlier than the start and was clamped to the start to keep the interval ordered. |
| `status` | Overall `success`, `partial`, or `failed`. |
| `providers` | Outcome index for every CIM class/registry query. Each entry contains `source`, `status`, `error_category`, `native_hresult`, and `records_returned`. |
| `computer_identity.computer_system` | `Win32_ComputerSystem` identity/configuration records. |
| `computer_identity.system_product` | `Win32_ComputerSystemProduct` vendor/product/identifier records. |
| `computer_identity.computer_names` | NetBIOS, DNS host/domain/FQDN, and physical computer-name forms from `GetComputerNameExW`. |
| `windows_identity.operating_system` | OS edition/caption/version/build, architecture, paths, locale, flags, install/boot times, and WMI memory counters from `Win32_OperatingSystem`. |
| `windows_identity.version_registry` | The narrowly selected current-version values listed above. `UBR` is the build revision when exposed; registry fields do not replace CIM values. `ProductId` is not a product key. |
| `windows_identity.architecture` | Native architecture and related system properties from `GetNativeSystemInfo`, plus architecture/bitness of this Python process. |
| `firmware_and_motherboard.bios` | BIOS/UEFI vendor, version, release time, serial and SMBIOS fields from `Win32_BIOS`. The provider may not identify firmware boot mode. |
| `firmware_and_motherboard.baseboard` | Board manufacturer/model/product/version/serial/part/SKU/hosting-board fields from `Win32_BaseBoard`. |
| `processors` | One record per `Win32_Processor` provider instance. Capability flags describe reported hardware/firmware support; they do not prove a feature is enabled or usable. |
| `memory.physical_memory_modules` | Per-module capacity, speeds, manufacturer/part/serial, locator, widths, type, form factor and voltage from `Win32_PhysicalMemory`. |
| `memory.memory_arrays` | Memory-array capacity/device count/type-related information from `Win32_PhysicalMemoryArray`. |
| `memory.os_memory_counters` | The OS-visible/free physical and OS virtual/paging counters from the same `Win32_OperatingSystem` record, retained with that provider's per-field details and units. |
| `memory.observed_memory_status` | Volatile `GlobalMemoryStatusEx` observations: load percent, physical total/available bytes, commit limit/available bytes, and virtual-address-space statistics. |
| `storage.physical_disks` | Physical disk devices from `Win32_DiskDrive`. |
| `storage.partitions` | Partition identifiers, size, offset, block and boot-related fields from `Win32_DiskPartition`. |
| `storage.logical_disks` | Drive-letter logical disks, filesystem, label, volume serial, size/free bytes, and provider fields from `Win32_LogicalDisk`. |
| `storage.volumes` | Volume IDs, drive letters, names/mount paths, labels, filesystem, capacity/free bytes, and boot/system flags from `Win32_Volume`. |
| `storage.disk_to_partition_relationships` | `Antecedent`/`Dependent` references from `Win32_DiskDriveToDiskPartition`, normalized to target `class_name` and key fields. |
| `storage.partition_to_logical_disk_relationships` | `Antecedent`/`Dependent` references from `Win32_LogicalDiskToPartition`, normalized to target `class_name` and key fields. |
| `storage.mount_points` | Volume-to-directory association (`Directory`, `Volume`) from `Win32_MountPoint`, normalized to target `class_name` and key fields if the VDS WMI provider is available. |
| `display_hardware` | Selected adapter, driver-version/date and current display-mode fields from `Win32_VideoController`; this is not a driver inventory. |
| `update_overview` | Selected `Win32_QuickFixEngineering` fields and `coverage_limitation`. |
| `clock_and_time_zone` | Uptime, UTC/local time observations, UTC offset, Windows zone identifier/names, transition rules, bias values, API return and UTC-source metadata. |
| `field_errors` | Per-provider, per-record field errors for `not_exposed`, `not_returned`, malformed association references, or malformed CIM date wrappers. |
| `errors` | Query/API-level failures with provider name, category and, when available, HRESULT or Win32 error code. No raw PowerShell error transcript is copied into the JSON. |
| `limitations` | Collector-wide known coverage and interpretation limitations. |

## 5. Coverage table

| Information | Provider/API | Meaning and units | Availability or limitation |
|---|---|---|---|
| OS caption, description, version, build, service-pack/build type, OS architecture, product type, SKU and suite flags | `Win32_OperatingSystem` | Provider strings/enumeration values/flags; architecture describes Windows, not Python | Null or unexposed properties remain explicit; version/build supplement comes from the separately labeled registry query. |
| Edition, display version, release ID, build revision, install type and product ID | Selected values under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | Registry-native strings/numbers; `UBR` is a build revision when available | Only named values are queried; no product key or full branch dump. |
| Computer, DNS, domain/workgroup, role, manufacturer, model and system type | `Win32_ComputerSystem` | Provider values; domain role is a Windows enumeration | `DomainRole`, `SystemType`, `PCSystemType`, and `PCSystemTypeEx` are preserved as reported; the report does not infer platform beyond explicit indicators. |
| NetBIOS/DNS computer names | `GetComputerNameExW` | Name strings | Some forms, especially domain-qualified names on non-domain systems, may be unavailable. |
| Product UUID and identifiers | `Win32_ComputerSystemProduct` | Firmware/provider strings | May be blank, placeholder, duplicated or not unique. |
| Virtualization indicator | `Win32_ComputerSystem.HypervisorPresent` | Boolean provider observation | Not sufficient to identify a virtualization platform. A null/unavailable value does not prove virtualization is absent. |
| BIOS/UEFI and motherboard identifiers | `Win32_BIOS`, `Win32_BaseBoard` | Firmware strings, SMBIOS version numbers and CIM date | May be firmware-supplied placeholder data. Firmware mode, Secure Boot and TPM are not asserted. |
| Processor identity, architecture, socket, core/thread and clock values | `Win32_Processor` | Architecture code; clock MHz; counts as reported | Per-provider instances; no exhaustive processor-group claim. |
| Virtualization capability properties | `Win32_Processor` | Boolean/provider capability flags | Capability is distinct from enabled/usable state; null/unsupported is not false. |
| Native system architecture and logical CPU count | `GetNativeSystemInfo` | Architecture code/name, count, page size and allocation granularity in bytes | Native system architecture is distinct from the Python process architecture. Processor-group coverage is not claimed exhaustive. |
| Python process architecture | Python `platform.machine()` and pointer size | Machine string and 32/64-bit process width | Describes the collector process, not the installed OS or CPU capability. |
| Installed modules and arrays | `Win32_PhysicalMemory`, `Win32_PhysicalMemoryArray` | Module capacity bytes; array maximum capacity in provider-reported KB; speeds MHz; voltage millivolts | Firmware/provider inventory can be incomplete and may include unavailable module details. |
| OS-visible/available physical RAM and memory load | `GlobalMemoryStatusEx` | Bytes and percent, observed at call time | Volatile; distinct from installed module capacity. |
| Commit limit/available and virtual address space | `GlobalMemoryStatusEx` | Bytes | Commit values are system commit accounting, not the actual pagefile.sys size or contents. |
| OS memory/paging counters | `Win32_OperatingSystem` | Values in provider-reported KB as documented in `field_units` | `TotalVirtualMemorySize`, `SizeStoredInPagingFiles`, and related fields are provider counters; no file is read. |
| Physical disks | `Win32_DiskDrive` | Size bytes; sector bytes; model/manufacturer/interface/media/serial strings | Device exposure and hardware metadata depend on provider/controller/firmware. |
| Partitions | `Win32_DiskPartition` | Size/offset/block size bytes; block and sector counts as labeled | Does not imply one physical disk maps to one volume. |
| Logical disks | `Win32_LogicalDisk` | Capacity/free space bytes; drive letter, filesystem and volume strings | Primarily drive-letter logical-disk view; not every volume has a drive letter. |
| Volumes and volume paths | `Win32_Volume` | Capacity/free bytes, filesystem, GUID/device identifier, drive letter/name | VDS WMI provider may be absent; volume names and letters are not interchangeable. |
| Disk/partition/logical-volume relationships | WMI association classes | Provider reference strings, preserved as references | Associations can be missing or many-to-many; not forced into a one-to-one mapping. |
| Directory mount points | `Win32_MountPoint` | Volume and mount directory provider references | Archived VDS provider may be absent or inaccessible; see class outcome. |
| Video adapters and active display mode | `Win32_VideoController` | `AdapterRAM` is the provider's `uint32` byte value; resolution pixels; refresh Hz; bits/pixel; driver date/version | `AdapterRAM` is not verified dedicated graphics memory. Microsoft says hardware incompatible with WDDM can return inaccurate properties; integrated GPU memory reporting can differ from Settings. |
| Quick-fix entries | `Win32_QuickFixEngineering` | Hotfix identifier, description and installation metadata | Microsoft documents only CBS-supplied entries; not a complete list of updates. `InstalledOn` remains an unparsed provider string. |
| Current Windows time-zone configuration | `GetDynamicTimeZoneInformation` | Windows key/name strings; bias and standard/daylight bias in minutes; SYSTEMTIME transition rule | Current configuration only; transition rule's `day` is a week number when `year` is zero. It does not reconstruct historical time-zone rules. |
| UTC and local time observations | `GetSystemTimePreciseAsFileTime`, `GetSystemTimeAsFileTime` fallback, Python local clock | UTC ISO 8601 with `Z`; local ISO 8601 includes offset; offset seconds | Clock can be inaccurate or unsynchronized. Calls occur at different moments. |
| Uptime and provider boot time | `GetTickCount64`, `Win32_OperatingSystem.LastBootUpTime` | Milliseconds/seconds since start; boot date includes the provider's round-trip value, .NET ticks, and normalized UTC where the kind/offset permits | Separate observations; elapsed uptime includes sleep and can differ slightly from subtraction using a later boot-time sample. |

### Exact selected provider and API fields

The following are the exact field names emitted under each CIM record's
`values` and `field_details`. The containing query identifies the source;
each per-field detail carries its `value`, status, reason and unit. The
`field_units` map also lists units/formats where clarification is needed. No
additional provider object properties are serialized.

| Record/query | Selected fields |
|---|---|
| `operating_system` | `Caption`, `Description`, `Version`, `BuildNumber`, `BuildType`, `CSDVersion`, `OSArchitecture`, `InstallDate`, `LastBootUpTime`, `WindowsDirectory`, `SystemDirectory`, `SystemDrive`, `OSLanguage`, `Locale`, `MUILanguages`, `CountryCode`, `CodeSet`, `OSType`, `OperatingSystemSKU`, `ProductType`, `SuiteMask`, `PortableOperatingSystem`, `Primary`, `DataExecutionPrevention_Available`, `DataExecutionPrevention_32BitApplications`, `DataExecutionPrevention_Drivers`, `DataExecutionPrevention_SupportPolicy`, `TotalVisibleMemorySize`, `FreePhysicalMemory`, `TotalVirtualMemorySize`, `FreeVirtualMemory`, `SizeStoredInPagingFiles`, `FreeSpaceInPagingFiles` |
| `computer_system` | `Name`, `DNSHostName`, `Domain`, `Workgroup`, `PartOfDomain`, `DomainRole`, `Manufacturer`, `Model`, `SystemType`, `PCSystemType`, `PCSystemTypeEx`, `SystemFamily`, `SystemSKUNumber`, `ChassisSKUNumber`, `HypervisorPresent`, `NumberOfProcessors`, `NumberOfLogicalProcessors`, `TotalPhysicalMemory`, `NetworkServerModeEnabled` |
| `computer_product` | `Vendor`, `Name`, `Version`, `IdentifyingNumber`, `SKUNumber`, `UUID` |
| `bios` | `Manufacturer`, `Name`, `Version`, `SMBIOSBIOSVersion`, `BIOSVersion`, `ReleaseDate`, `SerialNumber`, `SMBIOSMajorVersion`, `SMBIOSMinorVersion`, `SMBIOSPresent`, `SystemBiosMajorVersion`, `SystemBiosMinorVersion`, `CurrentLanguage`, `ListOfLanguages`, `PrimaryBIOS` |
| `baseboard` | `Manufacturer`, `Model`, `Product`, `Version`, `SerialNumber`, `PartNumber`, `SKU`, `HostingBoard` |
| `processors` | `Name`, `Manufacturer`, `Architecture`, `AddressWidth`, `DataWidth`, `ProcessorId`, `SocketDesignation`, `NumberOfCores`, `NumberOfEnabledCore`, `NumberOfLogicalProcessors`, `CurrentClockSpeed`, `MaxClockSpeed`, `ExtClock`, `VirtualizationFirmwareEnabled`, `VMMonitorModeExtensions`, `SecondLevelAddressTranslationExtensions`, `Characteristics`, `ThreadCount` |
| `physical_memory` | `Capacity`, `Speed`, `ConfiguredClockSpeed`, `Manufacturer`, `PartNumber`, `SerialNumber`, `DeviceLocator`, `BankLabel`, `DataWidth`, `TotalWidth`, `FormFactor`, `MemoryType`, `SMBIOSMemoryType`, `Attributes`, `ConfiguredVoltage`, `MinVoltage`, `MaxVoltage` |
| `physical_memory_arrays` | `Location`, `Manufacturer`, `Model`, `Name`, `MaxCapacity`, `MaxCapacityEx`, `MemoryDevices`, `MemoryErrorCorrection`, `Use` |
| `logical_disks` | `DeviceID`, `DriveType`, `FileSystem`, `VolumeName`, `VolumeSerialNumber`, `Size`, `FreeSpace`, `ProviderName`, `Compressed`, `VolumeDirty` |
| `volumes` | `DeviceID`, `DriveLetter`, `Name`, `Label`, `FileSystem`, `Capacity`, `FreeSpace`, `DriveType`, `BootVolume`, `SystemVolume` |
| `physical_disks` | `DeviceID`, `Index`, `Model`, `Manufacturer`, `SerialNumber`, `Size`, `InterfaceType`, `MediaType`, `FirmwareRevision`, `PNPDeviceID`, `BytesPerSector`, `Partitions`, `Signature` |
| `partitions` | `DeviceID`, `DiskIndex`, `Index`, `Name`, `Type`, `Size`, `StartingOffset`, `NumberOfBlocks`, `BlockSize`, `Bootable`, `BootPartition`, `PrimaryPartition`, `HiddenSectors` |
| `display_adapters` | `Name`, `Description`, `AdapterCompatibility`, `AdapterRAM`, `VideoProcessor`, `PNPDeviceID`, `DriverVersion`, `DriverDate`, `MinRefreshRate`, `MaxRefreshRate`, `CurrentNumberOfColors`, `CurrentScanMode`, `VideoMode`, `CurrentHorizontalResolution`, `CurrentVerticalResolution`, `CurrentRefreshRate`, `CurrentBitsPerPixel`, `VideoModeDescription` |
| `quick_fixes` | `HotFixID`, `Description`, `InstalledBy`, `InstalledOn`, `InstallDate`, `ServicePackInEffect`, `FixComments`, `Name`, `Status` |
| `disk_to_partition` | `Antecedent`, `Dependent`; each non-null reference is `{class_name, keys}` rather than a recursive CIM object dump. |
| `partition_to_logical_disk` | `Antecedent`, `Dependent`; each non-null reference is `{class_name, keys}` rather than a recursive CIM object dump. |
| `mount_points` | `Directory`, `Volume`; each non-null reference is `{class_name, keys}` rather than a recursive CIM object dump. |
| `windows_registry_identity` | `ProductName`, `EditionID`, `DisplayVersion`, `ReleaseId`, `CurrentBuild`, `CurrentBuildNumber`, `UBR`, `BuildLabEx`, `InstallationType`, `ProductId` |

The API sections have these exact keys:

| JSON object | Fields and units |
|---|---|
| `computer_names` | `netbios_name`, `dns_hostname`, `dns_domain`, `dns_fqdn`, `physical_netbios_name`, `physical_dns_hostname`, `physical_dns_domain`, `physical_dns_fqdn`; each is an API observation wrapper. |
| `architecture` | `native_system_architecture`, `native_processor_architecture_code`, `native_logical_processor_count`, `page_size_bytes`, `allocation_granularity_bytes`, `python_process_architecture`; each is an API observation wrapper. |
| `observed_memory_status` | `memory_load_percent` (percent), `os_visible_physical_total` (bytes), `available_physical` (bytes), `commit_limit` (bytes), `commit_available` (bytes), `user_mode_virtual_address_space` (bytes), `available_user_mode_virtual_address_space` (bytes), `available_extended_virtual` (bytes). Each has `value`, `source`, `status`, and `unit`. |
| `clock_and_time_zone` | `uptime_milliseconds` (ms), `uptime_seconds` (seconds), `uptime_observation_method`, `windows_time_zone_id`, `standard_name`, `daylight_name`, `standard_transition_rule`, `daylight_transition_rule`, `bias_minutes`, `standard_bias_minutes`, `daylight_bias_minutes`, `dynamic_daylight_time_disabled`, `time_zone_api_return_code`, `observed_utc`, `observed_utc_filetime_100ns`, `utc_clock_source`, `observed_local_time`, `current_utc_offset_seconds`, `precise_utc_api_available`. Each is an API observation wrapper. A transition-rule object contains `year`, `month`, `day_of_week`, `day`, `hour`, `minute`, `second`, and `milliseconds`. |

Other output metadata keys are enumerated in the JSON-shape, provider-status,
and error explanations above; the collector does not serialize extra
properties from CIM objects.

## 6. Interpretation details

### Installed, visible, available, and commit memory

Sum the `Capacity` values in `memory.physical_memory_modules` for the
provider-reported installed-module total. Compare that with
`GlobalMemoryStatusEx.os_visible_physical_total` and the OS-visible WMI
counter. Hardware-reserved memory and provider timing/rounding can make these
different. `available_physical` is only the memory available at the API call;
it changes continuously. `commit_limit` and `commit_available` describe
system commit accounting and are not the file size or contents of
`pagefile.sys`. A30 does not read RAM or pagefile contents.

### OS and process architecture

`Win32_OperatingSystem.OSArchitecture` and `GetNativeSystemInfo` describe OS
and native machine architecture. `python_process_architecture` describes only
the interpreter process (`platform.machine()` plus pointer width). A 32-bit
Python process can run on a 64-bit OS; do not substitute one value for the
other.

### Physical disk, partition, logical disk, volume

These are separate provider entities. `DiskDriveToDiskPartition`,
`LogicalDiskToPartition`, and `MountPoint` results retain provider reference
strings rather than guessing relationships from display names. A physical
disk may have multiple partitions; a volume may span, map to, or be exposed
differently from a simple drive letter. Volume GUID paths, drive letters, and
directory mount points are distinct. Association references are reduced to
the referenced CIM class name and the provider-declared key properties to
avoid recursively serializing unrelated target-instance properties. A missing
relationship result is not proof that no relationship exists.

For storage comparisons, `physical_disks[].Size` is physical device capacity;
`logical_disks[].Size`/`FreeSpace` and `volumes[].Capacity`/`FreeSpace` are
separate logical views. A30 does not calculate a combined “used” total.
Calculate a comparison from distinct drive letters only as
`Size - FreeSpace`, and do not add the logical-disk and volume views together.
Windows may display rounded decimal GB while providers return bytes; state the
unit conversion used in a comparison. A physical disk size close to 477 GiB
can correspond to a marketed 512 GB drive and is not expected to equal used
space across volumes.

### Firmware identifiers and capability flags

Serials, UUIDs, SKUs, part numbers, firmware dates and processor capability
flags are returned as exposed by Windows. They can be absent, duplicated,
placeholder strings, stale, or wrong; they are not guaranteed unique evidence
identities. `Win32_ComputerSystemProduct.UUID` is preserved as a
firmware/provider product UUID; it is not asserted to equal the Windows
Settings About **Device ID** or the registry `ProductId` (shown as **Product
ID** in Settings). A30 does not collect the Settings Device ID; do not compare
those distinct identifiers as though they were the same field.
`HypervisorPresent` does not name a hypervisor. Processor
virtualization capability does not prove firmware settings or Windows
features are enabled. A30 does not infer firmware boot mode, Secure Boot,
TPM presence/version, or system clock synchronization.

### Graphics memory and Windows edition comparisons

`display_hardware[].AdapterRAM` is emitted exactly as the
`Win32_VideoController` provider reports it, in bytes. The Microsoft class
defines this property as `uint32` and warns that hardware incompatible with
WDDM can produce inaccurate controller properties. It is therefore labeled
provider-reported adapter memory, **not verified dedicated VRAM**. For an
integrated GPU, do not treat a WMI value such as 1,024 MiB as contradicting a
Windows Settings graphics summary such as 128 MB without confirming that both
interfaces are reporting the same memory category.

The OS provider's `Win32_OperatingSystem.Caption` and the registry's
`CurrentVersion\ProductName` are retained separately. They may disagree (for
example, registry text can retain an earlier product label). Use
`Win32_OperatingSystem.Caption` as the A30 OS-provider edition value; do not
rewrite or silently reconcile the registry observation.

The Windows Feature Experience Pack and the Settings About **Pen and Touch**
summary are not selected A30 fields. Their values are unverified by this
collector; their absence from the report is not evidence that a pack, pen, or
touch capability is absent.

### Time, uptime, and historical timestamps

Collection start/end and observed UTC use the precise FILETIME API when
available and otherwise the documented FILETIME fallback; an API fallback
source is recorded. The UTC `value` fields end in `Z`. The `collection_*_local`
fields are converted from those exact UTC instants and include the local
offset. The Windows time-zone identifier is recorded separately. A backward
wall-clock adjustment during collection is indicated by
`collection_clock_adjusted`; in that case the recorded end is clamped to the
start.
`GetDynamicTimeZoneInformation` bias values and transition rules describe the
current Windows configuration. A Windows `SYSTEMTIME` transition rule uses
`month`, `day_of_week` (Sunday is zero), and `day` as the week number when its
`year` is zero; the supplied local transition clock is in hours, minutes,
seconds, and milliseconds. The time-zone API return code is 0 when there are
no transition dates/no daylight time, 1 while in the standard-time range, 2
while in the daylight-time range, and `0xFFFFFFFF` for an API error.
`GetTickCount64` reports elapsed milliseconds since startup, with seconds
derived from the same reading and typical system-timer resolution; the
separate `QueryUnbiasedInterruptTime` API reports working-state-only time and
is not used here. WMI boot time is another provider observation. Do not apply
today's offset to old evidence timestamps: historical daylight-saving rules
can differ. Nothing in these timestamps establishes a correct or synchronized
system clock.

### Quick-fix date coverage

The documented `Win32_QuickFixEngineering` provider does not enumerate every
Windows update mechanism. `InstalledOn` is retained as returned, without locale-dependent parsing. A
CIM `InstallDate` is returned as a .NET round-trip date string with its kind
and original ticks, plus normalized UTC when an offset is available.

## 7. Reading nulls, zeros, flags, and conflicts

- `null_value` means a provider exposed the property and returned null.
- `not_exposed` means that record did not expose a selected property; the
  reason is listed under `field_errors`. This optional limitation alone does
  not make the overall status partial.
- `not_returned` means the wrapper did not receive a selected field in its
  structured response and is treated as incomplete collection.
- `malformed_value` means an association property expected to contain a CIM
  reference or a CIM date wrapper contained an unexpected type/format; the
  output retains the raw value where available, the condition is recorded in
  `field_errors`, and overall status is partial.
- `unsupported` is a class/API availability outcome, not proof that the
  corresponding hardware or setting is absent. Optional unsupported providers
  are visible in `providers` and do not automatically fail the artifact.
- `access_denied`, `provider_failure`, `timeout`, and malformed/failed
  PowerShell are errors. The result is `partial` if useful data remains.
- Numeric `0` and Boolean `false` are retained as values and marked
  `available`; neither is converted to null.
- CIM, registry, and API values remain in their source-specific fields. For
  example, WMI's OS architecture is not overwritten by native API
  architecture, and module capacity is not overwritten by an observed
  available-RAM value.
- If separately sampled local-time/offset and Windows time-zone values appear
  inconsistent, retain both with their sources. They describe different API
  views and can reflect timing/configuration differences; A30 does not force
  one to overwrite the other.
- `field_units` documents non-obvious units/formats. Units are not guessed
  from magnitude. The original provider values remain in `values`.
- A status of `success` means supported queries completed; it does not mean
  every possible hardware field was present or that the snapshot is atomic.
- API observation statuses include `available`, `unavailable` (for a name
  form or optional value not supplied), `unsupported`, `access_denied`, and
  `provider_failure`; provider-level API outcomes are in `providers` or
  `errors`.

## 8. Illustrative output (not a live result)

The following is deliberately abbreviated. Actual output includes all selected
fields and sections:

```json
{
  "artifact_id": "A30",
  "collection_started_at_utc": {
    "value": "2025-02-01T12:00:00.123456Z",
    "source": "GetSystemTimePreciseAsFileTime",
    "filetime_100ns_since_1601": 133827984001234567
  },
  "collection_ended_at_utc": {
    "value": "2025-02-01T12:00:02.654321Z",
    "source": "GetSystemTimePreciseAsFileTime",
    "filetime_100ns_since_1601": 133827984026543210
  },
  "collection_started_at_local": {
    "value": "2025-02-01T04:00:00.123456-08:00",
    "source": "Converted from collection_started_at_utc using the local system time zone"
  },
  "collection_ended_at_local": {
    "value": "2025-02-01T04:00:02.654321-08:00",
    "source": "Converted from collection_ended_at_utc using the local system time zone"
  },
  "collection_time_zone_id": {
    "value": "Pacific Standard Time",
    "source": "GetDynamicTimeZoneInformation",
    "status": "available"
  },
  "collection_clock_adjusted": false,
  "status": "partial",
  "providers": {
    "operating_system": {
      "source": "Win32_OperatingSystem",
      "status": "success",
      "error_category": null,
      "native_hresult": null,
      "records_returned": 1
    },
    "mount_points": {
      "source": "Win32_MountPoint",
      "status": "unsupported",
      "error_category": "unsupported",
      "native_hresult": "0x80041010",
      "records_returned": 0
    },
    "display_adapters": {
      "source": "Win32_VideoController",
      "status": "access_denied",
      "error_category": "access_denied",
      "native_hresult": "0x80070005",
      "records_returned": 0
    }
  },
  "windows_identity": {
    "operating_system": {
      "source": "Win32_OperatingSystem",
      "status": "success",
      "error_category": null,
      "native_hresult": null,
      "records_returned": 1,
      "records": [
        {
          "values": {
            "Caption": "Example Windows edition",
            "OSArchitecture": "64-bit",
            "ProductType": 1
          },
          "field_units": {},
          "field_details": {
            "Caption": {
              "value": "Example Windows edition",
              "status": "available",
              "status_reason": "Provider returned a non-null value.",
              "unit": null
            },
            "OSArchitecture": {
              "value": "64-bit",
              "status": "available",
              "status_reason": "Provider returned a non-null value.",
              "unit": null
            },
            "ProductType": {
              "value": 1,
              "status": "available",
              "status_reason": "Provider returned a non-null value.",
              "unit": null
            }
          }
        }
      ]
    }
  },
  "errors": [
    {
      "provider": "Win32_VideoController",
      "category": "access_denied",
      "native_hresult": "0x80070005"
    }
  ],
  "limitations": [
    "Illustrative only; this is not a collected system result."
  ]
}
```

In a real result, `limitations` contains the collector's full fixed set of
coverage notes; errors and unsupported provider outcomes are separately
recorded.

## 9. Validation

### Manual live Windows validation

No automated A30 test file is included; validate collection manually using
these read-only comparisons and controlled fixtures where appropriate.

1. **OS identity:** Compare caption, edition, version/build, display version,
   architecture, install/boot dates and Windows paths with Settings >
   System > About, `winver`, and `msinfo32`. Use a read-only PowerShell query
   such as:

   ```powershell
   Get-CimInstance Win32_OperatingSystem |
     Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate,
       LastBootUpTime, WindowsDirectory, SystemDirectory, SystemDrive
   ```

   Compare build revision separately with the `UBR` registry value.
2. **Computer/firmware:** Compare `Win32_ComputerSystem`,
   `Win32_ComputerSystemProduct`, `Win32_BIOS`, and `Win32_BaseBoard` selected
   values with `msinfo32`, Settings, or vendor firmware information. Do not
   treat a blank/repeated serial or UUID as a unique identity.
3. **CPU/memory:** Compare processor name/counts and module data with Task
   Manager, `msinfo32`, and read-only `Get-CimInstance Win32_Processor` /
   `Win32_PhysicalMemory` queries. Compare installed module capacity against
   OS-visible memory in Task Manager; hardware-reserved space and differing
   sample times can explain differences.
4. **Storage:** Compare disk, partition, volume, letters, filesystem, capacity,
   and free space with Disk Management (view only) and read-only queries:

   ```powershell
   Get-CimInstance Win32_DiskDrive
   Get-CimInstance Win32_DiskPartition
   Get-CimInstance Win32_LogicalDisk
   Get-CimInstance Win32_Volume
   ```

   Inspect associations if available. Do not initialize, format, unlock,
   assign, mount, or change anything during validation.
5. **Display:** Compare active controller and current mode with Settings >
   System > Display and `Get-CimInstance Win32_VideoController`. AdapterRAM
   can be limited by the provider's 32-bit field.
6. **Updates:** Compare sample hotfix identifiers with
   `Get-CimInstance Win32_QuickFixEngineering`. Do not expect it to list every
   update source. Preserve any ambiguous `InstalledOn` text exactly.
7. **Time zone and clock:** Compare Settings > Time & language > Date & time
   with `Get-TimeZone` and the reported zone key/names/offset. Compare a
   recent UTC/local observation; do not change clock or zone to test.
8. **Boot and uptime:** Compare `LastBootUpTime` with Task Manager uptime or
   `Get-CimInstance Win32_OperatingSystem`. Allow for distinct measurement
   times, clock corrections and sleep.
9. **Units/timestamps:** Check byte totals against provider sizes,
   `field_units` for KB-to-byte distinctions, clock seconds against uptime
   milliseconds, and CIM date formatting. Confirm ambiguous QFE dates remain
   strings and are not locale-parsed.
10. **Provider failures/edge cases:** Use fixtures or mocks to simulate a
    missing CIM class, access denied, unsupported API, provider timeout,
    malformed JSON, zero/one/multiple records, blank or placeholder IDs, and
    fields with null, false, or zero. Verify a failed query is not rendered as
    proof that hardware is absent. Do not alter system settings or remove
    hardware to create a failure case.
11. **Output behavior:** Confirm UTF-8 by opening the JSON with a UTF-8-aware
    editor. Run twice to the same filename without `--overwrite` and confirm
    the first file remains unchanged. Test an existing folder and a path
    containing spaces.
12. **Working directory and launcher:** Start `launch.bat` from a different
    current directory and use a destination with spaces. Manually test an
    already elevated terminal, approve the UAC prompt, and cancel it; verify
    cancellation reports no collection. Confirm an elevated run waits and
    returns the collector's exit code. These UAC scenarios require a live
    interactive Windows session and are not covered by Python fixtures.
13. **Read-only check:** Compare relevant settings before/after collection and
    confirm no time, registry, firmware, TPM, Secure Boot, service, or storage
    configuration was changed.
14. **Documentation alignment:** Check each actual JSON key and selected
    provider field against the section and coverage tables above after any
    property-list change.

Automated test results, live comparisons, and manual UAC checks must be
reported separately. Do not mark a manual or live check complete unless it
was performed on the target Windows system.

## 10. Limitations and excluded scope

This is a current system-information snapshot, not a perfectly atomic view or
a historical reconstruction. WMI/CIM class availability and data quality vary
by Windows version, firmware, device, permissions, provider health, and
virtualized environment. Every query is independent; values can change
between calls. Unsupported and inaccessible providers remain explicit.

This artifact does not collect RAM or pagefile contents, full driver or
installed-software inventories, user/group information, network adapters,
BitLocker status, event logs, credentials, TPM secrets, disk images, or
filesystem artifacts. It does not hash data, create manifests or chain of
custody, manage cases, build timelines, or generate forensic reports.
