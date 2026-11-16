# A23 — Windows Drivers inventory collector

A23 is a read-only Windows collector for two different observations:

1. **Installed/configured driver services** from the local Service Control
   Manager (SCM), whether stopped, running, or in a transitional state.
2. **Currently visible loaded driver modules** from PSAPI.

The lists remain separate in the JSON. An installed service is not proof its
driver is currently loaded, and a loaded module is not guaranteed to map to
one service. A23 does not detect hidden drivers or claim to inventory every
kernel component.

## Collection methods and coverage

SCM enumeration uses documented `EnumServicesStatusExW` filters for
`SERVICE_DRIVER` (`SERVICE_KERNEL_DRIVER` plus
`SERVICE_FILE_SYSTEM_DRIVER`) and separately for
`SERVICE_RECOGNIZER_DRIVER`. The recognizer-driver type is not included in the
documented `SERVICE_DRIVER` composite filter, so it is queried separately.
`SERVICE_ADAPTER` (0x4) is reserved and is not treated as an installed driver
service category. All service states are requested.
Microsoft lists `EnumServicesStatusExW` as available from Windows XP desktop
and Windows Server 2003; this is also only an API minimum, not the supported
OS floor for the project's Python/pywin32 runtime.

For each discovered service, A23 uses pywin32 SCM handles and documented APIs
to query status, base configuration and supported `QueryServiceConfig2W`
levels. Enumeration uses continuation handles and grows bounded buffers after
`ERROR_MORE_DATA`; records returned before a later error are retained.
Individual open/query errors stay on their record. The SCM API can silently
omit services for which the caller lacks `SERVICE_QUERY_STATUS`; Windows does
not provide names or a count for those omissions.

Loaded modules are obtained from PSAPI `EnumDeviceDrivers`, then their base
names and paths are queried with `GetDeviceDriverBaseNameW` and
`GetDeviceDriverFileNameW`. Microsoft documents the `Psapi.dll` exports down
to Windows XP desktop/Windows Server 2003; on Windows 7/Server 2008 R2 and
later the same APIs are also exposed through `Kernel32.dll` as `K32...`
exports. A23 loads `Psapi.dll`. This API availability floor is not
certification of the complete A23 runtime on those older systems: the project
uses Python 3.12 and pywin32 312 and targets a currently supported Windows
desktop. Verify Python and pywin32 compatibility before deploying to an older
OS. Pointer arrays use the interpreter's native pointer width. The collector
increases the array as required and handles truncated strings by retrying with
larger buffers. Starting with Windows 11 version 24H2, `EnumDeviceDrivers` may
succeed but return all-null image addresses unless `SeDebugPrivilege` is
enabled. A23 attempts to enable that privilege only in its own process token
when it is present, restores the original enabled state, and closes the token.
Null addresses are reported as unusable, never interpreted as an empty
loaded-module list.

The collector does not query CIM. `Win32_SystemDriver`, `sc.exe`, and
`driverquery` are included below as independent manual comparison references;
their coverage and terminology are not identical to SCM or PSAPI.

## Requirements and privileges

- Windows on which the documented SCM and PSAPI interfaces are available.
- Intended deployment: Windows 11 or a Windows 10 edition still supported
  under its servicing lifecycle, with the project Python 3.12 environment.
  Older OS releases are not certified by this collector even where an
  individual API is documented as available.
- The existing Python interpreter:
  `E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe`
- `pywin32==312` in that existing environment (`win32service`, `win32api`,
  `win32security`). A23 does not install or update packages.
- Administrator approval is recommended and is requested by `launch.bat`.
  The collector attempts to use `SeDebugPrivilege` only for the current
  process's loaded-module query, if that privilege exists in its token. It
  does not modify machine policy. Elevation cannot guarantee complete SCM or
  module visibility.

If the dependency check reports missing modules, install manually only in the
existing project environment:

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" -m pip install "pywin32==312"
```

No separate elevation helper, script policy change, driver, or kernel
inspection component is used.

## Launching

Double-click `launch.bat`, or run it from Command Prompt:

```bat
"E:\FYP Custos Forensic Suite\artifacts\A23 - Drivers\launch.bat"
```

The launcher checks its current token first. If it is not elevated, it asks
Windows for standard UAC approval and starts the Python collector only after
approval. Cancellation or elevation failure exits without collection. The
launcher waits for the elevated Python process and returns its exit code.
With no arguments, the collector prompts for an output JSON path or existing
folder. Press Enter to save a timestamped JSON file in the A23 folder.

Command-line examples:

```bat
"E:\FYP Custos Forensic Suite\artifacts\A23 - Drivers\launch.bat" --output "E:\Evidence Folder\drivers.json"
"E:\FYP Custos Forensic Suite\artifacts\A23 - Drivers\launch.bat" --output "E:\Evidence Folder"
"E:\FYP Custos Forensic Suite\artifacts\A23 - Drivers\launch.bat" --output "E:\Evidence Folder\drivers.json" --overwrite
```

Run Python directly when elevation is not needed (it will not request UAC):

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" "E:\FYP Custos Forensic Suite\artifacts\A23 - Drivers\collector.py" --output "E:\Evidence Folder\drivers.json"
```

`--output` accepts a JSON filename or an existing directory. A directory
receives a new timestamped `Drivers-<UTC timestamp>.json` file. If
`--output` is omitted, a timestamped file is written in the A23 folder.
Existing files are refused unless `--overwrite` is explicitly supplied.
Parent folders are not created automatically. There is no content-copy mode;
driver binaries are never copied.

Exit codes:

- `0` — SCM and PSAPI observations completed without reported collection errors.
- `1` — partial provider visibility, access/query/enrichment failures, or
  unusable loaded-module addresses.
- `2` — required SCM inventory failed, invalid/output arguments, missing
  Python/dependency, UAC failure, or output could not be written.

An SCM failure with no service records is `failed`, not a successful empty
inventory. If SCM succeeds but optional PSAPI visibility fails, the overall
result is partial and the provider-specific outcome identifies the gap.

## Output files and layout

A23 emits one UTF-8 JSON file:

```text
<chosen folder>\
  Drivers-<UTC timestamp>.json
```

The file contains the full output document described below. A23 does not
create a second evidence file, copy binaries, calculate hashes, or emit a
manifest.
For readability, each installed driver-service record and each loaded-module
record is separated from the next record by a blank line. These blank lines
are legal JSON whitespace and do not affect parsing.

## JSON field guide

### Top-level document

- `artifact_id` — constant `A23`.
- `collection_started_at_utc`, `collection_ended_at_utc` — collection
  observation interval in ISO 8601 UTC (`Z`); not install/load times.
- `collection_started_at_local`, `collection_ended_at_local` — the same
  boundary instants in local ISO 8601 with explicit offsets.
- `collection_time_zone_id`, `collection_time_zone_id_source`,
  `collection_time_zone_id_error`, `collection_clock_adjusted` — detected
  Windows zone ID/source, lookup error if any, and backward-clock clamp
  indicator. Driver file timestamps remain source timestamps. See
  [`COLLECTION_TIMESTAMPS.md`](../COLLECTION_TIMESTAMPS.md).
- `status` — overall `success`, `partial`, or `failed`.
- `runtime.operating_system`, `windows_release`, `python_version`,
  `python_architecture_bits` — environment used for the run.
- `providers.installed_driver_services` — SCM provider/API names, attempted
  flag, status, enumeration completeness, filters, returned count and errors.
- `providers.loaded_driver_modules` — PSAPI provider/API names, attempted
  flag, status, enumeration completeness, module count, unusable-address
  count, observation time, debug-privilege result, errors and warnings.
- `coverage.installed_driver_services_complete`,
  `loaded_driver_modules_complete` — provider visibility assessments, not
  guarantees about hidden drivers or all kernel components.
- `coverage.hidden_drivers_detected` — always `false`; A23 makes no hidden
  driver detection claim.
- `coverage.meaning` — text describing the provider-limited completeness.
- `installed_driver_services` — configured SCM driver-service records.
- `loaded_driver_modules` — separate PSAPI module records.
- `correlation` — exact resolved-path matches, ambiguous cardinalities,
  unmatched records, method and limitations.
- `counts.installed_driver_services`, `loaded_driver_modules`,
  `correlated_paths`, `ambiguous_correlations`,
  `unmatched_driver_services`, `unmatched_loaded_modules`,
  `records_with_errors`, `overall_errors` — counts of the emitted records and
  errors.
- `errors` — provider-level errors with provider, category, Win32 error,
  exception type and message where available.
- `limitations` — run-wide coverage and interpretation warnings.

Each `service_type_filters` item records a service type filter name and
numeric value, per-filter status, `enumeration_complete`, `records_returned`,
and its errors. The SCM `SERVICE_DRIVER` value covers kernel and file-system
driver services; recognizer services are a separate filter. A failed filter
does not erase records returned by another filter.

### Installed driver-service record

- `identity.service_name` — SCM service key name.
- `identity.display_name` — name returned by enumeration.
- `identity.description` — `QueryServiceConfig2W` description value; null can
  mean no configured description or unavailable data (check configuration
  status/errors).
- `identity.enumerated_service_type_flags` — original numeric type flags,
  decoded labels, and unrecognized bits from SCM enumeration.
- `status.observation_time_utc` and `source` — time and API/snapshot used.
- `status.service_type_flags` — numeric service type, known labels, and
  unknown bits.
- `status.current_state` — numeric SCM state plus label, including stopped,
  pending, running, paused, or unknown state.
- `status.controls_accepted` — numeric control mask, labels, and unknown bits.
- `status.win32_exit_code`, `service_specific_exit_code`, `checkpoint`,
  `wait_hint_ms`, `process_id`, `service_flags` — values returned by
  `QueryServiceStatusEx`, or the enumeration snapshot if the specific query
  failed. Zero is preserved as zero. A PID of zero can be meaningful for a
  stopped service.
- `configuration.service_type_flags` — type from stored service configuration.
- `configuration.start_type` — numeric SCM start type and label (boot, system,
  automatic, demand, disabled, or unknown).
- `configuration.error_control` — numeric error-control setting and label.
- `configuration.binary_path_command` — original configured command string;
  never replaced by the resolved candidate.
- `configuration.load_order_group` — configured group; an empty string is
  preserved.
- `configuration.tag_id` — configured tag value, including zero.
- `configuration.dependencies` — dependency names; empty list means none were
  returned, null means unavailable.
- `configuration.configured_account` — configured service account text.
- `configuration.display_name_from_configuration` — configuration-query
  display name.
- `configuration.extended` — each supported config2 field is an object with
  `status` (`available`, `not_configured`, `unsupported`, or `query_failed`)
  and `value`. Fields include description, failure actions, delayed
  auto-start, failure-action flag, service SID type, required privileges,
  preshutdown timeout, trigger info, preferred node, and launch protection.
  Trigger binary data is represented as hexadecimal bytes. Optional
  unsupported levels do not silently erase the other configuration.
- `binary_metadata` — metadata about the configured image candidate; no
  binary is executed or copied.
- `enumeration_type_filters` — the SCM service-type filters that returned the
  record.
- `errors` — per-record query/enrichment errors. An unsupported optional
  config2 level is explicitly categorized and does not alone make the full
  collection fail.

### Binary metadata object

- `original_path` — exact provider path string.
- `path_resolution.status` — `resolved`, `not_configured`, `unresolved`, or
  `network_path_not_inspected`.
- `path_resolution.method` — documented mapping applied, such as
  `systemroot_mapping`, `query_dos_device_verified_nt_dos_path`, or
  `query_dos_device_reverse_mapping`.
- `path_resolution.candidate_path` — derived candidate path, not a rewrite of
  the original value.
- `path_resolution.reason` — why a candidate was unavailable.
- `filesystem_status` — `available`, `not_found`, `access_denied`,
  `not_regular_file`, `query_failed`, or a path-resolution status.
- `exists`, `accessible`, `is_regular_file`, `size_bytes` — current
  filesystem observations; non-files have null size.
- `creation_time_utc`, `creation_time_source`, `last_write_time_utc`,
  `last_access_time_utc` — current filesystem times and the field used for
  creation time. They are not historical install/load times.
- `version_info.status` — `available`, `not_present`,
  `dependency_unavailable`, `not_applicable` (no image file can be inspected),
  `not_checked` (path or file was unavailable before version lookup), or
  `query_failed`.
- `version_info.string_resources_status` — `available`, `not_present`,
  `not_checked`, or `query_failed` for descriptive string values.
- `version_info.file_version`, `product_version`, `company_name`,
  `product_name`, `original_filename` — fields present in the Windows version
  resource; individual values can be null.
- `version_info.error`, `version_info.string_errors`, and `errors` — version
  or filesystem query failures. Individual missing string values remain null;
  unexpected string-query errors are reported by field.
  Missing version resources are represented as `not_present`, not a
  collection failure.

Path resolution expands environment variables, maps `\SystemRoot\` using
Windows' system-root value, and uses `QueryDosDevice` to verify native `\??\`
drive names or reverse-map `\Device\...` paths. It does not merely strip a
device prefix. Unknown device forms remain unresolved. UNC paths are not
accessed. Quoted command paths are extracted; unquoted strings are considered
up to a `.sys`, `.dll`, or `.exe` boundary when available.

### Loaded-module record

- `module_index` — index in the PSAPI result for this observation.
- `module_basename`, `original_module_path` — names returned for a valid
  address; null when inaccessible/unavailable.
- `base_address` — hexadecimal address genuinely returned by PSAPI; null when
  the API supplied a null pointer.
- `provider` — `PSAPI`.
- `observation_time_utc` — time the module list was observed.
- `errors` — null addresses or individual PSAPI/file-enrichment errors.
- `binary_metadata` — same schema as the service binary metadata object,
  using the original PSAPI path.

A module address is an observation, not a durable identifier. It is not
persisted as evidence of a historical load event.

### Correlation, errors, and illustrative output

`correlation.method` is `exact_resolved_path_only`. `matches` contains
`normalized_path`, `service_names`, `module_indexes`,
`match_cardinality`, `confidence`, and `basis`. Multiple services/modules can
share one path; those matches are recorded as ambiguous rather than forced
one-to-one. `unmatched_service_names` and `unmatched_module_indexes` preserve
the remainder. A shared basename alone never creates a match.

Each error includes the field or provider, a category, a Windows error when
available, exception type when available, and a readable message. Categories
distinguish `access_denied`, `unsupported`, `not_found` (missing filesystem
path), `disappeared` (a service listed by enumeration no longer opens),
`unusable_address`, `version_resource_not_present`, and
`provider_api_failure`. `not_applicable` is used for version metadata when no
file image applies; `unresolved` is a path-resolution status, not a provider
failure.

Illustrative excerpt only — values below are examples, not a live collection:

```json
{
  "artifact_id": "A23",
  "status": "partial",
  "installed_driver_services": [
    {
      "identity": {
        "service_name": "ExampleDrv",
        "display_name": "Example Driver",
        "description": null
      },
      "status": {
        "current_state": {
          "value": 1,
          "label": "SERVICE_STOPPED"
        },
        "process_id": 0
      },
      "configuration": {
        "start_type": {
          "value": 3,
          "label": "SERVICE_DEMAND_START"
        },
        "binary_path_command": "\\SystemRoot\\System32\\drivers\\example.sys"
      }
    }
  ],
  "loaded_driver_modules": [
    {
      "module_index": 0,
      "module_basename": null,
      "original_module_path": null,
      "base_address": null,
      "errors": [
        {
          "field": "base_address",
          "category": "unusable_address"
        }
      ]
    }
  ]
}
```

### Coverage table

| Information | API/provider | Meaning | Required access | Limitation |
|---|---|---|---|---|
| Driver service names and display names | SCM `EnumServicesStatusExW` | Installed driver services visible to SCM | `SC_MANAGER_ENUMERATE_SERVICE`; readable service status visibility | SCM can silently omit services without query-status access |
| Driver categories and current state | SCM enumeration/status query | Original service-type flags and current SCM state | `SERVICE_QUERY_STATUS` | Installed/running service state does not prove a module mapping |
| Status codes, PID and service flags | `QueryServiceStatusEx` | Current service status fields | `SERVICE_QUERY_STATUS` | Live observation; may change during collection |
| Configuration, dependencies, account | `QueryServiceConfig` | Configured start and binary command settings | `SERVICE_QUERY_CONFIG` | Original command preserved; it is not itself a filesystem path |
| Description and extended configuration | `QueryServiceConfig2W` | Supported description, restart, trigger and security-related service options | `SERVICE_QUERY_CONFIG` | Older Windows may not support some optional levels |
| Loaded modules, names and image paths | PSAPI `EnumDeviceDrivers`, `GetDeviceDriverBaseNameW`, `GetDeviceDriverFileNameW` | Modules exposed by documented PSAPI interfaces | `SeDebugPrivilege` required for valid addresses on Windows 11 24H2+ | Null addresses mean unusable results, not no loaded drivers; hidden modules out of scope |
| Driver path mapping | Environment/SystemRoot and `QueryDosDeviceW` | Candidate local path for supported path forms | Local path visibility | Unknown device paths and network paths are not resolved/accessed |
| Size and filesystem times | Python filesystem metadata on resolved local candidate | Current file metadata | Read/stat access | Not installation/load time; files can disappear or change |
| File version information | pywin32 `GetFileVersionInfo` | Version resource values embedded in the file | Read access | Absent values are normal; metadata does not prove authenticity |
| File signature | Not implemented | No signature conclusion emitted | Not applicable | No trust, catalog, revocation, or offline policy is asserted |

## Validation guide

Run the fixture tests from this folder using the existing project Python:

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" -m unittest -v test_a23_drivers.py
```

For controlled live Windows validation, compare without changing services:

1. Compare service names and selected fields against:

   ```powershell
   Get-CimInstance Win32_SystemDriver |
     Select-Object Name,DisplayName,State,Started,StartMode,ServiceType,PathName,TagId
   ```

   CIM's provider/property semantics may differ; compare overlapping names and
   fields, not row-for-row completeness.
2. For a selected service name, compare status and configuration:

   ```bat
   sc.exe query ExampleDriver
   sc.exe qc ExampleDriver
   ```

3. Use `driverquery /v /fo csv` as another inventory reference. Its row
   terminology and loaded/configured coverage differ from SCM. Neither it nor
   `Win32_SystemDriver` is a guaranteed equivalent to the PSAPI module list.
4. Check both running and stopped service records. Do not start or stop a
   driver to create a test state.
5. Compare PSAPI names/paths to `driverquery` and CIM results where records
   overlap. Windows does not provide a simple, independent stock command that
   returns the same PSAPI base-address list; an absent cross-reference is not
   proof that PSAPI is wrong or that a hidden module exists.
6. Use fixtures/mocks for shared basenames, exact path matches, many-to-one
   correlation, unmatched modules, missing paths, unsupported config2
   levels, and provider errors. Check original path values remain unchanged.
7. Verify service enumeration continues after `ERROR_MORE_DATA`, and that
   all opened service, SCM and token handles close on success and failure.
8. Validate JSON with a UTF-8 decoder; check the UTC `Z` timestamps, counts,
   null/zero/empty-list semantics, output collision refusal, and
   `--overwrite`.
9. Launch from another working directory and test arguments/output names
   containing spaces. Manually test already-elevated launch, UAC approval,
   UAC cancellation, and exit-code forwarding on a controlled Windows host.
10. Confirm before/after service status and configuration are unchanged.
    A23 has no call path that loads, unloads, starts, stops, installs,
    removes, or reconfigures a driver.

Fixture tests do not replace live Windows validation. Do not claim live SCM,
PSAPI, cross-tool or manual UAC validation unless separately performed.

## Common issues and limitations

- **UAC cancelled:** collection is not started; run again and approve if
  authorized.
- **pywin32 modules missing:** install `pywin32==312` manually into the
  existing project `.venv`; the launcher never installs dependencies.
- **Access denied:** keep the per-provider or per-record error. Do not infer
  an empty driver inventory.
- **PSAPI returns null addresses:** check the `debug_privilege` provider field.
  On Windows 11 version 24H2 and later, enablement may be required for valid
  addresses. The collector only changes its own process token and restores it.
- **Binary path unresolved:** the original path remains in JSON. Unsupported
  device forms are not guessed, and UNC paths are not accessed.
- **File missing or inaccessible:** service/module records remain; filesystem
  enrichment reports the observed state and errors.
- **No version strings:** a missing version resource is not a collection
  failure and does not imply tampering.
- **Partial status:** review provider outcomes, errors, and each record's
  error list. Administrator access does not guarantee visibility of all
  records.

The collector takes a live observation. Service/module state can change while
it runs, and reading files can affect ordinary OS metadata such as access
times. There is no kernel snapshot, hidden-driver detection, signature
verification, binary acquisition, or authenticity verdict.

## Official references

- [Microsoft: EnumServicesStatusExW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexw)
- [Microsoft: QueryServiceStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex)
- [Microsoft: QueryServiceConfig](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw)
- [Microsoft: QueryServiceConfig2](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2w)
- [Microsoft: OpenService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openservicew)
- [Microsoft: EnumDeviceDrivers](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers)
- [Microsoft: GetDeviceDriverBaseName](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getdevicedriverbasenamew)
- [Microsoft: GetDeviceDriverFileName](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getdevicedriverfilenamew)
- [Microsoft: Win32_SystemDriver](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-systemdriver)
- [Microsoft: QueryDosDeviceW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-querydosdevicew)
- [Microsoft: OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
- [Microsoft: Enabling and Disabling Privileges](https://learn.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--)
- [Microsoft: GetFileVersionInfo](https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfow)
