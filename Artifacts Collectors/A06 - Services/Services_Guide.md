# A06 — Windows Services inventory

This collector records a read-only inventory of Win32 services from the local
Service Control Manager (SCM). It includes own-process and shared-process
services in running, stopped, and transitional states. Kernel and file-system
driver services are deliberately excluded; they belong to A23 — Drivers.

The collector does not change service state or configuration, execute service
commands, alter the registry, or collect service passwords. `launch.bat`
requests administrator approval through standard Windows UAC only when it is
not already running elevated. Elevation does not guarantee access to every
protected service field.

## Files and dependencies

- `collector.py` — reusable `collect_services(api=None)` function, CLI,
  SCM adapter, normalizer, and UTF-8 JSON writer.
- `launch.bat` — double-click/Command Prompt launcher using the existing
  project Python path and requesting elevation for the batch launcher itself.

Requirements: Windows desktop (the documented APIs have minimum client
support from Windows XP; trigger configuration starts with Windows 7, preferred
NUMA node with Windows 7, and launch protection with Windows 8.1). The
collector is developed and validated against 64-bit Windows 11 and 64-bit
Python 3.12. It expects pywin32 312 capabilities, namely `win32service`
service enumeration/query/security wrappers and `win32security` descriptor
conversion. The installed pywin32 version does not expose trigger, preferred
node, or launch-protection query levels; those use narrowly scoped ctypes
bindings to documented `Advapi32` `EnumServicesStatusExW` and
`QueryServiceConfig2W`. On the tested Windows 11 build the preferred-node
query returned Win32 error 87 for every service, so that information is
reported as unsupported on that host even though Microsoft documents the level
on Windows 7/Server 2008 R2 and later. No packages are installed automatically.

If pywin32 is missing, install it manually into the existing environment:

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" -m pip install "pywin32==312"
```

## Running

From Command Prompt, direct execution (does not itself elevate):

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" "E:\FYP Custos Forensic Suite\artifacts\A06 - Services\collector.py" --output "C:\Forensic Output\services.json"
```

If `--output` is omitted, the collector saves to a unique timestamped JSON
file in the A06 artifact folder. Supply `--output` to choose another
destination. If `--output` names an existing directory, the collector saves a
uniquely timestamped JSON file inside that directory. Otherwise it is treated
as the complete output file path. The parent directory must already exist.

Explicit replacement of an existing file:

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" "E:\FYP Custos Forensic Suite\artifacts\A06 - Services\collector.py" --output "C:\Forensic Output\services.json" --overwrite
```

The direct collector exits `0` for success, `1` for partial inventory and `2`
for failure. Existing outputs are never replaced without `--overwrite`.
Output directories must already exist.

Double-click `launch.bat`. If it is not already elevated, Windows displays its
standard administrator approval prompt; if already elevated, collection starts
without another prompt. When launched without arguments, it asks for an output
folder or JSON file path. Leave the prompt blank to save a uniquely timestamped
JSON file in the A06 artifact folder. From Command Prompt, you may pass an
explicit output path to skip the prompt:

```bat
"E:\FYP Custos Forensic Suite\artifacts\A06 - Services\launch.bat" --output "C:\Forensic Output\services.json"
"E:\FYP Custos Forensic Suite\artifacts\A06 - Services\launch.bat" --output "C:\Forensic Output\services.json" --overwrite
```

The launcher uses `E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe`,
requests elevation for the batch launcher itself, waits for the elevated
collector, and passes through its exit code. Cancellation or elevation failure
returns `2` without collection. A final `pause` keeps double-click output
visible. Some protected fields can remain inaccessible even when elevated;
inspect each record's errors and the inventory status.

An explicitly empty `--output` value is rejected before collection begins.
The default artifact-folder destination is used when no output path is
supplied.

## Output

The UTF-8 JSON document contains `artifact_id`, `collection_start_utc`,
`collection_end_utc`, `status`, `provider`, `enumeration`, `record_count`,
`services`, `errors`, and `limitations`. Each service record groups
`identity`, `status`, `configuration`, `security`, and `enrichment`, with a
per-record `errors` array. UTC observation times are not service installation,
execution, or configuration-change times.
The pretty-printed `services` array places a blank line between service records
to make record boundaries easier to see; it remains valid JSON.

### How to read the JSON

The top-level object describes the collection as a whole. Start with:

- `artifact_id` — should be `A06`.
- `collection_start_utc` and `collection_end_utc` — when this inventory ran,
  in UTC. `collection_start_local` and `collection_end_local` are the same
  instants in local ISO 8601 with offsets. `collection_time_zone_id` records
  the detected Windows zone identifier; a read error is reported in
  `collection_time_zone_id_error`. `collection_clock_adjusted` signals a
  backward wall-clock change that required clamping the end to the start.
  These are not service installation or change times. See
  [`COLLECTION_TIMESTAMPS.md`](../COLLECTION_TIMESTAMPS.md).
- `status` — `success` means queries completed without field failures;
  `partial` means one or more records/fields or enumeration pages could not
  be fully collected; `failed` means collection could not produce a usable
  inventory.
- `enumeration.complete` — whether all pages exposed by the SCM API were
  retrieved. This can be `true` even when individual fields later fail. It
  cannot reveal services silently omitted by Windows due to access checks.
- `record_count` — number of entries in `services`, not the number of running
  services.
- `provider.operating_system`, `windows_release`, and `windows_version` —
  identify the host OS/build so readers can assess API and configuration-class
  availability.
- `provider.python_version` and `python_architecture` — identify the runtime
  used to perform the collection and its bitness.
- `provider.provider` and `native_api` — identify SCM as the data provider and
  the native API family used for enumeration/configuration.
- `provider.pywin32_version` — identifies the installed pywin32 package
  version where it can be determined.
- `enumeration.service_type_filter` and `state_filter` — record which service
  type/state scope was requested. A06 requests Win32 services in all states.
- `enumeration.driver_services_included` — makes explicit whether A23 driver
  services are part of this artifact; it is false for A06.
- `enumeration.enumerated_record_count` — number of service records returned
  and retained from enumeration; compare it with `record_count`.
- `errors` and `limitations` — collection-wide API failures and known scope or
  compatibility notes. Each individual service also has its own `errors` list.

Each object in `services` is one service. Use `identity.service_name` as its
stable key for matching with `Get-Service`, `sc.exe`, or CIM. `display_name`
is the friendly Windows name; `description` is optional explanatory text.
Read the remaining groups as follows:

- `status` is the live observation. `observation_time_utc` tells when it was
  queried; `source` says whether it came from a fresh status query or the
  enumeration snapshot fallback. `current_state.value` is the original
  Windows number and `label` its known Windows name (for example, `1` /
  `SERVICE_STOPPED`, `4` / `SERVICE_RUNNING`). `process_id` is the service's
  reported PID; zero for a stopped service is valid. Multiple service records
  can have the same PID when they share a process. Exit codes, checkpoint and
  wait hint are provider-reported status values, not diagnoses.
- `configuration` contains configured values, which can differ from current
  status. `binary_path_command` is the exact configured command string, which
  may contain arguments; it is not a verified executable path. `dependencies`
  is a list and an empty list means none were returned. The service account is
  the configured logon account, not proof of the running process's token.
  `extended` holds additional SCM configuration. In particular,
  `delayed_auto_start` and `trigger_info` must be considered alongside
  `start_type`; a demand-start value alone does not describe every start
  condition.
- Numeric enum objects preserve the original integer in `value`. `label` (or
  `labels` for bit flags) is a readable interpretation of recognized values.
  `unknown_bits` preserves bits without a verified label; do not discard or
  reinterpret them. For example, `controls_accepted.value` is the original
  flag mask and `controls_accepted.labels` lists the recognized controls.
- `security` is the readable owner/group/DACL descriptor. `sddl` is its
  Windows textual form. `dacl_present: false` means no DACL was present;
  `dacl_present: true` together with `dacl_is_null: true` means a present but
  null DACL. `dacl_aces` lists entries when available. SACL/audit information
  is not requested or represented.
- `enrichment.service_dll` is optional narrow registry metadata. Its `source`,
  `registry_type`, and `value` identify where it came from and its stored type
  and value. A configured DLL path does not prove that DLL is loaded.
- `errors` explains field-level collection problems. `null` means no value was
  available; check the matching error before interpreting it. A missing
  `ServiceDll` is recorded as `service_dll: null` with
  `service_dll_availability: "not_configured"`. Empty strings, `false`, `0`,
  and empty lists are actual returned values and are not interchangeable with
  `null`.

Example reading: if one record has `current_state.label` equal to
`SERVICE_STOPPED`, `process_id` equal to `0`, and `dependencies` equal to
`[]`, it represents a stopped service with no dependencies reported—not a
missing record. If `preferred_node` is `null` and its error category is
`unsupported`, that configuration class was not supported by the provider or
OS; it does not mean the collector found a configured preferred node of zero.
If the overall status is `partial`, inspect record errors and the limitations
before relying on the inventory. A familiar or unusual service name, path, or
account is not by itself a maliciousness determination.

For a quick command-line summary in PowerShell, replace the file path below
with the JSON output path:

```powershell
$inventory = Get-Content -Raw -LiteralPath "C:\Forensic Output\services.json" |
  ConvertFrom-Json
"Status: $($inventory.status); records: $($inventory.record_count); enumeration complete: $($inventory.enumeration.complete)"
$inventory.services |
  Select-Object @{Name="Name";Expression={$_.identity.service_name}},
                @{Name="DisplayName";Expression={$_.identity.display_name}},
                @{Name="State";Expression={$_.status.current_state.label}},
                @{Name="PID";Expression={$_.status.process_id}},
                @{Name="StartType";Expression={$_.configuration.start_type.label}}
```

### Purpose of every service-record field

This section describes what each emitted field is for. These values support
inventory and comparison; an unusual value is not, by itself, evidence of
malicious activity.

**`identity`**

- `service_name` — SCM service key name. Use this to look up the same service
  with `sc.exe`, `Get-Service -Name`, or a CIM `Name` filter.
- `display_name` — human-facing service name used in Windows management tools.
- `description` — configured explanatory text, useful for understanding the
  service's stated role. It is provider-supplied text, not proof of behavior.

**`status` — observed runtime state**

- `observation_time_utc` — when the collector queried the status; use it to
  judge how close a comparison with another tool was in time.
- `source` — identifies a fresh `QueryServiceStatusEx` result or the
  enumeration-time status retained when refreshing status failed.
- `service_type` — service type bitmask. It identifies own-process/shared-
  process and other recognized service-type flags; `value` retains the
  original mask.
- `current_state` — whether the service was stopped, running, paused, or in a
  transition at observation time. Use the numeric value and label together.
- `controls_accepted` — control notifications the running service says it
  accepts, such as stop, pause/continue, shutdown, or power events. This is
  not a recommendation to send those controls.
- `win32_exit_code` — Win32 status/error code reported by the service for
  start/stop outcomes.
- `service_specific_exit_code` — service-defined code; Windows says it is
  meaningful when the Win32 code indicates a service-specific error.
- `checkpoint` — progress counter used while a service is in a pending
  transition; normally zero when no transition is pending.
- `wait_hint_ms` — service's estimated time for a pending transition, in
  milliseconds. It is not a measured duration.
- `process_id` — SCM-reported process identifier. Zero can be valid for a
  stopped service; equal nonzero PIDs can identify services sharing a process.
- `service_flags` — provider status flags, including the recognized system-
  process flag where applicable. The original value and unknown bits are
  preserved.

**`configuration` — configured behavior, not current runtime proof**

- `service_type` — service type stored in basic configuration; compare with
  the status type to notice a difference between configuration and observation.
- `start_type` — boot, system, automatic, demand, or disabled base start mode.
  It does not alone describe delayed automatic or trigger-based starts.
- `error_control` — configured severity/startup handling if this service
  fails during startup; it is not a rating of the service's current health.
- `binary_path_command` — exact configured service command line, including
  arguments. Use it to compare with `sc.exe qc`; do not treat it as a
  canonicalized or verified executable path.
- `load_order_group` — configured service group used in load ordering; an
  empty string means no group value was returned.
- `tag_id` — SCM tag associated with the load-order group, if assigned. Zero
  is retained as a legitimate returned value.
- `dependencies` — service names or load-order groups that must be available
  before this service can start. An empty list means no dependencies were
  returned.
- `configured_service_account` — account configured for service logon. It is
  not a query of the current process token and is not a password.
- `display_name_from_configuration` — display name returned by the basic
  configuration query; it can be compared to `identity.display_name`.
- `extended.delayed_auto_start` — whether the service has delayed automatic
  start configured; `false` is a real value, not missing data.
- `extended.failure_actions.ResetPeriod` — seconds after which the failure
  count resets according to SCM configuration.
- `extended.failure_actions.RebootMsg` — configured reboot message, or null
  when none is returned.
- `extended.failure_actions.Command` — configured command for a run-command
  failure action, or null when none is returned. The collector does not run it.
- `extended.failure_actions.Actions` — ordered configured responses to
  failures. Each item's `type.value` is the original action number and
  `type.label` is a known action name; `delay_ms` is its configured delay.
- `extended.failure_actions_on_non_crash` — whether failure actions are
  configured to run for non-crash failures as well.
- `extended.service_sid_type` — configured service SID mode (`NONE`,
  `UNRESTRICTED`, or `RESTRICTED` when recognized), relevant to the service's
  Windows security identity configuration.
- `extended.required_privileges` — privilege names the service declares as
  required; this is configuration metadata, not proof that a process token
  currently holds each privilege.
- `extended.preshutdown_timeout_ms` — configured time allowance in
  milliseconds for preshutdown handling.
- `extended.trigger_info.trigger_count` — number of configured service
  triggers. Zero means no triggers were returned.
- `extended.trigger_info.triggers` — each trigger's `trigger_type` identifies
  its event category, `action` identifies start/stop response, and
  `subtype_guid` preserves its subtype identifier. `data_items` contains the
  original data type and `data_hex`; `string_value` is additionally included
  only for string-typed items. Raw data is preserved without inferring its
  meaning.
- `extended.preferred_node.preferred_node` — configured preferred NUMA node
  when the provider returns this class. `delete_preference` preserves the
  associated delete flag.
- `extended.launch_protection` — configured service launch-protection value
  and readable label, when supported. It describes protection metadata; it
  does not mean the collector can inspect all protected service details.

**`security` — readable service-object permissions**

- `owner_sid` and `group_sid` — owner and primary group identifiers from the
  queried security descriptor, represented as SIDs.
- `dacl_present` — whether a discretionary access-control list is present in
  the descriptor.
- `dacl_is_null` — distinguishes a present null DACL from an absent DACL.
- `dacl_aces` — list of readable DACL entries. `ace_header` preserves ACE
  header values, `access_mask` preserves the permission bits granted/denied by
  that ACE, and `trustee_sid` identifies the principal. This is not a SACL.
- `sddl` — Windows textual representation of the retrieved owner, group, and
  DACL information, useful for comparison with `sc.exe sdshow`.
- `sacl_requested` — documents the collection boundary; it is false because
  the collector deliberately does not request SACL/audit data.

**`enrichment` — optional narrow registry observation**

- `service_dll` — configured `Parameters\ServiceDll` value, when present.
- `service_dll.source` — exact registry value location read.
- `service_dll.registry_type` — original Windows registry type number; it
  describes storage format, not trust or file validity.
- `service_dll.value` — stored value; environment-variable text is not
  expanded. Byte data, if returned, is represented as hex.
- `service_dll.value_encoding` — indicates hex encoding when byte data needed
  a safe textual representation; null otherwise.
- `service_dll.meaning` — explicitly warns that configuration does not prove
  the DLL is loaded.
- `service_dll_availability` — `"not_configured"` means the specific value
  was not present; it is distinct from an inaccessible registry query error.

**`errors` — collection problems for this record**

- `category` — broad class such as `access_denied`,
  `unsupported_configuration_class`, `service_disappeared`, or
  `provider_api_failure`. Unsupported optional classes are compatibility
  limitations and do not by themselves make the inventory partial.
- `field` — status/configuration/security/enrichment field affected.
- `winerror` — original Windows error code when available; null when the
  provider did not provide one.
- `message` — provider or exception text to help investigate the failure.
- `exception_type` — Python exception type where available.

If a field is null, use its matching error to tell whether it was inaccessible,
unsupported, or otherwise not returned. A null value without a matching error
can also mean the provider successfully returned no value for that optional
setting. Do not replace null with zero, false, or an empty list when comparing
records.

Unavailable fields are null; valid empty strings, empty dependency/privilege
lists, false booleans, and numeric zero are retained. Errors identify access
denial, unsupported configuration level, service disappearance, or general
provider/API failure. Unsupported optional classes are compatibility
limitations and do not by themselves make an inventory partial. Other field
query failures mark the result partial while retaining the enumerated record.
If enumeration fails after returning any entries, those entries remain and
`enumeration.complete` is false. Failure before any service is returned yields
status `failed`, not a successful empty result.

Microsoft documents that `EnumServicesStatusEx` silently omits services for
which the caller lacks `SERVICE_QUERY_STATUS`; Windows does not provide the
collector a list or count of those omitted entries. Thus `enumeration.complete`
means all pages exposed to this caller were read, not that this API limitation
can be disproven.

The original numeric flags are preserved alongside verified labels; unknown
bits remain visible in `unknown_bits`. The configured binary command is kept
verbatim, without assuming that it is a resolved executable path.

Security queries request only owner, group, and DACL data. The SDDL string is
generated from that descriptor. An absent DACL is distinguished from a present
null DACL. SACLs and audit-policy data are intentionally
not requested; the collector does not request `ACCESS_SYSTEM_SECURITY` or
enable privileges for them. A service account is configured logon metadata,
not proof of a process token identity. A PID may be shared across records, and
PID 0 may be valid for a stopped service.

## Permissions

The SCM enumeration request uses
`SC_MANAGER_ENUMERATE_SERVICE`; status uses `SERVICE_QUERY_STATUS`; basic and
extended configuration use `SERVICE_QUERY_CONFIG`; service security uses
`READ_CONTROL`; optional `ServiceDll` enrichment uses read access to the one
service's `Parameters` registry key. Windows ACLs may deny individual queries
even after elevation. Query failures are attached to the record rather than
causing it to be dropped.

## Live read-only validation

Run collection and select a destination with spaces. Compare several
services, including at least one running and one stopped service:

### Validate one service record

Use the service's SCM **service name** (not its display name) to select exactly
one record from the JSON. In this example, `Spooler` is the service name and
`C:\Forensic Output\services.json` is the collected file:

```powershell
$jsonPath = "C:\Forensic Output\services.json"
$serviceName = "Spooler"
$inventory = Get-Content -Raw -LiteralPath $jsonPath | ConvertFrom-Json
$record = @($inventory.services |
  Where-Object { $_.identity.service_name -eq $serviceName })

if ($record.Count -ne 1) {
  throw "Expected one record for '$serviceName'; found $($record.Count)."
}
$record = $record[0]
$record | ConvertTo-Json -Depth 20
```

Read `$record.errors` before treating any `null` field as absent. A matching
field error explains whether access was denied, the service disappeared, an
API failed, or a configuration class was unsupported. `enumeration.complete`
is about pages visible to the caller; it cannot detect entries the Windows API
silently omitted for access reasons. `status.observation_time_utc` records when
the live state was sampled.

Compare the same service independently, without sending it any control
commands:

```powershell
sc.exe queryex $serviceName
sc.exe qc $serviceName
sc.exe sdshow $serviceName
Get-CimInstance Win32_Service -Filter "Name='$serviceName'" |
  Select-Object Name,DisplayName,State,StartMode,StartName,PathName,ProcessId,ExitCode
```

Match `identity.service_name` and `display_name` first. Compare
`status.current_state`, process ID, exit codes, and accepted controls with
`sc.exe queryex` and CIM; compare the configured command string, start type,
dependencies, service account, group, and tag with `sc.exe qc` and CIM.
Compare the `D:` portion of `security.sddl` with `sc.exe sdshow` (the collector
SDDL can also include owner and group). Compare as soon as practical:
service state and PID can change between queries. Formatting and labels differ
between tools, so compare the underlying value/meaning rather than requiring
identical display text.

For an extended field, inspect that one record, for example:

```powershell
$record.configuration.extended |
  Select-Object delayed_auto_start,service_sid_type,required_privileges,
                preshutdown_timeout_ms,trigger_info,preferred_node,launch_protection
$record.configuration.extended.failure_actions | ConvertTo-Json -Depth 10
```

`null` with an `unsupported` error means the API level could not be queried on
that provider/OS, not that the configured value is zero or false. For
`enrichment.service_dll`, check its registry `source`, original
`registry_type`, and `value`; it is configuration evidence, not proof that a
DLL is loaded. No service needs to be started or stopped to validate a record.

1. Compare service name/display-name totals and representative entries with
   PowerShell `Get-Service` or Services.msc. `Get-Service` presentation and
   visibility can vary by OS/version and permissions; verify the intended
   Win32-service scope.
2. Compare status fields close in time with `sc.exe queryex <service_name>`.
   Service transitions between observations can explain differences.
3. Compare start type, binary command, dependencies, account, and display name
   with `sc.exe qc <service_name>`.
4. Compare suitable fields using read-only CIM, for example:

   ```powershell
   Get-CimInstance Win32_Service -Filter "Name='Spooler'" |
     Select-Object Name,DisplayName,State,StartMode,StartName,PathName,ProcessId,ExitCode
   ```

5. Compare readable service permissions using `sc.exe sdshow <service_name>`.
   The SDDL should represent owner/group/DACL, not SACL audit entries.
6. Check for stopped services with PID `0`, multiple service records with the
   same nonzero PID, dependencies, accounts, exact command strings, and
   descriptions in the JSON. Confirm delayed-auto and trigger-start metadata
   is not inferred solely from `start_type`.
7. Compare available extended configuration against read-only SCM queries or
   service properties on that Windows version. Unsupported classes should be
   documented, not treated as proof of absent configuration.
8. Do not start/stop services to manufacture test cases. Access-denied and
   disappeared-service behavior, plus continuation/buffer sizing, are tested
   using mocks.
9. Confirm the launcher from another working directory and an output path
   containing spaces. Confirm existing files are preserved unless
   `--overwrite` is supplied.
10. Manually verify UAC approval, cancellation, and launching from an already
    elevated Command Prompt. Verify `0`, `1`, and `2` propagate from the
    elevated process as described above.
11. The implementation uses query/enumeration APIs and opens the registry
    read-only. No control/configuration/registry write operation is called.

## Field coverage

| Field | API or source | Meaning | Required access | Availability or limitation |
|---|---|---|---|---|
| Name, display name, enumeration status | `EnumServicesStatusExW`, `SERVICE_WIN32`, `SERVICE_STATE_ALL` | Win32 own/shared-process service entries and enumeration-time status | `SC_MANAGER_ENUMERATE_SERVICE` | Drivers excluded by scope. Native paging retains partial results and reports incomplete enumeration. |
| Description | `QueryServiceConfig2(SERVICE_CONFIG_DESCRIPTION)` | Configured service description | `SERVICE_QUERY_CONFIG` | Null/error reported if inaccessible; empty string is preserved. |
| Current status and process data | `QueryServiceStatusEx(SC_STATUS_PROCESS_INFO)` | Type, state, controls, exit codes, checkpoint, wait hint, PID, flags | `SERVICE_QUERY_STATUS` | Live state can change; enum snapshot is retained if refresh fails. PID 0 and shared PIDs are valid. |
| Basic configuration | `QueryServiceConfig` | Type, start type, error control, binary command, group, tag, dependencies, configured account | `SERVICE_QUERY_CONFIG` | Command is preserved verbatim; config can differ from status observation time. |
| Delayed automatic start | `QueryServiceConfig2` level 3 | Delayed-auto boolean, distinct from basic start type | `SERVICE_QUERY_CONFIG` | Unsupported on older Windows versions. |
| Failure actions and non-crash flag | `QueryServiceConfig2` levels 2 and 4 | Reset period, reboot message, command, ordered actions/delays, flag | `SERVICE_QUERY_CONFIG` | Some versions/configurations may not support or expose the fields. |
| Service SID type and required privileges | `QueryServiceConfig2` levels 5 and 6 | Configured SID mode and required privilege names | `SERVICE_QUERY_CONFIG` | Unsupported classes are compatibility limitations. |
| Preshutdown timeout | `QueryServiceConfig2` level 7 | Configured preshutdown timeout in milliseconds | `SERVICE_QUERY_CONFIG` | Unsupported on older versions. |
| Trigger configuration | `QueryServiceConfig2` level 8 via ctypes | Trigger type/action, subtype GUID, typed data (raw hex; string items additionally decoded) | `SERVICE_QUERY_CONFIG` | Windows 7/Server 2008 R2 and later; binary meanings are not guessed. |
| Preferred NUMA node | `QueryServiceConfig2` level 9 via ctypes | Preferred node and deletion flag | `SERVICE_QUERY_CONFIG` | Windows 7/Server 2008 R2 and later; may not be configured. |
| Launch protection | `QueryServiceConfig2` level 12 via ctypes | Launch-protection value | `SERVICE_QUERY_CONFIG` | Windows 8.1/Server 2012 R2 and later; does not guarantee other protected details are readable. |
| Owner, group, DACL, SDDL | `QueryServiceObjectSecurity` + pywin32 descriptor conversion | Retrieved service-object security descriptor | `READ_CONTROL` | Absent and null DACL states are distinguished; SACL/audit data deliberately excluded; conversion/query errors recorded. |
| Service DLL | `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\ServiceDll` | Narrowly scoped configured registry value and original registry type | Read access to the specific registry key | Optional; not proof that DLL is loaded. Missing value is not configured. |

API references: Microsoft Learn documentation for
[`EnumServicesStatusEx`](https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexa),
[`QueryServiceConfig`](https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw),
[`QueryServiceConfig2`](https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2w),
[`QueryServiceStatusEx`](https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex),
[`QueryServiceObjectSecurity`](https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryserviceobjectsecurity),
and [service security and access rights](https://learn.microsoft.com/windows/win32/services/service-security-and-access-rights).
