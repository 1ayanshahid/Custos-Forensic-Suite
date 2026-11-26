# A22 — Installed Software

When run through `launch.bat`, generated output files are prefixed with `<Artifact Name>_`; the standardized hash/timestamp report is `<Artifact Name>_Hash & Timestamp Report.json`. Raw acquired data files retain their source names.


## Run and dependencies

Windows-only, elevated; uses Python `winreg`, `whoami.exe`, and standard
library modules. `--case-root` is metadata and `--output-dir` selects the
direct destination. Registry values are read-only; uninstall commands are
never executed.

## Output files and exact schemas

The fixed primary output name is `Installed Software_Inventory.json`.
A pre-existing name causes nonzero failure before collection; no run-ID
suffix is added. The standard hash/timestamp report is kept separately.

Inventory JSON root fields: `artifact` and `artifact_name` strings,
`collector_version` string, `run_id`, `started_utc`, `completed_utc`, and
`collected_utc` ISO-8601 UTC strings, `collection_status` string,
`host_name` string or null, `operating_system` string, integer
`registry_source_count` and `record_count`, `records` array, `registry_sources`
array, `errors` array, and `limitations` array. Every record has:
`source_hive` string, `source_registry_path` string, `registry_view` string,
`user_sid` string or null, `subkey_name` string,
`display_name`, `display_version`, `publisher`, `install_date`,
`install_location`, `uninstall_string` (string/JSON-safe value or null),
`selected_values` object, `all_registry_values` object,
`value_read_errors` array, `collected_utc` ISO-8601 UTC string.
`selected_values` contains present values for `DisplayName`,
`DisplayVersion`, `Publisher`, `InstallDate`, `InstallLocation`,
`InstallSource`, `UninstallString`, `QuietUninstallString`, `DisplayIcon`,
`URLInfoAbout`, `URLUpdateInfo`, `HelpLink`, `Comments`, `EstimatedSize`,
`WindowsInstaller`, `SystemComponent`, `ParentKeyName`,
`ParentDisplayName`, `ReleaseType`, `NoModify`, `NoRepair`, and `Language`;
each present value also has a `<field>_RegistryType` integer.
`all_registry_values`
maps value names to `{value, registry_type}` objects; `registry_type` is an
integer and `value` preserves JSON-safe registry types (bytes are
`{type:"bytes",hex:<hex string>}`). Missing values are omitted from
`selected_values`; common top-level fields become null. Read errors have
`field` and `error`, or `stage` and `error`; their exact occurrence depends
on the registry source.

Each registry-source result has `source`, `registry_path`,
`registry_view`, nullable `user_sid`, `status`, integer `subkeys_seen`,
integer `entries_recorded`, and `errors` array. Statuses include `COLLECTED`,
`COLLECTED_WITH_ERRORS`, `KEY_NOT_FOUND`, `ACCESS_DENIED`,
`ACCESS_OR_OPEN_ERROR`, `HIVE_NOT_LOADED`, `HIVE_ACCESS_ERROR`, and
`INVALID_ORIGINAL_SID`. Error entries record the failing stage/source/view
and error details. The separate hash/timestamp report covers saved outputs;
it does not hash individual registry values or source hives.

## Scope and alternate-account behavior

HKLM uninstall entries and both 32-/64-bit registry views are examined.
When original SID differs from the process token SID, the collector reads
`HKEY_USERS\<CUSTOS_ORIGINAL_SID>` only if that hive is already loaded;
`HIVE_NOT_LOADED`, `ACCESS_DENIED`, `HIVE_ACCESS_ERROR`, and
`INVALID_ORIGINAL_SID` are distinct source statuses. It does not substitute
the elevated administrator's HKCU, mount an offline hive, or claim original
HKCU coverage when the original hive is unavailable. Other loaded user hives
may also be enumerated. `user_sid:null` denotes machine-wide HKLM entries.

This is a logical inventory of current uninstall keys, not raw hive
acquisition, a complete inventory of installed software, or proof of
execution. Registry records can be stale, absent, or duplicated across views.

## Reading and validating results

### Detailed field reading and validation workflow

The inventory is a derived logical view of the configured uninstall/software registry sources, not a raw hive export. Read `source`, `registry_path`, `registry_view`, `user_sid`, `status`, `subkeys_seen`, `entries_recorded`, and `errors` for each source. Distinguish machine-wide from per-user records and 32-bit/64-bit registry views. Individual installed-software values can be absent, empty, or vendor-specific; an uninstall entry is not a guarantee the software is currently usable.

Use the hash/timestamp report to check saved outputs, then compare representative inventory records with the exact source registry key and view on the same host or a verified hive copy. Reconcile per-source `entries_recorded` with derived entries and inspect failures. Avoid treating display names as unique identities; compare publisher, version, install location, and key path. This collector's documented registry coverage is not a complete package inventory and may omit portable applications or products without uninstall keys.


**Start with:** `Installed Software_Inventory.json` and the hash/timestamp report. Check each documented status, count, source/profile scope, error, and limitation before interpreting records.

**Validate the run:** From the suite root, parse the primary JSON with the shared environment (for example, `".venv\Scripts\python.exe" -m json.tool "<selected-output-folder>\Installed Software_Inventory.json"`). Compare summary counts with the corresponding records and per-file outcomes, then check saved-output paths, sizes, and SHA-256 values in the hash/timestamp report; do not assume a parsed report or successful JSON parse proves a complete collection.

**Artifact-specific cross-check:** Read the inventory's records and per-source status using the field definitions above; then compare representative entries with the documented Windows uninstall/software registry sources and recorded registry views. Missing entries mean they were not returned from the queried sources, not that software was never installed.

Preserve the acquired originals. A zero count, empty array, unavailable source, or prior-run screenshot is not proof that the artifact never existed; interpret it only within the source and scope documented above.



## Output layout
The selected output directory contains `Installed Software_Inventory.json`
and the standard `<Artifact Name>_Hash & Timestamp Report.json`. No
acquisition-manifest or verification report is generated.
