# A20 — Startup Folders

When run through `launch.bat`, generated output files are prefixed with `<Artifact Name>_`; the standardized hash/timestamp report is `<Artifact Name>_Hash & Timestamp Report.json`. Raw acquired data files retain their source names.


## Run and dependencies

Windows-only; elevated token and Python standard library (including
`winreg`) are required. `--case-root` is metadata, `--output-dir` is the
direct destination, and `--run-id` optionally supplies the identifier.
Sources are the all-users Common Startup folder and Startup folders for
profiles discovered from the Windows ProfileList registry key.

## Files and schemas

`Startup Folders_Inventory.json` and the standard hash/timestamp report are
placed directly in the selected destination. Acquired files are placed at
`<output-dir>/<source_id>/<source-relative-path>`:
`CommonStartup/...` or `User_<SID>/...`. Original basenames and relative
paths are retained. The source/profile directory levels preserve provenance;
there is no timestamped run directory.

The inventory is UTF-8 JSON with root fields:
`schema_version` (string), `artifact_id`, `artifact_name`,
`collector_version`, `run_id`, `started_utc`, nullable `finished_utc`,
`case_root`, `run_directory`, `acquired_files_directory` (strings),
`system` (object), `sources`, `files`, `errors`, `skipped_paths`,
`summary` (object), `limitations` (string array), and final `result`.
`system` has string `hostname`, `platform`, `windows_version`,
`python_version`, boolean `administrator`.

Each `sources` entry has `source_id`, `scope`, `source_path`, optional `sid`
and `profile_path`, boolean `exists`, `enumeration_status`, and integer
`files_discovered`. Enumeration statuses include `NOT_STARTED`,
`SOURCE_MISSING`, `NOT_A_DIRECTORY`, `OUTPUT_OR_TOOL_PATH_EXCLUDED`,
`ENUMERATED`, and `ENUMERATED_WITH_ERRORS`.

Each `files` entry has `source_id`, `source_path`, POSIX-style
`relative_path`, `destination_path`, `status`, nullable hex strings
`sha256_before`, `sha256_copy`, `sha256_after`, `finished_utc`, booleans `hash_verified`
and `source_changed_or_unstable`, `errors` (string array), and, when
observed, `source_metadata_before`, `copy_metadata`, `source_metadata_after`.
Metadata objects use integer `size_bytes`, `mtime_ns`, `ctime_ns`, `atime_ns`
and ISO-8601 UTC strings `mtime_utc`, `ctime_utc`, `atime_utc`. The inventory's
`timestamp_field_meanings` explains each field: `mtime` is last content
modification; on Windows with Python 3.12, `ctime` is creation time (for the
copy, typically when the copy was created); and `atime` is last access, which
may be updated by collection. `_utc` values are UTC; the `*_ns` values are
integer filesystem timestamp values, not UTC times. File statuses are `STARTED`, `HASH_MISMATCH`, `COPIED_SOURCE_UNSTABLE`,
`COPIED_VERIFIED`, or `FAILED`; hash/source-change booleans remain false if
the corresponding check could not complete. Error entries have UTC
`timestamp_utc`, `stage`, `path`,
`error_type`, `error` strings. Skipped-path entries have `path`, `reason`,
`source_id` strings.

`summary` has integer counts `source_folders_examined`,
`source_folders_found`, `files_discovered`, `files_copied`, `hash_verified`,
`failed_files`, `source_changed_or_unstable`, `bytes_copied`,
`errors_recorded`, `skipped_paths`. `result` is `COMPLETED`,
`COMPLETED_WITH_ERRORS`, `NO_FILES_DISCOVERED`, or
`COMPLETED_WITH_VERIFICATION_ISSUES`. The inventory includes collection outcome/counts and errors. No separate
acquisition-manifest or verification report is generated.

Times ending `_utc` are ISO-8601 UTC strings. Nanosecond fields are integer
filesystem metadata units, not converted wall-clock times. SHA-256 values
cover whole source/copy bytes; before/copy/after comparisons detect observed
changes but do not establish completeness or authenticity. An existing inventory or temporary file returns nonzero before collection.
Per-file path conflicts are recorded as errors and result in a nonzero exit.

## Limits and scan safety

Only Startup-folder contents are scanned; Run keys, services, tasks, WMI,
and other persistence locations are out of scope. The collector does not
follow symbolic links. An output directory equal to or inside a discovered
recursively scanned source is rejected before walking; the source walk is
not narrowed. Outside that condition, only exact workspace-managed
runtime/tool/script paths are excluded. Live collection is not atomic.

## Reading and validating results

### Detailed field reading and validation workflow

Read `source_id` and `source_path` first to identify Common Startup versus a specific user's Startup path. `relative_path` and `destination_path` show where a copied item was placed; size/timestamp fields describe the source observation. `status`, `hash_verified`, `source_changed_or_unstable`, and `errors` distinguish a verified copy, an unstable source, and a failed acquisition. The inventory's `summary` and `skipped_paths` explain scan coverage; missing folders should not be counted as empty successful folders.

Validate each copied file by comparing source-relative path, length and hashes in the inventory and hash/timestamp report, and inspect the preserved directory layout. For a shortcut or script, use a read-only parser/viewer rather than executing it. Presence in Startup means a configured startup candidate, not proof it ran; correlate separately with logon/task/process evidence. Check permission and skipped-path records before claiming complete user coverage.


**Start with:** `Startup Folders_Inventory.json` and the standard hash/timestamp report. Check each documented status, count, source/profile scope, error, and limitation before interpreting records.

**Validate the run:** From the suite root, parse the inventory with the shared environment (for example, `".venv\Scripts\python.exe" -m json.tool "<selected-output-folder>\Startup Folders_Inventory.json"`). Compare summary counts with the corresponding records and per-file outcomes, then check saved paths, sizes, and SHA-256 values against the acquired copies using the hash/timestamp report.

**Artifact-specific cross-check:** Use the inventory's `sources`, `files`, `summary`, `errors`, and `skipped_paths` to distinguish absent folders, inaccessible paths, skipped items, and copied files. Preserve the `CommonStartup/` and `User_<SID>/` directory structure; compare listed source-relative paths and hash fields with the acquired copies. A file in Startup is a configured candidate, not proof that it executed.

Preserve the acquired originals. A zero count, empty array, unavailable source, or prior-run screenshot is not proof that the artifact never existed; interpret it only within the source and scope documented above.



## Output layout
The selected output directory contains exactly two top-level files: the artifact's primary report and `<Artifact Name>_Hash & Timestamp Report.json`. The hash/timestamp report contains saved-file hashes and timestamps only; it never includes a `manifest` section or embeds auxiliary reports. Files acquired from Windows are kept in a dedicated artifact-named `_files` subfolder. Auxiliary acquisition/verification summaries and human-readable status logs are not emitted as separate top-level reports.
