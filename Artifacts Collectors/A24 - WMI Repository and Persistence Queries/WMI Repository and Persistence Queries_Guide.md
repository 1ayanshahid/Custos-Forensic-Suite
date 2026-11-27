# A24 — WMI Repository and Persistence Queries

When run through `launch.bat`, generated output files are prefixed with `<Artifact Name>_`; the standardized hash/timestamp report is `<Artifact Name>_Hash & Timestamp Report.json`. Raw acquired data files retain their source names.


## Run and dependencies

Windows-only and elevated. Python standard library runs Windows PowerShell
WMI/CIM queries and `wevtutil`. `--case-root` is metadata;
`--output-dir` is the direct destination. `--skip-operational-log` omits
the optional WMI-Activity Operational EVTX export.

## Files and schemas

When requested and export succeeds, raw `WMI-Activity_Operational.evtx` is
saved. PowerShell stdout is kept in memory for parsing and is not emitted as
a separate file. The primary persistence report uses the collector's run-ID
convention: `WMI Repository and Persistence Queries_WMI_Persistence_<run_id>.json`.
The summary object is consolidated into the standard hash/timestamp report
rather than emitted separately. No separate acquisition-manifest or
verification report is generated, and no timestamped directory is created.
Existing planned outputs
cause a nonzero collision failure.

The persistence JSON root has `module`, `version`, `artifact`, `run_id`,
UTC ISO-8601 `collected_utc`, `computer_name`, `collector_user`, `case_root`,
`inventory`, `wmi_activity_log`, `commands`, `errors`, `limitations`.
`inventory` is null if PowerShell output cannot be parsed; otherwise it is
the raw PowerShell JSON object: `ComputerName` string,
`CollectionTimeLocal` ISO-8601 local time with offset, integer
`NamespaceCount`, `EventFilterCount`, `EventConsumerCount`, `BindingCount`,
arrays `Namespaces`, `NamespaceErrors`, `EventFilters`, `EventConsumers`,
`FilterToConsumerBindings`, and `RepositoryMetadata` object or null.
Namespace entries have `Namespace` string, integer `Depth`, `Status`.
Namespace errors have `Namespace`, `Operation`, `Error` strings. Filter,
consumer, and binding entries have `Namespace`, `ClassName`, and `Properties`
object; `Properties` is a CIM property bag whose names and JSON types come
from the live provider and can contain null values. Repository metadata has
`Path`, `Exists` boolean, `Files` array, and when the repository directory
is present, `Attributes`, UTC ISO-8601 `CreationTimeUtc`/
`LastWriteTimeUtc`; when absent it has `Error` and empty `Files`. File
entries have `Name`, `FullName`, integer `Length`,
UTC ISO-8601 creation/write times, and string `Attributes`. When repository
listing is unavailable, `Exists:false`, `Error`, and empty `Files` are
reported.

`wmi_activity_log` has `channel`, `status`, and on success `path`, integer
`size`, SHA-256 hex `sha256`; failed/skipped records can have `error`.
Statuses are `EXPORTED`, `EXPORT_FAILED_OR_UNAVAILABLE`, or
`SKIPPED_BY_ARGUMENT`. Command records have `argv` string array,
UTC ISO-8601 `started_utc`/`ended_utc`, nullable integer `exit_code`,
decoded `stdout`/`stderr`, Base64 original byte strings
`stdout_base64`/`stderr_base64`, nullable `error`, and numeric
`duration_seconds`.

The summary has fields: module/version/artifact,
run ID, UTC `collected_utc`, `computer_name`, `case_root`, `status`,
nullable integer `namespace_count`, `event_filter_count`,
`event_consumer_count`, `binding_count`, integer
`namespace_error_count`/`error_count`, `wmi_activity_log_status`,
`evidence_json`, and `errors` array.
Statuses include `SUCCESS`, `PARTIAL`, `SOURCE_AVAILABLE_EMPTY`,
`VERIFICATION_FAILED`.

SHA-256 covers whole emitted files, not individual WMI objects or the source
repository. UTC timestamps are ISO-8601 with offset; PowerShell collection
time is local. Duration is seconds. The collector inventories repository
metadata only; it does not copy or repair repository files.

## Limits

Namespace traversal stops at depth 8; errors are distinct from an empty
query result. Only the listed standard permanent-event consumer classes
are queried. Live WMI state is not an atomic snapshot, and subscriptions
alone do not establish maliciousness. The event channel can be inaccessible,
disabled, or have limited retention.

## Reading and validating results

### Detailed field reading and validation workflow

Separate the acquisition-run record from WMI persistence results and event evidence. The run log's `argv`, timestamps, exit code, stdout/stderr and duration show what command was attempted; raw command output preserves provider text. The normalized inventory records the queried namespace/class/object and parse status. WMI-Activity EVTX evidence is a separate source, not a serialization of the live persistence query. Review per-query errors and status before treating an empty class result as absence.

Validate the saved event log in Event Viewer and compare representative parsed records with provider/event IDs and times in that file. Compare normalized WMI records with the same class/namespace using read-only CIM queries where possible; use the acquired raw command output to diagnose parsing differences. Reconcile counts and run IDs with the primary output and file hashes with the standard hash/timestamp report. Collection of a WMI object is configuration/persistence evidence, not proof it executed or that the repository is complete.


**Start with:** `WMI Repository and Persistence Queries_WMI_Persistence_<run_id>.json` and the standard hash/timestamp report. Check each documented status, count, source/profile scope, error, and limitation before interpreting records.

**Validate the run:** From the suite root, parse the primary JSON with the shared environment (for example, `".venv\Scripts\python.exe" -m json.tool "<selected-output-folder>\WMI Repository and Persistence Queries_WMI_Persistence_<run_id>.json"`). Compare summary counts with the corresponding records and per-file outcomes, then check saved-output paths, sizes, and SHA-256 values in the hash/timestamp report; do not assume a parsed report or successful JSON parse proves a complete collection.

**Artifact-specific cross-check:** Review each WMI query/result status and the summary counts before interpreting the persistence records. Treat `WMI-Activity_Operational.evtx` as raw event evidence; open it in Event Viewer or a compatible EVTX reader and correlate event time/provider with the WMI query output. The collector's WMI results and event log have different scopes and should not be treated as interchangeable.

Preserve the acquired originals. A zero count, empty array, unavailable source, or prior-run screenshot is not proof that the artifact never existed; interpret it only within the source and scope documented above.



## Output layout
The selected output directory contains the persistence report and
`<Artifact Name>_Hash & Timestamp Report.json`. The optional EVTX is kept in
the artifact-named `_Files` folder. No separate acquisition-manifest or
verification report is generated.
