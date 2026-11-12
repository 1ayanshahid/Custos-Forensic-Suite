# A07 — Scheduled Tasks Enumeration

When run through `launch.bat`, generated output files are prefixed with `<Artifact Name>_`; the standardized hash/timestamp report is `<Artifact Name>_Hash & Timestamp Report.json`. Raw acquired data files retain their source names.


## Run and dependencies

`collector.py` is Windows-only and requires an elevated token. It uses Python
standard-library modules, Windows PowerShell with the `ScheduledTasks` module,
and `wevtutil`. `--case-root` is recorded metadata; `--output-dir` is the
single destination (default: this folder). `--skip-task-files` and
`--skip-operational-log` omit their respective optional acquisitions.

## Files and schemas

The primary `Scheduled Tasks Enumeration_<run_id>.json` and hash/timestamp
report are at the output root. Supporting outputs and acquired files are under
`Scheduled Tasks Enumeration_Files/`.

* `Scheduled Tasks Enumeration_Files/TaskDefinitionFiles/<Windows System32\Tasks relative path>` — original
  task-store bytes and filenames, copied without content transformation.
* `Scheduled Tasks Enumeration_Files/TaskScheduler_Operational.evtx` — raw EVTX export; it is not parsed into
  an A73 inventory.
* `Scheduled Tasks Enumeration_<run_id>.json` — UTF-8 JSON inventory wrapper at the output root:
  `module`, `version`, `artifact`, `run_id`, `collected_utc`,
  `computer_name`, `collector_user`, `case_root`, `status`, `inventory`,
  `commands`, `task_definition_files`, `task_scheduler_operational_log`,
  `errors`, `limitations`; strings unless noted, `status` is currently null
  (the wrapper initializes it but does not update it), `inventory` is null if
  parsing failed, `commands` is an object keyed by command role, and the
  task-file/errors/limitations fields are arrays.
* The parsed `inventory` object is PowerShell's `ComputerName` (string),
  `CollectionTimeLocal` (ISO-8601 local time with offset),
  `TaskCount` (integer), `GlobalErrors` (string array), and `Tasks` (array).
  Each task has string-valued `TaskName`, `TaskPath`, `State`, `Author`,
  `Description`, `URI`, `Source`, `Date`, `ExportedXml`, nullable/string
  `ExportError`; nested `Principal` has string `UserId`, `GroupId`,
  `LogonType`, `RunLevel`, `DisplayName`; `Settings` has boolean-or-null
  `Enabled`, `Hidden`, `AllowDemandStart`, `StartWhenAvailable`,
  `RunOnlyIfIdle`, `WakeToRun`, integer-or-null `Priority`, and string
  `ExecutionTimeLimit`, `MultipleInstances`; `Actions` is an array of
  objects (`ActionType`, `Execute`, `Arguments`, `WorkingDirectory`,
  `ClassId`, `Data`, all strings); `Triggers` is an array of objects with
  string `TriggerType`, `StartBoundary`, `EndBoundary`,
  `ExecutionTimeLimit`, `UserId`, `Subscription`, `StateChange` and
  boolean-or-null `Enabled`. Missing PowerShell strings may appear as empty
  strings; empty arrays mean no returned elements, not necessarily proof of
  absence if errors exist.
* `task_definition_files` entries have `source_path`, `destination_path`,
  `status`, `source_sha256_before`, `acquired_sha256`,
  `source_sha256_after` (hex strings or null), `source_size_before`,
  `source_size_after`, `acquired_size` (integer bytes or null),
  `source_changed_during_acquisition` (boolean or null), and `error`
  (string or null). Statuses include `ACQUIRED_VERIFIED`,
  `VERIFICATION_FAILED`, `SOURCE_CHANGED_OR_DISAPPEARED`,
  `ACQUISITION_FAILED`.
* `task_scheduler_operational_log` has `channel`, `status`, and, on success,
  `path`, integer `size`, SHA-256 `sha256`; failure may include `error`.
  Status is `EXPORTED`, `EXPORT_FAILED_OR_UNAVAILABLE`, or
  `SKIPPED_BY_ARGUMENT`.
The summary object has module/version/artifact/run/time/host/case strings,
`status`, nullable integer `task_count`, integer task-file acquired/error
counts, `operational_log_status`, integer `error_count`, `evidence_json`,
and `errors` and `limitations` arrays. It is consolidated into the standard
hash/timestamp report rather than emitted separately. No acquisition-manifest
or verification report is generated.

SHA-256 is over the acquired file bytes, then rechecked with byte length;
hashes do not prove source completeness or event interpretation. Run IDs
are names only and do not change timestamps or event data. UTC timestamps
are ISO-8601 with `+00:00`; the nested `CollectionTimeLocal` is local time.
Output conflicts fail rather than overwrite existing fixed files. A conflict
on a dynamically discovered task file is recorded as an acquisition error and
the collector exits nonzero.

## Task Scheduler Operational log (A73): validation and interpretation

A07 is the sole collector for A73 Task Scheduler Operational events; do not
run a second collector or duplicate the export. It exports
`Microsoft-Windows-TaskScheduler/Operational` with `wevtutil epl` without
enabling or changing the channel. The raw EVTX is written as the fixed-name
`Scheduled Tasks Enumeration_Files/TaskScheduler_Operational.evtx` in the selected `--output-dir`.
`--skip-operational-log` sets
`task_scheduler_operational_log.status` to `SKIPPED_BY_ARGUMENT`; otherwise
the status is `EXPORTED` or `EXPORT_FAILED_OR_UNAVAILABLE`.

The collector checks for a successful `wevtutil` exit code and an existing,
non-empty EVTX file, then hashes and re-hashes the copied bytes. It does
**not** call `wevtutil gli`, parse EVTX records, interpret event IDs, count
events, or create a parsed A73 JSON inventory. Thus `EXPORTED` means the
export command and file checks succeeded, not that every record was
semantically validated. Existing fixed EVTX output is not overwritten; a
collision causes A07 to exit nonzero. Use A07's inventory and
hash/timestamp report alongside the raw EVTX.

For interpretation, preserve the raw EVTX and independently open or query the
copy with native Windows Event Viewer/`wevtutil`; verify the channel and
record count, inspect event XML and message rendering, and correlate task
path/name, event record ID, event time, action/process context, and adjacent
records. The A07 task inventory is a collection-time view, not proof that a
task ran; an event alone also needs contextual validation. Event timestamps
are in EVTX/XML system-time representations; A07 does not normalize them.
Disabled channels, retention rollover, access errors, and task changes during
collection can make results incomplete.

The recursive task-store walker refuses an output directory equal to or
inside the task-store root instead of narrowing its scan. It otherwise omits
only exact managed runtime/tool/script paths and does not follow symlinks.



## Output layout
The selected output directory contains the artifact's primary report and
`<Artifact Name>_Hash & Timestamp Report.json`. Task files and the optional
EVTX are kept in the artifact-named `_Files` folder. No separate acquisition-
manifest or verification report is generated.
