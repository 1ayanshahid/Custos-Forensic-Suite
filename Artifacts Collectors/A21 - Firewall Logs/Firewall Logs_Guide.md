# A21 — Firewall Logs

When run through `launch.bat`, generated output files are prefixed with `<Artifact Name>_`; the standardized hash/timestamp report is `<Artifact Name>_Hash & Timestamp Report.json`. Raw acquired data files retain their source names.


## Run and dependencies

Windows; requires administrator permission to enable firewall logging, query
profiles, and read configured logs. The collector enables allowed and blocked
traffic logging for Domain, Private, and Public profiles before discovery.
Logging only records events from that point onward; it cannot recover earlier
events. Python uses its standard library and PowerShell firewall cmdlets.
`--output-dir` is the direct destination and defaults to this folder.

## Files and schemas

For each configured log acquired, the original bytes are copied under
`Firewall Logs_Files` using its original basename (for example
`pfirewall.log`); different configured paths with the same basename collide
and are not renamed. `Firewall Logs_Files\Firewall Logs_hash.json` contains
`artifact_id`, `artifact_name`, UTC ISO-8601 `generated`, and `files` array.
Each file entry has `source_path`, `evidence_path`, SHA-256 hex `sha256`,
and integer byte `size`.

`Firewall Logs.json` is UTF-8 JSON with `artifact_id`, `artifact_name`, constant
`source_type` (`Windows Firewall text log`), UTC ISO-8601 `generated`,
`source_evidence` array (same four fields as the hash manifest),
`parsed_files` array, integer `record_count`, integer
`malformed_record_count`, `records` array, and `malformed_records` array.
`parsed_files` entries have `path`, `status`, and may have integer
`record_count`, integer `malformed_count`, or string `error`; statuses
include `PARSED`, `NO_FIELDS_HEADER`, `PARSE_FAILED`. Each parsed record
uses the source file's `#Fields:` header as exact key names; values are
strings except `-` is converted to JSON null. `_source_file` adds the
acquired path string. A malformed record has integer `line_number`,
`field_count`, `expected_field_count`, string-array `raw_values`,
`reason` (`field_count_mismatch`), and `_source_file`.

The CLI prints a JSON status object but does not save that object separately.
Its exact root fields are `artifact_id`, `artifact_name`, `collector`,
UTC `acquisition_started`, `status`, `source`, `profiles`, `evidence`,
`derived`, `errors`, and UTC `acquisition_completed`.
`source` is the last configured source path examined and has `path`,
boolean `exists`, and where available integer `size`, UTC `modified_time`,
`status`, and `error`. `evidence` has `files` and `hash_manifest`;
`derived` has `json`, integer `record_count`, and integer
`malformed_record_count`. `profiles` contains objects returned by
`Get-NetFirewallProfile` (provider fields/types depend on Windows).
Statuses include
`SUCCESS`, `COLLECTED_BUT_NOT_PARSED`, `SOURCE_UNAVAILABLE`,
`SOURCE_NOT_CONFIGURED`, and `ACCESS_DENIED_OR_DISCOVERY_FAILED`.
Discovery/no-config/no-acquired-file early returns do not create the JSON
and hash outputs.

The log bytes are untouched; parsing decodes ASCII with replacement,
removes NUL padding only in memory, reads the latest `#Fields:` header, and
splits whitespace-separated values. SHA-256 covers whole copied bytes.
Times are ISO-8601 UTC strings; firewall record time fields remain source
strings and are not normalized. Fixed `Firewall Logs_hash.json`, `Firewall Logs.json`, and
same-basename copy collisions fail with nonzero status; no existing output
is overwritten.

## Limits

Only paths configured by discovered firewall profiles are considered. If no
log file exists when collection runs, there are no raw log bytes to copy; run
the collector again after Windows has recorded firewall events. Profile/log
configuration and header field names vary. No source/log absence proves that
traffic did or did not occur; malformed rows are retained rather than silently
discarded.

## Reading and validating results

### Detailed field reading and validation workflow

`Firewall Logs.json` is parsed firewall text-log data;
`Firewall Logs_Files\Firewall Logs_hash.json` describes copied source files. `record_count` counts successfully parsed rows; `malformed_record_count` counts rows retained in `malformed_records`, not omitted silently. `parsed_files.status` differentiates parsed, missing-fields-header, and parse-failed outcomes. Parsed record keys are defined by the log's `#Fields:` header and values remain strings except source `-` values mapped to JSON null. The CLI status object is printed, not saved as another output.

Validate a sample by tracing `_source_file` to the copied log and comparing its fields with the raw line after the documented whitespace/NUL handling. Compare totals in JSON and SHA256 file entries; verify hash/size. A parser success does not prove the source log was complete or logging had been enabled earlier. Do not interpret absence of firewall rows as absence of network traffic.


**Start with:** `Firewall Logs.json` and `Firewall Logs_Files\Firewall Logs_hash.json`. Use the file and field definitions in the output/files section above; distinguish the structured inventory/results from any human-readable report and from raw acquired evidence. Check each documented status, count, source/profile scope, error, and limitation before interpreting records.

**Validate the run:** From the suite root, parse the primary JSON with the shared environment (for example, `".venv\Scripts\python.exe" -m json.tool "<selected-output-folder>\Firewall Logs.json"`). Compare summary counts with the corresponding records and per-file outcomes, then check saved-output paths, sizes, and SHA-256 values in the hash/timestamp report; do not assume a parsed report or successful JSON parse proves a complete collection.

**Artifact-specific cross-check:** Read `Firewall Logs.json` as parsed firewall text-log records and use `record_count`, `malformed_record_count`, `parsed_files`, and `malformed_records` to judge parser coverage. Compare representative parsed entries with the original copied `pfirewall.log` lines under `Firewall Logs_Files` and review the SHA-256/size entries in `Firewall Logs_Files\Firewall Logs_hash.json`. The guide's documented log format and configured source paths limit what an empty result means.

Preserve the acquired originals. A zero count, empty array, unavailable source, or prior-run screenshot is not proof that the artifact never existed; interpret it only within the source and scope documented above.



## Output layout
The selected output directory contains exactly two top-level files: the artifact's primary report and `<Artifact Name>_Hash & Timestamp Report.json`. The hash/timestamp report contains saved-file hashes and timestamps only; it never includes a `manifest` section or embeds auxiliary reports. Files acquired from Windows are kept in a dedicated artifact-named `_files` subfolder. Auxiliary acquisition/verification summaries and human-readable status logs are not emitted as separate top-level reports.
