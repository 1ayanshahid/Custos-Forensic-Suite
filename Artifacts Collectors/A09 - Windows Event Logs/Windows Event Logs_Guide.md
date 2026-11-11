# A09 Windows Event Logs

Source: Windows Event Log channels via wevtutil

Method: wevtutil epl exports each channel to .evtx

Privilege: Administrator

Output: Windows Event Logs_Files/*.evtx + Windows Event Logs_Output.json (channel + SHA-256)
Hash and timestamp report (launcher): Windows Event Logs_Hash & Timestamp Report.json


Prerequisite order: Run A09 before A28 - RDP History from Events and Server
Context. A28 verifies the Security/System EVTX files against this manifest,
including acquisition time, size, SHA-256, EVTX signature, and wevtutil
readability. This manifest does not record a source-computer ID; A28 displays
the acquisition timestamp and asks you to confirm the intended exports.

Validation: See the artifact-specific interpretation and validation steps below. Prior-run counts and screenshots are illustrative only; compare with the current host and collection time.

Limits: Raw EVTX preservation only — parsing into individual records
       is a separate analysis job (python-evtx / EvtxECmd).
       wevtutil preallocates .evtx files to channel max size, so
       byte count does not equal event count.
       PowerShell/Operational channel was absent on this host
       (not all channels exist by default). Missing/disabled
       channels are recorded as errors or absent, not empty results.

Provenance: each record carries a per-file `collected_at` UTC timestamp.

## Understanding and validating A09 results

### Detailed field reading and validation workflow

Treat each result row as one channel-export outcome. `channel` says which log was requested, `saved_as` points to the EVTX evidence, and `status`/`stderr` explain whether the export completed. `size` measures the container, while `sha256` identifies its bytes; neither value is an event count. A channel can export successfully but contain no matching events, and preallocated EVTX files may be large despite few records.

For each channel, open the exact saved EVTX in Event Viewer and verify the channel/provider metadata. Compare the file's size/hash to the result row before analysis. If you also use `wevtutil` or another parser, point it at that same acquired file rather than querying the live channel and expecting an exact count match. Live logs can change after export. An export error, missing channel, or disabled logging must remain distinct from a successful empty channel.


From the suite root, check JSON syntax with the shared environment: `".venv\Scripts\python.exe" -m json.tool "<selected-output-folder>\Windows Event Logs_Output.json"` (replace the placeholder with the actual default or custom output directory).

`Windows Event Logs_Output.json` is the export status/manifest, not a parsed list of Windows events. Read each record's `channel`, `status`, `collected_at`, `saved_as`, `size`, and `sha256`, then map it to its `.evtx` file. A successful export does not mean the channel contains events relevant to a particular question.

Validate EVTX files by opening them in Event Viewer or a compatible read-only parser and checking the channel and records. Compare manifest size/hash with each saved EVTX and, where possible, compare scope with the same host's Event Viewer/`wevtutil` view. EVTX files may be preallocated to a channel's maximum size; file size is not an event count. This collector preserves raw EVTX and does not decode events into JSON.


### Full-source EVTX evidence
The collector also saves full-source `.evtx` exports with `wevtutil epl`, without an event-ID, time, or count filter. Existing JSON query filters and limits remain unchanged. Source channels: System, Application, Security, PowerShell/Operational.
Exports do not clear logs or copy locked live files. They are Windows-generated logical exports, not byte-for-byte copies of the original live EVTX. Access denial, unavailable channels/utilities, and missing or empty output are recorded as export errors; successful JSON is retained. Export failures make collection partial/nonzero. Saved EVTX and JSON are included in the combined saved-file integrity report. Existing outputs and reports are preserved using collision-safe suffixed filenames. Administrator rights may be required.
