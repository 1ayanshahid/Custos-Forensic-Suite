# A28 RDP History from Events and Server Context

Source: `A09 - Windows Event Logs\output\Security.evtx` and
        `A09 - Windows Event Logs\output\System.evtx`

Method: wevtutil qe /lf:true to query exported EVTX files; XML parsed
        with ElementTree; filter for RDP-relevant Event IDs

Privilege: Administrator (for A09 acquisition)

Output: RDP History from Events and Server Context_Output/RDP History from Events and Server Context_Output.json
Hash and timestamp report (launcher): RDP History from Events and Server Context_Hash & Timestamp Report.json


Prerequisite: A28 runs A09 - Windows Event Logs quietly first, then
validates Security.evtx and System.evtx against A09's configured output,
manifest, file sizes, SHA-256 values, EVTX signatures, and wevtutil readability.
Missing or invalid event-log exports stop collection with an error.

Validation: See the artifact-specific interpretation and validation steps below. Prior-run counts and screenshots are illustrative only; compare with the current host and collection time.

Limits: Server-side evidence of logon/session activity. LogonType=10
        suggests RemoteInteractive but not every 4624 is RDP. 1149 is
        RemoteConnectionManager auth. Absent auditing is not proof of
        no RDP activity. Reads only from already-exported A09 EVTX
        files — does not re-query the live system.

## Understanding and validating A28 results

### Detailed field reading and validation workflow

Read `sources` before `events`: it describes which A09 Security/System exports were found and accepted. `event_id` identifies the event type; `time_created_utc` is the provider timestamp. `logon_type`, `target_user`, `ip_address`, and `source_host` may be present only for relevant schemas. Event 4624 is a successful logon, 4625 is a failed attempt, 1149 is RemoteConnectionManager authentication, and 21/22/25 are Terminal Services lifecycle events; correlate them instead of counting each as a complete RDP session. A 4624 with logon type 10 is a useful indicator but still needs contextual fields.

Validate selected events against the exact Security/System EVTX files A28 consumed, matching event ID, provider, record ID/time, and relevant account/address data. Confirm A09 manifest/hash and review each source status plus A28 errors. Do not substitute live channel results collected later. Missing audit policy, retention, or exported channels can explain gaps; a result with no matching event is not proof of no RDP activity.


From the suite root, check JSON syntax with the shared environment: `".venv\Scripts\python.exe" -m json.tool "<selected-output-folder>\RDP History from Events and Server Context_Output.json"` (replace the placeholder with the actual default or custom output directory).

`RDP History from Events and Server Context_Output.json` reports processing of A09 `Security.evtx` and `System.evtx`. Read `sources` and their statuses before interpreting `count`/`events`. Records have `event_id`, `time_created_utc`, and applicable `logon_type`, `target_user`, `ip_address`, or `source_host` fields. IDs 4624/4625/1149 and Terminal Services 21/22/25 have different meanings; 4624 type 10 can support a RemoteInteractive interpretation but is not alone proof of RDP.

Validate that the A09 files and manifest match the inputs, then compare event ID, timestamp, provider, and record details in the exact EVTX using Event Viewer or a compatible parser. Review errors and source counts. Disabled auditing, retention, or missing channels can leave gaps; no match does not prove no RDP activity.


### Full-source EVTX evidence
The collector also saves full-source `.evtx` exports with `wevtutil epl`, without an event-ID, time, or count filter. Existing JSON query filters and limits remain unchanged. A28 exports the complete Security and System A09 prerequisite EVTX files using `/lf:true`; it does not substitute current live channels for those saved sources.
Exports do not clear logs or copy locked live files. They are Windows-generated logical exports, not byte-for-byte copies of the original live EVTX. Access denial, unavailable channels/utilities, and missing or empty output are recorded as export errors; successful JSON is retained. Export failures make collection partial/nonzero. Saved EVTX and JSON are included in the combined saved-file integrity report. Existing outputs and reports are preserved using collision-safe suffixed filenames. Administrator rights may be required.
