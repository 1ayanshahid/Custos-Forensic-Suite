# A42 — Logon Sessions

A42 creates one report from three distinct, read-only local sources: current Windows Terminal Services (WTS) sessions, current LSA authentication sessions, and matching historical logon/session events still retained in the local Windows Security event log.

**Coverage warning:** these sources are related but not interchangeable. WTS session IDs are not LSA authentication LUIDs or historical event identifiers. LSA enumeration is a current snapshot, not historical. Historical coverage comes only from retained Security events for the selected event IDs, and depends on audit policy, log retention, permissions, and event availability. The report does not claim to recover all past authentication activity.

## What is a WTS session?

Windows assigns a WTS session identifier to a console or Remote Desktop Services session. `WTSEnumerateSessions` can return sessions in active, disconnected, connecting, listening, or other documented connection states. A disconnected session is not necessarily logged off. An active state means the session is connected and signed in; it does not prove someone is currently using its keyboard.

Session 0 is not a normal interactive desktop session, but A42 preserves it if returned. Session IDs can be reused after a session ends; do not use an ID alone as a permanent identity. User context and client context are separate: the username/domain describe the account associated with the session, while client name/address/protocol describe provider-reported client metadata. A client name or address does not prove the authenticated identity of a device or reveal a user's public Internet address.

Enumeration and per-session queries happen at different moments. Sessions can change or disappear while the collector is running; the result is not an atomic snapshot.

## APIs, information classes, and coverage

The installed Windows environment was inspected as 64-bit Windows 11, Python 3.12.10, pywin32 312. The installed `win32ts` binding exposes enumeration, individual information queries, and active-console lookup. Live inspection showed that it returns Python dictionaries/strings/integers for the basic classes and raises `NotImplementedError` for information classes 24 and 25. A42 uses ctypes only for those two raw structures. Pywin32's `WTSEnumerateSessions` and `WTSQuerySessionInformation` implementations call `WTSFreeMemory` for their allocated buffers; A42's ctypes path also frees its buffer in a `finally` block, including failures.

The supplied project handbook and Tools & Artifact Details document paths were not accessible in this environment. This implementation follows the current A42 scope and the Microsoft references below; those project documents were not reviewed.

| Information | WTS API/information class | Meaning | Availability or limitation |
|---|---|---|---|
| Enumerated session ID, station, state | `WTSEnumerateSessionsW` → `WTS_SESSION_INFO` | Initial WTS session identifier, station name, and `WTS_CONNECTSTATE_CLASS` value. | Uses the current local server handle; returned records are retained even if later enrichment fails. |
| Active physical console ID | `WTSGetActiveConsoleSessionId` | Identifies the session attached to the physical console at the time of the call. | `0xFFFFFFFF` means no active console session ID is available; output uses null and does not match it to a session. |
| Username | `WTSQuerySessionInformationW` → `WTSUserName` (5) | Username associated with the WTS session. | Empty string is retained and reported as absent user information; query errors are distinct. |
| Domain name | `WTSDomainName` (7) | Provider-returned account domain component. | May be empty or unavailable; A42 does not perform account resolution. |
| Session/station name | `WTSWinStationName` (6) | WTS session name. | Kept independently from the enumerated station value; provider results may differ during changes. |
| Queried connection state | `WTSConnectState` (8) | A second state observation for comparison with enumeration. | State discrepancies are recorded instead of replacing the original enumerated state. |
| Client name | `WTSClientName` (10) | Provider-reported client name. | Empty values can be expected, including for console contexts. |
| Client network address | `WTSClientAddress` (14) → `WTS_CLIENT_ADDRESS` | Address family and 20 raw address bytes. | IPv4 decoding uses the documented two-byte offset; IPv6 uses the documented first 16 bytes. Other families are kept raw. Console protocol is not decoded as a remote address. |
| Client protocol | `WTSClientProtocolType` (16) | 0 console, 1 legacy ICA, 2 RDP. | Unknown numeric values are preserved and labeled unknown. |
| Client build | `WTSClientBuildNumber` (9) | Client build number. | Provider value, including zero, is preserved. |
| Product identifier | `WTSClientProductId` (12) | Client-specific USHORT product identifier. | Provider value, including zero, is preserved. |
| Hardware identifier | `WTSClientHardwareId` (13) | Client-specific ULONG. | Microsoft documents it as reserved for future use and always zero; retained but not interpreted. |
| Client display | `WTSClientDisplay` (15) → `WTS_CLIENT_DISPLAY` | Horizontal/vertical resolution and color-depth code. | Color-depth codes are described below; absent/failed queries remain unavailable. |
| Session times and traffic | `WTSSessionInfo` (24) → `WTSINFOW` | Connection state, session ID, station/user/domain, five FILETIME timestamps, and six traffic counters. | Documented for Windows Vista SP1 / Windows Server 2008 and later. Returned structure size is checked before decoding. |
| Extended session times, flags, traffic | `WTSSessionInfoEx` (25) → `WTSINFOEXW` level 1 | Session ID/state, session flags, station/user/domain, five FILETIME timestamps, and six counters. | Documented for Windows 7 / Windows Server 2008 R2 and later. Unsupported levels or short buffers are errors; the session record remains. |
| Is remote session | `WTSIsRemoteSession` (29) | Boolean provider value indicating whether the queried session is remote. | A distinct Boolean; false is retained and is not treated as missing. |
| Idle time and simple counter classes | Classes 17–22 | Obsolete individual fields. | Not queried: Microsoft documents these as unsupported and directs callers to the `WTSINFO` structure's `LastInputTime` for idle calculations. |
| WTS client-information aggregate | `WTSClientInfo` (23) | Broad client information structure. | Not queried because it includes a password member; the collector must not retrieve credential fields. |
| Current local scope | `WTS_CURRENT_SERVER_HANDLE` / null handle | Calls the current local WTS server. | A42 does not call `WTSOpenServer` for a remote host. |

### Current LSA authentication sessions

A42 separately calls pywin32 `win32security.LsaEnumerateLogonSessions` and `LsaGetLogonSessionData`. This includes the locally existing LSA logon sessions exposed by the provider, such as interactive, service, batch, and network logon types where returned. Each LSA record uses its **authentication LUID** as its identity and keeps that distinct from the WTS session ID. The provider-reported Terminal Services session number, if present, is emitted under `terminal_services_session_id`; it is not substituted for the LUID.

The LSA record contains username, domain, SID, UPN, authentication package, original logon-type number and a known label, provider-reported terminal-services session number, logon server, DNS domain, logon/logoff/kickoff times, and additional non-credential fields returned by pywin32. Fields whose names indicate password, credential, token, or secret material are excluded. No passwords or tokens are requested. Microsoft documents that `LsaGetLogonSessionData` requires the caller to own the session or be a local system administrator. The installed pywin32 APIs return Python values; the wrapper manages the native LSA result buffers.

| Information | LSA API | Meaning | Availability or limitation |
|---|---|---|---|
| Current authentication-session identifiers | `LsaEnumerateLogonSessions` | LUIDs for currently existing local LSA logon sessions. | Includes authentication/logon types beyond interactive WTS sessions, as returned by Windows. Does not enumerate ended historical sessions. |
| Per-LUID details | `LsaGetLogonSessionData` | User/domain/SID, authentication package, logon type, session number, logon time and related provider data. | A query can fail after enumeration; its LUID record is retained with a per-record error. Some fields may be empty, sentinel, or inaccessible. |
| SID conversion | pywin32 SID conversion | Converts returned SID to its string representation. | Conversion errors are recorded; the session is retained. |
| Logon type | `SECURITY_LOGON_TYPE` values returned by LSA | Raw value plus a label for recognized values. | Unknown numeric values are preserved; labels are not guessed. |

### Historical Security log events

The collector queries the **local** `Security` channel from oldest retained matching event to newest. It captures every retained match for this selected set: **4624** successful logon, **4625** failed logon attempt, **4634** logoff, **4647** user-initiated logoff, **4648** explicit-credentials logon attempt, **4672** special privileges assigned to a new logon, **4776** NTLM credential validation, **4778** session reconnect, **4779** session disconnect, **4800** workstation lock, and **4801** workstation unlock.

Windows Event Log APIs (`EvtQuery`, `EvtNext`, `EvtRender`, and `EvtClose` from `wevtapi`) retrieve and render each matching event as XML. A42 preserves the full event XML and also exposes its system metadata and EventData values as fields. Event XML contains event-specific fields, so the structured EventData list is intentionally generic and does not infer the meaning of similarly named fields across different IDs.

A 4625 is a failed attempt, not a created session. A 4648 or 4776 is authentication activity and does not prove that a session was established. A 4634 or 4647 indicates a logoff event; reconnect/disconnect and lock/unlock records describe different events, not new logons. Event versions and available fields vary. When an event includes a logon LUID, it remains an event-provided value and is never relabeled as a WTS session ID.

| Information | Windows Event Log source | Meaning | Availability or limitation |
|---|---|---|---|
| Historical logon/logoff/authentication/session events | Local `Security` channel; selected event IDs listed above | Events retained in the channel for the selected categories, queried in chronological order. | Only events audited and still retained are available. Cleared, overwritten, unaudited, or denied history cannot be recovered. |
| Event system metadata | `EvtRender` XML `System` element | `provider`, `event_id` and optional `event_id_attributes`, `version`, `level`, `task`, `opcode`, `keywords`, raw `time_created`, normalized `time_created_utc/local/status`, `eventRecordID`, `correlation`, `execution`, `channel`, `computer`, and `security`. | Exact fields vary by event; full XML is retained. |
| Event-specific fields | `EventData` or `UserData` in rendered XML | Raw name/value pairs and any user-data XML. | No single schema fits all event IDs; empty values and repeated names are preserved. |

### Native structure checks

`WTS_CLIENT_ADDRESS` is a DWORD family plus 20 bytes (24 bytes total); `WTS_CLIENT_DISPLAY` is three DWORDs (12 bytes). On the inspected 64-bit Windows/Python ABI, the Unicode structures measured as `WTSINFO` = 216 bytes, `WTSINFOEX_LEVEL1W` = 224 bytes, and `WTSINFOEXW` = 232 bytes with its union at offset 8. A42 checks the returned byte count against the selected structure's runtime `ctypes.sizeof` before copying. `WTSINFOEXW.Level` must be 1. The WTS-allocated buffer is always released with `WTSFreeMemory`, also when decoding fails.

The pywin32 source for `win32ts.WTSEnumerateSessions` and `win32ts.WTSQuerySessionInformation` is linked below; both wrappers release a non-null WTS buffer after building Python objects. The WTS API contract also requires `WTSFreeMemory` for buffers returned by WTS APIs.

### Session flags

`WTSINFOEX_LEVEL1W.SessionFlags` is treated as a documented session lock-state value, not a bitmask: 0 is locked, 1 is unlocked, and `0xFFFFFFFF` is unknown. Microsoft documents reversed 0/1 interpretation on Windows 7 and Windows Server 2008 R2 due to a defect. A42 checks the Windows version and labels that legacy mapping; unrecognized values are preserved without interpretation. This field is not proof of a user's presence or activity.

### Timestamps and counters

`LogonTime`, `ConnectTime`, `DisconnectTime`, `LastInputTime`, and provider `CurrentTime` are 100-nanosecond Windows FILETIME counts since 1601-01-01 UTC. Each output preserves the raw count and gives the UTC conversion plus the host-timezone representation with numeric offset. Zero is a sentinel and produces no date; negative or out-of-range values are not converted. A42 never uses the current offset as if it were the historical offset.

The derived `idle_duration` uses `LastInputTime` and `CurrentTime` from the same preferred provider structure. It is null if either value is missing/zero, if values conflict, or if either timestamp is future-dated relative to the observation time. Since the observation timestamp is represented to microsecond precision, the future check compares both values at that precision; sub-microsecond FILETIME ticks are not treated as a confident future date. It is a derived duration, not proof of a particular human action. Traffic counters are cumulative since the client connected; the byte counters distinguish compressed from uncompressed data, and frame counters count frames. They do not provide packets, content, or per-connection history.

## Requirements and launcher

- Windows 10/11 or a supported Windows Server installation with local WTS, LSA, and Windows Event Log APIs.
- 64-bit Windows Python 3.10 or newer. Run the project-root `setup_environment.bat` once to create `.venv` and install the pinned dependencies from `requirements-dev-lock.txt`.
- pywin32, including `win32ts` and `win32security`. ctypes is part of Python; it supplies the WTS structures not decoded by this pywin32 build and the documented Windows Event Log API entry points needed to close every event handle explicitly.
- Administrator access is requested by the launcher. Reading the Security log may be denied without the required rights; `LsaGetLogonSessionData` requires session ownership or local administrator rights. WTS and LSA visibility also depend on permissions and Windows/provider behavior. Elevation does not guarantee every field or event is available.
- The WTS structure classes have documented minimums of Vista SP1/Server 2008 for `WTSSessionInfo` and Windows 7/Server 2008 R2 for `WTSSessionInfoEx`. LSA enumeration begins on Windows XP/Server 2003; Windows Event Log query/render APIs begin on Vista/Server 2008. A42 targets Windows 10/11 and supported Windows Server versions.
- The historical Security event query has no time cutoff and no artificial record cap. It can take time and produce a large JSON file when the local log retains many matching events.

Run the project-root `setup_environment.bat` before the first artifact launcher. It prepares Python dependencies but does not install optional external tools or grant administrator permissions.

`launch.bat` checks for administrator access, requests the standard UAC approval if necessary, waits for the elevated process, and forwards the collector's 0/1/2 exit code. Cancelling UAC stops collection. The launcher never bypasses UAC or changes execution policy.

## Run A42

Double-click `launch.bat`. With no arguments, it prompts for an output JSON file or existing directory; press Enter for a timestamped JSON file in the A42 folder.

From this artifact folder in Command Prompt:

```bat
launch.bat
launch.bat --output "D:\Case Files\Logon Sessions.json"
launch.bat --output "D:\Case Files\Logon Sessions_Output"
launch.bat --output "D:\Case Files\Logon Sessions.json" --overwrite
```

Direct Python CLI use is available for a future caller or for manual operation:

```bat
..\..\.venv\Scripts\python.exe collector.py --output "D:\Case Files\Logon Sessions.json"
```

An existing output file is protected unless `--overwrite` is specified. Exit codes: **0** all three sources succeeded, **1** at least one source is partial or failed while another source completed, **2** all three sources failed or report writing failed. A failed source is not presented as a successful empty inventory; inspect each source status and its errors.

## Files and JSON output

Files in this artifact folder:

- `collector.py` — reusable provider, collection/normalization functions, JSON writer, and CLI.
- `launch.bat` — the single double-click/Command Prompt launcher, including administrator and UAC logic.
- `README.md` — this guide.
- `Logon Sessions-<UTC timestamp>.json` — the generated report in the chosen destination.

JSON uses UTF-8 and pretty formatting with a blank line between consecutive object records in arrays, so one record is visually separated from the next without changing the JSON. Dates are represented by the UTC value ending in `Z` and a corresponding local value with numeric offset.

### Top-level fields

| Field | Meaning |
|---|---|
| `artifact_id` | Always `A42`. |
| `local_time_basis` | States that `_local` timestamps use the collector host's configured timezone and carry an explicit numeric offset. |
| `collection_started_at_utc`, `collection_ended_at_utc` | Collection start/end in UTC. |
| `collection_started_at_local`, `collection_ended_at_local` | Same instants in local time with numeric offset. |
| `scope` | Current local WTS sessions, current local LSA authentication sessions, and selected historical events retained in the local Security channel; no remote server is queried. |
| `status` | `success`, `partial`, or `failed`. `success` means all three source collections completed; `partial` means one or more source collections were partial/failed but at least one completed; `failed` means all three sources failed. |
| `providers` | Provider names/roles, queried WTS classes, and selected Security event IDs. Pywin32 manages its WTS/LSA wrapper buffers; ctypes uses `WTSFreeMemory` for the two raw WTS structures and `EvtClose` for Windows Event Log handles. |
| `windows_version` | Major, minor, and build used to gate documented structure availability and session-flag interpretation; null if unavailable. |
| `enumeration_complete` | Whether WTS session enumeration returned a valid sequence; see `current_wts_status`, `current_lsa_sessions.enumeration_complete`, and `historical_security_events.enumeration_complete` for each source. |
| `current_wts_status` | `success`, `partial`, or `failed` for WTS enumeration/enrichment alone. |
| `active_console_session_id` | Active physical console WTS session ID, or null if unavailable. |
| `active_console_status` | `available`, `no_active_console_session`, `query_failed`, `malformed_provider_value`, or `not_queried` on total enumeration failure. |
| `current_lsa_sessions` | Container with `status`, `enumeration_complete`, `record_count`, `observed_at_utc`, `observed_at_local`, `sessions`, and LSA `errors`. |
| `historical_security_events` | Container with `status`, `enumeration_complete`, `record_count`, query metadata, collection start/end UTC/local times, `events`, and event-query `errors`. |
| `record_counts` | Counts by `current_wts_sessions`, `current_lsa_authentication_sessions`, and `historical_security_events`. |
| `record_count` | Sum of all retained WTS, LSA, and historical event records. |
| `sessions` | WTS records only: one for each enumerated session with a valid ID, including session 0 and sessions whose queries failed. |
| `errors` | All-source errors tagged with their `source`; per-record errors remain inside their source record and are also represented here where applicable. |
| `limitations` | Scope and interpretation cautions, including event auditing and retention limits. |
| `output_path` | Absolute output JSON path added by the writer. |

### Session record fields

| Field | Meaning |
|---|---|
| `session_identity.session_id` | WTS session identifier; may be reused and is not an LSA logon ID. |
| `session_identity.win_station_name` | Station/session name from `WTSEnumerateSessions`. |
| `session_identity.connection_state_value`, `connection_state_label` | Original enumerated state and label: `active`, `connected`, `connect_query`, `shadow`, `disconnected`, `idle`, `listen`, `reset`, `down`, `initializing`, or `unknown_provider_state`. |
| `session_identity.observed_at_utc`, `observed_at_local` | Time enumeration/query processing for this record completed. |
| `session_identity.provider` | Enumeration provider that supplied the original record. |
| `session_identity.matches_active_physical_console_session` | True/false when the active-console ID is available; otherwise null. |
| `session_identity.active_console_comparison_status` | `compared`, `no_active_console_session`, `query_failed`, or `malformed_provider_value`. |
| `session_identity.query_connection_state_value`, `query_connection_state_label` | Separate `WTSConnectState` observation; null if unavailable. |
| `session_identity.state_changed_during_collection` | True if enumerated and queried state values differ; false otherwise. |
| `user_context.username`, `domain_name` | Objects with `value` and `status` (`available`, `absent`, or `unavailable`). Empty string is preserved for an absent value. |
| `user_context.qualified_username` | `domain\username` when both are available, username alone if only it is available, otherwise null. |
| `user_context.status` | `available`, `absent`, or `inaccessible`. A blank username is not itself an error. |
| `client_context.client_name` | Provider-returned value/status. |
| `client_context.protocol_type_value`, `protocol_type_label` | Original numeric protocol and label (`console`, `ica_legacy`, `rdp`, or unknown). |
| `client_context.address` | `address_family_value`/`address_family_label`, original `raw_bytes_hex`, optional `decoded_address`, and `status`. Status is `decoded_ipv4_documented_offset`, `decoded_ipv6_documented_layout`, `raw_bytes_only`, `address_family_unspecified`, `malformed_address_buffer`, `unavailable`, or `not_applicable_console_protocol`. No console remote address is invented. |
| `client_context.client_build_number` | Value/status; zero remains zero. |
| `client_context.product_identifier` | Product ID value/status; zero remains zero. |
| `client_context.hardware_identifier` | Value/status and reserved-use meaning. |
| `client_context.display` | Resolution and color-depth values or null if unavailable. Depth values: 1=4bpp, 2=8bpp, 4=16bpp, 8=24-bit RGB, 16=15bpp, 24=24bpp, 32=32bpp. |
| `client_context.is_remote_session` | Provider Boolean; false is meaningful and retained. |
| `extended_information.wts_session_info` | Normalized WTSINFO fields or null when unsupported/failed. |
| `extended_information.wts_session_info_ex` | Normalized WTSINFOEX level 1 fields or null when unsupported/failed. |
| `extended_information.preferred_source` | `WTSSessionInfoEx`, `WTSSessionInfo`, or null; used for the derived idle duration. |
| `extended_information.idle_duration` | Derived seconds/status/source/observation time; null duration unless provider times are usable, not future-dated, and consistent. Status distinguishes `derived`, `zero_sentinel`, `invalid_or_unavailable_timestamp`, `future_provider_timestamp`, and `inconsistent_provider_timestamps`. |
| `extended_information.session_flags` | Raw SessionFlags value/hex and version-aware interpretation, or null when extended info is unavailable. |
| `information_class_status` | Status for every queried information class, including `available`, `not_applicable`, `access_denied`, `unsupported_information_class`, `session_disappeared`, `provider_failure`, or malformed data with its error. |
| `record_status` | `success` if queried classes completed; `partial` when one or more information classes failed. |
| `errors` | Per-session WTS query, malformed-data, or state-change errors. Failed queries do not remove the session. |

Each WTSINFO/WTSINFOEX `times` entry contains `raw_100ns`, `utc`, `local`, and `status`. Timestamp statuses include `available`, `zero_sentinel`, `invalid_value`, `invalid_provider_value`, and `out_of_range`. `traffic_counters` has six counter objects; each preserves `value`, `unit`, and `meaning`:

| Counter | Unit | Direction/meaning |
|---|---|---|
| `incoming_bytes_uncompressed` | bytes | Uncompressed RDP data, client to server, since connection. |
| `outgoing_bytes_uncompressed` | bytes | Uncompressed RDP data, server to client, since connection. |
| `incoming_frames` | frames | RDP frames, client to server, since connection. |
| `outgoing_frames` | frames | RDP frames, server to client, since connection. |
| `incoming_bytes_compressed` | bytes | Compressed RDP data, client to server, since connection. |
| `outgoing_bytes_compressed` | bytes | Compressed RDP data, server to client, since connection. |

`structure_size` records the expected native structure size; `buffer_size` records the actual returned byte count. WTSINFOEX also records its `level`, session state, station name, username/domain, and session flags. Error objects include a `category` and available operation/message/native error details; per-session entries are associated with `session_id` and may include `detail` or both compared states.

### Current LSA session records

`current_lsa_sessions` is a separate source container; its status, enumeration completeness, count, observation UTC/local times, records, and errors do not change the meaning of `sessions` (the WTS array).

| Field | Meaning |
|---|---|
| `authentication_session_identity.authentication_luid_value`, `authentication_luid_hex` | LSA authentication-session identifier from the provider, shown as the original numeric value and 64-bit hexadecimal form. It is not a WTS session ID. |
| `authentication_session_identity.identifier_type` | Explicit label distinguishing the LUID from WTS session IDs. |
| `user_context.username`, `domain_name`, `sid`, `upn` | LSA-reported user values, each wrapped as `value` and `status`. SID conversion failures are recorded on the session. |
| `logon_context.authentication_package` | Package name reported for this current authentication session. |
| `logon_context.logon_type_value`, `logon_type_label` | Original LSA logon-type value and known label; unknown values are retained with `unknown_logon_type`. |
| `logon_context.terminal_services_session_id` | LSA provider's session-number field, wrapped as `value`/`status`; it is not used as the authentication LUID or WTS session ID. |
| `logon_context.logon_server`, `dns_domain_name` | Provider-returned server and DNS-domain strings with value/status. |
| `logon_context.logon_time`, `logoff_time`, `kickoff_time` | Objects containing `provider_value`, normalized `utc`, `local`, and `status`. The 1601 sentinel has no converted date. |
| `logon_context.additional_noncredential_provider_fields` | Other pywin32-returned provider values as JSON-safe values; keys naming passwords, credentials, tokens, or secrets are omitted. |
| `record_status`, `errors` | `success` or `partial`; LUID records remain even when data/SID conversion fails. Error details include operation, category, type, native code, and message when available. |

### Historical Security event records

Each object in `historical_security_events.events` preserves both a parsed view and the complete rendered XML.

| Field | Meaning |
|---|---|
| `event_metadata` | System information parsed from the event's `<System>` element: provider attributes; `event_id` and optional attributes; version, level, task, opcode, keywords; original `time_created` attributes; normalized `time_created_utc`, `time_created_local`, and `time_created_status`; event record ID; correlation, execution, and security attributes; channel and computer. |
| `event_type_label` | Known label for the selected event ID (for example `successful_logon`, `failed_logon_attempt`, `logoff`, `session_reconnected`, or `workstation_locked`). |
| `event_data` | Ordered list of every `<Data>` item with `name`, all XML `attributes`, and `value`. Empty values and duplicate names remain separate entries. |
| `user_data_xml` | Serialized `<UserData>` subtree when present; otherwise null. |
| `raw_xml` | Full event XML as rendered by Windows, preserving additional fields and event-specific structure. |
| `record_status`, `errors` | `success` when rendered/parsed, otherwise `partial` with the rendering or parsing error. A query-level failure is reported by the source container and overall `errors`. |

The source container's `query` names the channel, selected event IDs and labels, chronological direction, and all-retained-records range. `collection_started_at_utc/local` and `collection_ended_at_utc/local` bound the query. `enumeration_complete` is false when query iteration or handle cleanup fails. `record_count` counts records retained, including individually malformed records.

### Errors and unavailable values

- `access_denied`: Windows denied the query; session row remains.
- `unsupported_information_class`: the provider or this Windows version does not support the requested class; row remains.
- `session_disappeared`: WTS reported a missing/invalid session during enrichment; the initially enumerated row remains.
- `provider_failure`: another WTS/pywin32/API error.
- `malformed_provider_data`: a WTS structure or field had an invalid type/size/level.
- `malformed_provider_record` / `malformed_enumeration_result`: required provider data was malformed. A record without a valid session ID cannot be identified or retained.
- `malformed_provider_value`: active-console lookup did not return a valid ID.
- `provider_state_changed_during_collection`: the state changed between enumeration and query.
- `lsa_session_record_error`: an LSA per-LUID query or SID conversion error; the LUID remains.
- `security_event_query_failure`: the event query could not be opened or advanced, commonly due to Security-log permissions or provider errors.
- `malformed_security_event_result` / `incomplete_security_event_enumeration`: the event provider returned malformed data or did not complete.
- `event_handle_release_failure`: Windows reported failure closing an event/query handle.
- `not_applicable`: class is outside the documented support for the detected Windows version.
- `absent`: a legitimate empty user/client string; not a query failure.
- `null`: unavailable/not returned; never means numeric zero or Boolean false.

An active session does not prove keyboard activity. Last-input time is not logon time or proof of an action. The optional aggregate `WTSClientInfo` class is intentionally excluded because its structure includes a password field. No passwords, tokens, screens, clipboard, or LSASS memory are accessed; LSA session metadata is retrieved only through the documented LSA session-data API.

### Illustrative record excerpt

This synthetic example is shortened for readability. It is not a claim that a particular session or address was observed:

```json
{
  "session_identity": {
    "session_id": 12,
    "win_station_name": "RDP-Tcp#1",
    "connection_state_value": 4,
    "connection_state_label": "disconnected",
    "matches_active_physical_console_session": false
  },
  "user_context": {
    "username": { "value": "Example User", "status": "available" },
    "domain_name": { "value": "LAB", "status": "available" },
    "qualified_username": "LAB\\Example User",
    "status": "available"
  },
  "client_context": {
    "protocol_type_value": 2,
    "protocol_type_label": "rdp",
    "address": {
      "address_family_value": 2,
      "address_family_label": "AF_INET",
      "raw_bytes_hex": "0000c0a8010a0000000000000000000000000000",
      "decoded_address": "192.168.1.10",
      "status": "decoded_ipv4_documented_offset"
    }
  }
}
```

The following abbreviated LSA and historical-event excerpt is also synthetic. In particular, the LUID and event record ID are examples, not a correlation claim:

```json
{
  "authentication_session_identity": {
    "authentication_luid_value": 123,
    "authentication_luid_hex": "0x000000000000007B",
    "identifier_type": "LSA authentication LUID; not a WTS session ID"
  },
  "logon_context": {
    "logon_type_value": 10,
    "logon_type_label": "remote_interactive"
  },
  "event_metadata": {
    "event_id": 4624,
    "eventRecordID": "9876",
    "time_created_utc": "2026-10-11T09:00:00.000000Z"
  },
  "event_data": [
    {
      "name": "TargetLogonId",
      "attributes": { "Name": "TargetLogonId" },
      "value": "0x000000000000007B"
    }
  ],
  "raw_xml": "<Event>... complete Windows-rendered event XML ...</Event>"
}
```

## Validation

### Fixture validation

The deterministic fixture test file was removed as requested and is not included or runnable from this folder. The earlier WTS-only fixture results do not validate the newly added LSA or Security-event collection. Use the live checks below and the report's per-source completeness/status fields; do not treat an empty or denied source as a successful full inventory.

### Live comparisons

Run A42 and compare close in time with:

```bat
quser
qwinsta
```

Also inspect **Task Manager → Users** where available. Compare session ID, username, station, and state. `quser`, `qwinsta`, Task Manager, and WTS may show different subsets or fields due to permissions, platform, timing, and their own display rules; do not treat textual output as identical data. Check the physical-console ID separately when available. Compare any already-existing, authorized RDP sessions without creating or disrupting sessions for testing.

For current LSA coverage, inspect `current_lsa_sessions` for several logon types where present and compare the LSA logon type, username/SID, and LSA-reported terminal-services session number with independent local observations. Do not expect every LSA session to have a WTS session.

For history, open **Event Viewer → Windows Logs → Security**, filter the selected event IDs (4624, 4625, 4634, 4647, 4648, 4672, 4776, 4778, 4779, 4800, 4801), and compare record IDs/timestamps and event-specific fields close in time. Event Viewer and A42 may show different results due to privileges, retention/rollover, audit policy, query time, and display formatting. Verify `raw_xml` retains the rendered event and `event_data` preserves names, duplicate fields, and empty values. Never clear the log or manufacture logon events for validation.

Confirm launching from another working directory, an output path containing spaces and `&`, output refusal/explicit overwrite, UAC approval/cancellation, already-elevated execution, and exit-code/argument preservation. Actual UAC paths require manual Windows checks. Confirm no session state changed and that no password, token, credential, or LSASS-memory API was used.

## Common limitations and remedies

- **pywin32 missing:** rerun the project-root `setup_environment.bat`; the artifact launcher never installs dependencies.
- **UAC cancelled:** no collection begins; rerun and approve only if authorized.
- **Security event query access denied:** run through the launcher and approve UAC if authorized; if it remains denied, preserve the report as partial and inspect `historical_security_events.errors`.
- **No historical events returned:** this may mean no matching records remain, relevant auditing was disabled, the log rolled over/was cleared, or event versions differ. A zero count is not proof that logons never occurred.
- **Large report/slow query:** all retained matching Security records are collected without a time cutoff or cap; destination disk space and runtime depend on Security-log size.
- **LSA query errors:** inspect the affected authentication LUID record and its error; LSA enumeration can succeed while details for individual sessions are unavailable.
- **Some fields are denied/unsupported:** retain the partial report and inspect `information_class_status` and `errors`; administrator access does not ensure query permission.
- **Session absent from comparison tool:** compare at nearly the same time and consider that each tool may expose a different session subset.
- **Address is null or raw-only:** this may be non-IP, console, malformed, unsupported, or unavailable metadata. A42 does not invent an endpoint.
- **Partial status:** session rows are still preserved; inspect each query's status rather than interpreting null fields as empty values.
- **State differs:** sessions can connect/disconnect between enumeration and enrichment; both values are retained and the discrepancy is reported.

## Official references

- [WTSEnumerateSessionsW](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsw)
- [WTSQuerySessionInformationW](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw)
- [WTSFreeMemory](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsfreememory)
- [WTSGetActiveConsoleSessionId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-wtsgetactiveconsolesessionid)
- [WTS_INFO_CLASS](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ne-wtsapi32-wts_info_class)
- [WTS_CONNECTSTATE_CLASS](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ne-wtsapi32-wts_connectstate_class)
- [WTS_SESSION_INFO](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wts_session_infow)
- [WTS_CLIENT_ADDRESS](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wts_client_address)
- [WTS_CLIENT_DISPLAY](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wts_client_display)
- [WTSINFO](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfow)
- [WTSINFOEXW](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoexw)
- [WTSINFOEX_LEVEL1_W](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w)
- [pywin32 `win32tsmodule.cpp`](https://github.com/mhammond/pywin32/blob/main/win32/src/win32tsmodule.cpp) — implementation and WTS buffer release for the Python bindings.
- [LsaEnumerateLogonSessions](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumeratelogonsessions)
- [LsaGetLogonSessionData](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsagetlogonsessiondata)
- [LsaFreeReturnBuffer](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsafreereturnbuffer)
- [SECURITY_LOGON_TYPE](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ne-ntsecapi-security_logon_type)
- [pywin32 `win32security.i`](https://github.com/mhammond/pywin32/blob/main/win32/src/win32security.i) — LSA wrapper implementations and native return-buffer handling.
- [EvtQuery](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtquery)
- [EvtNext](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnext)
- [EvtRender](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender)
- [EvtClose](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtclose)
- [Security event 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) — successful logon/session creation.
- [Security event 4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625) — failed logon attempt.
- [Security event 4634](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4634) — logon session terminated.
- [Security event 4778](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4778) — session reconnected.
- [Security event 4779](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4779) — session disconnected.
