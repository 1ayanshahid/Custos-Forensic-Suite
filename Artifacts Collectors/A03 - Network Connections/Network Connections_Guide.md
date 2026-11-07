# A03 — Network Connections Artifact Guide

## Purpose

A03 takes a one-time, read-only snapshot of the local computer's IPv4 and IPv6 TCP and UDP endpoints. It records endpoint addresses and state where applicable, then adds available process and Windows owner-module information.

The snapshot is not a history or a packet capture. Connections can appear or disappear while providers are being queried. A missing field is not proof that the endpoint or process does not exist.

## Start collection

### Use `launch.bat`

Double-click `launch.bat`, or run it from Command Prompt. It requests administrator access through the Windows User Account Control (UAC) prompt first. After approval, enter either a JSON filename or an existing folder. If you enter a folder, a timestamped JSON file is created inside it. Press Enter to use the suggested JSON path in the A03 folder.

The launcher uses the project interpreter:

```text
E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe
```

It does not install dependencies. If `psutil` is missing, install it manually from Command Prompt:

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" -m pip install psutil
```

If UAC is cancelled, collection does not start. Administrator rights can improve visibility, but do not guarantee access to protected processes or every optional field.

### Run the collector directly

The same collector can be called without the launcher:

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" "E:\FYP Custos Forensic Suite\artifacts\A03 - Network Connections\collector.py" --output "D:\Evidence Output\network.json"
```

To intentionally replace an existing file, add `--overwrite`. Without it, an existing output is protected.

The `--output` path may be either a JSON file path or an existing directory. For example, `--output "D:\Evidence Output"` creates a timestamped JSON file in that directory. The parent directory must already exist; the collector does not create directories.

## Providers used

| Provider | Information it contributes |
|---|---|
| `psutil.net_connections(kind='inet')` | Windows internet socket records and available PID, TCP status, and descriptor information. |
| `GetExtendedTcpTable` owner-module tables | IPv4/IPv6 TCP endpoint tuples, TCP state, owner PID, Windows context-bind creation timestamp, and opaque module ownership data that can be resolved by the owner-module API. |
| `GetExtendedUdpTable` owner-module tables | IPv4/IPv6 UDP local endpoints, owner PID where available, context-bind creation timestamp, and resolvable owner-module information. UDP rows do not identify a remote peer or TCP state. |
| `GetOwnerModuleFromTcpEntry`, `GetOwnerModuleFromTcp6Entry`, `GetOwnerModuleFromUdpEntry`, `GetOwnerModuleFromUdp6Entry` | Best-effort module name/path for a specific owner-module table row. Resolution can fail, for example, if Windows denies access or the endpoint changes during lookup. |
| `psutil.Process(pid)` | Best-effort process name, executable path, command line, username, parent PID, and process creation time. Process identity is checked with its creation time. |

The providers are queried separately, not as one atomic system snapshot. The collector reconciles duplicate endpoint views using address family, transport, and endpoint address/port/scope—not PID alone. Provider-specific observations and disagreements are retained for interpretation.

## Reading the JSON

### Top-level fields

| Field | Meaning |
|---|---|
| `schema_version` | Version of the JSON data layout. |
| `artifact` | Artifact identifier; expected value is `A03`. |
| `artifact_name` | Human-readable artifact name. |
| `source` | General description of the collected data. |
| `collection_started_at_utc`, `collection_ended_at_utc` | Start and end of collection in UTC. A `+00:00` suffix identifies UTC. |
| `collection_status` | `success`, `partial`, or `failed`. `partial` means at least one provider, field, or record had a limitation; consult provider statuses and errors. |
| `endpoint_count` | Number of reconciled endpoint records in `endpoints`. |
| `provider_reconciliation` | Explains endpoint identity and how duplicate provider rows are merged. |
| `field_coverage` | Provider and availability notes for groups of collected fields. |
| `providers_attempted` | Provider-by-provider status, row counts, optional-field counts, errors, and unavailable fields. |
| `provider_disagreements` | Fields for which providers returned conflicting observations. A disagreement is not necessarily a collector failure; providers may have observed changing endpoint data. |
| `limitations` | Known limits of the one-time collection. |
| `errors` | Unexpected or actionable failures, including endpoint field errors, provider failures, malformed records, and reconciliation issues. This may be empty even when collection status is `partial` due to unavailable optional fields. |
| `endpoints` | The collected TCP and UDP endpoint records. Each object is one endpoint, separated visually by a blank line in the JSON file for readability. |

### Endpoint fields

| Field | Meaning |
|---|---|
| `address_family` | `IPv4` or `IPv6`. |
| `transport_protocol` | `TCP` or `UDP`. |
| `local_address` | Local endpoint object containing `ip`, `port`, and `scope_id`. |
| `remote_address` | Remote IP/port/scope for TCP when present. UDP uses `null`; listeners may have no meaningful remote endpoint. |
| `tcp_state` | Windows TCP state such as `LISTEN` or `ESTABLISHED`. UDP has no TCP state and uses `null`. |
| `owning_pid` | Process identifier reported by a provider. PID 0 is a valid TCP value; for UDP, Windows documents PID 0 as unavailable. |
| `owning_process_name` | Best-effort process name. |
| `executable_path` | Best-effort executable path. Some processes do not have a normal accessible path. |
| `command_line` | Best-effort process command-line argument list. Protected process access can be denied. |
| `username` | Best-effort account name associated with the process. |
| `parent_pid` | Best-effort parent process identifier. |
| `process_creation_time_utc` | UTC creation time of the owning process. This is **not** the endpoint's creation time. |
| `process_creation_time_unix_seconds` | The same process creation time as Unix epoch seconds. |
| `endpoint_creation_time_utc` | Windows owner-module table's context-bind creation time converted to UTC, when available. This reflects the Windows bind context and is not necessarily when application data began. |
| `endpoint_creation_time_filetime_100ns` | Original Windows FILETIME tick value for the context-bind timestamp. |
| `owning_module_info` | When resolved, an object with `module_name`, `module_path`, and `information_class`. It may be `null` when the API cannot resolve it. |
| `first_observed_at_utc`, `last_observed_at_utc` | When this endpoint tuple was observed while this one collection was running. These do not record past or future observations and are not connection lifetime timestamps. Duplicate provider observations can produce slightly different values. |
| `application_protocol_hint` | An unconfirmed candidate based on transport and a recognized port. It is not protocol identification: the collector does not inspect traffic or payloads. |
| `socket_descriptor` | Descriptor if psutil supplies a non-negative value; Windows commonly does not expose one here. |
| `source_providers` | Providers contributing observations to this reconciled record. |
| `provider_values` | Provider-specific values retained to help inspect how a reconciled record was assembled. |
| `provider_disagreements` | Conflicting values retained on this endpoint, where present. These are also summarized in the top-level `provider_disagreements` list. |
| `field_unavailability` | Explanation for unavailable or inapplicable optional fields. This is a visibility/coverage limitation, not necessarily a failed endpoint enumeration. |
| `field_errors` | Unexpected failures encountered while retrieving fields for this endpoint. |
| `collection_status` | Status of this endpoint record. `partial` means some relevant information could not be collected. |

### Address object

An address object has this shape:

```json
{
  "ip": "192.0.2.10",
  "port": 443,
  "scope_id": null
}
```

For IPv6, `scope_id` may identify the interface scope for a scoped address. For IPv4 it is `null` and marked not applicable. An IP address of `0.0.0.0` or `::` is a wildcard binding, meaning the endpoint is bound across local interfaces rather than to one specific local address.

### Protocol-hint object

Example:

```json
{
  "status": "unconfirmed",
  "candidates": [
    {
      "candidate": "HTTPS",
      "matched_side": "remote",
      "matched_port": 443
    }
  ],
  "basis": "Transport and well-known port mapping only; no traffic or payload was inspected."
}
```

Port numbers are conventional, not proof. An application may use a non-standard port, or unrelated software may use a familiar port.

## Understanding availability and errors

- `supported`: the provider returned the field.
- `not_applicable`: the field does not apply, such as TCP state for UDP or an IPv4 scope ID.
- `unsupported`: the selected source does not expose that field for this record. For example, psutil-only records do not contain the IP Helper bind timestamp.
- `unavailable`: the field is relevant but could not be resolved or was not supplied.
- `access_denied`: Windows or the process provider denied access. Running elevated can help but cannot override all Windows protections.
- `provider_failure`: an unexpected API/provider failure. Read its message and the corresponding entry in `errors` or `providers_attempted`.
- `ProviderDisagreement`: providers returned different values for the same reconciled endpoint. Endpoint tables are sampled at different times, so a rapidly changing endpoint or PID reuse can produce disagreement.

Do not interpret every `null` as zero, empty, or absent on the computer. Use `field_unavailability`, `field_errors`, the provider record, and `field_coverage` to understand why a value is missing. A field with no error or unavailability explanation may simply not be applicable to that endpoint type.

## Validate one record

1. Choose an endpoint from `endpoints`. Note its `address_family`, protocol, local address/port, remote address/port if applicable, TCP state if applicable, and PID.
2. For a TCP record, compare promptly with the read-only Windows endpoint query below. Substitute the PID and local port from the chosen JSON record:

   ```powershell
   Get-NetTCPConnection -OwningProcess 1116 -LocalPort 49670 |
       Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
   ```

3. For a UDP record, compare its local endpoint and PID:

   ```powershell
   Get-NetUDPEndpoint -OwningProcess 1116 -LocalPort 5353 |
       Select-Object LocalAddress, LocalPort, OwningProcess
   ```

4. Confirm the current process information for the PID, while remembering that a PID can exit or be reused:

   ```powershell
   Get-CimInstance Win32_Process -Filter "ProcessId = 1116" |
       Select-Object ProcessId, Name, ParentProcessId, ExecutablePath, CommandLine, CreationDate
   ```

5. Compare the process `CreationDate` with `process_creation_time_utc`, accounting for formatting/timezone conversion. Do not compare it to `endpoint_creation_time_utc`; those describe different events.

Example: query a specific record from a JSON file by PID and local port:

```powershell
$file = "D:\Evidence Output\network.json"
$json = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
$json.endpoints |
    Where-Object {
        $_.owning_pid -eq 1116 -and
        $_.transport_protocol -eq "TCP" -and
        $_.local_address.port -eq 49670
    } |
    Format-List
```

Use values from the record being checked, not the example PID/port above. Compare soon after acquisition: Windows endpoint cmdlets take a later snapshot, so differences can result from live connections changing or provider visibility. A missing match does not by itself prove the collector is wrong or that the endpoint never existed.

## Scope and limitations

A03 does not collect packet contents, byte counts, historical/closed connections, DNS cache, firewall rules, adapter inventory, or verified application-layer protocols. It does not create connections, resolve addresses to hostnames, or modify network settings. The endpoint tables are live snapshots from separate providers, and process/module enrichment is best-effort.
