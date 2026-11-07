# A05 — IPv4 ARP/Neighbor Cache Collector Guide

This guide describes the JSON written by [`collector.py`](./collector.py), how
to run it, and how to validate individual records. The collector is limited to
the local Windows **IPv4** neighbor table. Windows calls the API a neighbor
table; IPv4 entries are commonly called the ARP cache. IPv6 Neighbor Discovery
is a different protocol and is not collected by A05.

## Collection method and requirements

A05 uses the documented Windows IP Helper API directly:

- `GetIpNetTable2(AF_INET)` is the authoritative source of neighbor rows. It
  returns interface-scoped IPv4 address, physical-address bytes and length,
  state, flags, and the reachability-time union.
- `FreeMibTable` releases the table buffer allocated by `GetIpNetTable2`. The
  collector calls it in a `finally` path, including when row decoding fails.
- `GetIfEntry2` is used as a read-only interface enrichment lookup for alias,
  description, and GUID. Results are cached once per distinct interface LUID
  (using index if the LUID is zero). An interface lookup failure does not
  discard its neighbor row.

No second neighbor provider is queried and the collector does not silently
switch providers after a failure. `GetIpNetTable2(AF_INET)` returns the IPv4
neighbor table visible to this local API call. It does not guarantee access to
every isolated network compartment or to rows that Windows no longer exposes.
Administrator access is required by this launcher's policy, but it does not
make an API query universally require elevation or guarantee complete system
visibility.

Microsoft documents `GetIpNetTable2`, `MIB_IPNET_TABLE2`,
`MIB_IPNET_ROW2`, `SOCKADDR_INET`, `NET_LUID`, `MIB_IF_ROW2`, `GetIfEntry2`,
and `FreeMibTable` for Windows Vista and later (and Server 2008 and later for
the IP Helper API functions). Current Windows versions are the intended
operating environment. The implementation uses Python `ctypes` and other
standard-library modules only:

- Python 3.10 or newer is required by the source syntax; the existing project
  environment is Python 3.12.10.
- Use a Windows Python interpreter whose architecture matches the Windows
  process/DLL environment. The current project interpreter is 64-bit. Before
  collection, the program checks documented structure sizes and offsets and
  fails rather than reading an unexpected layout.
- No PyPI packages, PowerShell module, SDK, compiler, or automatic dependency
  installation is required for the native collector.

The collector makes no changes to neighbor entries, interfaces, routes, or
network configuration. It does not resolve addresses, send packets, ping,
scan, perform DNS lookups, or request neighbor resolution.

## Launching and output destination

### Double-click or Command Prompt

Double-click [`launch.bat`](./launch.bat), or run it from Command Prompt. The
launcher checks the current token and requests standard Windows UAC elevation
when needed. Collection starts only after elevation succeeds. Cancelling or
failing UAC returns without collecting. When launched without arguments, the
elevated process asks for an output destination and keeps the final result
visible until Enter is pressed.

At the prompt, enter either:

- A full JSON file path, such as `D:\Testing Folder\arp.json`; or
- An existing folder, such as `D:\Testing Folder`. A timestamped
  `ARP Cache_arp_cache_YYYYMMDD_HHMMSS.json` file is saved inside the folder.

Press Enter to use the suggested timestamped JSON path in the A05 folder.
Parent folders must already exist; the collector does not create directories.

Example from any working directory:

```bat
"E:\FYP Custos Forensic Suite\artifacts\A05 - ARP Cache\launch.bat"
```

With command-line arguments:

```bat
"E:\FYP Custos Forensic Suite\artifacts\A05 - ARP Cache\launch.bat" --output "D:\Testing Folder\arp snapshot.json"
```

### Direct Python call

The reusable collection entry point does not require `launch.bat`:

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" "E:\FYP Custos Forensic Suite\artifacts\A05 - ARP Cache\collector.py" --output "D:\Testing Folder\arp snapshot.json"
```

Direct Python execution does not request UAC elevation. `launch.bat` contains
the administrator check and requests elevation through the normal Windows UAC
prompt before starting collection.

Existing output files are refused. To intentionally replace a JSON file, pass
`--overwrite`:

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" "E:\FYP Custos Forensic Suite\artifacts\A05 - ARP Cache\collector.py" --output "D:\Testing Folder\arp snapshot.json" --overwrite
```

### Exit codes

| Exit code | Meaning |
|---:|---|
| 0 | Collection completed with `success`. |
| 1 | Collection completed but is `partial`, for example because an interface lookup failed or an unexpected value was observed. Valid rows are still retained. |
| 2 | Collection/provider/output failed, command-line arguments were invalid, or the required output could not be written. A provider failure is not represented as a successful empty table. |
| 1223 from the elevation helper | UAC was cancelled or elevation failed; collection was not started. The exact presentation of a Windows process exit code may depend on the caller. |

## JSON structure

The output is UTF-8 JSON. Blank lines between array objects are for human
readability only; they do not affect parsing. Each neighbor record is a
separate object in `neighbors`, with a visible blank space before the next
object.

### Top-level fields

| Field | Meaning |
|---|---|
| `schema_version` | Version of the JSON layout. |
| `artifact` | Artifact identifier, `A05`. |
| `artifact_name` | Human-readable name, `ARP Cache`. |
| `source` | Description of the data source. |
| `collection_started_at_utc` | Collection start time in ISO 8601 UTC form, ending in `+00:00`. |
| `collection_ended_at_utc` | Collection end time in ISO 8601 UTC form, ending in `+00:00`. This is not an entry's creation time. |
| `collection_status` | `success`, `partial`, or `failed`. |
| `provider` | The selected provider family, Windows IP Helper API. |
| `collection_scope` | States the IPv4-only and process-visible API scope. |
| `deduplication` | States that records are not deduplicated; interface identity is kept per row. |
| `neighbor_count` | Number of serialized items in `neighbors`. |
| `interface_count` | Number of distinct interface lookups retained in `interfaces`. |
| `providers_attempted` | Per-API outcomes, return codes, row/lookup counts, scope, and errors. |
| `interfaces` | Cached `GetIfEntry2` enrichment results, one per distinct interface lookup key. |
| `limitations` | Known visibility and interpretation boundaries. |
| `errors` | Provider, row-decoding, memory-release, or interface lookup errors. Inspect these before relying on the snapshot. |
| `neighbors` | The IPv4 neighbor rows returned by the provider. |

### `providers_attempted` entries

Each provider result identifies the API, status, relevant return code/count,
scope, and `errors`. A `GetIpNetTable2` result with status `success` and
`rows_returned: 0` can be a valid empty snapshot. Windows' `ERROR_NOT_FOUND`
means no matching neighbor rows were found; it is not treated as a failed
enumeration. Other nonzero API return codes are provider failures unless
documented otherwise.

`GetIfEntry2` is enrichment, not a second neighbor-table provider. Its
`lookups_attempted` is the number of unique interface identities looked up.
If it fails, the corresponding row remains in `neighbors` with unavailable
interface details and the overall collection is partial.

### Fields in each `neighbors` record

| Field | Meaning |
|---|---|
| `record_index` | Zero-based position of this returned row in the saved array. It is not a permanent record ID. |
| `observed_at_utc` | UTC time recorded by this collector around the table acquisition. It is an observation time, not a neighbor-entry creation or packet timestamp. |
| `source_api` | The API that supplied the neighbor row, `GetIpNetTable2(AF_INET)`. |
| `address_family` | `IPv4` when the returned sockaddr reports `AF_INET`; unexpected families are retained as null here and reported in `address_family_value`/errors. |
| `address_family_value` | Numeric Winsock address-family value from the native row. |
| `neighbor_address_ipv4` | Decoded IPv4 address, or null if decoding is unavailable/unexpected. |
| `address_bytes_hex` | Original address-union bytes in hexadecimal. |
| `interface_index` | Windows interface index associated with the neighbor. It may change when an adapter is disabled/enabled and should not be treated as permanent identity. Zero is preserved if returned. |
| `interface_luid_decimal` | Exact 64-bit interface LUID represented as a decimal string to avoid precision loss in JSON consumers using floating-point numbers. |
| `interface_luid_hex` | Same LUID in fixed-width hexadecimal form. |
| `physical_address_length_reported` | Original byte length reported by Windows. A zero length is preserved. Windows documents up to 32 bytes in this structure. |
| `physical_address_bytes_hex` | Raw physical-address bytes, uppercase hex without separators. An empty string represents a returned length of zero; a non-six-byte address is still retained here. |
| `mac_address` | Colon-separated uppercase address only when exactly six physical-address bytes are reported and present. Otherwise null; see `field_availability`. |
| `neighbor_state_value` | Original numeric `NL_NEIGHBOR_STATE` value. Preserve this even when the state label is unknown. |
| `neighbor_state_label` | Label for documented state codes. Unknown values remain null instead of receiving an invented meaning. |
| `neighbor_state_meaning` | Short explanation for a mapped state, based on Microsoft's documented enum description. `Maximum` is the documented sentinel and is not a legal row state. |
| `router_flag` | `IsRouter` bit from the row's flags. Both `true` and `false` are preserved observations. |
| `unreachable_flag` | `IsUnreachable` bit from the row's flags. It is separate from the state enum and is not inferred from it. |
| `flags_raw_hex` | Original flags byte in hex; bit 0 is `IsRouter`, bit 1 is `IsUnreachable`, as defined by `MIB_IPNET_ROW2`. |
| `reachability_time_value_ms` | Original 32-bit reachability-time union value, in milliseconds. Zero is a valid preserved value. |
| `reachability_time_union_member` | Null. The API structure exposes a union of `LastReachable` and `LastUnreachable` but supplies no discriminator identifying which alias applies to this row. |
| `reachability_time_meaning` | States that the raw value is in milliseconds and explains why the union alias is not guessed. This is not a time-since-observation or last-packet value. |
| `interface` | Cached interface index/LUID, GUID, alias, description, lookup status, and lookup errors. |
| `field_availability` | Field-specific reason a value is unsupported/unavailable/partial. For example, a non-six-byte address has no conventional MAC string, while its bytes remain captured. |
| `field_errors` | Per-row issues, including failed interface enrichment. A row is not dropped because a field failed. |
| `collection_status` | `success` or `partial` for this record. It indicates whether this row had a collection/availability issue; it is not a Windows neighbor state. |

### Interface objects

Each object in `interfaces`, and the cached object nested in each neighbor,
contains:

| Field | Meaning |
|---|---|
| `interface_index` | Index reported for the resolved interface. |
| `interface_luid_decimal`, `interface_luid_hex` | Exact LUID representations used to retain interface identity. |
| `interface_guid` | GUID from the documented interface row, when lookup succeeds. |
| `interface_alias` | Windows interface alias, for example a user-facing adapter name. |
| `interface_description` | Windows interface description, often the adapter/driver description. It is not a hostname or remote-device identity. |
| `lookup_status` | `success` or `failed`. |
| `field_errors` | Error messages for failed alias/description/GUID lookup. |

### Neighbor-state values

Microsoft documents these enum values in order:

| Value | Label | Practical reading |
|---:|---|---|
| 0 | `Unreachable` | Windows reports the neighbor unreachable. |
| 1 | `Incomplete` | Address resolution is in progress; a link-layer address may not yet be known. |
| 2 | `Probe` | Windows is checking reachability of a neighbor no longer known to be reachable. |
| 3 | `Delay` | Windows delays probing while awaiting a higher-layer reachability confirmation. |
| 4 | `Stale` | A cached mapping exists, but current reachability is not confirmed. |
| 5 | `Reachable` | Windows considers the neighbor recently reachable. |
| 6 | `Permanent` | Windows reports a permanent entry. |
| 7 | `Maximum` | Enum sentinel; Microsoft says this is not a legal neighbor-row state. |

These are the Windows neighbor-state values. A state does not prove that a
remote device is currently online at the time you later inspect the file.
State transitions and cache rows can change during collection.

A returned row with no physical-address bytes is still retained. Its
`mac_address` is null with an `unavailable` reason, and that row is marked
`partial` because a conventional MAC value could not be supplied; this can
make the overall snapshot `partial` even when the native table call succeeded
and the top-level `errors` array is empty. A non-six-byte physical address is
also retained raw and cannot be represented as a conventional six-byte MAC.
If Windows returns the `Maximum` sentinel or an unmapped state code, A05
retains the numeric value, marks the label unavailable/unsupported, reports a
row error where appropriate, and marks the affected record/collection
partial.

## Validate one record

Use a JSON parser to load a saved file; do not infer record boundaries by
counting lines. In PowerShell:

```powershell
$path = 'D:\Testing Folder\arp snapshot.json'
$doc = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json

$doc.artifact
$doc.collection_status
$doc.neighbor_count
$doc.neighbors.Count
```

`artifact` should be `A05`, and `neighbor_count` should equal
`neighbors.Count`. Parse/compare timestamps:

```powershell
[DateTimeOffset]::Parse($doc.collection_started_at_utc).Offset
[DateTimeOffset]::Parse($doc.collection_ended_at_utc).Offset
[DateTimeOffset]::Parse($doc.neighbors[0].observed_at_utc).Offset
```

Each offset should be zero (`00:00:00`).

Choose a returned record by **IP and interface**, not IP alone:

```powershell
$record = $doc.neighbors |
    Where-Object {
        $_.neighbor_address_ipv4 -eq '192.168.1.1' -and
        $_.interface_index -eq 12
    } |
    Select-Object -First 1

$record | ConvertTo-Json -Depth 20
```

Replace the example address/index with an actual item. Validate each value:

1. Compare `neighbor_address_ipv4` with the IPv4 value shown by the read-only
   Windows query below.
2. Compare `interface_index` with the matching interface row. When interfaces
   have the same neighbor IP, retain both rows if their interface identity
   differs.
3. Compare `physical_address_length_reported` with the number of bytes
   represented by `physical_address_bytes_hex`. For a six-byte address,
   `mac_address` should contain the same bytes in colon-separated form. For
   any other length, check that `mac_address` is null and the raw bytes remain.
4. Compare `neighbor_state_value` and `neighbor_state_label` with
   `Get-NetNeighbor`. An unknown numeric value is retained with a null label;
   do not assign your own label.
5. Check both boolean flags directly; do not assume they can be derived from
   the state.
6. Interpret `reachability_time_value_ms` only with its union-member and
   meaning fields. It is not a record creation timestamp.
7. Inspect `field_availability`, `field_errors`, and top-level `errors` before
   treating any null as evidence that Windows returned no information.

## Compare against read-only Windows tools

Run comparisons close together in time. The neighbor table can change while
being inspected. These commands are checks only; they do not modify the cache.

### Primary comparison: `Get-NetNeighbor`

```powershell
$record = $doc.neighbors[0]
Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object {
        $_.IPAddress -eq $record.neighbor_address_ipv4 -and
        $_.InterfaceIndex -eq $record.interface_index
    } |
    Format-List *
```

Compare IP address, interface index, `LinkLayerAddress`, and `State`. PowerShell
may format the physical address differently. Incomplete/unreachable rows can
have an empty/zero-like link-layer field; compare the provider's value with
A05's raw length and bytes instead of requiring a six-byte MAC. `Get-NetNeighbor`
may expose properties such as `PolicyStore`; A05 does not invent fields absent
from its native `MIB_IPNET_ROW2` API.

Inspect the full table, without formatted table parsing, when checking record
coverage:

```powershell
Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
    Select-Object IPAddress, InterfaceIndex, LinkLayerAddress, State, PolicyStore
```

The cmdlet's returned properties can vary by Windows/NetTCPIP version. This
command is a separate live query, not an atomic view of the earlier snapshot.

### Secondary comparison: `arp -a`

```powershell
arp -a
```

`arp -a` is a secondary human-readable check. It may group entries by
interface, format the address/state differently, and omit native details such
as exact state codes, flags, interface LUID, raw physical-address length,
reachability union, and provider metadata. Do not parse its console table as
the collector's source of truth. Its coverage may not match the native API's
full interface/compartment visibility.

### Explaining differences

The neighbor table is live. Rows can be added, aged, or transition among
Incomplete, Reachable, Stale, Delay, Probe, Unreachable, and Permanent while
the collector and comparison commands run. A row appearing in one result but
not another can be a timing difference, a visibility difference, or a
provider-specific view. Record the timestamps, interface identity, and exact
values; do not claim a mismatch proves omission without a controlled
time-aligned test.

## Automated fixture tests

Run the A05 fixtures from Command Prompt:

```bat
cd /d "E:\FYP Custos Forensic Suite\artifacts\A05 - ARP Cache"
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" -m unittest -v test_collector.py
```

Fixtures are synthetic and do not alter the real ARP cache. They exercise:

- Documented structure size/offset guards.
- Zero-, one-, and multiple-row table traversal.
- `FreeMibTable` invocation after success, provider failure with a returned
  pointer, and row-normalization failure.
- Six-byte, zero-length, and non-six-byte physical addresses.
- Preservation of zero reachability values and both false/true flags.
- Incomplete, unreachable, permanent, and unknown state values (the live
  provider is not modified to manufacture those entries).
- Interface lookup caching and interface-enrichment failure without dropping
  neighbor rows.
- JSON parseability, whitespace-separated records, existing-output
  protection, output folders with spaces, and provider failure not being
  presented as an empty successful snapshot.

The test suite also performs a live read-only native query on Windows. It
checks the returned family/count and does not populate, clear, or otherwise
modify the neighbor table.

## Additional validation checklist

| Check | How |
|---|---|
| Multiple interfaces | Compare records with different `interface_index`/LUID values; match each separately in `Get-NetNeighbor`. A machine may not have multiple active interfaces with neighbor rows. |
| Incomplete/unreachable live entries | Inspect existing rows only. Do not clear the table or trigger resolution to force a state. Use fixtures if no live example exists. |
| Permanent entries | Use fixture rows with state value 6 if no suitable live entry exists. Do not add a real static ARP entry for this test. |
| Zero, single, multiple rows | Automated fixtures construct those table shapes. A zero-entry native live table is also valid when Windows returns `ERROR_NOT_FOUND`. |
| Physical-address lengths | Fixtures cover 0, 3, 6, and 8-byte cases. Six bytes alone produces formatted `mac_address`; all reported bytes/length are retained. |
| Structure and traversal | Automated checks assert `SOCKADDR_INET`, row/table offsets, and key `MIB_IF_ROW2` field offsets against documented layouts; live tests invoke the actual APIs. |
| Memory cleanup | Fixtures count `FreeMibTable` calls after successful reads, a native error with a non-null allocated table, and a normalization exception. |
| Interface failure | Fixture returns an error from `GetIfEntry2`; verifies the row remains and collection is partial. |
| Unknown state | Fixture uses an undocumented numeric code; verifies the code is preserved and label is null/unsupported. |
| Provider failure | Fixture returns a failing Windows error code and verifies status is `failed`, not successful empty. |
| Output-write failure | Automated fixture targets a missing parent folder and expects a visible `FileNotFoundError`. |
| UTF-8/UTC/overwrite | Parse fixture JSON as UTF-8, parse UTC offsets, and verify existing output is refused without `--overwrite`. |
| Another working directory | Run the absolute `launch.bat` command from a different `cd` directory; the helper resolves its files from `$PSScriptRoot`. |
| Output spaces | Use `"D:\Testing Folder\arp snapshot.json"` or enter an existing folder with spaces. |
| UAC approval/cancellation/already elevated | Must be tested interactively on the target machine. This workspace validation does not claim those manual flows were performed. |
| Arguments/exit across UAC | Pass a quoted path with spaces through `launch.bat`; compare the resulting path and exit code. This should be confirmed through an actual UAC-approved run. |
| No table changes/network traffic | Review the code path: it calls only `GetIpNetTable2`, `GetIfEntry2`, and `FreeMibTable`; it contains no cache modification, resolution, ping, scan, DNS lookup, or packet-send call. |

Do not clear the real cache to manufacture a test. Any separately authorized
test setup that creates local traffic must be a distinct action and must not
become part of normal A05 collection.

## Scope and interpretation limitations

- A05 records a one-time local IPv4 neighbor-table snapshot, not ARP traffic
  history or remote hosts' caches.
- Expired entries no longer returned by Windows cannot be reconstructed.
- The API scope is the table visible to this process; visibility into isolated
  network compartments is not guaranteed.
- IP Helper returns a numeric interface index and LUID; indices can change
  after adapter changes. Alias/description enrichment is best-effort.
- A physical address is a link-layer value, not proof of a specific vendor or
  device identity. No vendor/hostname lookup is performed.
- The reachability union is a duration value in milliseconds. It is not a
  creation time, last packet time, or historical timer log.
- No process, username, traffic counter, packet contents, or application
  protocol is associated with a neighbor row.

## Microsoft references

- [GetIpNetTable2 function](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipnettable2)
- [MIB_IPNET_TABLE2 structure](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipnet_table2)
- [MIB_IPNET_ROW2 structure](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipnet_row2)
- [SOCKADDR_INET union](https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_inet)
- [NET_LUID union](https://learn.microsoft.com/en-us/windows/win32/api/ifdef/ns-ifdef-net_luid_lh)
- [NL_NEIGHBOR_STATE enumeration](https://learn.microsoft.com/en-us/windows/win32/api/nldef/ne-nldef-nl_neighbor_state)
- [MIB_IF_ROW2 structure](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2)
- [GetIfEntry2 function](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getifentry2)
- [FreeMibTable function](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-freemibtable)
