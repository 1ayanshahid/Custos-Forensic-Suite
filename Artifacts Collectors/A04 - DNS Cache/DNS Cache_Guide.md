# A04 — DNS Cache Collector Guide

This guide explains how to read, interpret, and validate the JSON produced by
the A04 collector. It applies to output from [`collector.py`](./collector.py),
whether started directly or through [`launch.bat`](./launch.bat).

## What A04 collects

A04 takes a read-only snapshot of records currently returned by Windows
`Get-DnsClientCache` in the `DnsClient` PowerShell module. It asks the provider
for the unfiltered local cache, preserves the returned records and their
properties, and adds a small set of clearly labeled normalized values for
convenience.

The original provider values are the primary evidence for what Windows
returned. Normalized values are interpretations of those values and do not
replace them.

The collector does **not** flush the cache, perform DNS lookups, change system
settings, or collect historical DNS queries. It cannot report entries that the
selected provider does not expose, including any expired entries it no longer
returns or application-specific caches. Administrator access does not remove
these provider limitations.

## Run the collector

For an individually downloaded A04 package, extract it and run its
`setup_environment.bat` before moving the files. Setup creates `.venv` beside
the setup file. The launcher checks the project root, the A04 package's parent,
and the A04 folder for that environment. An environment created in a separate
package is not shared.

Double-click `launch.bat` to check/request administrator access and then enter
either:

- A full path ending in a JSON filename, such as
  `D:\Testing Folder\dns-cache.json`; or
- An existing folder, such as `D:\Testing Folder`. A timestamped
  `DNS Cache_dns_cache_YYYYMMDD_HHMMSS.json` file is created inside it.

Press Enter at the prompt to save a timestamped file in the A04 folder.
Collection does not begin if the UAC request is cancelled or fails.

From Command Prompt, a file path can also be provided as an argument:

```bat
"E:\FYP Custos Forensic Suite\artifacts\A04 - DNS Cache\launch.bat" --output "D:\Testing Folder\dns-cache.json"
```

To use the collector directly, use the project's existing Python interpreter.
Direct Python execution does not request administrator elevation:

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" "E:\FYP Custos Forensic Suite\artifacts\A04 - DNS Cache\collector.py" --output "D:\Testing Folder\dns-cache.json"
```

The output directory must already exist. Existing output files are refused by
default. Add `--overwrite` only when you intentionally want to replace the
specified JSON file.

The collector uses Python's standard library and Windows PowerShell's
`DnsClient` module; it does not install packages automatically.

## Reading the JSON document

The file is ordinary UTF-8 JSON. Blank lines between array items are only for
readability; they do not separate files or invalidate the JSON. Parse the file
with a JSON-aware viewer or parser rather than counting visual lines.

### Document-level fields

| Field | Meaning |
|---|---|
| `schema_version` | Version of the collector's JSON document layout. |
| `artifact` | Artifact identifier; this collector writes `A04`. |
| `artifact_name` | Human-readable artifact name, `DNS Cache`. |
| `source` | Description of the local Windows DNS cache source. |
| `collection_started_at_utc` | Collector start time as an ISO 8601 timestamp with an explicit UTC offset (`+00:00`). |
| `collection_ended_at_utc` | Collector end time as an ISO 8601 timestamp with an explicit UTC offset (`+00:00`). This is not the time a DNS record was first created or cached. |
| `collection_status` | `success`, `partial`, or `failed`; see [Collection status and errors](#collection-status-and-errors). |
| `record_count` | Number of serialized items in `records`. Check this against `records.length` in a JSON viewer. |
| `provider` | Provider identity, PowerShell/module information, returned property coverage, and collection scope. |
| `limitations` | Scope and interpretation caveats applicable to this snapshot. |
| `errors` | Provider and record/field problems reported by the collector. An empty array means no error was reported; it does not mean Windows exposed historical or otherwise hidden cache data. |
| `records` | The endpoint-like DNS cache entries actually returned by the provider and serialized by the collector. Each array item is one provider record. |

### `provider` fields

| Field | Meaning |
|---|---|
| `name` | PowerShell command used: `Get-DnsClientCache`. |
| `module` | PowerShell module supplying the command, normally `DnsClient`. |
| `powershell_version` | Windows PowerShell version used for the provider query. |
| `records_returned` | Number of raw provider rows received before JSON record validation. Compare it with `record_count`; a difference can indicate a malformed row reported in `errors`. |
| `properties_returned_union` | Sorted union of provider property names seen across the returned rows/schema. This shows which properties were exposed in this run, not that every property applies to every row. |
| `property_types_returned` | Provider-reported/observed types for each property across the response. A property may have multiple types or `null`. |
| `expected_cache_properties_not_returned` | Expected cache fields absent from the returned property union. An empty list means those expected names appeared in the response; it does not promise future Windows versions expose the same set. |
| `filters_applied` | Empty for this collector: no record, type, name, status, or section filters are intentionally applied. |
| `coverage` | The collector's statement that it retains the records/properties returned by this provider without those filters. It is not a guarantee of visibility beyond the provider. |

## Reading one record

Each item in `records` contains these sections:

| Field | Meaning |
|---|---|
| `record_index` | Zero-based position in the collector's serialized record array. This is a convenient locator, not a permanent identifier. Ordering can change between snapshots. |
| `provider_record_index` | Zero-based position assigned while the provider result was read. Normally corresponds to `record_index`; it is retained to make the source order explicit. |
| `provider_values` | Original property names and values read from this provider row. Start here when investigating what Windows returned. Unknown properties are retained rather than discarded. |
| `provider_property_types` | Type information for the properties present in this row. The exact type labels come from the PowerShell/CIM object where available. |
| `provider_properties_present` | Names of properties that were successfully read into `provider_values` for this row. A property can be present with a `null` value. |
| `provider_null_properties` | Names of present properties whose value was `null`. This differs from a property missing from the row. |
| `normalized` | Convenience interpretations derived from selected provider fields. Refer to the field explanations below and confirm against `provider_values`. |
| `field_limitations` | Reasons a normalized field could not be populated, for example because its source property was missing, null, or could not be converted. |
| `field_errors` | Errors reading individual properties from this row, if any. These do not necessarily invalidate other fields or records. |

### Provider properties

The selected Windows version may expose additional properties. The names below
are commonly returned by the inspected provider; always use
`properties_returned_union` and each row's `provider_values` as the authority
for a specific collection.

| Provider property | How to understand it |
|---|---|
| `Entry` | Provider's cache entry/group name. It is preserved in `provider_values` and exposed separately as `normalized.cache_entry_name`; it is not the individual DNS record name. |
| `Name` | Provider's individual DNS record name. It is preserved in `provider_values` and used for `normalized.record_name`. It can differ from `Entry`, for example for CNAME-chain records. |
| `Type` | Provider's numeric DNS type code. The collector preserves the original value and maps recognized codes to a mnemonic in `normalized`. See [DNS type codes](#dns-type-codes). |
| `Data` | Provider's record data as returned, often displayed as text. Interpret it together with `Type`; it is not necessarily a hostname or an IP address. |
| `DataLength` | Provider's numeric data-length field. This is preserved as returned; do not assume it is the character count of the JSON `Data` string. |
| `TimeToLive` | Provider's TTL value. The collector uses this as the preferred source for normalized `time_to_live_seconds`. |
| `TTL` | Additional TTL property sometimes present on the PowerShell object. It is retained separately. The collector uses it only when `TimeToLive` is null or unavailable. If both are present, compare the original values rather than treating their duplication as separate cache records. |
| `Status` | Provider status code. It is copied to `normalized.status_code` but deliberately not assigned an undocumented success/failure meaning. |
| `Section` | Provider section code. It is copied to `normalized.section_code`; no undocumented label is inferred. |
| `Caption` | Provider-supplied descriptive metadata. It may be null. |
| `Description` | Provider-supplied descriptive metadata. It may be null. |
| `ElementName` | Provider-supplied descriptive metadata. An empty string is a returned value, not the same as null or an absent field. |
| `InstanceID` | Provider/CIM instance metadata. It may be null and is not treated as a durable forensic identifier. |
| `PSComputerName` | PowerShell remoting metadata, often null during a local query. It is retained when exposed. |
| Any other property | Preserved dynamically in `provider_values`, with its type where available. Do not ignore unfamiliar fields; consult Windows documentation for their semantics before drawing conclusions. |

The collector excludes PowerShell/CIM wrapper objects (`CimClass`,
`CimInstanceProperties`, and `CimSystemProperties`) because they describe the
object wrapper rather than cache-record properties. It does not use a fixed
allow-list for the actual cache properties.

### Normalized fields

| Normalized field | Source and interpretation |
|---|---|
| `record_name` | Direct copy of provider `Name`, identifying the individual DNS record. If `Name` is null or absent, the normalized value remains null and a field limitation is recorded. |
| `cache_entry_name` | Direct copy of provider `Entry`, identifying the cache entry/group associated with the DNS record. It may differ from `record_name`; the original provider field remains unchanged in `provider_values`. A limitation is recorded if `Entry` is null or missing. |
| `record_type_code` | Integer interpretation of provider `Type`; the original value remains in `provider_values`. |
| `record_type_name` | Mnemonic for a type code in the collector's mapping; otherwise `null`. |
| `record_type_label` | Same mnemonic when recognized, or an explicit `Unmapped DNS record type code N` label when a numeric code is not in the local mapping. |
| `record_data` | Direct copy of provider `Data`, without DNS lookup or name resolution. |
| `data_length_bytes` | Integer interpretation of provider `DataLength`; `bytes` is the provider field's intended unit, not a recomputed length of the displayed string. |
| `status_code` | Integer interpretation of provider `Status`, if available. It is not a decoded status message. |
| `section_code` | Integer interpretation of provider `Section`, if available. It is not a decoded section name. |
| `time_to_live_seconds` | Integer interpretation of `TimeToLive`, falling back to `TTL` only if the former is null/unavailable. This is the provider's TTL value at snapshot time, not a timestamp or historical duration measurement. |

`0`, `""`, and `null` are not interchangeable. A zero is retained if Windows
returned zero. An empty string is retained if Windows returned an empty string.
`null` means a property was present but its value was null. A property absent
from `provider_values` was not successfully returned for that row.

### DNS type codes

`record_type_name` is a convenience mnemonic generated from the collector's
local mapping. The raw number in `provider_values.Type` and
`normalized.record_type_code` is the value to preserve and compare. The
collector does not query DNS to interpret record data. Unmapped numbers remain
in the JSON without a guessed label.

The local mapping includes these common types and additional assigned or
protocol/meta mnemonics:

| Code | Mnemonic | General use |
|---:|---|---|
| 1 | A | IPv4 address record |
| 2 | NS | Name-server record |
| 5 | CNAME | Canonical-name alias |
| 6 | SOA | Zone authority/start-of-authority data |
| 12 | PTR | Reverse-name pointer |
| 13 | HINFO | Host information |
| 15 | MX | Mail-exchange data |
| 16 | TXT | Text data |
| 17 | RP | Responsible person |
| 18 | AFSDB | AFS database location |
| 24 | SIG | Signature (legacy DNSSEC type) |
| 25 | KEY | Key (legacy DNSSEC type) |
| 28 | AAAA | IPv6 address record |
| 29 | LOC | Location data |
| 33 | SRV | Service location |
| 35 | NAPTR | Naming authority pointer |
| 39 | DNAME | Delegation/name redirection |
| 41 | OPT | EDNS pseudo-record |
| 42 | APL | Address-prefix list |
| 43 | DS | Delegation signer |
| 44 | SSHFP | SSH fingerprint |
| 45 | IPSECKEY | IPsec key |
| 46 | RRSIG | DNSSEC resource-record signature |
| 47 | NSEC | DNSSEC next-secure record |
| 48 | DNSKEY | DNSSEC public key |
| 49 | DHCID | DHCP identifier |
| 50 | NSEC3 | Hashed DNSSEC next-secure record |
| 51 | NSEC3PARAM | NSEC3 parameters |
| 52 | TLSA | TLS association data |
| 55 | HIP | Host identity protocol |
| 59 | CDS | Child DS |
| 60 | CDNSKEY | Child DNSKEY |
| 64 | SVCB | Service binding |
| 65 | HTTPS | HTTPS service binding |
| 99 | SPF | SPF text record type |
| 249 | TKEY | Transaction key |
| 250 | TSIG | Transaction signature |
| 251 | IXFR | Incremental zone-transfer query type |
| 252 | AXFR | Full zone-transfer query type |
| 255 | ANY | Meta/query type, not an ordinary data-record type |
| 257 | CAA | Certificate-authority authorization |

The descriptions are short orientation aids, not a decoding of the `Data`
field. For authoritative assignments and definitions, see the
[IANA DNS Parameters registries](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml).

## Collection status and errors

| Status | Meaning |
|---|---|
| `success` | Provider query completed, records were serialized, and no provider or row/property error was reported. This only describes the successful snapshot from the selected provider. |
| `partial` | Some provider/record/property diagnostic or malformed row was reported. Use `errors` to identify it; valid records and fields are retained where possible. |
| `failed` | The provider result could not be acquired. The CLI exits nonzero and reports the failure; a failed provider query must not be interpreted as a confirmed empty cache. |

Each error object contains an `error_type` and explanatory `message`; fields
such as `record_index`, `field`, or `return_code` may be present depending on
where the problem occurred. Read errors in context:

- A provider command failure means the cache query itself did not complete.
- A malformed provider row means that row could not be represented as a normal
  record; check `records_returned`, `record_count`, and the error details.
- A field read error concerns that property; other properties in that record
  can still be useful.
- A field limitation in `field_limitations` is not necessarily an error. It
  explains why a normalized value is null (for example, the provider returned
  null or omitted the source field).

Typical process exit codes are `0` for success, `1` for a partial collection,
and `2` for a failed collection or invalid/unwritable output. If the user
cancels or elevation fails in the launcher, it exits without starting
collection; the helper reports the elevation problem. Do not use an output
file's existence alone as proof that the latest collection succeeded.

## Validate the output

Run comparisons close together in time. The DNS cache can change while it is
being read, so record counts or TTL values may legitimately differ between
commands. Do not use `Resolve-DnsName`, `nslookup`, `ping`, or another lookup
to validate this artifact: those can perform a new lookup and change the cache.

### 1. Confirm the JSON parses and counts agree

In PowerShell, set `$path` to the JSON file and run:

```powershell
$path = 'D:\Testing Folder\DNS Cache_dns_cache_20261010_031716.json'
$doc = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json

$doc.artifact
$doc.collection_status
$doc.record_count
$doc.records.Count
```

Expected: `A04`; a status of `success` (or a reported `partial`/`failed`
condition); and `record_count` equal to `records.Count`. Empty `records` with
`success` means the provider successfully returned no rows at that instant; it
does not mean the provider query failed.

### 2. Check the recorded time is explicitly UTC

```powershell
[DateTimeOffset]::Parse($doc.collection_started_at_utc).Offset
[DateTimeOffset]::Parse($doc.collection_ended_at_utc).Offset
```

Both should be `00:00:00`. These times bracket the collection; they are not
per-record creation or cache-entry insertion times.

### 3. Validate one selected record against Windows

First choose a row using its name and type, and inspect every preserved value:

```powershell
$doc.records |
    Where-Object {
        $_.normalized.record_name -eq 'example.test' -and
        $_.normalized.record_type_code -eq 1
    } |
    ForEach-Object {
        $_.provider_values | Format-List *
        $_.normalized | Format-List *
    }
```

Replace the example name and type with a record actually present in the
snapshot. If a name has multiple records, inspect all matches and compare
`Data`, `Type`, and other values; do not assume the name alone uniquely
identifies a cache record.

Query the cache read-only and inspect the provider's raw fields:

```powershell
Get-DnsClientCache -Entry 'example.test' -ErrorAction Stop |
    Format-List *
```

Compare the returned `Entry`, `Name`, `Type`, `Data`, `DataLength`,
`TimeToLive`/`TTL`, `Status`, and `Section` with the matching JSON
`provider_values`. Use the exact property names returned on your Windows
version. A record can expire or change between the snapshot and this check;
if it no longer appears, that alone does not prove the collector omitted it.

### 4. Validate normalized fields one by one

For the selected JSON record:

1. Compare `normalized.record_name` with `provider_values.Name`. This is the
   individual DNS record name shown by `ipconfig /displaydns`.
2. Compare `normalized.cache_entry_name` with `provider_values.Entry`. This is
   the cache entry/group name and can differ from the individual record name.
3. Compare `normalized.record_type_code` with numeric `provider_values.Type`.
   If `record_type_name` is null, check whether the code is absent from the
   local mnemonic mapping; the original numeric code should still be present.
4. Compare `normalized.record_data` directly with `provider_values.Data`.
   Interpret it using the type, not by assuming every value is an IP address.
5. Compare `data_length_bytes` with `provider_values.DataLength`. Do not
   recompute this from the visible text string.
6. Compare `status_code` and `section_code` with the respective provider
   fields. Treat them as codes unless you have authoritative documentation for
   their exact meanings on that Windows version.
7. Compare `time_to_live_seconds` with `TimeToLive`; if that is null or absent,
   compare it with `TTL`. If both values are present, retain and report both
   original values.
8. Inspect `field_limitations` before interpreting a normalized null. Then
   inspect `provider_properties_present`, `provider_null_properties`, and
   `field_errors` to distinguish missing, null, and unreadable values.

The same check can be automated for a selected record:

```powershell
$record = $doc.records[0]
$record.provider_values | Format-List *
$record.provider_property_types | Format-List *
$record.provider_properties_present
$record.provider_null_properties
$record.normalized | Format-List *
$record.field_limitations | Format-List *
$record.field_errors | Format-List *
```

### 5. Compare a JSON snapshot with `ipconfig /displaydns`

Capture `ipconfig /displaydns` as text and collect the JSON as close together
as practical. Record both capture times. The DNS cache can change between
observations, so the record totals need not match.

Match records independent of order using the tuple **record name, DNS type,
and record data**:

- JSON record name: `provider_values.Name` (also
  `normalized.record_name`). Do not group or match individual records by
  `Entry`; it can name a cache entry that groups several DNS records.
- JSON type: numeric `provider_values.Type` or its recognized
  `normalized.record_type_name`; compare with the record-type name/code shown
  by `ipconfig`.
- JSON data: `provider_values.Data` or `normalized.record_data`; compare with
  the type-specific `A`, `AAAA`, `CNAME`, `PTR`, `MX`, or other record data
  line in `ipconfig`.

Keep duplicate tuples as separate occurrences (compare counts per tuple,
rather than converting records to a set). For each matched record, compare
`DataLength`/`normalized.data_length_bytes` with the displayed data length and
`Section`/`normalized.section_code` with the displayed section. Report
mismatches in these fields separately from TTL. Compare
`TimeToLive`/`TTL`/`normalized.time_to_live_seconds` independently: TTL is
expected to count down, so a lower value in the later capture is not by itself
a collection error. State the measured capture-time interval and TTL delta.

Report unmatched records in both directions:

- **JSON only** — returned by `Get-DnsClientCache` but not visible in the
  `ipconfig` capture.
- **ipconfig only** — visible in the command output but not present in the JSON.

Do not treat either unmatched list or different total counts as an automatic
collector failure. They are comparison results; assess timing, cache changes,
duplicate records, and provider/output coverage. Retain the raw values and
document the exact match key and any type/data normalization used.

### 5. Check property coverage for the snapshot

```powershell
$doc.provider.properties_returned_union
$doc.provider.property_types_returned | ConvertTo-Json -Depth 10
$doc.provider.expected_cache_properties_not_returned

$record = $doc.records[0]
$record.provider_values.PSObject.Properties.Name
```

`properties_returned_union` is across the collection. Check each row's
`provider_properties_present` for row-level availability. When independently
querying Windows, inspect actual properties without relying on a fixed list:

```powershell
$rows = @(Get-DnsClientCache -ErrorAction Stop)
$rows | Select-Object -First 1 | Format-List *
```

The live query and saved snapshot may differ because cache contents can change.
Compare promptly and use stable rows/values; do not treat a later property
difference as proof that an earlier snapshot was incomplete.

### 6. Inspect errors and limitations

```powershell
$doc.errors | ConvertTo-Json -Depth 20
$doc.limitations
$doc.records |
    Where-Object {
        $_.field_errors.Count -gt 0 -or
        $_.field_limitations.Count -gt 0
    } |
    Select-Object record_index, field_errors, field_limitations |
    Format-List
```

Investigate any non-empty `errors` list before relying on the snapshot. A
limitation describes unavailable or unnormalized information; it does not
silently manufacture a value.

### 7. Verify output-folder and overwrite behavior

Use a new, existing folder whose name contains spaces. Enter that folder at the
launcher prompt. Verify that one timestamped `.json` file is created inside
the folder and that it parses as described above.

For overwrite protection, run the collector again with the same **file path**
and without `--overwrite`. It should refuse to replace that file and return a
failure exit code. Only test `--overwrite` with a disposable output you are
prepared to replace.

## Interpretation cautions

- A successful snapshot is not a history of DNS requests and does not establish
  which process caused a cache entry.
- The collection timestamps are not record creation times. TTL is a
  provider-reported remaining/associated value, not an exact wall-clock expiry
  timestamp.
- A DNS name and `Data` value should be interpreted in the context of the
  record type; the collector does not resolve names or verify their current
  answers.
- A null field, an empty string, and an absent field convey different
  observations.
- `Status` and `Section` remain raw codes because this collector does not
  assert code meanings it cannot verify.
- Negative-cache entries are retained if `Get-DnsClientCache` returns them, but
  the provider may not expose a dedicated negative-cache indicator.
- No record returned by the provider is intentionally filtered by name, type,
  status, or section. This completeness claim is limited to the provider's
  returned data and to values that the PowerShell object allowed the collector
  to read.

## References

- Microsoft Learn: [`Get-DnsClientCache`](https://learn.microsoft.com/powershell/module/dnsclient/get-dnsclientcache)
- IANA: [Domain Name System (DNS) Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
