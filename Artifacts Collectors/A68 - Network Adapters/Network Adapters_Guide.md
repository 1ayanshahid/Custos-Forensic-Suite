# A68 — Network Adapters Collector

## Purpose and scope

A68 records the local Windows network interfaces that the selected Windows providers expose, plus their current adapter, address, IP-interface, gateway, DNS, DHCP, device and counter observations. It includes physical, virtual, VPN, tunnel, loopback, hidden, enabled, disabled, connected and disconnected interfaces when the providers return them.

An adapter inventory is a point-in-time configuration observation, not a complete network history. An installed device can be administratively disabled, and an enabled interface can have no connected media. “Physical” and “virtual” are recorded only when a provider explicitly supplies those indicators; A68 does not guess from adapter names.

A68 is strictly read-only. It does not enable, disable, reset or reconfigure interfaces; renew DHCP; connect to a network; send probes; resolve hostnames; scan the network; collect active connections, Wi-Fi credentials, DNS cache, ARP cache, Bluetooth history or the full route table.

## Requirements and administrator launch

- Windows with Windows PowerShell and the documented NetAdapter, NetTCPIP and DnsClient providers where available.
- Python 3.10 or newer. The launcher uses `E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe`.
- No third-party packages; no package installation or environment modification is performed.
- The launcher checks for administrator status and requests standard Windows UAC approval if needed. Cancelling UAC stops the collection. Administrator access does not guarantee that every provider or field is available.

The supplied handbook and Tools & Artifact Details paths were not available in the implementation environment. The collection design and units below were checked against the official provider and API documentation linked at the end of this guide.

## Run A68

Double-click `launch.bat`, or invoke it from Command Prompt:

```bat
call "E:\FYP Custos Forensic Suite\artifacts\A68 - Network Adapters\launch.bat"
call "E:\FYP Custos Forensic Suite\artifacts\A68 - Network Adapters\launch.bat" --output-dir "D:\Forensic Output"
call "E:\FYP Custos Forensic Suite\artifacts\A68 - Network Adapters\launch.bat" --overwrite
```

Direct Python invocation is also available:

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" "E:\FYP Custos Forensic Suite\artifacts\A68 - Network Adapters\collector.py" --output-dir "D:\Forensic Output"
```

If no `--output-dir` argument is supplied, the launcher asks only:

> Enter a custom save folder, or press Enter to save in this artifact folder.

Press Enter to use the A68 folder. A custom destination must already exist and be writable; errors are displayed, and A68 does not silently choose another directory. `--output-dir` skips the prompt. Without an output argument, the current directory does not affect the default destination.

The output is `network_adapters.json`. If that file already exists, a unique UTC-timestamped filename is selected automatically. `--overwrite` explicitly replaces only the standard filename. JSON is UTF-8, indented, and contains a blank line between adjacent object records for readability; normal JSON parsers accept this whitespace.

| Exit code | Meaning |
|---|---|
| `0` | Every selected provider query completed successfully. This means complete coverage for those providers, not every device Windows could possibly know about. |
| `1` | Partial provider coverage. A keyboard interruption also exits with `1` but does not write a completed report. |
| `2` | Required `Get-NetAdapter -IncludeHidden` enumeration failed, output failed, or launch/elevation failed. Successful WMI rows remain in provider outcomes but do not turn primary enumeration failure into success. |

## Providers selected and why

The collector runs a fixed PowerShell script through `powershell.exe -NoProfile -NonInteractive -Command`. To avoid Windows command-line length limits, the fixed script is UTF-8 encoded and base64-transferred in a dedicated child-process environment variable; the PowerShell command-line expression is constant, and no path or other user-controlled value is interpolated into script code. Subprocess arguments are passed as a list with `shell=False`. It sets UTF-8 output encoding, catches each provider query independently, emits structured JSON, and applies a 90-second process timeout.

- `Get-NetAdapter -IncludeHidden` is the primary interface inventory. It supplies interface identity, current/admin/media/operational states, explicit `HardwareInterface`, `Virtual` and `Hidden` properties when present, media type, MAC/link-layer address, MTU, receive/transmit rates and adapter driver fields.
- `Get-NetIPInterface` supplies IPv4/IPv6 IP-interface rows, family-specific MTU and metric, DHCP setting, forwarding, advertising and router-discovery settings.
- `Get-NetIPAddress` supplies every returned IPv4/IPv6 address, prefix, origin, address state, skip-as-source and preferred/valid lifetimes. IPv4 subnet mask is separately labeled as derived from its prefix length.
- `Get-NetIPConfiguration -All` supplies configuration for all interfaces, including virtual, loopback and disconnected interfaces, with gateways, DNS configuration and profile objects when returned.
- `Get-DnsClientServerAddress` separately records DNS server lists by interface and address family.
- `Get-DnsClient` records connection-specific and configured suffix lists plus DNS registration flags. This supplements the suffix/search-order fields in `Win32_NetworkAdapterConfiguration`.
- `Win32_NetworkAdapter` supplements interface inventory with PnP/device identifiers, `PhysicalAdapter`, connection status, provider/device errors, permanent address and adapter vendor/product/driver-service information.
- `Win32_NetworkAdapterConfiguration` supplements DHCP enablement/server/lease times, legacy IPv4/IPv6 address and subnet lists, default gateways, DNS suffix/search order, DNS registration flags, MTU and connection metric.
- `Get-NetAdapterStatistics` adds optional byte, packet, error and discard counters.

No native `GetAdaptersAddresses` or `GetIfTable2` structure is decoded. These have variable-length, linked native structures, while the selected documented structured Windows providers cover the intended configuration fields and expose hidden adapters through the NetAdapter cmdlet. Consequently native-only fields or interfaces absent from those providers may not appear. Provider availability, query failures and empty inventories are explicit in the result.

## Reading `network_adapters.json`

### Top-level fields

| Field | Meaning |
|---|---|
| `artifact_id` | Always `A68`. |
| `collection_method` | Selected structured PowerShell and CIM methods. |
| `collection_started_at_utc`, `collection_ended_at_utc` | Collection clock timestamps in UTC ending in `Z`. |
| `collection_started_at_local`, `collection_ended_at_local` | The corresponding clock instants with numeric local offset. |
| `local_timezone_name` | Local zone name/abbreviation. Use the numeric offset for the exact timestamp. |
| `local_machine.computer_name` | Provider computer name, with the Python host name as a fallback. |
| `local_machine.scope` | States that the inventory is local only. |
| `status` | `success`, `partial`, or `failed`. |
| `enumeration_completeness` | Selected provider scope, whether hidden adapters were requested, adapter-provider success, and the limitation that visibility is provider-bounded. |
| `provider_outcomes` | PowerShell version and each provider’s own outcome and records. |
| `adapters` | Per-Get-NetAdapter interface records enriched with records linked from other providers. If primary enumeration fails, successfully returned WMI rows are still preserved in `provider_outcomes.wmi_adapter`, but overall status is failed. |
| `unmatched_provider_records` | Provider keys mapped to zero-based indexes for records not uniquely linked. `ambiguous_wmi_adapter` indexes are also retained. |
| `reconciliation` | Matching rules and explicit notes that disagreements are preserved and provider values are not overwritten. |
| `counts` | Provider object counts, primary adapter counts, linked records, unmatched records, IPv4/IPv6 record counts and provider error count. |
| `errors` | Provider key/name, outcome status, observation time and structured error. |
| `limitations` | Interpretation and collection limitations emitted with each run. |
| `actual_output_path` | Chosen result-file path. |

### Provider outcomes and records

Each provider outcome contains:

- `provider`: documented cmdlet/class used.
- `status`: `success`, `unsupported`, `access_denied`, `provider_failure`, or `malformed_provider_response`.
- `observed_at_utc`: UTC time captured immediately before that query.
- `object_count`: count on success; null when the query did not yield a trustworthy inventory.
- `records`: selected provider fields in provider order. A successful empty result has `object_count: 0` and `records: []`; that differs from provider failure.
- `_unavailable_fields`: list of selected fields not exposed on that particular provider object. A field present with JSON null is instead listed as a property and not included in this array.
- `error`: null on success or a message, PowerShell error ID and exception type when available.

`provider_outcomes.powershell_version` identifies the shell version. The provider keys are `net_adapter`, `ip_interface`, `ip_address`, `ip_configuration`, `dns_server`, `dns_client`, `wmi_adapter`, `wmi_configuration`, and `adapter_statistics`.

Every record preserves a `provider` field. Null means that selected provider did not expose that property on that object; zero, false and empty lists are retained as actual returned values. Unavailable provider queries are reported in the provider outcome, not converted into empty results.

### Primary adapter fields (`net_adapter`)

Properties in the emitted primary record are:

- Identity: `Name`, `InterfaceAlias`, `InterfaceDescription`, `InterfaceName`, `InterfaceGuid`, `NetLuid`, `NetLuidIndex`, `InterfaceIndex`, `ifIndex`, `ifAlias`, `ifDesc`, `ifName`.
- State: `Status`, `AdminStatus`, `InterfaceAdminStatus`, `InterfaceOperationalStatus`, `ifOperStatus`, `MediaConnectionState`, `MediaConnectState`.
- Classification: `MediaType`, `PhysicalMediaType`, `NdisPhysicalMedium`, `HardwareInterface`, `Virtual`, `Hidden`, `TunnelType`, `InterfaceType`, and `ifType`. The latter interface/tunnel fields are null if the selected provider does not expose them; booleans and provider enum numbers/labels are preserved, and no classification is guessed from name.
- Link: `MtuSize`, `ReceiveLinkSpeed`, `TransmitLinkSpeed`, `LinkSpeed`, `MacAddress`, `LinkLayerAddress`.
- Additional link metadata: `PermanentAddress`, `SupportedMaximumTransmissionUnit`, `ConnectorPresent`, `FullDuplex`, `LinkTechnology`, `Speed`, `MaxSpeed`, `PortType`, `OtherPortType`, `NetworkAddresses`, and `NdisVersion`, when exposed. `Speed`/`MaxSpeed` numeric values are provider-reported bits per second; the formatted `LinkSpeed` string is preserved as returned.
- Driver/device information: `DriverVersion`, `DriverVersionString`, `DriverDate`, `DriverDateData`, `DriverInformation`, `DriverFileName`, `DriverDescription`, `DriverProvider`, `DriverName`, and `PnPDeviceID`.
- Relevant down reasons: `OperationalStatusDownMediaDisconnected`, `OperationalStatusDownInterfacePaused`, `OperationalStatusDownLowPowerState`, and `OperationalStatusDownDefaultPortNotAuthenticated`.
- Derived address bytes: `derived_physical_address_bytes` and `derived_physical_address_length_bytes` are produced only when `MacAddress` (or, if absent, `LinkLayerAddress`) parses as hexadecimal octets. `derived_permanent_address_bytes` and `derived_permanent_address_length_bytes` are similarly derived from `PermanentAddress`. Arrays contain byte values and lengths are byte counts derived from provider text, not native API-reported lengths. Missing or unparseable strings produce nulls; original provider text is retained.

Some fields can be null on an OS version or provider that does not return them. The provider’s raw speed value is retained. A display value such as `1 Gbps` is a link-rate report, not measured throughput. MTU is in bytes as defined by the provider. A68 does not call native `GetAdaptersAddresses` or `GetIfTable2`, so it does not claim native physical-address-length fields.

### Supplemental CIM adapter fields (`wmi_adapter`)

`matched_wmi_adapter_records` retains each matched WMI record, its zero-based `provider_record_index` and `reconciliation_match`, plus the fields `Name`, `Description`, `Caption`, `DeviceID`, `GUID`, `Index`, `InterfaceIndex`, `PNPDeviceID`, `AdapterType`, `AdapterTypeId`, `PhysicalAdapter`, `NetEnabled`, `NetConnectionID`, `NetConnectionStatus`, `Status`, `StatusInfo`, `Availability`, `ConfigManagerErrorCode`, `ConfigManagerUserConfig`, `LastErrorCode`, `ErrorDescription`, `Installed`, `Manufacturer`, `ProductName`, `ServiceName`, `MACAddress`, `PermanentAddress`, `Speed`, `MaxSpeed`, `TunnelType`, `InstallDate`, and `TimeOfLastReset`.

WMI speed values are bits per second when populated; unlike NetAdapter’s display string, the numeric provider values are preserved. WMI `DateTime` and `DateTimeOffset` values are objects containing the original `raw_value` and normalized UTC `normalized_utc` ISO 8601 value; `DateTime` values also include `kind` and `conversion_note`, while `DateTimeOffset` values include the original `offset`. For `DateTimeKind.Unspecified`, .NET treats the value as local time; the result records this assumption, and conversion uses .NET timezone rules for the timestamp rather than blindly applying the current offset. A `PermanentAddress` is provider metadata, not proof of a device’s permanent identity.

### Linked IP, DNS, and configuration records

`adapters[n]` contains:

- `net_adapter_record_index`: zero-based index into `provider_outcomes.net_adapter.records`.
- `identity_match_key`: `[identifier_type, normalized_value]`, or null if no supported identifier is exposed.
- `net_adapter`: the original selected primary-provider record.
- `matched_wmi_adapter_records`: matched WMI records with their source record indexes.
- `matched_wmi_configuration_records`: matched WMI TCP/IP configuration records with source indexes.
- `identity_match_rule`: how a WMI adapter matched or why no unique match was possible.
- `interface_index`: current primary provider interface index, if exposed.
- `linked_configuration`: each key (`ip_interface`, `ip_address`, `ip_configuration`, `dns_server`, `dns_client`, `adapter_statistics`) maps to all records with a unique matching interface index. Each includes the originating `provider_record_index` and provider fields. `Get-NetAdapterStatistics` does not consistently expose an interface index, so records without one remain in `provider_outcomes.adapter_statistics` and are listed as unmatched rather than linked by display name.
- `identity_disagreement`: side-by-side provider field values where matched identity/configuration sources disagree.
- `record_errors`: failed/unsupported IP, address, configuration, DNS, or statistics provider outcomes that limited enrichment for this adapter. A provider-wide failure is repeated here for each primary adapter it could have enriched.

The matching order for adapter providers is the first available unique normalized GUID, LUID, interface index, or PnP identifier. If an identifier is unavailable or has no match, the next identifier may be tried; duplicate matches are left unmatched. The selected identifier type appears as `reconciliation_match`. Conflicting identity fields remain visible in `identity_disagreement`. Address/configuration records link by interface index. Display name and MAC address are never the sole match key. Interface GUIDs, LUIDs and indexes identify current interfaces and are not permanent evidence IDs.

### IP interface fields (`ip_interface`)

Each IPv4/IPv6 row can contain `AddressFamily`, `InterfaceAlias`, `InterfaceIndex`, `CompartmentId`, `ConnectionState`, `Forwarding`, `Advertising`, `RouterDiscovery`, `ManagedAddressConfiguration`, `OtherStatefulConfiguration`, `Dhcp`, `AutomaticMetric`, `InterfaceMetric`, `NlMtu`, `NeighborDiscoverySupported`, `WeakHostSend`, `WeakHostReceive`, `IgnoreDefaultRoutes`, `AdvertiseDefaultRoute`, `CurrentHopLimit`, `ReachableTime`, `RetransmitTime`, `Store`, `TunnelType`, `InterfaceType`, and `ifType`.

The IP interface’s metric and MTU are per address family; `NlMtu` is bytes and `InterfaceMetric` is a route-preference value, not speed. `Dhcp`, `AutomaticMetric`, forwarding, advertising, router discovery, managed/other stateful configuration, weak-host handling, and default-route flags retain provider booleans/enums. `CurrentHopLimit` is the IP hop-limit value. `ReachableTime` and `RetransmitTime` are provider timing values (milliseconds on the Windows IP interface API); their original values are retained. `CompartmentId` and `Store` identify Windows IP compartment/configuration context. None of these flags proves actual packet forwarding or route reachability.

### IP address fields (`ip_address`)

Every provider row is retained; addresses are not reduced to one per adapter. Fields include `AddressFamily`, `InterfaceAlias`, `InterfaceIndex`, `IPAddress`, `PrefixLength`, `PrefixOrigin`, `SuffixOrigin`, `AddressState`, `AddressOrigin`, `AddressType`, `Type`, `SkipAsSource`, `PreferredLifetime`, `ValidLifetime`, `SubnetMask`, `IPv4Address`, and `IPv6Address`.

- `PrefixLength` is in bits. `derived_subnet_mask` is generated only for valid IPv4 prefix lengths (0–32); it is labeled as derived, not provider-returned.
- IPv6 textual zone/scope suffix, if present in `IPAddress`, is also reported as `ipv6_scope_id`. It is not discarded during parsing.
- Preferred/valid lifetime values returned as `TimeSpan` are objects with `raw_value`, `total_seconds`, and `interpretation`. `TimeSpan.MaxValue` is labeled `maximum_sentinel_or_indefinite` and has null seconds. If a provider returns a numeric lifetime, the original numeric field remains, and `PreferredLifetimeInterpretation`/`ValidLifetimeInterpretation` and `...Seconds` explain whether it is interpreted as seconds or a maximum sentinel.
- `prefix_length_unit` is `bits`. `subnet_mask_derivation` is `derived_from_prefix_length`, `not_applicable_ipv6`, or `unavailable_address_family`.

Address `Type` can distinguish unicast/anycast/multicast when the provider provides that property; null is not treated as unicast.

### Gateways, DNS and profiles (`ip_configuration`, `dns_server`, `dns_client`)

`Get-NetIPConfiguration -All` records `InterfaceAlias`, `InterfaceIndex`, `InterfaceDescription`, `CompartmentId`, `IPv4Address`, `IPv6Address`, `IPv6TemporaryAddress`, `IPv6LinkLocalAddress`, `IPv4DefaultGateway`, `IPv6DefaultGateway`, `DNSServer`, and `NetProfile`. Nested values are serialized as JSON objects/lists using an explicit relevant-subfield allowlist: interface alias/description/index, address family/address/prefix/origins/state/type/skip-as-source/lifetimes, next hop/route metric/destination prefix/state/protocol/policy store, DNS server addresses/connection-specific suffix, profile name/category/connectivity, and compartment/connection state. `_omitted_property_names` lists other nested-provider property names without serializing their values to avoid arbitrary nested provider dumps.

`Get-DnsClientServerAddress` records `InterfaceAlias`, `InterfaceIndex`, `AddressFamily`, and the full `ServerAddresses` list. Order is the provider-returned order only; A68 does not claim this is actual resolver selection order. Configured DNS does not prove a server responded.

`Get-DnsClient` records `InterfaceAlias`, `InterfaceIndex`, `ConnectionSpecificSuffix`, `ConnectionSpecificSuffixSearchList`, `SuffixSearchList`, `RegisterThisConnectionsAddress`, and `UseSuffixWhenRegistering`. These are configuration fields only; they do not prove registration or name resolution occurred.

`Win32_NetworkAdapterConfiguration` records `Index`, `InterfaceIndex`, `SettingID`, `Description`, `DHCPEnabled`, `DHCPServer`, `DHCPLeaseObtained`, `DHCPLeaseExpires`, `DefaultIPGateway`, `GatewayCostMetric`, `DNSServerSearchOrder`, `DNSDomain`, `DNSDomainSuffixSearchOrder`, `DNSHostName`, `FullDNSRegistrationEnabled`, `DomainDNSRegistrationEnabled`, `IPAddress`, `IPSubnet`, `IPEnabled`, `MTU`, and `IPConnectionMetric`.

WMI address/gateway/DNS fields are retained as arrays, including multiple entries. Lease dates returned as dates preserve their provider value and normalized UTC conversion as described above; `DateTimeKind.Unspecified` carries the explicit local-time assumption. They describe provider-observed lease metadata, not independently verified lease validity. DNS suffix registration booleans and suffix lists are configuration, not proof of DNS registration.

### Counters (`adapter_statistics`)

The counter record includes `InterfaceAlias`, `InterfaceDescription`, `Name`, `Source`, `ReceivedBytes`, `SentBytes`, unicast/multicast/broadcast byte and packet fields, `ReceivedPacketErrors`, `OutboundPacketErrors`, `ReceivedDiscardedPackets`, `OutboundDiscardedPackets`, and `SupportedStatistics`. Missing selected fields are listed in `_unavailable_fields`.

`counter_unit` is added to each normalized statistics record: `*Bytes` are bytes, `*Packets` are packets, and error/discard fields are counts. Each value is an observation at that provider query time. Counters may reset, wrap, or update; they are not tied to a particular connection, user, or event.

### Unmatched, conflicts and errors

`unmatched_provider_records` contains provider names mapped to zero-based source-record indexes. This includes WMI adapters/configuration without a unique primary adapter, and IP/DNS/counter records without a uniquely indexed primary adapter. Original rows remain present in `provider_outcomes`; unmatched does not mean discarded. `ambiguous_wmi_adapter` contains WMI adapter indexes whose first matching identity key matched more than one primary record.

`identity_disagreement` retains both provider labels and values. A68 does not select one source as truth by overwriting the other. Provider observation timestamps help explain why runtime values can differ.

Common provider outcome states:

- `success`: query succeeded, including a valid empty list.
- `unsupported`: required cmdlet is unavailable in this Windows environment.
- `access_denied`: provider explicitly reported an access/authorization error.
- `provider_failure`: query failed for another provider reason.
- `timeout`: the overall PowerShell query exceeded 90 seconds.
- `malformed_provider_response`: JSON/provider structure did not meet the expected shape.

`null` means unavailable/not exposed, not zero or false. An empty list is a successfully returned empty list. Zero counters/metrics and false flags are valid provider values. `unsupported` and failed values are not represented as successful empty inventories. A disappeared interface can cause a later enrichment provider not to return the interface; queries are sequential, and the unmatched row remains in the provider output. A68 does not claim it independently proved a device disappeared.

## Coverage table

| Information | API/provider | Meaning and units | Availability or limitation |
|---|---|---|---|
| Adapter inventory and hidden interfaces | `Get-NetAdapter -IncludeHidden` | Current exposed adapter objects and selected state/identity fields | Hidden request is provider-bounded; no historical inventory guarantee. |
| Adapter GUID, LUID, indexes, PnP ID | NetAdapter; `Win32_NetworkAdapter` | Current provider identifiers | May be missing or differ; not permanent evidence IDs. |
| Tunnel and interface type | NetAdapter, `Get-NetIPInterface`, WMI | Provider values when exposed | Not consistently exposed by selected providers; null is retained rather than inferred from names. |
| Physical/virtual indication | NetAdapter `HardwareInterface`, `Virtual`; WMI `PhysicalAdapter` | Boolean provider classifications | Null where unsupported; no name-based guesses. |
| Admin/operational/media state | NetAdapter and `Win32_NetworkAdapter` | Provider state/enumerations | Distinct concepts; connected state is not inferred from installed state. |
| Current/permanent address text and derived bytes | NetAdapter; WMI `MACAddress`, `PermanentAddress` | Provider text plus parsed byte-array/count where hexadecimal parsing succeeds | Byte count is derived, not a native reported length; not device identity proof. |
| MTU and link speed | NetAdapter `MtuSize`, receive/transmit speed; WMI `MTU`, `Speed`, `MaxSpeed` | MTU bytes; WMI speeds bits/sec; display rates preserved as strings | Reported rate, not measured throughput; may be null/zero. |
| IP-family interface settings | `Get-NetIPInterface` | Metric, MTU, DHCP, forwarding/router discovery and family state | Separate IPv4/IPv6 provider rows. |
| IPv4/IPv6 addresses | `Get-NetIPAddress` | Address, prefix bits, origins, state, lifetime and skip-as-source | All returned records retained; scope suffix retained. |
| Default gateway/profile | `Get-NetIPConfiguration -All`; WMI configuration | Provider gateway objects/arrays, profile and suffix metadata | Not a complete route table or reachability test. |
| DNS servers and suffix settings | `Get-DnsClientServerAddress`; `Get-DnsClient`; WMI configuration | Provider-ordered DNS addresses, per-interface suffix lists and registration flags | Does not establish resolver response, actual resolver selection or completed DNS registration. |
| DHCP/lease | IP-interface settings; `Win32_NetworkAdapterConfiguration` | Per-family DHCP flags, server address and date objects with raw value and normalized UTC | Lease state not independently verified; unspecified WMI date-kind conversion assumption is explicit. |
| Driver/device metadata | `Win32_NetworkAdapter`; NetAdapter driver fields | Version/date/provider, PnP ID, device error/status | Limited metadata only; not A23 full driver inventory. |
| Counters | `Get-NetAdapterStatistics` | Byte, packet, error and discard observations | Optional; rows lacking interface index remain unmatched rather than being linked by name; may reset/update and are not event attribution. |
| Collection times | Python UTC/local clock; per-provider UTC observation | ISO 8601 instants | Providers are queried sequentially, not atomically. |

## Validation

Use read-only comparisons; do not change interface settings to manufacture test cases.

1. Compare adapter identity and state:

   ```powershell
   Get-NetAdapter -IncludeHidden |
       Select-Object Name, InterfaceDescription, InterfaceGuid, InterfaceIndex,
                     NetLuid, Status, AdminStatus, MediaConnectionState,
                     HardwareInterface, Virtual, Hidden, MtuSize,
                     ReceiveLinkSpeed, TransmitLinkSpeed
   ```

2. Compare full interface IP configuration, including disconnected and virtual interfaces:

   ```powershell
   Get-NetIPConfiguration -All
   Get-NetIPAddress
   Get-NetIPInterface
   ```

3. Compare DNS server configuration:

   ```powershell
   Get-DnsClientServerAddress
   Get-DnsClient
   ```

4. Use `ipconfig /all` only as a secondary manual view. It is localized formatted text and is not parsed by A68.
5. Confirm all returned addresses, gateway objects and DNS servers remain present in the corresponding arrays, including more than one per interface.
6. Automated fixtures cover physical-address lengths including non-six-byte values, malformed/missing addresses, IPv4/IPv6 prefixes and zones, unique/ambiguous identity matching, unmatched provider rows, provider failure, malformed JSON, timeout, output collision/overwrite protection, invalid paths and UTF-8. A live dynamic test cannot safely manufacture every physical, tunnel, VPN, disconnected or loopback state; compare existing interfaces where present and use fixtures for absent types.
7. Compare provider records with close timing. Differences in status, leases or counters can result from interfaces or configuration changing between observations.
8. Inspect only read-only settings before and after a run to verify A68 made no adapter, IP, DNS, gateway, metric, DHCP, firewall or driver changes.
9. Test default Enter behavior, custom paths containing spaces, invalid destinations, naming collision, `--overwrite`, UTF-8 JSON, local/UTC timestamps and launching from another working directory.
10. Manually test already-elevated launch, UAC approval/cancellation, argument paths with spaces, argument forwarding and exit-code propagation. Automated tests or PowerShell parsing do not prove an interactive UAC prompt works.
11. Compare A68 folder contents before/after and verify A66/other artifact folders remain unchanged.
12. Confirm README descriptions against provider outcomes and emitted JSON fields.
13. Native buffer-resize and `FreeMibTable` cleanup tests are not applicable: this implementation does not call `GetAdaptersAddresses`, `GetIfTable2`, or `GetIfEntry2` and does not allocate those native buffers. Provider process timeout, malformed output, and independent-provider failure are tested instead.

## Common errors and limitations

- **PowerShell, cmdlet or CIM provider unavailable:** the provider outcome states unsupported/failure. Use a supported Windows environment; no dependencies are installed automatically.
- **Provider access denied or timeout:** inspect the corresponding `provider_outcomes` entry. Other successful provider records remain available.
- **No adapter rows:** only a successful `Get-NetAdapter -IncludeHidden` or WMI query with count zero means that provider returned an empty inventory. If both adapter enumeration providers fail, status is failed.
- **Unmatched rows:** providers use different identifiers or can observe interface changes between sequential queries. Source rows and unmatched indexes are preserved.
- **Counters unmatched:** `Get-NetAdapterStatistics` may expose no interface index; A68 retains these rows without unsafe display-name-only matching.
- **Null fields:** the selected provider may not expose them on that adapter/OS/version; null is not converted into a fabricated default.
- **Counters/speeds/state differences:** values are provider observations at different times; reported speed is not throughput.
- **UAC cancelled:** collection does not start. Relaunch and approve only if authorized.
- **Invalid output destination:** choose an existing writable directory; A68 does not silently fall back.

## Illustrative result fragment (not a live example)

```json
{
  "artifact_id": "A68",
  "status": "partial",
  "collection_started_at_utc": "2026-10-12T00:00:00.000000Z",
  "collection_started_at_local": "2026-10-12T05:00:00.000000+05:00",
  "adapters": [
    {
      "net_adapter_record_index": 0,
      "identity_match_key": ["guid", "11111111-2222-3333-4444-555555555555"],
      "interface_index": 12,
      "net_adapter": {
        "provider": "Get-NetAdapter -IncludeHidden",
        "InterfaceAlias": "Example VPN",
        "HardwareInterface": false,
        "Virtual": true,
        "ReceiveLinkSpeed": 0
      },
      "linked_configuration": {
        "ip_address": [
          {
            "provider_record_index": 0,
            "IPAddress": "fe80::1234%12",
            "PrefixLength": 64,
            "ipv6_scope_id": "12"
          }
        ]
      }
    }
  ]
}
```

This fragment illustrates structure only. It does not indicate a real adapter or imply that every provider returns every field.

## Official references

- [Get-NetAdapter](https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapter) — adapter inventory and `-IncludeHidden`.
- [Get-NetAdapterStatistics](https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapterstatistics) — adapter counters.
- [Get-NetIPConfiguration](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipconfiguration) — all-interface configuration and gateways.
- [Get-NetIPAddress](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress) — addresses, prefixes, origins and lifetimes.
- [Get-NetIPInterface](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipinterface) — family-specific interface settings.
- [Get-DnsClientServerAddress](https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientserveraddress) — per-interface DNS addresses.
- [Get-DnsClient](https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclient) — interface DNS suffix and registration settings.
- [Win32_NetworkAdapter](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-networkadapter) — adapter/device and physical-adapter fields.
- [Win32_NetworkAdapterConfiguration](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-networkadapterconfiguration) — DHCP, gateways, DNS and lease properties.
- [GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses) and [GetIfTable2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getiftable2) — documented native alternatives not used by this implementation.
- [Python subprocess](https://docs.python.org/3/library/subprocess.html#subprocess.run) — argument-list process invocation.
