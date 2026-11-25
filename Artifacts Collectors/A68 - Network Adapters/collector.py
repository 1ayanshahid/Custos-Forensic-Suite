"""Collect local Windows network-adapter metadata using read-only providers."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

ARTIFACT_ID = "A68"
ARTIFACT_DIRECTORY = Path(__file__).resolve().parent
POWERSHELL_TIMEOUT_SECONDS = 90

POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$ProgressPreference = 'SilentlyContinue'
$relevantNestedProperties = @(
    'InterfaceAlias', 'InterfaceDescription', 'InterfaceIndex', 'ifIndex',
    'AddressFamily', 'IPAddress', 'PrefixLength', 'PrefixOrigin', 'SuffixOrigin',
    'AddressState', 'AddressOrigin', 'AddressType', 'SkipAsSource',
    'PreferredLifetime', 'ValidLifetime', 'NextHop', 'RouteMetric',
    'DestinationPrefix', 'State', 'Protocol', 'PolicyStore', 'ServerAddresses',
    'ConnectionSpecificSuffix', 'Name', 'NetworkCategory', 'IPv4Connectivity',
    'IPv6Connectivity', 'CompartmentId', 'ConnectionState'
)

function Convert-ProviderValue {
    param([AllowNull()][object]$Value, [int]$Depth = 0)
    if ($null -eq $Value) { return $null }
    if ($Depth -gt 6) { return '[nested provider value omitted: maximum depth reached]' }
    if ($Value -is [DateTime]) {
        return [ordered]@{
            raw_value = $Value.ToString('o')
            kind = $Value.Kind.ToString()
            normalized_utc = $Value.ToUniversalTime().ToString('o')
            conversion_note = if ($Value.Kind -eq [DateTimeKind]::Unspecified) {
                'DateTimeKind.Unspecified interpreted as local time by .NET.'
            } else {
                'UTC conversion uses the DateTime value and its kind.'
            }
        }
    }
    if ($Value -is [DateTimeOffset]) {
        return [ordered]@{
            raw_value = $Value.ToString('o')
            offset = $Value.Offset.ToString()
            normalized_utc = $Value.UtcDateTime.ToString('o')
            conversion_note = 'Original offset preserved; normalized value is UTC.'
        }
    }
    if ($Value -is [TimeSpan]) {
        $meaning = 'duration'
        if ($Value -eq [TimeSpan]::MaxValue) { $meaning = 'maximum_sentinel_or_indefinite' }
        elseif ($Value -eq [TimeSpan]::MinValue) { $meaning = 'minimum_sentinel' }
        return [ordered]@{
            raw_value = $Value.ToString('c')
            total_seconds = if ($Value -eq [TimeSpan]::MaxValue) { $null } else { $Value.TotalSeconds }
            interpretation = $meaning
        }
    }
    if ($Value -is [System.Net.IPAddress]) {
        return $Value.ToString()
    }
    if ($Value -is [System.Array]) {
        $values = @()
        foreach ($item in $Value) {
            $values += ,(Convert-ProviderValue -Value $item -Depth ($Depth + 1))
        }
        return ,$values
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $converted = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $converted[[string]$key] = Convert-ProviderValue -Value $Value[$key] -Depth ($Depth + 1)
        }
        return $converted
    }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [ValueType]) {
        return $Value
    }
    $allProperties = @($Value.PSObject.Properties | Where-Object {
        $_.Name -notin @(
            'CimClass', 'CimInstanceProperties', 'CimSystemProperties',
            'PSComputerName', 'RunspaceId', 'PSShowComputerName'
        )
    })
    if ($allProperties.Count -gt 0) {
        $properties = @($allProperties | Where-Object {
            $_.Name -in $relevantNestedProperties
        })
        $converted = [ordered]@{}
        foreach ($property in $properties) {
            $converted[$property.Name] = Convert-ProviderValue `
                -Value $property.Value -Depth ($Depth + 1)
        }
        $omitted = @($allProperties | Where-Object {
            $_.Name -notin $relevantNestedProperties
        } | ForEach-Object { $_.Name })
        if ($omitted.Count -gt 0) {
            $converted['_omitted_property_names'] = $omitted
        }
        return $converted
    }
    return [string]$Value
}

function Get-SelectedRecord {
    param([object]$Item, [string[]]$Properties, [string]$Source)
    $record = [ordered]@{ provider = $Source }
    $unavailable = @()
    foreach ($name in $Properties) {
        $property = $Item.PSObject.Properties[$name]
        if ($null -ne $property) {
            $record[$name] = Convert-ProviderValue $property.Value
        }
        else {
            $record[$name] = $null
            $unavailable += $name
        }
    }
    $record['_unavailable_fields'] = $unavailable
    return [pscustomobject]$record
}

function Invoke-ProviderQuery {
    param(
        [string]$Name,
        [string]$Kind,
        [string]$CommandName,
        [string]$ClassName,
        [scriptblock]$Query,
        [string[]]$Properties
    )
    $observed = [DateTimeOffset]::UtcNow.ToString('o')
    $availability = 'available'
    if ($Kind -eq 'cmdlet' -and $null -eq (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
        $availability = 'unsupported'
    }
    if ($Kind -eq 'cim' -and $null -eq (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
        $availability = 'unsupported'
    }
    if ($availability -eq 'unsupported') {
        return [pscustomobject]@{
            provider = $Name; status = 'unsupported'; observed_at_utc = $observed
            object_count = $null; records = @()
            error = [pscustomobject]@{ message = 'Required PowerShell cmdlet is unavailable.' }
        }
    }
    try {
        $items = @(& $Query)
        $records = @(
            foreach ($item in $items) {
                Get-SelectedRecord -Item $item -Properties $Properties -Source $Name
            }
        )
        return [pscustomobject]@{
            provider = $Name; status = 'success'; observed_at_utc = $observed
            object_count = $records.Count; records = $records; error = $null
        }
    }
    catch {
        $category = 'provider_failure'
        if ($_.Exception -is [System.UnauthorizedAccessException] -or
            $_.FullyQualifiedErrorId -match 'AccessDenied|Unauthorized') {
            $category = 'access_denied'
        }
        elseif ($_.FullyQualifiedErrorId -match 'CommandNotFound|InvalidClass|ClassNotFound|InvalidNamespace') {
            $category = 'unsupported'
        }
        return [pscustomobject]@{
            provider = $Name; status = $category; observed_at_utc = $observed
            object_count = $null; records = @()
            error = [pscustomobject]@{
                message = $_.Exception.Message
                error_id = $_.FullyQualifiedErrorId
                exception_type = $_.Exception.GetType().FullName
            }
        }
    }
}

$adapterProperties = @(
    'Name', 'InterfaceAlias', 'InterfaceDescription', 'InterfaceName',
    'InterfaceGuid', 'NetLuid', 'NetLuidIndex', 'InterfaceIndex', 'ifIndex',
    'ifAlias', 'ifDesc', 'ifName', 'Status', 'AdminStatus',
    'InterfaceAdminStatus', 'InterfaceOperationalStatus', 'ifOperStatus',
    'MediaConnectionState', 'MediaConnectState', 'MediaType',
    'PhysicalMediaType', 'NdisPhysicalMedium', 'HardwareInterface', 'Virtual',
    'TunnelType', 'InterfaceType', 'ifType', 'PermanentAddress',
    'SupportedMaximumTransmissionUnit', 'ConnectorPresent', 'FullDuplex',
    'LinkTechnology', 'Speed', 'MaxSpeed', 'PortType', 'OtherPortType',
    'NetworkAddresses', 'NdisVersion', 'DriverVersionString',
    'Hidden', 'MtuSize', 'ReceiveLinkSpeed', 'TransmitLinkSpeed',
    'LinkSpeed', 'MacAddress', 'LinkLayerAddress', 'DriverVersion',
    'DriverDate', 'DriverDateData', 'DriverInformation', 'DriverFileName',
    'DriverDescription', 'DriverProvider', 'DriverName', 'PnPDeviceID',
    'OperationalStatusDownMediaDisconnected',
    'OperationalStatusDownInterfacePaused',
    'OperationalStatusDownLowPowerState',
    'OperationalStatusDownDefaultPortNotAuthenticated'
)
$wmiAdapterProperties = @(
    'Name', 'Description', 'Caption', 'DeviceID', 'GUID', 'Index',
    'InterfaceIndex', 'PNPDeviceID', 'AdapterType', 'AdapterTypeId',
    'PhysicalAdapter', 'NetEnabled', 'NetConnectionID',
    'NetConnectionStatus', 'Status', 'StatusInfo', 'Availability',
    'ConfigManagerErrorCode', 'ConfigManagerUserConfig', 'LastErrorCode',
    'ErrorDescription', 'Installed', 'Manufacturer', 'ProductName', 'ServiceName',
    'MACAddress', 'PermanentAddress', 'Speed', 'MaxSpeed', 'TunnelType',
    'InstallDate', 'TimeOfLastReset'
)
$ipInterfaceProperties = @(
    'AddressFamily', 'InterfaceAlias', 'InterfaceIndex', 'CompartmentId',
    'ConnectionState', 'Forwarding', 'Advertising', 'RouterDiscovery',
    'ManagedAddressConfiguration', 'OtherStatefulConfiguration', 'Dhcp',
    'AutomaticMetric', 'InterfaceMetric', 'NlMtu', 'NeighborDiscoverySupported',
    'WeakHostSend', 'WeakHostReceive', 'IgnoreDefaultRoutes',
    'AdvertiseDefaultRoute', 'CurrentHopLimit', 'ReachableTime',
    'RetransmitTime', 'Store', 'TunnelType', 'InterfaceType', 'ifType'
)
$ipAddressProperties = @(
    'AddressFamily', 'InterfaceAlias', 'InterfaceIndex', 'IPAddress',
    'PrefixLength', 'PrefixOrigin', 'SuffixOrigin', 'AddressState',
    'AddressOrigin', 'AddressType', 'Type', 'SkipAsSource',
    'PreferredLifetime', 'ValidLifetime', 'SubnetMask', 'IPv4Address',
    'IPv6Address'
)
$configurationProperties = @(
    'InterfaceAlias', 'InterfaceIndex', 'InterfaceDescription',
    'CompartmentId', 'IPv4Address', 'IPv6Address',
    'IPv6TemporaryAddress', 'IPv6LinkLocalAddress', 'IPv4DefaultGateway',
    'IPv6DefaultGateway', 'DNSServer', 'NetProfile'
)
$dnsProperties = @(
    'InterfaceAlias', 'InterfaceIndex', 'AddressFamily', 'ServerAddresses'
)
$dnsClientProperties = @(
    'InterfaceAlias', 'InterfaceIndex', 'ConnectionSpecificSuffix',
    'ConnectionSpecificSuffixSearchList', 'SuffixSearchList',
    'RegisterThisConnectionsAddress', 'UseSuffixWhenRegistering'
)
$wmiConfigurationProperties = @(
    'Index', 'InterfaceIndex', 'SettingID', 'Description', 'DHCPEnabled',
    'DHCPServer', 'DHCPLeaseObtained', 'DHCPLeaseExpires',
    'DefaultIPGateway', 'GatewayCostMetric', 'DNSServerSearchOrder',
    'DNSDomain', 'DNSDomainSuffixSearchOrder', 'DNSHostName',
    'FullDNSRegistrationEnabled', 'DomainDNSRegistrationEnabled',
    'IPAddress', 'IPSubnet', 'IPEnabled', 'MTU', 'IPConnectionMetric'
)
$statisticsProperties = @(
    'InterfaceAlias', 'InterfaceDescription', 'Name', 'Source',
    'ReceivedBytes', 'SentBytes', 'ReceivedUnicastBytes', 'SentUnicastBytes',
    'ReceivedUnicastPackets', 'SentUnicastPackets',
    'ReceivedMulticastBytes', 'SentMulticastBytes',
    'ReceivedMulticastPackets', 'SentMulticastPackets',
    'ReceivedBroadcastBytes', 'SentBroadcastBytes',
    'ReceivedBroadcastPackets', 'SentBroadcastPackets',
    'ReceivedPacketErrors', 'OutboundPacketErrors',
    'ReceivedDiscardedPackets', 'OutboundDiscardedPackets',
    'SupportedStatistics'
)

$outcomes = [ordered]@{}
$outcomes['net_adapter'] = Invoke-ProviderQuery `
    -Name 'Get-NetAdapter -IncludeHidden' -Kind cmdlet -CommandName Get-NetAdapter `
    -Query { Get-NetAdapter -IncludeHidden -ErrorAction Stop } `
    -Properties $adapterProperties
$outcomes['ip_interface'] = Invoke-ProviderQuery `
    -Name 'Get-NetIPInterface' -Kind cmdlet -CommandName Get-NetIPInterface `
    -Query { Get-NetIPInterface -ErrorAction Stop } -Properties $ipInterfaceProperties
$outcomes['ip_address'] = Invoke-ProviderQuery `
    -Name 'Get-NetIPAddress' -Kind cmdlet -CommandName Get-NetIPAddress `
    -Query { Get-NetIPAddress -ErrorAction Stop } -Properties $ipAddressProperties
$outcomes['ip_configuration'] = Invoke-ProviderQuery `
    -Name 'Get-NetIPConfiguration -All' -Kind cmdlet -CommandName Get-NetIPConfiguration `
    -Query { Get-NetIPConfiguration -All -ErrorAction Stop } `
    -Properties $configurationProperties
$outcomes['dns_server'] = Invoke-ProviderQuery `
    -Name 'Get-DnsClientServerAddress' -Kind cmdlet -CommandName Get-DnsClientServerAddress `
    -Query { Get-DnsClientServerAddress -ErrorAction Stop } -Properties $dnsProperties
$outcomes['dns_client'] = Invoke-ProviderQuery `
    -Name 'Get-DnsClient' -Kind cmdlet -CommandName Get-DnsClient `
    -Query { Get-DnsClient -ErrorAction Stop } -Properties $dnsClientProperties
$outcomes['wmi_adapter'] = Invoke-ProviderQuery `
    -Name 'Get-CimInstance Win32_NetworkAdapter' -Kind cim -CommandName Get-CimInstance `
    -ClassName Win32_NetworkAdapter `
    -Query { Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction Stop } `
    -Properties $wmiAdapterProperties
$outcomes['wmi_configuration'] = Invoke-ProviderQuery `
    -Name 'Get-CimInstance Win32_NetworkAdapterConfiguration' -Kind cim `
    -CommandName Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration `
    -Query { Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop } `
    -Properties $wmiConfigurationProperties
$outcomes['adapter_statistics'] = Invoke-ProviderQuery `
    -Name 'Get-NetAdapterStatistics' -Kind cmdlet -CommandName Get-NetAdapterStatistics `
    -Query { Get-NetAdapterStatistics -ErrorAction Stop } `
    -Properties $statisticsProperties

$result = [pscustomobject]@{
    powershell_version = $PSVersionTable.PSVersion.ToString()
    computer_name = [Environment]::MachineName
    providers = [pscustomobject]$outcomes
}
[Console]::Out.WriteLine(($result | ConvertTo-Json -Depth 14 -Compress))
"""


def _canonical_integrity_report(report):
    # Isolated embedded implementation: collector globals cannot shadow its imports.
    _inline_namespace = {}
    exec('"""Canonical post-save integrity reports; never evidence of acquisition-time hashing."""\nimport hashlib\nfrom datetime import datetime, timezone\nfrom pathlib import Path\n\n\ndef _now():\n    return datetime.now(timezone.utc).isoformat()\n\n\ndef _metadata(info):\n    return (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_dev, info.st_ino)\n\n\ndef _read_hash(path):\n    digest = hashlib.sha256()\n    with path.open(\'rb\') as stream:\n        for chunk in iter(lambda: stream.read(1024 * 1024), b\'\'):\n            digest.update(chunk)\n    return digest.hexdigest()\n\n\ndef canonical_report(source):\n    root = Path(source[\'output_directory\']).resolve()\n    outputs = []\n    for original in source.get(\'outputs\', []):\n        entry = dict.fromkeys((\'path\', \'size_bytes\', \'sha256\', \'verification_sha256\',\n                              \'last_modified_utc\', \'hash_timestamp_utc\',\n                              \'verification_timestamp_utc\', \'verification_status\', \'error\'))\n        entry[\'path\'] = original[\'path\']\n        entry[\'verification_status\'] = \'failed\'\n        try:\n            path = (root / original[\'path\']).resolve()\n            path.relative_to(root)\n            before = path.stat()\n            metadata = _metadata(before)\n            entry[\'size_bytes\'] = before.st_size\n            entry[\'last_modified_utc\'] = datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat()\n            entry[\'sha256\'] = _read_hash(path)\n            entry[\'hash_timestamp_utc\'] = _now()\n            if _metadata(path.stat()) != metadata:\n                raise RuntimeError(\'Saved file metadata changed during first read\')\n            entry[\'verification_sha256\'] = _read_hash(path)\n            entry[\'verification_timestamp_utc\'] = _now()\n            if _metadata(path.stat()) != metadata:\n                raise RuntimeError(\'Saved file metadata changed during independent verification read\')\n            if entry[\'sha256\'] != entry[\'verification_sha256\']:\n                raise RuntimeError(\'Saved-file SHA-256 mismatch between independent reads\')\n            entry[\'verification_status\'] = \'verified\'\n        except (OSError, ValueError, RuntimeError) as exc:\n            entry[\'error\'] = str(exc)\n        outputs.append(entry)\n    failed = any(item[\'verification_status\'] == \'failed\' for item in outputs)\n    return {\n        \'schema_version\': 1,\n        \'artifact_id\': source.get(\'artifact_id\'),\n        \'artifact_name\': source.get(\'artifact_name\') or root.name.removesuffix(\'_Output\'),\n        \'collector\': source.get(\'collector\', \'collector.py\'),\n        \'hash_algorithm\': \'SHA-256\',\n        \'verification_status\': \'failed\' if failed else \'verified\' if outputs else \'not_run\',\n        \'verification_method\': \'Two independent reads of saved output files; SHA-256 comparison and size, mtime, ctime, device and file identity stability checks. Not acquisition-time hashing.\',\n        \'collection_started_at_utc\': source.get(\'collection_started_at_utc\'),\n        \'collection_ended_at_utc\': source.get(\'collection_ended_at_utc\'),\n        \'collection_status\': \'partial\' if failed and source.get(\'collection_exit_code\') == 0 else source.get(\'collection_status\'),\n        \'collection_exit_code\': 1 if failed and source.get(\'collection_exit_code\') == 0 else source.get(\'collection_exit_code\'),\n        \'output_directory\': str(root),\n        \'outputs\': sorted(outputs, key=lambda item: item[\'path\'].casefold()),\n        \'manifest\': source.get(\'consolidated_reports\', source.get(\'manifest\', {})),\n        \'error\': source.get(\'error\'),\n        \'errors\': source.get(\'errors\', []),\n        \'generated_at_utc\': _now(),\n        \'generated_at_local\': datetime.now().astimezone().isoformat(),\n    }\n', _inline_namespace)
    report.setdefault('artifact_name', _inline_namespace['Path'](__file__).resolve().parent.name.split(' - ', 1)[1])
    canonical = _inline_namespace['canonical_report'](report)
    manifest = report.get('consolidated_reports', report.get('manifest', {}))
    if manifest == {}:
        canonical.pop('manifest', None)
    else:
        canonical['manifest'] = manifest
    return canonical


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def clock_values() -> tuple[str, str, str]:
    local = dt.datetime.now().astimezone()
    return (
        local.astimezone(dt.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        local.isoformat(timespec="microseconds"),
        local.tzname() or "local",
    )


def _normalize_guid(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().strip("{}").lower()
    try:
        return str(uuid.UUID(text))
    except (ValueError, AttributeError):
        return text or None


def _index(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def adapter_match_keys(record: dict[str, Any]) -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []
    guid = _normalize_guid(record.get("InterfaceGuid") or record.get("GUID"))
    if guid:
        keys.append(("guid", guid))
    luid = record.get("NetLuid")
    if luid not in (None, ""):
        keys.append(("luid", str(luid).casefold()))
    index = _index(record.get("InterfaceIndex") or record.get("ifIndex"))
    if index is not None and index > 0:
        keys.append(("ifindex", str(index)))
    pnp_id = record.get("PNPDeviceID")
    if isinstance(pnp_id, str) and pnp_id:
        keys.append(("pnp", pnp_id.casefold()))
    return keys


def adapter_match_key(record: dict[str, Any]) -> tuple[str, str] | None:
    keys = adapter_match_keys(record)
    return keys[0] if keys else None


def _physical_address_details(value: Any) -> tuple[list[int] | None, int | None]:
    if not isinstance(value, str):
        return None, None
    text = value.strip()
    if not text:
        return None, None
    if re.fullmatch(r"[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2})+", text):
        octets = re.split(r"[:-]", text)
    elif re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", text):
        octets = [text[index:index + 2] for index in range(0, len(text), 2)]
    else:
        return None, None
    values = [int(octet, 16) for octet in octets]
    return values, len(values)


def ipv4_subnet_mask(prefix_length: Any) -> str | None:
    if isinstance(prefix_length, bool) or not isinstance(prefix_length, int):
        return None
    if not 0 <= prefix_length <= 32:
        return None
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_length}").netmask)


def normalize_record(record: dict[str, Any], provider_key: str) -> dict[str, Any]:
    result = dict(record)
    for field in ("PreferredLifetime", "ValidLifetime"):
        value = result.get(field)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            result[f"{field}Interpretation"] = (
                "maximum_sentinel_or_indefinite"
                if value >= 0xFFFFFFFF
                else "seconds"
            )
            result[f"{field}Seconds"] = None if value >= 0xFFFFFFFF else value
    if provider_key == "ip_address":
        address = result.get("IPAddress")
        family = str(result.get("AddressFamily", "")).casefold()
        result["derived_subnet_mask"] = None
        if isinstance(address, str):
            try:
                parsed = ipaddress.ip_address(address.split("%", 1)[0])
                if parsed.version == 4:
                    result["derived_subnet_mask"] = ipv4_subnet_mask(
                        result.get("PrefixLength")
                    )
                else:
                    result["ipv6_scope_id"] = (
                        address.split("%", 1)[1] if "%" in address else None
                    )
            except ValueError:
                result["normalization_error"] = "invalid_ip_address"
        result["prefix_length_unit"] = "bits"
        result["subnet_mask_derivation"] = {
            "ipv4": "derived_from_prefix_length",
            "2": "derived_from_prefix_length",
            "internetwork": "derived_from_prefix_length",
            "ipv6": "not_applicable_ipv6",
            "23": "not_applicable_ipv6",
            "internetworkv6": "not_applicable_ipv6",
        }.get(family, "unavailable_address_family")
    if provider_key in ("net_adapter", "wmi_adapter"):
        address_field = (
            "MacAddress" if provider_key == "net_adapter" else "MACAddress"
        )
        address_value = result.get(address_field)
        if not address_value and provider_key == "net_adapter":
            address_value = result.get("LinkLayerAddress")
        address_bytes, address_length = _physical_address_details(address_value)
        result["derived_physical_address_bytes"] = address_bytes
        result["derived_physical_address_length_bytes"] = address_length
        permanent_value = result.get("PermanentAddress")
        permanent_bytes, permanent_length = _physical_address_details(permanent_value)
        result["derived_permanent_address_bytes"] = permanent_bytes
        result["derived_permanent_address_length_bytes"] = permanent_length
    if provider_key == "adapter_statistics":
        result["counter_unit"] = "bytes for *Bytes; packets for *Packets; count for errors/discards"
    return result


def _successful_records(outcome: Any) -> list[dict[str, Any]]:
    if not isinstance(outcome, dict) or outcome.get("status") != "success":
        return []
    records = outcome.get("records")
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
        return []
    return records


def _normalize_outcome(key: str, outcome: Any) -> dict[str, Any]:
    if not isinstance(outcome, dict):
        return {
            "provider": key,
            "status": "malformed_provider_response",
            "observed_at_utc": None,
            "object_count": None,
            "records": [],
            "error": {"message": "Provider outcome was not an object."},
        }
    result = dict(outcome)
    if result.get("status") != "success":
        result["records"] = []
        return result
    records = result.get("records")
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
        result.update({
            "status": "malformed_provider_response",
            "object_count": None,
            "records": [],
            "error": {"message": "Successful provider outcome did not contain an array of records."},
        })
        return result
    if result.get("object_count") != len(records):
        result.update({
            "status": "malformed_provider_response",
            "object_count": None,
            "records": [],
            "error": {"message": "Provider object_count did not match its record array."},
        })
        return result
    result["records"] = [
        normalize_record(record, key) for record in records
    ]
    return result


PROVIDER_KEYS = (
    "net_adapter",
    "ip_interface",
    "ip_address",
    "ip_configuration",
    "dns_server",
    "dns_client",
    "wmi_adapter",
    "wmi_configuration",
    "adapter_statistics",
)

INTERFACE_LINKED_PROVIDERS = (
    "ip_interface",
    "ip_address",
    "ip_configuration",
    "dns_server",
    "dns_client",
    "adapter_statistics",
)


def reconcile_providers(provider_outcomes: dict[str, Any]) -> dict[str, Any]:
    adapters = _successful_records(provider_outcomes.get("net_adapter"))
    wmi_adapters = _successful_records(provider_outcomes.get("wmi_adapter"))
    configurations = _successful_records(provider_outcomes.get("wmi_configuration"))
    records_by_key: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = {}
    for index, record in enumerate(adapters):
        for key in adapter_match_keys(record):
            records_by_key.setdefault(key, []).append((index, record))

    attached_wmi: set[int] = set()
    ambiguous_wmi: list[int] = []
    wmi_match_rules: dict[int, str] = {}
    for wmi_index, wmi_record in enumerate(wmi_adapters):
        matches: list[tuple[int, dict[str, Any]]] = []
        matched_by: tuple[str, str] | None = None
        for key in adapter_match_keys(wmi_record):
            candidates = records_by_key.get(key, [])
            if candidates:
                matches = candidates
                matched_by = key
                break
        if matched_by is not None and len(matches) == 1:
            attached_wmi.add(wmi_index)
            wmi_match_rules[wmi_index] = matched_by[0]
            matches[0][1].setdefault("_linked_wmi_adapter_indexes", []).append(wmi_index)
        elif matched_by is not None and len(matches) > 1:
            ambiguous_wmi.append(wmi_index)
    for adapter in adapters:
        adapter.setdefault("_linked_wmi_adapter_indexes", [])

    linked_configuration: set[int] = set()
    for config_index, config in enumerate(configurations):
        interface_index = _index(config.get("InterfaceIndex"))
        if interface_index is None:
            continue
        matches = [
            adapter for adapter in adapters
            if _index(adapter.get("InterfaceIndex") or adapter.get("ifIndex")) == interface_index
        ]
        if len(matches) == 1:
            matches[0].setdefault("_linked_wmi_configuration_indexes", []).append(config_index)
            linked_configuration.add(config_index)
    for adapter in adapters:
        adapter.setdefault("_linked_wmi_configuration_indexes", [])

    linked: dict[str, list[dict[str, Any]]] = {}
    unmatched: dict[str, list[int]] = {}
    for provider_key in INTERFACE_LINKED_PROVIDERS:
        provider_records = _successful_records(provider_outcomes.get(provider_key))
        by_index: dict[int, list[dict[str, Any]]] = {}
        unmatched_indexes: list[int] = []
        for record_index, record in enumerate(provider_records):
            index = _index(record.get("InterfaceIndex") or record.get("ifIndex"))
            if index is None:
                unmatched_indexes.append(record_index)
                continue
            matches = [
                adapter for adapter in adapters
                if _index(adapter.get("InterfaceIndex") or adapter.get("ifIndex")) == index
            ]
            if len(matches) == 1:
                by_index.setdefault(index, []).append({
                    "provider_record_index": record_index,
                    **record,
                })
            else:
                unmatched_indexes.append(record_index)
        linked[provider_key] = []
        for index, items in by_index.items():
            linked[provider_key].append({
                "interface_index": index,
                "provider_records": items,
            })
        unmatched[provider_key] = unmatched_indexes

    adapter_records: list[dict[str, Any]] = []
    for adapter_index, adapter in enumerate(adapters):
        record = {
            "net_adapter_record_index": adapter_index,
            "identity_match_key": adapter_match_key(adapter),
            "net_adapter": adapter,
            "matched_wmi_adapter_records": [
                {
                    "provider_record_index": index,
                    "reconciliation_match": wmi_match_rules[index],
                    **wmi_adapters[index],
                }
                for index in adapter.get("_linked_wmi_adapter_indexes", [])
            ],
            "matched_wmi_configuration_records": [
                {"provider_record_index": index, **configurations[index]}
                for index in adapter.get("_linked_wmi_configuration_indexes", [])
            ],
        }
        if adapter.get("_linked_wmi_adapter_indexes"):
            record["identity_match_rule"] = (
                "matched on " + ", ".join(
                    wmi_match_rules[item]
                    for item in adapter["_linked_wmi_adapter_indexes"]
                )
            )
        else:
            record["identity_match_rule"] = "no unique WMI adapter match"
        index = _index(adapter.get("InterfaceIndex") or adapter.get("ifIndex"))
        record["interface_index"] = index
        record["linked_configuration"] = {
            provider_key: next(
                (entry["provider_records"] for entry in linked[provider_key]
                 if entry["interface_index"] == index),
                [],
            )
            for provider_key in INTERFACE_LINKED_PROVIDERS
        }
        record["identity_disagreement"] = _identity_disagreements(
            adapter,
            [
                wmi_adapters[item]
                for item in adapter.get("_linked_wmi_adapter_indexes", [])
            ],
        )
        record["record_errors"] = [
            {
                "provider_key": provider_key,
                "provider": provider_outcomes[provider_key].get("provider"),
                "status": provider_outcomes[provider_key].get("status"),
                "observed_at_utc": provider_outcomes[provider_key].get("observed_at_utc"),
                "error": provider_outcomes[provider_key].get("error"),
            }
            for provider_key in INTERFACE_LINKED_PROVIDERS
            if provider_outcomes.get(provider_key, {}).get("status") != "success"
        ]
        record.pop("_linked_wmi_adapter_indexes", None)
        record.pop("_linked_wmi_configuration_indexes", None)
        adapter_records.append(record)

    unmatched["wmi_adapter"] = [
        index for index in range(len(wmi_adapters)) if index not in attached_wmi
    ]
    unmatched["wmi_configuration"] = [
        index for index in range(len(configurations)) if index not in linked_configuration
    ]
    unmatched["ambiguous_wmi_adapter"] = ambiguous_wmi
    return {
        "adapters": adapter_records,
        "unmatched_provider_record_indexes": unmatched,
        "matching_rule": (
            "Adapter providers link only on a unique normalized GUID, LUID, interface index, "
            "or PnP identifier; IP/DNS/configuration records link by interface index. "
            "Display name and MAC address are never sole match keys."
        ),
        "scope_note": "GUIDs, LUIDs, and interface indexes identify current interfaces; they are not permanent evidence identifiers.",
    }


def _identity_disagreements(
    primary: dict[str, Any],
    secondary_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    disagreements: list[dict[str, Any]] = []
    pairs = (
        ("InterfaceAlias", "NetConnectionID"),
        ("InterfaceDescription", "Description"),
        ("InterfaceGuid", "GUID"),
        ("InterfaceIndex", "InterfaceIndex"),
        ("MacAddress", "MACAddress"),
        ("PhysicalMediaType", "AdapterType"),
        ("HardwareInterface", "PhysicalAdapter"),
    )
    for secondary in secondary_records:
        for primary_field, secondary_field in pairs:
            first = primary.get(primary_field)
            second = secondary.get(secondary_field)
            if first is None or second is None:
                continue
            if primary_field in ("InterfaceGuid", "GUID"):
                first_normalized = _normalize_guid(first) or str(first).casefold()
                second_normalized = _normalize_guid(second) or str(second).casefold()
            elif primary_field in ("MacAddress", "MACAddress"):
                first_normalized = re.sub(r"[^0-9a-f]", "", str(first).casefold())
                second_normalized = re.sub(r"[^0-9a-f]", "", str(second).casefold())
                first_normalized = first_normalized or str(first).casefold()
                second_normalized = second_normalized or str(second).casefold()
            else:
                first_normalized = str(first).casefold()
                second_normalized = str(second).casefold()
            if first_normalized != second_normalized:
                disagreements.append({
                    "primary_provider_field": primary_field,
                    "primary_value": first,
                    "secondary_provider_field": secondary_field,
                    "secondary_value": second,
                })
    return disagreements


def _provider_failure(name: str, message: str, status: str = "provider_failure") -> dict[str, Any]:
    return {
        "provider": name,
        "status": status,
        "observed_at_utc": utc_now(),
        "object_count": None,
        "records": [],
        "error": {"message": message},
    }


def _empty_failed_providers(message: str, status: str) -> dict[str, Any]:
    return {
        key: _provider_failure(key, message, status)
        for key in PROVIDER_KEYS
    }


def build_document(
    provider_data: dict[str, Any] | None,
    *,
    collection_started_at_utc: str | None = None,
    collection_started_at_local: str | None = None,
    local_timezone_name: str | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    if collection_started_at_utc is None or collection_started_at_local is None:
        (
            collection_started_at_utc,
            collection_started_at_local,
            captured_timezone,
        ) = clock_values()
        local_timezone_name = local_timezone_name or captured_timezone
    local_timezone_name = local_timezone_name or "local"
    source = provider_data if isinstance(provider_data, dict) else {}
    normalized_providers = {
        key: _normalize_outcome(
            key,
            source.get("providers", {}).get(key)
            if isinstance(source.get("providers"), dict)
            else None,
        )
        for key in PROVIDER_KEYS
    }
    reconciliation = reconcile_providers(normalized_providers)

    adapter_status = normalized_providers["net_adapter"]["status"]
    primary_success = adapter_status == "success"
    all_success = all(
        normalized_providers[key]["status"] == "success"
        for key in PROVIDER_KEYS
    )
    status = "failed" if not primary_success else ("success" if all_success else "partial")
    errors = [
        {
            "provider_key": key,
            "provider": outcome.get("provider"),
            "status": outcome.get("status"),
            "observed_at_utc": outcome.get("observed_at_utc"),
            "error": outcome.get("error"),
        }
        for key, outcome in normalized_providers.items()
        if outcome.get("status") != "success"
    ]
    provider_counts = {
        key: outcome.get("object_count")
        for key, outcome in normalized_providers.items()
    }
    end_utc, end_local, end_timezone_name = clock_values()
    return {
        "artifact_id": ARTIFACT_ID,
        "collection_method": (
            "Structured read-only Windows PowerShell NetAdapter, NetTCPIP, DnsClient, "
            "and CIM providers"
        ),
        "collection_started_at_utc": collection_started_at_utc,
        "collection_started_at_local": collection_started_at_local,
        "collection_ended_at_utc": end_utc,
        "collection_ended_at_local": end_local,
        "local_timezone_name": end_timezone_name or local_timezone_name,
        "local_machine": {
            "computer_name": source.get("computer_name") or socket.gethostname(),
            "scope": "local computer and interfaces visible to selected Windows providers",
        },
        "status": status,
        "enumeration_completeness": {
            "status": (
                "complete_for_selected_providers"
                if all_success
                else "partial_or_failed"
            ),
            "provider_scope": list(PROVIDER_KEYS),
            "primary_adapter_provider_succeeded": primary_success,
            "hidden_adapters_requested": True,
            "all_provider_queries_succeeded": all_success,
            "meaning": (
                "Completeness means the selected providers returned successfully; "
                "it does not guarantee every hidden device or historical adapter is visible."
            ),
        },
        "provider_outcomes": {
            "powershell_version": source.get("powershell_version"),
            **normalized_providers,
        },
        "adapters": reconciliation["adapters"],
        "unmatched_provider_records": reconciliation["unmatched_provider_record_indexes"],
        "reconciliation": {
            "matching_rule": reconciliation["matching_rule"],
            "scope_note": reconciliation["scope_note"],
            "identity_disagreements_preserved": True,
            "providers_are_not_overwritten": True,
        },
        "counts": {
            "providers": provider_counts,
            "net_adapter_records": len(_successful_records(normalized_providers["net_adapter"])),
            "wmi_adapter_records": len(_successful_records(normalized_providers["wmi_adapter"])),
            "linked_adapter_records": len(reconciliation["adapters"]),
            "unmatched_provider_records": {
                key: len(indexes)
                for key, indexes in reconciliation["unmatched_provider_record_indexes"].items()
            },
            "ipv4_address_records": sum(
                1 for record in _successful_records(normalized_providers["ip_address"])
                if str(record.get("AddressFamily", "")).casefold() in ("ipv4", "2", "internetwork")
            ),
            "ipv6_address_records": sum(
                1 for record in _successful_records(normalized_providers["ip_address"])
                if str(record.get("AddressFamily", "")).casefold() in ("ipv6", "23", "internetworkv6")
            ),
            "error_count": len(errors),
        },
        "errors": errors,
        "limitations": [
            "Queries run sequentially and do not form an atomic snapshot; interfaces and settings may change during collection.",
            "Get-NetAdapter -IncludeHidden requests hidden adapters exposed by that provider; it does not guarantee discovery of every hidden, removed, historical, or provider-inaccessible device.",
            "A physical/virtual classification is reported only from explicit provider properties; names are not used to guess.",
            "Administrative, operational, and media-connection states are distinct provider observations.",
            "Configured gateways do not prove reachability and are not a complete route-table acquisition.",
            "Configured DNS servers do not prove a resolver answered a query or indicate actual resolver selection order.",
            "DHCP configuration and lease timestamps do not independently prove that a lease remains valid.",
            "Link speeds are provider-reported link rates, not measured throughput.",
            "Counters are observational interface values, may reset, and do not identify a particular connection, user, or event.",
            "GUIDs, LUIDs, interface indexes, MAC addresses, and device IDs are not asserted to be permanent identifiers.",
            "Null, unsupported, unavailable, empty, zero, and false values are kept distinct where providers expose the distinction.",
            "No active connection, route table, network scan, hostname lookup, Wi-Fi credential/profile, DNS cache, ARP cache, or Bluetooth history is collected.",
        ],
        "actual_output_path": output_path,
    }


def run_powershell_query(timeout: int = POWERSHELL_TIMEOUT_SECONDS) -> dict[str, Any]:
    if os.name != "nt":
        raise OSError("A68 requires local Windows PowerShell and Windows network providers.")
    encoded_script = base64.b64encode(POWERSHELL_SCRIPT.encode("utf-8")).decode("ascii")
    environment = os.environ.copy()
    environment["CUSTOS_A68_SCRIPT_B64"] = encoded_script
    command = (
        "$ErrorActionPreference = 'Stop'; "
        "$script = [Text.Encoding]::UTF8.GetString("
        "[Convert]::FromBase64String($env:CUSTOS_A68_SCRIPT_B64)); "
        "& ([scriptblock]::Create($script))"
    )
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        capture_output=True,
        env=environment,
        timeout=timeout,
        check=False,
        shell=False,
    )
    stdout = completed.stdout.decode("utf-8-sig", errors="strict").strip()
    stderr = completed.stderr.decode("utf-8-sig", errors="replace").strip()
    if completed.returncode != 0:
        raise RuntimeError(
            f"PowerShell provider script exited with {completed.returncode}: "
            f"{stderr or stdout or 'no diagnostic output'}"
        )
    try:
        document = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"PowerShell returned invalid JSON: {exc}; stderr={stderr!r}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("providers"), dict):
        raise ValueError("PowerShell output must be a JSON object with provider outcomes.")
    return document


def _resolve_output_directory(value: str | None) -> Path:
    if value is None:
        if sys.stdin.isatty():
            supplied = input(
                "Enter a custom save folder, or press Enter to save in this artifact folder. "
            ).strip().strip('"')
            value = supplied or str(ARTIFACT_DIRECTORY)
        else:
            value = str(ARTIFACT_DIRECTORY)
    if not value.strip():
        raise ValueError("The output directory cannot be empty.")
    directory = Path(os.path.expandvars(os.path.expanduser(value.strip().strip('"'))))
    directory = directory.resolve(strict=True)
    if not directory.is_dir():
        raise NotADirectoryError(f"Output destination is not a directory: {directory}")
    if not os.access(directory, os.W_OK):
        raise PermissionError(f"Output directory is not writable: {directory}")
    return directory


def _default_output_path(directory: Path, overwrite: bool) -> Path:
    standard = directory / "network_adapters.json"
    if overwrite or not standard.exists():
        return standard
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    candidate = directory / f"network_adapters_{stamp}.json"
    while candidate.exists():
        candidate = directory / f"network_adapters_{stamp}_{secrets.token_hex(3)}.json"
    return candidate


def write_json_output(path: Path, document: dict[str, Any], overwrite: bool) -> None:
    text = json.dumps(document, ensure_ascii=False, indent=2, default=str)
    text = re.sub(r"},\n(?=\s*{)", "},\n\n", text)
    temporary: Path | None = None
    try:
        for _ in range(10):
            candidate = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
            try:
                stream = candidate.open("x", encoding="utf-8", newline="\n")
                temporary = candidate
                break
            except FileExistsError:
                continue
        else:
            raise FileExistsError("Could not allocate a unique temporary output file.")
        with stream:
            stream.write(text)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, path)
        elif os.name == "nt":
            os.rename(temporary, path)
        else:
            os.link(temporary, path)
            temporary.unlink()
    except Exception as write_error:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as cleanup_error:
                raise OSError(
                    f"{write_error}; temporary output cleanup failed for "
                    f"{temporary}: {cleanup_error}"
                ) from write_error
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect local Windows network-adapter metadata without changing configuration."
    )
    parser.add_argument(
        "--output-dir",
        help="Existing output directory. Omit for the optional save-folder prompt.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly replace network_adapters.json in the chosen output directory.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        output_directory = _resolve_output_directory(args.output_dir)
        output_path = _default_output_path(output_directory, args.overwrite)
        start_utc, start_local, timezone_name = clock_values()
        try:
            provider_data = run_powershell_query()
        except subprocess.TimeoutExpired as exc:
            provider_data = {
                "computer_name": socket.gethostname(),
                "providers": _empty_failed_providers(
                    f"PowerShell network query timed out after {exc.timeout} seconds.",
                    "timeout",
                ),
            }
        except (OSError, RuntimeError, ValueError) as exc:
            provider_data = {
                "computer_name": socket.gethostname(),
                "providers": _empty_failed_providers(str(exc), "provider_failure"),
            }
        document = build_document(
            provider_data,
            collection_started_at_utc=start_utc,
            collection_started_at_local=start_local,
            local_timezone_name=timezone_name,
            output_path=str(output_path),
        )
        write_json_output(output_path, document, args.overwrite)
        print(f"A68 status: {document['status']}")
        print(f"A68 output: {output_path}")
        if document["status"] == "failed":
            return 2
        if document["status"] == "partial":
            return 1
        return 0
    except KeyboardInterrupt:
        print("A68 interrupted; no complete successful result is claimed.", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        print(f"A68 failed: {exc}", file=sys.stderr)
        return 2


def _run_with_integrity_manifest(main):
    import builtins
    import datetime as _integrity_datetime
    import hashlib as _integrity_hashlib
    import json as _integrity_json
    import os as _integrity_os
    import secrets as _integrity_secrets
    import sys as _integrity_sys
    from pathlib import Path as _IntegrityPath

    arguments = _integrity_sys.argv[1:]
    if any(argument in {"-h", "--help"} for argument in arguments):
        return main()

    launcher_output_response = None
    launcher_output_directory = None
    collector_directory = _IntegrityPath(_integrity_sys.argv[0]).resolve().parent
    artifact_id = collector_directory.name.split(" ", 1)[0]
    artifact_display_name = collector_directory.name.split(" - ", 1)[1]
    default_output_directory = collector_directory / f"{artifact_display_name}_Output"
    output_option_by_id = {
        "A01": "--output-dir", "A02": "--output", "A03": "--output",
        "A04": "--output", "A05": "--output", "A06": "--output",
        "A17": "--output-dir", "A18": "--output-dir", "A23": "--output",
        "A25": "--output", "A30": "--output", "A31": "--output",
        "A40": "--output", "A41": "--output", "A42": "--output",
        "A46": "--output", "A47": "--output", "A48": "--output",
        "A51": "--output-dir", "A52": "--output-dir",
        "A59": "--output-dir", "A66": "--output-dir",
        "A68": "--output-dir", "X14": "--output-dir",
        "X15": "--output-dir", "X16": "--output-dir",
        "X18": "--output-dir", "X20": "--output-dir",
        "X22": "--output-dir", "X23": "--output-dir",
        "X26": "--output-dir", "X29": "--output-dir",
        "X32": "--output-dir",
    }
    has_output = any(
        argument.partition("=")[0] in {
            "-o", "--out", "--output", "--output-dir", "--output-directory"
        }
        for argument in arguments
    )
    if not has_output:
        output_option = output_option_by_id.get(artifact_id)
        if output_option is None:
            raise RuntimeError(f"No launcher output option is configured for {artifact_id}.")
        selected_folder = ""
        if _integrity_os.environ.get("CUSTOS_LAUNCHER_OUTPUT_PROMPT") == "1":
            selected_folder = input(
                f"Enter a custom output folder, or press Enter for the default [{default_output_directory}]: "
            ).strip().strip("\"'")
        output_directory = _IntegrityPath(
            _integrity_os.path.expandvars(
                _integrity_os.path.expanduser(selected_folder)
            )
        ) if selected_folder else default_output_directory
        output_directory = output_directory.resolve()
        output_directory.mkdir(parents=True, exist_ok=True)
        launcher_output_directory = output_directory
        if artifact_id in {
            "A01", "A17", "A18", "A23", "A25", "A30", "A31",
            "A40", "A41", "A42", "A46", "A47", "A48", "A51",
            "A52", "A59", "A66", "A68",
        }:
            launcher_output_response = str(output_directory)
        else:
            arguments.extend((output_option, str(output_directory)))
            _integrity_sys.argv[:] = [_integrity_sys.argv[0], *arguments]

    def utc_now():
        return _integrity_datetime.datetime.now(
            _integrity_datetime.timezone.utc
        ).isoformat(timespec="microseconds").replace("+00:00", "Z")

    def snapshot(directory):
        if not directory.is_dir():
            return {}
        result = {}
        skipped = {".git", ".venv", "venv", "__pycache__", "output & validation"}
        def raise_walk_error(error):
            raise error
        for current, folders, filenames in _integrity_os.walk(
            directory, onerror=raise_walk_error
        ):
            folders[:] = [name for name in folders if name.casefold() not in skipped]
            for filename in filenames:
                path = _IntegrityPath(current) / filename
                if path.is_symlink():
                    continue
                info = path.stat()
                result[path] = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        return result

    collector_directory = _IntegrityPath(_integrity_sys.argv[0]).resolve().parent
    output_options = {
        "-o": False, "--out": False, "--output": False,
        "--output-dir": True, "--output-directory": True,
        "--destination": True, "--dest": True,
    }
    selected = None
    for index, argument in enumerate(arguments):
        option, separator, value = argument.partition("=")
        if option in output_options:
            if separator:
                selected = (value, output_options[option])
            elif index + 1 < len(arguments) and not arguments[index + 1].startswith("-"):
                selected = (arguments[index + 1], output_options[option])
    if selected is None:
        configured = next((
            value for name, value in _integrity_os.environ.items()
            if name.startswith("CUSTOS_") and "OUTPUT" in name and value.strip()
        ), None)
        if configured:
            selected = (configured, False)
    if selected is None or not selected[0].strip():
        output_root = default_output_directory
    else:
        value, is_directory = selected
        output_root = _IntegrityPath(
            _integrity_os.path.expandvars(
                _integrity_os.path.expanduser(value.strip().strip("\"'"))
            )
        )
        if not output_root.is_absolute():
            output_root = _IntegrityPath.cwd() / output_root
        if not is_directory and output_root.suffix and not output_root.is_dir():
            output_root = output_root.parent
        output_root = output_root.resolve()

    if launcher_output_directory is not None:
        output_root = launcher_output_directory

    before = snapshot(output_root)
    started_at = utc_now()
    original_input = builtins.input

    def tracked_input(prompt=""):
        nonlocal output_root, before, launcher_output_response
        is_output_prompt = any(
            word in prompt.casefold() for word in ("output", "destination", "save")
        )
        if is_output_prompt and launcher_output_response is not None:
            response = launcher_output_response
            launcher_output_response = None
        elif is_output_prompt and not _integrity_sys.stdin.isatty():
            response = str(default_output_directory)
        else:
            response = original_input(prompt)
            if is_output_prompt and not response.strip():
                response = str(default_output_directory)
        if is_output_prompt:
            value = response.strip().strip("\"'")
            if value:
                output_root = _IntegrityPath(
                    _integrity_os.path.expandvars(
                        _integrity_os.path.expanduser(value)
                    )
                )
                if not output_root.is_absolute():
                    output_root = _IntegrityPath.cwd() / output_root
                output_root = output_root.resolve()
                before = snapshot(output_root)
        return response

    result = 0
    failure = None
    builtins.input = tracked_input
    try:
        result = main()
    except BaseException as error:
        failure = error
        result = error.code if isinstance(error, SystemExit) and isinstance(error.code, int) else 1
    finally:
        builtins.input = original_input

    ended_at = utc_now()
    artifact_id = collector_directory.name.split(" ", 1)[0]
    artifact_display_name = collector_directory.name.split(" - ", 1)[1]
    run_timestamp = _integrity_datetime.datetime.now(
        _integrity_datetime.timezone.utc
    ).strftime("%Y%m%dT%H%M%S.%fZ")
    manifest_path = output_root / f"{artifact_display_name}_Hash & Timestamp Report.json"
    outputs = []
    verification_errors = 0
    for path, metadata in snapshot(output_root).items():
        if path == manifest_path or before.get(path) == metadata:
            continue
        try:
            info = path.stat()
            current = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if current != metadata:
                raise RuntimeError(f"Output changed before SHA-256 calculation: {path}")
            digest = _integrity_hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            info = path.stat()
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != current:
                raise RuntimeError(f"Output changed during SHA-256 calculation: {path}")
        except (OSError, RuntimeError) as error:
            verification_errors += 1
            print(f"SHA-256 verification failed for {path}: {error}", file=_integrity_sys.stderr)
            outputs.append({
                "path": path.relative_to(output_root).as_posix(),
                "size_bytes": metadata[0],
                "sha256": None,
                "verification_status": "failed",
                "error": str(error),
            })
            continue
        outputs.append({
            "path": path.relative_to(output_root).as_posix(),
            "size_bytes": metadata[0],
            "sha256": digest.hexdigest(),
            "verification_status": "verified",
        })
    outputs.sort(key=lambda item: item["path"].casefold())
    verification_status = "failed" if verification_errors else "verified" if outputs else "not_run"
    if verification_errors and result == 0:
        result = 1
    report = {
        "artifact_id": artifact_id,
        "collector": _IntegrityPath(_integrity_sys.argv[0]).name,
        "hash_algorithm": "SHA-256",
        "verification_status": verification_status,
        "verification_method": "File size, modification time, and creation time remained unchanged during SHA-256 calculation.",
        "collection_started_at_utc": started_at,
        "collection_ended_at_utc": ended_at,
        "collection_status": "partial" if result == 1 else "completed" if result == 0 else "failed",
        "collection_exit_code": result,
        "output_directory": str(output_root),
        "outputs": outputs,
    }
    if failure is not None and not isinstance(failure, SystemExit):
        report["error"] = {"type": type(failure).__name__, "message": str(failure)}

    if not output_root.is_dir() and result != 0:
        output_root = default_output_directory
        output_root.mkdir(parents=True, exist_ok=True)
        manifest_path = output_root / manifest_path.name
        report["output_directory"] = str(output_root)
        report["outputs"] = []
    else:
        output_root.mkdir(parents=True, exist_ok=True)
    temporary_path = manifest_path.with_name(
        f".{manifest_path.name}.{_integrity_secrets.token_hex(4)}.tmp"
    )
    report = _canonical_integrity_report(report)
    result = report["collection_exit_code"]
    try:
        with temporary_path.open("x", encoding="utf-8", newline="\n") as stream:
            _integrity_json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            _integrity_os.fsync(stream.fileno())
        _integrity_os.replace(temporary_path, manifest_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    if failure is not None:
        raise failure.with_traceback(failure.__traceback__)
    return result


if __name__ == "__main__":
    raise SystemExit(_run_with_integrity_manifest(main))
