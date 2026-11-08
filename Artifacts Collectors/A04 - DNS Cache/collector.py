"""Collect the current Windows DNS client cache without modifying it."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DNS_RECORD_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    13: "HINFO",
    15: "MX",
    16: "TXT",
    17: "RP",
    18: "AFSDB",
    24: "SIG",
    25: "KEY",
    28: "AAAA",
    29: "LOC",
    33: "SRV",
    35: "NAPTR",
    39: "DNAME",
    41: "OPT",
    42: "APL",
    43: "DS",
    44: "SSHFP",
    45: "IPSECKEY",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    49: "DHCID",
    50: "NSEC3",
    51: "NSEC3PARAM",
    52: "TLSA",
    55: "HIP",
    59: "CDS",
    60: "CDNSKEY",
    64: "SVCB",
    65: "HTTPS",
    99: "SPF",
    249: "TKEY",
    250: "TSIG",
    251: "IXFR",
    252: "AXFR",
    255: "ANY",
    257: "CAA",
}

EXPECTED_CACHE_PROPERTIES = (
    "Entry",
    "Name",
    "Type",
    "Status",
    "Data",
    "DataLength",
    "TTL",
    "TimeToLive",
    "Section",
)

POWERSHELL_QUERY = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
try {
    Import-Module DnsClient -ErrorAction Stop
    $records = @(Get-DnsClientCache -ErrorAction Stop)
    $outputRecords = New-Object 'System.Collections.Generic.List[object]'
    $schema = [ordered]@{}
    $recordIndex = 0

    foreach ($record in $records) {
        $values = [ordered]@{}
        $types = [ordered]@{}
        $fieldErrors = [ordered]@{}
        $cimTypes = @{}

        foreach ($cimProperty in $record.CimInstanceProperties) {
            $cimTypes[$cimProperty.Name] = [string]$cimProperty.CimType
        }

        foreach ($property in $record.PSObject.Properties) {
            if ($property.Name -in @('CimClass', 'CimInstanceProperties', 'CimSystemProperties')) {
                continue
            }

            try {
                $value = $property.Value
                $values[$property.Name] = $value
                if ($cimTypes.ContainsKey($property.Name)) {
                    $types[$property.Name] = $cimTypes[$property.Name]
                } elseif ($null -eq $value) {
                    $types[$property.Name] = 'null'
                } else {
                    $types[$property.Name] = $value.GetType().FullName
                }
                if (-not $schema.Contains($property.Name)) {
                    $schema[$property.Name] = $types[$property.Name]
                }
            } catch {
                $fieldErrors[$property.Name] = $_.Exception.Message
                if (-not $schema.Contains($property.Name)) {
                    $schema[$property.Name] = 'provider_read_error'
                }
            }
        }

        $outputRecords.Add([ordered]@{
            provider_record_index = $recordIndex
            provider_values = $values
            provider_property_types = $types
            provider_field_errors = $fieldErrors
        })
        $recordIndex++
    }

    $payload = [ordered]@{
        provider_name = 'Get-DnsClientCache'
        provider_module = 'DnsClient'
        powershell_version = $PSVersionTable.PSVersion.ToString()
        provider_property_types = $schema
        records = $outputRecords.ToArray()
    }
    $json = ConvertTo-Json -InputObject $payload -Depth 100 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    [Console]::Out.WriteLine([Convert]::ToBase64String($bytes))
} catch {
    [Console]::Error.WriteLine($_.Exception.ToString())
    exit 1
}
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
    return datetime.now(timezone.utc).isoformat()


def _normalize_utc_timestamp(value: str | datetime) -> datetime:
    timestamp = (
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        if isinstance(value, str)
        else value
    )
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def _collection_time_metadata(started_at_utc: str, ended_at_utc: str) -> dict[str, Any]:
    started = _normalize_utc_timestamp(started_at_utc)
    observed_end = _normalize_utc_timestamp(ended_at_utc)
    clock_adjusted = observed_end < started
    ended = max(started, observed_end)
    timezone_id = None
    timezone_id_error = None
    timezone_id_source = (
        r"HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation\TimeZoneKeyName"
    )
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
        ) as key:
            timezone_id = winreg.QueryValueEx(key, "TimeZoneKeyName")[0]
        if not isinstance(timezone_id, str) or not timezone_id.strip():
            timezone_id = None
            timezone_id_error = "The Windows TimeZoneKeyName value was empty or malformed."
    except (ImportError, OSError) as exc:
        timezone_id_error = f"{type(exc).__name__}: {exc}"
    return {
        "collection_started_at_utc": started.isoformat(),
        "collection_ended_at_utc": ended.isoformat(),
        "collection_started_at_local": started.astimezone().isoformat(),
        "collection_ended_at_local": ended.astimezone().isoformat(),
        "collection_time_zone_id": timezone_id,
        "collection_time_zone_id_source": timezone_id_source,
        "collection_time_zone_id_error": timezone_id_error,
        "collection_clock_adjusted": clock_adjusted,
    }


def _powershell_executable() -> str:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def _run_provider() -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    if os.name != "nt":
        return None, [
            {
                "error_type": "UnsupportedPlatform",
                "message": "Get-DnsClientCache is supported only on Windows.",
            }
        ]

    encoded_command = base64.b64encode(
        POWERSHELL_QUERY.encode("utf-16le")
    ).decode("ascii")
    command = [
        _powershell_executable(),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        encoded_command,
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return None, [
            {
                "error_type": "ProviderTimeout",
                "message": f"Get-DnsClientCache exceeded 120 seconds: {exc}",
            }
        ]
    except OSError as exc:
        return None, [
            {
                "error_type": "ProviderProcessError",
                "message": f"Could not start Windows PowerShell: {exc}",
            }
        ]

    stdout_lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    payload_lines = [
        line for line in stdout_lines if re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", line)
    ]
    errors: list[dict[str, Any]] = []
    if completed.returncode != 0:
        errors.append(
            {
                "error_type": "ProviderCommandFailed",
                "return_code": completed.returncode,
                "message": completed.stderr.strip()
                or "Get-DnsClientCache failed without diagnostic text.",
            }
        )
        return None, errors
    if len(payload_lines) != 1:
        errors.append(
            {
                "error_type": "MalformedProviderOutput",
                "message": (
                    "Expected one base64-encoded provider document from PowerShell; "
                    f"received {len(payload_lines)} candidate lines."
                ),
                "stdout": completed.stdout[:4000],
                "stderr": completed.stderr.strip() or None,
            }
        )
        return None, errors

    extras = [line for line in stdout_lines if line not in payload_lines]
    if extras:
        errors.append(
            {
                "error_type": "UnexpectedProviderOutput",
                "message": "PowerShell wrote additional output besides the serialized provider result.",
                "output_lines": extras,
            }
        )

    try:
        raw_json = base64.b64decode(payload_lines[0], validate=True).decode("utf-8")
        payload = json.loads(raw_json)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(
            {
                "error_type": "MalformedProviderOutput",
                "message": f"Could not decode the Get-DnsClientCache result: {exc}",
            }
        )
        return None, errors
    if not isinstance(payload, dict) or not isinstance(payload.get("records"), list):
        errors.append(
            {
                "error_type": "MalformedProviderOutput",
                "message": "The PowerShell response did not contain a records array.",
            }
        )
        return None, errors
    if completed.stderr.strip():
        errors.append(
            {
                "error_type": "ProviderDiagnostic",
                "message": completed.stderr.strip(),
            }
        )
    return payload, errors


def _as_optional_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _normalize_record(
    provider_values: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, str]]:
    record_name = provider_values.get("Name")
    cache_entry_name = provider_values.get("Entry")

    raw_type = provider_values.get("Type")
    type_code = _as_optional_int(raw_type)
    type_name = DNS_RECORD_TYPES.get(type_code) if type_code is not None else None

    raw_ttl = provider_values.get("TimeToLive")
    if raw_ttl is None:
        raw_ttl = provider_values.get("TTL")
    ttl_seconds = _as_optional_int(raw_ttl)

    normalized = {
        "record_name": record_name,
        "cache_entry_name": cache_entry_name,
        "record_type_code": type_code,
        "record_type_name": type_name,
        "record_data": provider_values.get("Data"),
        "data_length_bytes": _as_optional_int(provider_values.get("DataLength")),
        "status_code": _as_optional_int(provider_values.get("Status")),
        "section_code": _as_optional_int(provider_values.get("Section")),
        "time_to_live_seconds": ttl_seconds,
    }

    limitations: dict[str, str] = {}
    for output_field, source_fields in (
        ("record_name", ("Name",)),
        ("cache_entry_name", ("Entry",)),
        ("record_type_code", ("Type",)),
        ("record_data", ("Data",)),
        ("data_length_bytes", ("DataLength",)),
        ("status_code", ("Status",)),
        ("section_code", ("Section",)),
        ("time_to_live_seconds", ("TimeToLive", "TTL")),
    ):
        found_property = next(
            (field for field in source_fields if field in provider_values), None
        )
        if found_property is None:
            limitations[output_field] = (
                "Provider did not return any source property for this normalized field."
            )
        elif provider_values[found_property] is None:
            limitations[output_field] = (
                f"Provider returned null for source property {found_property}."
            )
        elif normalized[output_field] is None:
            limitations[output_field] = (
                f"Could not normalize provider value from {found_property}; "
                "the original value is retained in provider_values."
            )
    if type_code is not None and type_name is None:
        normalized["record_type_label"] = f"Unmapped DNS record type code {type_code}"
    else:
        normalized["record_type_label"] = type_name
    return normalized, limitations


def _build_document(
    started_at: str,
    payload: dict[str, Any] | None,
    provider_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    provider_name = "Get-DnsClientCache"
    raw_records = payload.get("records", []) if payload is not None else []
    schema = payload.get("provider_property_types", {}) if payload is not None else {}
    records: list[dict[str, Any]] = []
    record_errors: list[dict[str, Any]] = []
    all_properties = set(schema)
    property_types: dict[str, set[str]] = {
        str(name): {str(type_name)} for name, type_name in schema.items()
    }

    for index, raw_record in enumerate(raw_records):
        if not isinstance(raw_record, dict):
            record_errors.append(
                {
                    "record_index": index,
                    "error_type": "MalformedProviderRecord",
                    "message": "Provider record was not a JSON object.",
                }
            )
            continue
        provider_values = raw_record.get("provider_values")
        provider_types = raw_record.get("provider_property_types")
        provider_field_errors = raw_record.get("provider_field_errors")
        if not isinstance(provider_values, dict):
            record_errors.append(
                {
                    "record_index": index,
                    "error_type": "MalformedProviderRecord",
                    "message": "Provider record did not contain provider_values.",
                }
            )
            continue
        if not isinstance(provider_types, dict):
            provider_types = {}
        if not isinstance(provider_field_errors, dict):
            provider_field_errors = {}

        all_properties.update(provider_values)
        for name, type_name in provider_types.items():
            property_types.setdefault(str(name), set()).add(str(type_name))
        normalized, limitations = _normalize_record(provider_values)
        records.append(
            {
                "record_index": index,
                "provider_record_index": raw_record.get(
                    "provider_record_index", index
                ),
                "provider_values": provider_values,
                "provider_property_types": provider_types,
                "provider_properties_present": list(provider_values),
                "provider_null_properties": [
                    name for name, value in provider_values.items() if value is None
                ],
                "normalized": normalized,
                "field_limitations": limitations,
                "field_errors": provider_field_errors,
            }
        )
        for field, message in provider_field_errors.items():
            record_errors.append(
                {
                    "record_index": index,
                    "field": field,
                    "error_type": "ProviderFieldReadError",
                    "message": str(message),
                }
            )

    status = "failed" if payload is None else (
        "partial" if provider_errors or record_errors else "success"
    )
    timestamps = _collection_time_metadata(started_at, utc_now())
    return {
        "schema_version": 1,
        "artifact": "A04",
        "artifact_name": "DNS Cache",
        "source": "Current local Windows DNS client cache",
        **timestamps,
        "collection_status": status,
        "record_count": len(records),
        "provider": {
            "name": provider_name,
            "module": payload.get("provider_module") if payload else "DnsClient",
            "powershell_version": (
                payload.get("powershell_version") if payload else None
            ),
            "records_returned": len(raw_records),
            "properties_returned_union": sorted(all_properties),
            "property_types_returned": {
                name: sorted(types) for name, types in sorted(property_types.items())
            },
            "expected_cache_properties_not_returned": sorted(
                set(EXPECTED_CACHE_PROPERTIES) - all_properties
            ),
            "filters_applied": [],
            "coverage": (
                "Every record returned by Get-DnsClientCache is retained. Each "
                "returned provider property is copied dynamically into "
                "provider_values, including unfamiliar properties and null values. "
                "No record-type, status, or name filters are used."
            ),
        },
        "limitations": [
            "This is a snapshot of records exposed by Get-DnsClientCache at collection time.",
            "The provider does not promise expired entries, all historical queries, or application-specific DNS caches.",
            "Administrator access does not expand the provider's defined cache coverage or guarantee every field is available.",
            "The collector does not flush the DNS cache, perform DNS lookups, or change system settings.",
            "Status and section values are retained as provider codes; no undocumented semantic labels are inferred.",
            "All records the provider returns are included without filters, including negative-cache entries if exposed by the provider. The provider result may not expose a dedicated negative-cache indicator.",
            "Unknown properties and DNS type codes are preserved in the original provider values even when no normalized type label is available.",
        ],
        "errors": provider_errors + record_errors,
        "records": records,
    }


def _write_json(destination: Path, document: dict[str, Any], overwrite: bool) -> None:
    if not destination.parent.is_dir():
        raise FileNotFoundError(f"Output directory does not exist: {destination.parent}")
    if not overwrite and os.path.lexists(destination):
        raise FileExistsError(f"Refusing to overwrite existing output: {destination}")

    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as handle:
            temporary_path = handle.name
            handle.write("{\n")
            for item_index, (key, value) in enumerate(document.items()):
                if item_index:
                    handle.write(",\n")
                handle.write(f"  {json.dumps(key, ensure_ascii=True)}: ")
                if key in ("records", "errors") and isinstance(value, list):
                    handle.write("[\n")
                    for index, item in enumerate(value):
                        if index:
                            handle.write(",\n\n\n")
                        encoded = json.dumps(item, ensure_ascii=True, indent=2)
                        handle.write(textwrap.indent(encoded, "    "))
                    if value:
                        handle.write("\n")
                    handle.write("  ]")
                else:
                    encoded = json.dumps(value, ensure_ascii=True, indent=2)
                    handle.write(textwrap.indent(encoded, "  "))
            handle.write("\n}\n")
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temporary_path, destination)
        else:
            os.rename(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def _resolve_output_destination(output_path: str | os.PathLike[str]) -> Path:
    raw_path = os.fspath(output_path)
    requested = Path(os.path.abspath(Path(raw_path).expanduser()))
    if requested.is_dir():
        filename = datetime.now().strftime("DNS Cache_dns_cache_%Y%m%d_%H%M%S.json")
        return requested / filename
    if raw_path.endswith((os.sep, os.altsep) if os.altsep else (os.sep,)):
        raise FileNotFoundError(f"Output directory does not exist: {requested}")
    return requested


def collect_dns_cache(
    output_path: str | os.PathLike[str],
    overwrite: bool = False,
) -> dict[str, Any]:
    """Collect all records and exposed properties from Get-DnsClientCache."""
    started_at = utc_now()
    destination = _resolve_output_destination(output_path)
    if not overwrite and os.path.lexists(destination):
        raise FileExistsError(f"Refusing to overwrite existing output: {destination}")
    if not destination.parent.is_dir():
        raise FileNotFoundError(f"Output directory does not exist: {destination.parent}")

    payload, provider_errors = _run_provider()
    document = _build_document(started_at, payload, provider_errors)
    _write_json(destination, document, overwrite)
    return document


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect a read-only snapshot of the Windows DNS client cache."
    )
    parser.add_argument(
        "--output",
        required=True,
        help=(
            "Destination path for the UTF-8 JSON output; an existing directory "
            "receives a timestamped JSON file"
        ),
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly allow replacing an existing output file",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        destination = _resolve_output_destination(args.output)
        document = collect_dns_cache(destination, overwrite=args.overwrite)
    except (OSError, ValueError) as exc:
        print(
            json.dumps({"collection_status": "failed", "error": str(exc)}),
            file=sys.stderr,
        )
        return 2

    print(
        json.dumps(
            {
                "collection_status": document["collection_status"],
                "record_count": document["record_count"],
                "properties_returned": len(
                    document["provider"]["properties_returned_union"]
                ),
                "error_count": len(document["errors"]),
                "output": str(destination),
            },
            ensure_ascii=True,
        )
    )
    if document["collection_status"] == "failed":
        return 2
    return 1 if document["collection_status"] == "partial" else 0


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
        "A60": "--output-dir", "A67": "--output-dir",
        "A69": "--output-dir", "X14": "--output-dir",
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
            "A52", "A60", "A67", "A69",
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
