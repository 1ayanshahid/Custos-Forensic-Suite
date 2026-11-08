"""Collect a read-only snapshot of Windows TCP and UDP endpoints."""

from __future__ import annotations

import argparse
import ctypes
import ipaddress
import json
import os
import socket
import sys
import tempfile
import textwrap
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import psutil
except ImportError as exc:
    raise SystemExit(
        "A03 requires psutil. Install it in the project environment with: "
        '"E:\\FYP Custos Forensic Suite\\.venv\\Scripts\\python.exe" -m pip install psutil'
    ) from exc

ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_DATA = 232
ERROR_ACCESS_DENIED = 5
ERROR_NOT_FOUND = 1168
ERROR_RETRY = 1237
TCP_TABLE_OWNER_MODULE_ALL = 8
UDP_TABLE_OWNER_MODULE = 2
TCPIP_OWNER_MODULE_INFO_BASIC = 0
MAX_IP_HELPER_BUFFER = 64 * 1024 * 1024
MAX_BUFFER_ATTEMPTS = 4

TCP_STATES = {
    1: "CLOSED",
    2: "LISTEN",
    3: "SYN_SENT",
    4: "SYN_RECEIVED",
    5: "ESTABLISHED",
    6: "FIN_WAIT_1",
    7: "FIN_WAIT_2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB",
}
PSUTIL_TCP_STATES = {
    "CLOSE": "CLOSED",
    "SYN_RECV": "SYN_RECEIVED",
    "FIN_WAIT1": "FIN_WAIT_1",
    "FIN_WAIT2": "FIN_WAIT_2",
}


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


def _collection_time_metadata(started_at_utc: str, ended_at_utc: str) -> dict[str, Any]:
    started = datetime.fromisoformat(started_at_utc.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )
    observed_end = datetime.fromisoformat(ended_at_utc.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )
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


def _format_win_error(code: int) -> str:
    try:
        return ctypes.FormatError(code).strip()
    except (AttributeError, OSError, ValueError):
        return f"Windows error {code}"


def _address_object(
    address: str,
    port: int,
    scope_id: int | None,
    family: str,
) -> dict[str, Any]:
    return {
        "ip": address,
        "port": port,
        "scope_id": scope_id if family == "IPv6" else None,
    }


def _decode_api_ipv4(value: int) -> str:
    return socket.inet_ntop(
        socket.AF_INET, int(value).to_bytes(4, byteorder="little")
    )


def _decode_api_port(value: int) -> int:
    return socket.ntohs(int(value) & 0xFFFF)


def _decode_api_scope(value: int) -> int:
    return socket.ntohl(int(value))


def _decode_api_pid(value: int, protocol: str) -> int | None:
    pid = int(value)
    if protocol == "UDP" and pid == 0:
        return None
    return pid


def _filetime_to_utc(value: int) -> str:
    if value < 0:
        raise ValueError(f"Windows returned a negative FILETIME value: {value}.")
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return (epoch + timedelta(microseconds=value // 10)).isoformat()


def _resolve_owner_module(
    iphlpapi: Any,
    protocol: str,
    family: str,
    row: ctypes.Structure,
) -> tuple[dict[str, Any] | None, str | None]:
    suffix = ("Tcp" if protocol == "TCP" else "Udp") + (
        "Entry" if family == "IPv4" else "6Entry"
    )
    function_name = f"GetOwnerModuleFrom{suffix}"
    try:
        function = getattr(iphlpapi, function_name)
    except AttributeError as exc:
        return None, f"unsupported: {function_name} is unavailable: {exc}"

    function.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    function.restype = ctypes.c_ulong
    size = ctypes.c_ulong(0)
    result = int(
        function(
            ctypes.byref(row),
            TCPIP_OWNER_MODULE_INFO_BASIC,
            None,
            ctypes.byref(size),
        )
    )
    if result not in (0, ERROR_INSUFFICIENT_BUFFER):
        if result == ERROR_ACCESS_DENIED:
            return None, (
                "access_denied: Windows denied owner-module resolution "
                f"({function_name}: {_format_win_error(result)})."
            )
        if result in (ERROR_NOT_FOUND, ERROR_RETRY):
            return None, (
                "unavailable: endpoint changed during lookup or Windows could not "
                f"resolve owner-module information ({function_name}: "
                f"{_format_win_error(result)})."
            )
        return None, f"provider_failure: {function_name}: {_format_win_error(result)}"
    if size.value <= 0 or size.value > MAX_IP_HELPER_BUFFER:
        return None, f"provider_failure: {function_name} returned invalid size {size.value}."

    for _ in range(MAX_BUFFER_ATTEMPTS):
        buffer = ctypes.create_string_buffer(size.value)
        result = int(
            function(
                ctypes.byref(row),
                TCPIP_OWNER_MODULE_INFO_BASIC,
                buffer,
                ctypes.byref(size),
            )
        )
        if result == 0:
            break
        if result != ERROR_INSUFFICIENT_BUFFER:
            if result == ERROR_ACCESS_DENIED:
                return None, (
                    "access_denied: Windows denied owner-module resolution "
                    f"({function_name}: {_format_win_error(result)})."
                )
            if result in (ERROR_NOT_FOUND, ERROR_RETRY):
                return None, (
                    "unavailable: endpoint changed during lookup or Windows could "
                    f"not resolve owner-module information ({function_name}: "
                    f"{_format_win_error(result)})."
                )
            return None, (
                f"provider_failure: {function_name}: {_format_win_error(result)}"
            )
        if size.value <= 0 or size.value > MAX_IP_HELPER_BUFFER:
            return None, f"provider_failure: {function_name} returned invalid size {size.value}."
    else:
        return None, f"provider_failure: {function_name} buffer size kept changing."

    class BasicInfo(ctypes.Structure):
        _fields_ = [
            ("module_name", ctypes.c_void_p),
            ("module_path", ctypes.c_void_p),
        ]

    def read_buffer_string(pointer: int | None) -> str | None:
        if not pointer:
            return None
        base_address = ctypes.addressof(buffer)
        string_address = int(pointer)
        end_address = base_address + size.value
        if not (
            base_address + ctypes.sizeof(BasicInfo)
            <= string_address
            < end_address
        ):
            raise ValueError("owner-module string pointer lies outside its API buffer")
        character_count = (end_address - string_address) // ctypes.sizeof(
            ctypes.c_wchar
        )
        characters: list[str] = []
        for index in range(character_count):
            character = ctypes.c_wchar.from_address(
                string_address + index * ctypes.sizeof(ctypes.c_wchar)
            ).value
            if character == "\0":
                return "".join(characters)
            characters.append(character)
        raise ValueError("owner-module string is not terminated inside its API buffer")

    try:
        info = ctypes.cast(buffer, ctypes.POINTER(BasicInfo)).contents
        module_name = read_buffer_string(info.module_name)
        module_path = read_buffer_string(info.module_path)
    except (ValueError, OSError) as exc:
        return None, f"provider_failure: {function_name} returned invalid strings: {exc}"
    if module_name is None and module_path is None:
        return None, f"unavailable: {function_name} returned no module strings."
    return {
        "module_name": module_name,
        "module_path": module_path,
        "information_class": "TCPIP_OWNER_MODULE_INFO_BASIC",
    }, None


def _psutil_address(value: Any, family: str) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        host = str(value[0])
        port = int(value[1])
        scope_id: int | None = None
        if family == "IPv6":
            if len(value) > 3:
                scope_id = int(value[3])
            if "%" in host:
                host, scope_text = host.rsplit("%", 1)
                if scope_id is None:
                    try:
                        scope_id = int(scope_text)
                    except ValueError:
                        scope_id = socket.if_nametoindex(scope_text)
        parsed = ipaddress.ip_address(host)
        return _address_object(str(parsed), port, scope_id, family)
    except (IndexError, TypeError, ValueError, OSError) as exc:
        raise ValueError(f"Unexpected psutil socket address {value!r}: {exc}") from exc


def _psutil_endpoint(connection: Any) -> dict[str, Any]:
    family_value = int(connection.family)
    if family_value == socket.AF_INET:
        family = "IPv4"
    elif family_value == socket.AF_INET6:
        family = "IPv6"
    else:
        raise ValueError(f"Unsupported address family returned: {family_value}")

    socket_type = int(connection.type)
    if socket_type == socket.SOCK_STREAM:
        protocol = "TCP"
    elif socket_type == socket.SOCK_DGRAM:
        protocol = "UDP"
    else:
        raise ValueError(f"Unsupported internet socket type returned: {socket_type}")

    local = _psutil_address(connection.laddr, family)
    if local is None:
        raise ValueError("psutil returned an endpoint without a local address.")
    remote = _psutil_address(connection.raddr, family)
    if protocol == "UDP":
        remote = None

    pid_value = connection.pid
    pid = int(pid_value) if pid_value is not None and int(pid_value) >= 0 else None
    status = (
        PSUTIL_TCP_STATES.get(str(connection.status), str(connection.status))
        if protocol == "TCP"
        else None
    )
    return _new_endpoint(
        family=family,
        protocol=protocol,
        local_address=local,
        remote_address=remote,
        tcp_state=status,
        owning_pid=pid,
        source="psutil.net_connections",
        fd=int(connection.fd) if connection.fd is not None else None,
    )


def enumerate_psutil_endpoints() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Enumerate psutil's system-wide IPv4/IPv6 internet socket records."""
    provider = {
        "provider": "psutil.net_connections(kind='inet')",
        "status": "failed",
        "endpoint_count": 0,
        "errors": [],
    }
    endpoints: list[dict[str, Any]] = []
    try:
        raw_records = psutil.net_connections(kind="inet")
    except psutil.AccessDenied as exc:
        provider["errors"].append(
            {"error_type": "AccessDenied", "message": str(exc) or "Access denied."}
        )
        return endpoints, provider
    except psutil.Error as exc:
        provider["errors"].append(
            {"error_type": type(exc).__name__, "message": str(exc)}
        )
        return endpoints, provider
    except OSError as exc:
        provider["errors"].append(
            {"error_type": type(exc).__name__, "message": str(exc)}
        )
        return endpoints, provider

    try:
        for index, connection in enumerate(raw_records):
            try:
                endpoints.append(_psutil_endpoint(connection))
            except (AttributeError, TypeError, ValueError, OverflowError) as exc:
                provider["errors"].append(
                    {
                        "error_type": "MalformedProviderRecord",
                        "record_index": index,
                        "message": str(exc),
                    }
                )
    except TypeError as exc:
        provider["errors"].append(
            {
                "error_type": "MalformedProviderOutput",
                "message": f"psutil did not return an iterable of endpoints: {exc}",
            }
        )
    provider["endpoint_count"] = len(endpoints)
    provider["status"] = "partial" if provider["errors"] else "success"
    return endpoints, provider


def _new_endpoint(
    family: str,
    protocol: str,
    local_address: dict[str, Any],
    remote_address: dict[str, Any] | None,
    tcp_state: str | None,
    owning_pid: int | None,
    source: str,
    fd: int | None = None,
) -> dict[str, Any]:
    observed_at = utc_now()
    state_status = "supported" if protocol == "TCP" else "not_applicable"
    remote_status = "supported" if protocol == "TCP" else "not_applicable"
    scope_status = "supported" if family == "IPv6" else "not_applicable"
    pid_status = "supported" if owning_pid is not None else "unavailable"
    pid_errors: dict[str, str] = {}
    if owning_pid is None and source == "psutil.net_connections":
        pid_status = "access_denied"
        pid_errors["owning_pid"] = (
            "psutil reports PID as unavailable when the current privileges cannot identify socket ownership."
        )
    return {
        "address_family": family,
        "transport_protocol": protocol,
        "local_address": local_address,
        "remote_address": remote_address,
        "tcp_state": tcp_state if protocol == "TCP" else None,
        "owning_pid": owning_pid,
        "owning_process_name": None,
        "executable_path": None,
        "command_line": None,
        "username": None,
        "parent_pid": None,
        "process_creation_time_utc": None,
        "process_creation_time_unix_seconds": None,
        "endpoint_creation_time_utc": None,
        "endpoint_creation_time_filetime_100ns": None,
        "owning_module_info": None,
        "first_observed_at_utc": observed_at,
        "last_observed_at_utc": observed_at,
        "application_protocol_hint": None,
        "socket_descriptor": fd if fd is not None and fd >= 0 else None,
        "source_providers": [source],
        "provider_values": {
            source: {
                "owning_pid": owning_pid,
                "tcp_state": tcp_state if protocol == "TCP" else None,
                "local_address": local_address,
                "remote_address": remote_address,
                "endpoint_creation_time_utc": None,
                "endpoint_creation_time_filetime_100ns": None,
                "owning_module_info": None,
                "first_observed_at_utc": observed_at,
                "last_observed_at_utc": observed_at,
            }
        },
        "provider_disagreements": {},
        "field_unavailability": {},
        "field_status": {
            "address_family": "supported",
            "transport_protocol": "supported",
            "local_address": "supported",
            "remote_address": remote_status,
            "local_scope_id": scope_status,
            "remote_scope_id": scope_status if protocol == "TCP" else "not_applicable",
            "tcp_state": state_status,
            "owning_pid": pid_status,
            "owning_process_name": "pending",
            "executable_path": "pending",
            "command_line": "pending",
            "username": "pending",
            "parent_pid": "pending",
            "process_creation_time_utc": "pending",
            "endpoint_creation_time_utc": "unsupported",
            "endpoint_creation_time_filetime_100ns": "unsupported",
            "owning_module_info": "unsupported",
            "first_observed_at_utc": "supported",
            "last_observed_at_utc": "supported",
            "application_protocol_hint": "pending",
            "socket_descriptor": (
                "supported"
                if fd is not None and fd >= 0
                else "unsupported"
            ),
        },
        "field_errors": pid_errors,
        "collection_status": "pending",
        "_identity_pid": owning_pid,
    }


def _ip_helper_rows(api_name: str, family: str, protocol: str) -> tuple[list[dict[str, Any]], int]:
    """Read one documented owner-module IP Helper table, bounded to 4 negotiations."""
    if os.name != "nt":
        raise OSError("IP Helper tables are supported only on Windows.")

    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    if protocol == "TCP":
        function = iphlpapi.GetExtendedTcpTable
        table_class = TCP_TABLE_OWNER_MODULE_ALL
    else:
        function = iphlpapi.GetExtendedUdpTable
        table_class = UDP_TABLE_OWNER_MODULE
    function.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    function.restype = ctypes.c_ulong

    address_family = socket.AF_INET if family == "IPv4" else socket.AF_INET6
    size = ctypes.c_ulong(0)
    result = int(
        function(None, ctypes.byref(size), 0, address_family, table_class, 0)
    )
    if result not in (0, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_DATA):
        raise OSError(result, _format_win_error(result))
    if result == ERROR_NO_DATA or size.value == 0:
        return [], result

    buffer: ctypes.Array[ctypes.c_char] | None = None
    for _ in range(MAX_BUFFER_ATTEMPTS):
        if size.value <= 0 or size.value > MAX_IP_HELPER_BUFFER:
            raise ValueError(
                f"{api_name} requested an unreasonable buffer size: {size.value}."
            )
        buffer = ctypes.create_string_buffer(size.value)
        result = int(
            function(
                buffer,
                ctypes.byref(size),
                0,
                address_family,
                table_class,
                0,
            )
        )
        if result == 0:
            break
        if result == ERROR_NO_DATA:
            return [], result
        if result != ERROR_INSUFFICIENT_BUFFER:
            raise OSError(result, _format_win_error(result))
    else:
        raise OSError(
            ERROR_INSUFFICIENT_BUFFER,
            f"{api_name} buffer size kept changing after {MAX_BUFFER_ATTEMPTS} attempts.",
        )

    if buffer is None:
        raise OSError(f"{api_name} returned success without a result buffer.")
    raw = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_uint32))
    row_count = int(raw[0])

    if protocol == "TCP" and family == "IPv4":
        class Row(ctypes.Structure):
            _fields_ = [
                ("state", ctypes.c_uint32),
                ("local_address", ctypes.c_uint32),
                ("local_port", ctypes.c_uint32),
                ("remote_address", ctypes.c_uint32),
                ("remote_port", ctypes.c_uint32),
                ("pid", ctypes.c_uint32),
                ("creation_filetime", ctypes.c_uint64),
                ("owning_module_info", ctypes.c_uint64 * 16),
            ]
    elif protocol == "TCP":
        class Row(ctypes.Structure):
            _fields_ = [
                ("local_address", ctypes.c_ubyte * 16),
                ("local_scope", ctypes.c_uint32),
                ("local_port", ctypes.c_uint32),
                ("remote_address", ctypes.c_ubyte * 16),
                ("remote_scope", ctypes.c_uint32),
                ("remote_port", ctypes.c_uint32),
                ("state", ctypes.c_uint32),
                ("pid", ctypes.c_uint32),
                ("creation_filetime", ctypes.c_uint64),
                ("owning_module_info", ctypes.c_uint64 * 16),
            ]
    elif family == "IPv4":
        class Row(ctypes.Structure):
            _fields_ = [
                ("local_address", ctypes.c_uint32),
                ("local_port", ctypes.c_uint32),
                ("pid", ctypes.c_uint32),
                ("creation_filetime", ctypes.c_uint64),
                ("flags", ctypes.c_uint32),
                ("owning_module_info", ctypes.c_uint64 * 16),
            ]
    else:
        class Row(ctypes.Structure):
            _fields_ = [
                ("local_address", ctypes.c_ubyte * 16),
                ("local_scope", ctypes.c_uint32),
                ("local_port", ctypes.c_uint32),
                ("pid", ctypes.c_uint32),
                ("creation_filetime", ctypes.c_uint64),
                ("flags", ctypes.c_uint32),
                ("owning_module_info", ctypes.c_uint64 * 16),
            ]

    row_size = ctypes.sizeof(Row)
    row_alignment = ctypes.alignment(Row)
    rows_offset = (
        ctypes.sizeof(ctypes.c_uint32) + row_alignment - 1
    ) // row_alignment * row_alignment
    expected_size = rows_offset + row_count * row_size
    if row_count > (MAX_IP_HELPER_BUFFER // max(row_size, 1)):
        raise ValueError(f"{api_name} returned an unreasonable row count: {row_count}.")
    if expected_size > len(buffer):
        raise ValueError(
            f"{api_name} reported {row_count} rows but its buffer is too small."
        )

    rows: list[dict[str, Any]] = []
    row_pointer = ctypes.cast(
        ctypes.addressof(buffer) + rows_offset,
        ctypes.POINTER(Row),
    )
    for index in range(row_count):
        row = row_pointer[index]
        if family == "IPv4":
            local_ip = _decode_api_ipv4(row.local_address)
            local_scope = None
        else:
            local_ip = socket.inet_ntop(
                socket.AF_INET6, bytes(row.local_address)
            )
            local_scope = _decode_api_scope(row.local_scope)
        local_port = _decode_api_port(row.local_port)
        local = _address_object(local_ip, local_port, local_scope, family)

        remote: dict[str, Any] | None = None
        state: str | None = None
        if protocol == "TCP":
            if family == "IPv4":
                remote_ip = _decode_api_ipv4(row.remote_address)
                remote_scope = None
            else:
                remote_ip = socket.inet_ntop(
                    socket.AF_INET6, bytes(row.remote_address)
                )
                remote_scope = _decode_api_scope(row.remote_scope)
            remote = _address_object(
                remote_ip,
                _decode_api_port(row.remote_port),
                remote_scope,
                family,
            )
            state_value = int(row.state)
            state = TCP_STATES.get(state_value, f"UNKNOWN_{state_value}")

        endpoint = _new_endpoint(
            family=family,
            protocol=protocol,
            local_address=local,
            remote_address=remote,
            tcp_state=state,
            owning_pid=_decode_api_pid(row.pid, protocol),
            source=api_name,
        )
        filetime = int(row.creation_filetime)
        try:
            endpoint["endpoint_creation_time_utc"] = _filetime_to_utc(filetime)
            endpoint["endpoint_creation_time_filetime_100ns"] = filetime
            endpoint["field_status"]["endpoint_creation_time_utc"] = "supported"
            endpoint["field_status"]["endpoint_creation_time_filetime_100ns"] = (
                "supported"
            )
        except (OverflowError, ValueError) as exc:
            endpoint["field_errors"]["endpoint_creation_time_utc"] = (
                f"provider_failure: invalid Windows FILETIME: {exc}"
            )
            endpoint["field_status"]["endpoint_creation_time_utc"] = (
                "provider_failure"
            )
            endpoint["field_errors"]["endpoint_creation_time_filetime_100ns"] = (
                f"provider_failure: invalid Windows FILETIME: {exc}"
            )
            endpoint["field_status"]["endpoint_creation_time_filetime_100ns"] = (
                "provider_failure"
            )

        module_info, module_error = _resolve_owner_module(
            iphlpapi, protocol, family, row
        )
        endpoint["owning_module_info"] = module_info
        if module_error is None:
            endpoint["field_status"]["owning_module_info"] = "supported"
        elif module_error.startswith(("unavailable:", "access_denied:")):
            endpoint["field_status"]["owning_module_info"] = (
                "access_denied"
                if module_error.startswith("access_denied:")
                else "unavailable"
            )
            endpoint["field_unavailability"]["owning_module_info"] = module_error
        else:
            endpoint["field_status"]["owning_module_info"] = module_error.split(
                ":", 1
            )[0]
            endpoint["field_errors"]["owning_module_info"] = module_error
        source_values = endpoint["provider_values"][api_name]
        source_values["endpoint_creation_time_utc"] = endpoint[
            "endpoint_creation_time_utc"
        ]
        source_values["endpoint_creation_time_filetime_100ns"] = (
            endpoint["endpoint_creation_time_filetime_100ns"]
        )
        source_values["owning_module_info"] = module_info
        source_values["first_observed_at_utc"] = endpoint[
            "first_observed_at_utc"
        ]
        source_values["last_observed_at_utc"] = endpoint[
            "last_observed_at_utc"
        ]
        rows.append({"endpoint": endpoint, "row_index": index})
        if protocol == "UDP" and int(row.pid) == 0:
            rows[-1]["endpoint"]["field_status"]["owning_pid"] = "unavailable"
            rows[-1]["endpoint"]["field_unavailability"]["owning_pid"] = (
                "unavailable: Windows IP Helper documents PID 0 as owner information unavailable for UDP rows."
            )
    return rows, result


def enumerate_ip_helper_endpoints() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Enumerate documented IPv4/IPv6 TCP and UDP owner-module tables."""
    endpoints: list[dict[str, Any]] = []
    providers: list[dict[str, Any]] = []
    for protocol in ("TCP", "UDP"):
        for family in ("IPv4", "IPv6"):
            api_name = f"GetExtended{protocol}Table({family}, owner-module)"
            provider = {
                "provider": api_name,
                "status": "failed",
                "endpoint_count": 0,
                "errors": [],
                "additional_fields": [
                    "owning_pid",
                    *(("tcp_state",) if protocol == "TCP" else ()),
                    "endpoint_creation_time_utc",
                    "endpoint_creation_time_filetime_100ns",
                    "owning_module_info",
                ],
            }
            try:
                rows, return_code = _ip_helper_rows(api_name, family, protocol)
                for wrapped in rows:
                    endpoints.append(wrapped["endpoint"])
                provider["endpoint_count"] = len(rows)
                provider["endpoint_creation_timestamp_count"] = sum(
                    row["endpoint"]["endpoint_creation_time_utc"] is not None
                    for row in rows
                )
                provider["owner_module_info_count"] = sum(
                    row["endpoint"]["owning_module_info"] is not None
                    for row in rows
                )
                provider["record_field_unavailability"] = [
                    {
                        "row_index": row["row_index"],
                        "fields": row["endpoint"]["field_unavailability"],
                    }
                    for row in rows
                    if row["endpoint"]["field_unavailability"]
                ]
                provider["record_field_errors"] = [
                    {
                        "row_index": row["row_index"],
                        "fields": row["endpoint"]["field_errors"],
                    }
                    for row in rows
                    if row["endpoint"]["field_errors"]
                ]
                provider["status"] = (
                    "partial"
                    if any(
                        row["endpoint"]["field_errors"]
                        or row["endpoint"]["field_unavailability"]
                        for row in rows
                    )
                    else "success"
                )
                provider["return_code"] = return_code
                if return_code == ERROR_NO_DATA:
                    provider["empty_reason"] = "Windows reported no table data."
            except (OSError, ValueError, AttributeError, ctypes.ArgumentError) as exc:
                error_code = getattr(exc, "winerror", None)
                provider["errors"].append(
                    {
                        "error_type": type(exc).__name__,
                        "windows_error_code": error_code,
                        "message": str(exc),
                    }
                )
            providers.append(provider)
    return endpoints, providers


def _endpoint_key(endpoint: dict[str, Any]) -> tuple[Any, ...]:
    local = endpoint["local_address"]
    remote = endpoint["remote_address"]

    def address_key(value: dict[str, Any] | None) -> tuple[Any, ...] | None:
        if value is None:
            return None
        return (value.get("ip"), value.get("port"), value.get("scope_id"))

    return (
        endpoint["address_family"],
        endpoint["transport_protocol"],
        address_key(local),
        address_key(remote),
    )


def reconcile_endpoints(
    provider_endpoints: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Merge duplicate provider views by endpoint tuple, retaining disagreements."""
    reconciled: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    errors: list[dict[str, Any]] = []
    for incoming in provider_endpoints:
        try:
            key = _endpoint_key(incoming)
            candidates = reconciled[key]
            incoming_pid = incoming.get("owning_pid")
            chosen: dict[str, Any] | None = None
            if incoming["transport_protocol"] == "TCP":
                chosen = candidates[0] if candidates else None
            elif candidates:
                exact = [
                    candidate
                    for candidate in candidates
                    if incoming_pid is not None
                    and candidate.get("_identity_pid") == incoming_pid
                ]
                if exact:
                    chosen = exact[0]
                else:
                    compatible = [
                        candidate
                        for candidate in candidates
                        if candidate.get("_identity_pid") is None
                        or incoming_pid is None
                    ]
                    if len(compatible) == 1:
                        chosen = compatible[0]
                    elif incoming_pid is None and compatible:
                        source = incoming["source_providers"][0]
                        for candidate in compatible:
                            if source not in candidate["source_providers"]:
                                candidate["source_providers"].append(source)
                            values = incoming.get("provider_values", {}).get(source, {})
                            candidate["provider_values"][source] = values
                            candidate["provider_disagreements"].setdefault(
                                "owning_pid",
                                [
                                    {
                                        "provider": prior_source,
                                        "value": prior_values.get("owning_pid"),
                                    }
                                    for prior_source, prior_values
                                    in candidate["provider_values"].items()
                                    if prior_values.get("owning_pid") is not None
                                ],
                            )
                            unknown_entry = {"provider": source, "value": None}
                            if unknown_entry not in candidate[
                                "provider_disagreements"
                            ]["owning_pid"]:
                                candidate["provider_disagreements"][
                                    "owning_pid"
                                ].append(unknown_entry)
                        errors.append(
                            {
                                "provider": source,
                                "error_type": "AmbiguousUDPReconciliation",
                                "message": (
                                    "A UDP endpoint without an owner PID matched "
                                    f"{len(compatible)} distinct owner records."
                                ),
                                "local_address": incoming["local_address"],
                            }
                        )
                        continue
                    elif not candidates:
                        chosen = None

            if chosen is None:
                candidates.append(incoming)
                continue

            source = incoming["source_providers"][0]
            if source not in chosen["source_providers"]:
                chosen["source_providers"].append(source)
            incoming_values = incoming.get("provider_values", {}).get(source, {})
            chosen["provider_values"][source] = incoming_values

            for field in (
                "owning_pid",
                "tcp_state",
                "local_address",
                "remote_address",
                "endpoint_creation_time_utc",
                "endpoint_creation_time_filetime_100ns",
                "owning_module_info",
            ):
                old_value = chosen.get(field)
                new_value = incoming.get(field)
                if new_value is None or old_value == new_value:
                    continue
                if old_value is None:
                    chosen[field] = new_value
                    if field == "owning_pid":
                        chosen["field_status"]["owning_pid"] = "supported"
                        chosen["field_errors"].pop("owning_pid", None)
                    elif field in (
                        "endpoint_creation_time_utc",
                        "endpoint_creation_time_filetime_100ns",
                        "owning_module_info",
                    ):
                        chosen["field_status"][field] = "supported"
                        chosen["field_errors"].pop(field, None)
                    chosen["_identity_pid"] = (
                        new_value if field == "owning_pid" else chosen["_identity_pid"]
                    )
                    continue
                disagreement_values = chosen["provider_disagreements"].setdefault(
                    field, []
                )
                for prior_source, values in chosen["provider_values"].items():
                    prior_value = values.get(field)
                    if prior_value is not None:
                        entry = {"provider": prior_source, "value": prior_value}
                        if entry not in disagreement_values:
                            disagreement_values.append(entry)
                new_entry = {"provider": source, "value": new_value}
                if new_entry not in disagreement_values:
                    disagreement_values.append(new_entry)
                if field == "owning_pid" and source.startswith("GetExtended"):
                    chosen[field] = new_value
            if chosen.get("owning_pid") is None and incoming_pid is not None:
                chosen["owning_pid"] = incoming_pid
                chosen["field_status"]["owning_pid"] = "supported"
                chosen["field_errors"].pop("owning_pid", None)
                chosen["_identity_pid"] = incoming_pid
            observed_values = [
                value
                for value in (
                    chosen.get("first_observed_at_utc"),
                    incoming.get("first_observed_at_utc"),
                )
                if value is not None
            ]
            if observed_values:
                chosen["first_observed_at_utc"] = min(observed_values)
            observed_values = [
                value
                for value in (
                    chosen.get("last_observed_at_utc"),
                    incoming.get("last_observed_at_utc"),
                )
                if value is not None
            ]
            if observed_values:
                chosen["last_observed_at_utc"] = max(observed_values)
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(
                {
                    "provider": incoming.get("source_providers", ["unknown"])[0],
                    "error_type": "MalformedEndpoint",
                    "message": str(exc),
                }
            )

    result: list[dict[str, Any]] = []
    for candidate_list in reconciled.values():
        result.extend(candidate_list)
    return result, errors


def _process_metadata(pid: int) -> tuple[dict[str, Any], dict[str, str]]:
    metadata: dict[str, Any] = {
        "owning_process_name": None,
        "executable_path": None,
        "command_line": None,
        "username": None,
        "parent_pid": None,
        "process_creation_time_utc": None,
    }
    errors: dict[str, str] = {}
    try:
        process = psutil.Process(pid)
        before = process.create_time()
        for field, getter in (
            ("owning_process_name", process.name),
            ("executable_path", process.exe),
            ("command_line", process.cmdline),
            ("username", process.username),
            ("parent_pid", process.ppid),
        ):
            try:
                value = getter()
                metadata[field] = value
                if value is None:
                    errors[field] = (
                        "unavailable: the process provider returned no value."
                    )
            except psutil.AccessDenied as exc:
                errors[field] = f"access_denied: {str(exc) or 'Windows denied access.'}"
            except psutil.NoSuchProcess as exc:
                errors[field] = f"process_exited: {str(exc) or 'Process exited during lookup.'}"
            except psutil.Error as exc:
                errors[field] = f"provider_failure: {type(exc).__name__}: {exc}"
        after = process.create_time()
        if before != after:
            for field in (
                "owning_process_name",
                "executable_path",
                "command_line",
                "username",
                "parent_pid",
                "process_creation_time_unix_seconds",
            ):
                metadata[field] = None
                errors[field] = "pid_reused: process creation time changed during lookup."
            errors["process_creation_time_utc"] = (
                "pid_reused: process creation time changed during lookup."
            )
        else:
            metadata["process_creation_time_unix_seconds"] = before
            metadata["process_creation_time_utc"] = datetime.fromtimestamp(
                before, timezone.utc
            ).isoformat()
    except psutil.AccessDenied as exc:
        metadata = {field: None for field in metadata}
        for field in metadata:
            errors[field] = f"access_denied: {str(exc) or 'Windows denied access.'}"
    except psutil.NoSuchProcess as exc:
        metadata = {field: None for field in metadata}
        for field in metadata:
            errors[field] = f"process_exited: {str(exc) or 'Process exited during lookup.'}"
    except psutil.Error as exc:
        metadata = {field: None for field in metadata}
        for field in metadata:
            errors[field] = f"provider_failure: {type(exc).__name__}: {exc}"
    return metadata, errors


def enrich_process_details(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add best-effort process metadata while retaining endpoints with no owner."""
    cache: dict[int, tuple[dict[str, Any], dict[str, str]]] = {}
    for endpoint in endpoints:
        pid = endpoint.get("owning_pid")
        if pid is None:
            for field in (
                "owning_process_name",
                "executable_path",
                "command_line",
                "username",
                "parent_pid",
                "process_creation_time_utc",
                "process_creation_time_unix_seconds",
            ):
                endpoint["field_status"][field] = "unavailable"
            endpoint["field_errors"].setdefault(
                "owning_pid",
                "No provider supplied an owning PID for this endpoint.",
            )
            endpoint["collection_status"] = "partial"
            continue

        if pid not in cache:
            cache[pid] = _process_metadata(pid)
        metadata, errors = cache[pid]
        errors = dict(errors)
        endpoint.update(metadata)
        system_idle_executable = (
            pid == 0
            and metadata.get("owning_process_name") == "System Idle Process"
            and errors.get("executable_path", "").startswith("access_denied:")
        )
        if system_idle_executable:
            errors.pop("executable_path", None)
        unavailable_fields = {
            field: message
            for field, message in errors.items()
            if message.startswith(
                ("access_denied:", "process_exited:", "pid_reused:", "unavailable:")
            )
        }
        for field in unavailable_fields:
            errors.pop(field)
        endpoint["field_errors"].update(errors)
        endpoint["field_unavailability"].update(unavailable_fields)
        if system_idle_executable:
            endpoint["field_unavailability"]["executable_path"] = (
                "not_applicable: Windows does not expose a normal executable path "
                "for the System Idle Process."
            )
        for field in metadata:
            endpoint["field_status"][field] = (
                "supported" if metadata[field] is not None else "unavailable"
            )
        for field, message in endpoint["field_unavailability"].items():
            if field in metadata:
                endpoint["field_status"][field] = message.split(":", 1)[0]
        if "executable_path" in endpoint["field_unavailability"]:
            endpoint["field_status"]["executable_path"] = "not_applicable"
        endpoint["collection_status"] = (
            "partial" if errors else "success"
        )
    return endpoints


PORT_PROTOCOL_HINTS: dict[tuple[str, int], tuple[str, ...]] = {
    ("TCP", 20): ("FTP-data",),
    ("TCP", 21): ("FTP-control",),
    ("TCP", 22): ("SSH",),
    ("TCP", 25): ("SMTP",),
    ("TCP", 53): ("DNS",),
    ("TCP", 80): ("HTTP",),
    ("TCP", 110): ("POP3",),
    ("TCP", 143): ("IMAP",),
    ("TCP", 389): ("LDAP",),
    ("TCP", 443): ("HTTPS",),
    ("TCP", 445): ("SMB",),
    ("TCP", 465): ("SMTP over TLS",),
    ("TCP", 587): ("SMTP submission",),
    ("TCP", 636): ("LDAPS",),
    ("TCP", 993): ("IMAPS",),
    ("TCP", 995): ("POP3 over TLS",),
    ("TCP", 3389): ("RDP",),
    ("UDP", 53): ("DNS",),
    ("UDP", 67): ("DHCP server",),
    ("UDP", 68): ("DHCP client",),
    ("UDP", 123): ("NTP",),
    ("UDP", 161): ("SNMP",),
    ("UDP", 162): ("SNMP trap",),
    ("UDP", 443): ("QUIC / HTTP/3 candidate",),
    ("UDP", 514): ("Syslog",),
    ("UDP", 5353): ("mDNS",),
}


def _application_protocol_hint(endpoint: dict[str, Any]) -> dict[str, Any]:
    protocol = endpoint["transport_protocol"]
    matches: list[dict[str, Any]] = []
    for side in ("local", "remote"):
        address = endpoint.get(f"{side}_address")
        if address is None:
            continue
        port = address.get("port")
        if port is None:
            continue
        candidates = PORT_PROTOCOL_HINTS.get((protocol, int(port)), ())
        for candidate in candidates:
            matches.append(
                {
                    "candidate": candidate,
                    "matched_side": side,
                    "matched_port": int(port),
                }
            )
    return {
        "status": "unconfirmed" if matches else "no_hint",
        "candidates": matches,
        "basis": "Transport and well-known port mapping only; no traffic or payload was inspected.",
    }


def _finalize_endpoint(endpoint: dict[str, Any]) -> None:
    protocol = endpoint["transport_protocol"]
    family = endpoint["address_family"]
    if protocol == "UDP":
        endpoint["remote_address"] = None
        endpoint["tcp_state"] = None
        endpoint["field_status"]["remote_address"] = "not_applicable"
        endpoint["field_status"]["tcp_state"] = "not_applicable"
        endpoint["field_status"]["remote_scope_id"] = "not_applicable"
    if family == "IPv4":
        endpoint["field_status"]["local_scope_id"] = "not_applicable"
        endpoint["field_status"]["remote_scope_id"] = (
            "not_applicable" if protocol == "UDP" else "not_applicable"
        )
    endpoint["application_protocol_hint"] = _application_protocol_hint(endpoint)
    endpoint["field_status"]["application_protocol_hint"] = (
        endpoint["application_protocol_hint"]["status"]
    )
    endpoint["collection_status"] = (
        "partial"
        if endpoint.get("field_errors")
        or endpoint.get("field_unavailability")
        or endpoint.get("owning_pid") is None
        or endpoint.get("owning_process_name") is None
        else endpoint.get("collection_status", "success")
    )
    endpoint.pop("field_status", None)
    endpoint.pop("_identity_pid", None)


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
                encoded_key = json.dumps(key, ensure_ascii=True)
                handle.write(f"  {encoded_key}: ")
                if key in ("errors", "endpoints") and isinstance(value, list):
                    handle.write("[\n")
                    for record_index, record in enumerate(value):
                        if record_index:
                            handle.write(",\n\n")
                        encoded_record = json.dumps(
                            record, ensure_ascii=True, indent=2
                        )
                        handle.write(textwrap.indent(encoded_record, "    "))
                    if value:
                        handle.write("\n")
                    handle.write("  ]")
                else:
                    encoded_value = json.dumps(
                        value, ensure_ascii=True, indent=2
                    )
                    handle.write(textwrap.indent(encoded_value, "  "))
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
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return requested / f"Network Connections_{timestamp}.json"
    if raw_path.endswith((os.sep, os.altsep) if os.altsep else (os.sep,)):
        raise FileNotFoundError(f"Output directory does not exist: {requested}")
    return requested


def collect_network_connections(
    output_path: str | os.PathLike[str],
    overwrite: bool = False,
) -> dict[str, Any]:
    """Collect, reconcile, enrich, and save a Windows endpoint snapshot."""
    started_at = utc_now()
    destination = _resolve_output_destination(output_path)
    if not overwrite and os.path.lexists(destination):
        raise FileExistsError(f"Refusing to overwrite existing output: {destination}")
    if not destination.parent.is_dir():
        raise FileNotFoundError(f"Output directory does not exist: {destination.parent}")

    providers: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    psutil_endpoints, psutil_provider = enumerate_psutil_endpoints()
    providers.append(psutil_provider)
    api_endpoints, api_providers = enumerate_ip_helper_endpoints()
    providers.extend(api_providers)
    endpoints, reconciliation_errors = reconcile_endpoints(
        psutil_endpoints + api_endpoints
    )
    errors.extend(reconciliation_errors)
    enrich_process_details(endpoints)
    provider_disagreements: list[dict[str, Any]] = []
    for endpoint in endpoints:
        _finalize_endpoint(endpoint)
        if endpoint["field_errors"]:
            errors.append(
                {
                    "endpoint": {
                        "address_family": endpoint["address_family"],
                        "transport_protocol": endpoint["transport_protocol"],
                        "local_address": endpoint["local_address"],
                        "remote_address": endpoint["remote_address"],
                    },
                    "owning_pid": endpoint["owning_pid"],
                    "error_type": "EndpointFieldError",
                    "fields": endpoint["field_errors"],
                }
            )
        for field, disagreements in endpoint["provider_disagreements"].items():
            provider_disagreements.append(
                {
                    "endpoint": {
                        "address_family": endpoint["address_family"],
                        "transport_protocol": endpoint["transport_protocol"],
                        "local_address": endpoint["local_address"],
                        "remote_address": endpoint["remote_address"],
                    },
                    "field": field,
                    "error_type": "ProviderDisagreement",
                    "values": disagreements,
                }
            )

    successful_providers = sum(
        provider["status"] in ("success", "partial") for provider in providers
    )
    failed_providers = sum(provider["status"] == "failed" for provider in providers)
    for provider in providers:
        for provider_error in provider["errors"]:
            errors.append(
                {
                    "provider": provider["provider"],
                    **provider_error,
                }
            )
    if successful_providers == 0:
        status = "failed"
    elif (
        failed_providers
        or any(provider["status"] == "partial" for provider in providers)
        or errors
        or any(
            endpoint["collection_status"] == "partial" for endpoint in endpoints
        )
    ):
        status = "partial"
    else:
        status = "success"

    finished_at = utc_now()
    document = {
        "schema_version": 1,
        "artifact": "A03",
        "artifact_name": "Network Connections",
        "source": "Current local Windows TCP and UDP endpoint tables",
        **_collection_time_metadata(started_at, finished_at),
        "collection_status": status,
        "endpoint_count": len(endpoints),
        "provider_reconciliation": {
            "endpoint_identity": (
                "Address family, transport, local address/port/scope, and for TCP "
                "the remote address/port/scope. PID is not used alone as identity."
            ),
            "tcp": "Provider rows with the same TCP 4-tuple are merged; owner/state conflicts are retained.",
            "udp": "Matching local endpoint rows are merged when ownership agrees or one provider has no PID; distinct known owners are retained.",
            "provider_disagreements": "All conflicting provider field values are retained separately in the top-level provider_disagreements section; these are observations, not collection errors.",
        },
        "field_coverage": {
            "address_family_protocol_local_remote": {
                "provider": "psutil.net_connections(kind='inet') plus GetExtendedTcpTable/GetExtendedUdpTable",
                "supported_conditions": "IPv4/IPv6 TCP/UDP rows returned during each provider query.",
                "unavailability": "Provider failure, malformed records, or live endpoint changes; UDP remote peer is not applicable.",
            },
            "ipv6_scope_ids": {
                "provider": "psutil IPv6 address tuple and IP Helper IPv6 owner-module rows",
                "supported_conditions": "IPv6 endpoints; IP Helper scope IDs and network byte order are converted to host-order integers.",
                "unavailability": "Not applicable to IPv4; null only when a source does not expose the scope value.",
            },
            "tcp_state": {
                "provider": "GetExtendedTcpTable MIB_TCPROW_OWNER_MODULE/MIB_TCP6ROW_OWNER_MODULE and psutil status",
                "supported_conditions": "TCP endpoints; API state numbers are mapped to documented Windows state names.",
                "unavailability": "Not applicable to UDP; unknown numeric Windows state is retained as UNKNOWN_<number>.",
            },
            "owning_pid": {
                "provider": "Windows IP Helper owner-module tables and psutil endpoint pid",
                "supported_conditions": "PID is available; PID 0 is retained for TCP, while Microsoft defines UDP PID 0 as unavailable.",
                "unavailability": "Provider access/visibility limits; null with a field_unavailability explanation or field error where available.",
            },
            "process_metadata": {
                "provider": "psutil.Process(pid)",
                "supported_conditions": "Owner PID is available and field access succeeds; PID creation time is checked before/after lookup.",
                "unavailability": "Access denied, process exit, PID reuse, or provider error; null with field-level status/error. System Idle Process executable path is marked not applicable.",
            },
            "field_unavailability": {
                "provider": "Windows APIs and psutil field lookups",
                "supported_conditions": "Unavailable optional fields retain a field_unavailability explanation without being reported as collector failures.",
                "unavailability": "Access denied, process exit, endpoint disappearance during module lookup, and not-applicable fields are limitations; unexpected provider failures remain in errors.",
            },
            "process_creation_time": {
                "provider": "psutil.Process.create_time()",
                "supported_conditions": "Returned value is recorded both as Unix epoch seconds and UTC ISO 8601.",
                "unavailability": "Owner process exited, access was denied, or PID identity changed during lookup.",
            },
            "endpoint_creation_time_utc": {
                "provider": "GetExtendedTcpTable/GetExtendedUdpTable owner-module rows (liCreateTimestamp FILETIME)",
                "supported_conditions": "The Windows row supplies the context-bind creation timestamp; the original 100-nanosecond FILETIME integer and converted UTC timestamp are both retained.",
                "unavailability": "Null for psutil-only records or when the provider row/timestamp is unavailable or invalid. This is a context-bind timestamp, not necessarily the moment application data began.",
            },
            "endpoint_creation_time_filetime_100ns": {
                "provider": "GetExtendedTcpTable/GetExtendedUdpTable owner-module rows (liCreateTimestamp)",
                "supported_conditions": "The original unsigned FILETIME tick value is retained alongside its UTC conversion.",
                "unavailability": "Null when the owner-module timestamp is unavailable or invalid.",
            },
            "owning_module_info": {
                "provider": "GetOwnerModuleFromTcpEntry/GetOwnerModuleFromTcp6Entry/GetOwnerModuleFromUdpEntry/GetOwnerModuleFromUdp6Entry (TCPIP_OWNER_MODULE_INFO_BASIC)",
                "supported_conditions": "When the owner-module endpoint row is returned and Windows resolves module name and/or full path.",
                "unavailability": "Null with a field_unavailability reason when the endpoint changes before resolution or Windows supplies no module strings; API failures are retained as field errors.",
            },
            "first_observed_at_utc_last_observed_at_utc": {
                "provider": "Collector observation time while each provider row is enumerated",
                "supported_conditions": "Records when this endpoint tuple was observed during this single acquisition; duplicate provider observations are combined using earliest/latest observation times.",
                "unavailability": "These fields do not imply historical monitoring, and do not establish actual endpoint creation or lifetime.",
            },
            "application_protocol_hint": {
                "provider": "Collector-side well-known port mapping",
                "supported_conditions": "A recognized transport/port tuple yields one or more candidates marked unconfirmed.",
                "unavailability": "No hint when the port is unmapped. No packets, payloads, TLS metadata, or application protocol negotiation are inspected.",
            },
            "socket_descriptor": {
                "provider": "psutil endpoint fd",
                "supported_conditions": "Only when psutil returns a non-negative descriptor.",
                "unavailability": "Windows commonly supplies -1; then value is null and status is unsupported.",
            },
        },
        "providers_attempted": providers,
        "provider_disagreements": provider_disagreements,
        "limitations": [
            "This is a live snapshot. Connections and owners can change while providers are queried.",
            "The IP Helper tables are queried separately and are not an atomic snapshot with psutil.",
            "Process metadata is a later best-effort lookup; PID reuse is checked using process creation time but cannot be made race-free.",
            "Administrator privileges can improve visibility but do not guarantee access to every owner field.",
            "Owner-module APIs provide context-bind FILETIME and best-effort module name/path, not a guarantee of the application component responsible for all traffic.",
            "First/last observed timestamps cover only the observations made within this one acquisition; no monitoring or historical closed-connection collection is performed.",
            "Application-protocol hints are unconfirmed port-based candidates, not protocol identification; no packet contents or traffic indicators are collected.",
            "Windows endpoint tables do not provide packet contents, byte counts, or historical connections.",
            "UDP records do not identify a remote peer; UDP state is not applicable.",
            "An endpoint port number does not prove an application-layer protocol.",
        ],
        "errors": errors,
        "endpoints": endpoints,
    }
    if status == "failed":
        document["errors"].append(
            {
                "error_type": "EndpointEnumerationFailed",
                "message": "All endpoint providers failed; no successful empty snapshot is reported.",
            }
        )
    _write_json(destination, document, overwrite)
    return document


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect a read-only snapshot of current Windows TCP/UDP endpoints."
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
        document = collect_network_connections(destination, overwrite=args.overwrite)
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
                "endpoint_count": document["endpoint_count"],
                "provider_count": len(document["providers_attempted"]),
                "error_count": len(document["errors"]),
                "output": str(destination),
            },
            ensure_ascii=True,
        )
    )
    return 0 if document["collection_status"] == "success" else 1


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
