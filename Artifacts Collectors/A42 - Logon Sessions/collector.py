"""Read-only collection of local WTS, LSA, and retained Security-log sessions."""

from __future__ import annotations

import argparse
import ctypes
import ipaddress
import json
import os
import socket
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

ARTIFACT_ID = "A42"
EXIT_SUCCESS = 0
EXIT_PARTIAL = 1
EXIT_FAILURE = 2
DEFAULT_OUTPUT_DIRECTORY = Path(__file__).resolve().parent / "Logon Sessions_Output"
LOCAL_TIME_BASIS = "Host-configured local timezone; ISO 8601 numeric UTC offset included."

WTS_USER_NAME = 5
WTS_WIN_STATION_NAME = 6
WTS_DOMAIN_NAME = 7
WTS_CONNECT_STATE = 8
WTS_CLIENT_BUILD_NUMBER = 9
WTS_CLIENT_NAME = 10
WTS_CLIENT_PRODUCT_ID = 12
WTS_CLIENT_HARDWARE_ID = 13
WTS_CLIENT_ADDRESS = 14
WTS_CLIENT_DISPLAY = 15
WTS_CLIENT_PROTOCOL_TYPE = 16
WTS_SESSION_INFO = 24
WTS_SESSION_INFO_EX = 25
WTS_IS_REMOTE_SESSION = 29
WTS_CURRENT_SERVER_HANDLE = ctypes.c_void_p()
WTS_ACTIVE_CONSOLE_SESSION_ID_NONE = 0xFFFFFFFF
ERROR_ACCESS_DENIED = 5
ERROR_NOT_SUPPORTED = 50
ERROR_INVALID_PARAMETER = 87
ERROR_CTX_WINSTATION_NAME_INVALID = 7001
ERROR_CTX_WINSTATION_NOT_FOUND = 7022
ERROR_NO_MORE_ITEMS = 259
ERROR_INSUFFICIENT_BUFFER = 122

HISTORICAL_EVENT_IDS = (
    4624,
    4625,
    4634,
    4647,
    4648,
    4672,
    4776,
    4778,
    4779,
    4800,
    4801,
)
HISTORICAL_EVENT_LABELS = {
    4624: "successful_logon",
    4625: "failed_logon_attempt",
    4634: "logoff",
    4647: "user_initiated_logoff",
    4648: "explicit_credentials_logon_attempt",
    4672: "special_privileges_assigned",
    4776: "ntlm_credential_validation",
    4778: "session_reconnected",
    4779: "session_disconnected",
    4800: "workstation_locked",
    4801: "workstation_unlocked",
}
LOGON_TYPE_LABELS = {
    0: "undefined",
    2: "interactive",
    3: "network",
    4: "batch",
    5: "service",
    7: "unlock",
    8: "network_cleartext",
    9: "new_credentials",
    10: "remote_interactive",
    11: "cached_interactive",
    12: "cached_remote_interactive",
    13: "cached_unlock",
}

CONNECT_STATE_LABELS = {
    0: "active",
    1: "connected",
    2: "connect_query",
    3: "shadow",
    4: "disconnected",
    5: "idle",
    6: "listen",
    7: "reset",
    8: "down",
    9: "initializing",
}
PROTOCOL_LABELS = {0: "console", 1: "ica_legacy", 2: "rdp"}
ADDRESS_FAMILY_LABELS = {
    0: "unspecified",
    2: "AF_INET",
    6: "AF_IPX",
    17: "AF_NETBIOS",
    23: "AF_INET6",
}

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
WINSTATIONNAME_LENGTH = 32
DOMAIN_LENGTH = 17
USERNAME_LENGTH = 20


class WTS_CLIENT_ADDRESS_STRUCT(ctypes.Structure):
    _fields_ = [
        ("AddressFamily", ctypes.c_uint32),
        ("Address", ctypes.c_ubyte * 20),
    ]


class WTS_CLIENT_DISPLAY_STRUCT(ctypes.Structure):
    _fields_ = [
        ("HorizontalResolution", ctypes.c_uint32),
        ("VerticalResolution", ctypes.c_uint32),
        ("ColorDepth", ctypes.c_uint32),
    ]


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
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def local_time_from_utc(timestamp: str) -> str | None:
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (OSError, OverflowError, ValueError):
        return None
    if parsed.utcoffset() is None:
        return None
    return parsed.astimezone().isoformat(timespec="microseconds")


def _native_code(exc: BaseException) -> int | str | None:
    winerror = getattr(exc, "winerror", None)
    if isinstance(winerror, int):
        return winerror
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], int):
        return args[0]
    return None


def _error_record(exc: BaseException, *, operation: str) -> dict[str, Any]:
    code = _native_code(exc)
    if isinstance(exc, (TypeError, ValueError)):
        category = "malformed_provider_data"
    elif isinstance(exc, NotImplementedError) or code == ERROR_NOT_SUPPORTED:
        category = "unsupported_information_class"
    elif code == ERROR_ACCESS_DENIED:
        category = "access_denied"
    elif code in (
        ERROR_CTX_WINSTATION_NAME_INVALID,
        ERROR_CTX_WINSTATION_NOT_FOUND,
    ):
        category = "session_disappeared"
    else:
        category = "provider_failure"
    return {
        "operation": operation,
        "category": category,
        "type": type(exc).__name__,
        "native_code": code,
        "message": str(exc),
    }


def normalize_filetime(value: Any) -> dict[str, Any]:
    if not isinstance(value, int) or isinstance(value, bool):
        return {
            "raw_100ns": None,
            "utc": None,
            "local": None,
            "status": "invalid_provider_value",
        }
    if value == 0:
        return {
            "raw_100ns": value,
            "utc": None,
            "local": None,
            "status": "zero_sentinel",
        }
    if value < 0:
        return {
            "raw_100ns": value,
            "utc": None,
            "local": None,
            "status": "invalid_value",
        }
    try:
        timestamp = (FILETIME_EPOCH + timedelta(microseconds=value // 10)).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return {
            "raw_100ns": value,
            "utc": None,
            "local": None,
            "status": "out_of_range",
        }
    return {
        "raw_100ns": value,
        "utc": timestamp,
        "local": local_time_from_utc(timestamp),
        "status": "available",
    }


def interpret_session_flags(
    value: Any, windows_version: tuple[int, int, int] | None
) -> dict[str, Any]:
    if not isinstance(value, int) or isinstance(value, bool):
        return {
            "value": None,
            "hex": None,
            "interpretation": "unavailable",
            "interpretation_status": "invalid_provider_value",
        }
    unsigned = value & 0xFFFFFFFF
    if unsigned == 0xFFFFFFFF:
        interpretation = "unknown"
        status = "documented_unknown_sentinel"
    elif value not in (0, 1):
        interpretation = "unrecognized_value"
        status = "unrecognized_provider_value"
    elif windows_version is None:
        interpretation = "lock_state_not_interpreted"
        status = "windows_version_unavailable"
    elif windows_version[:2] == (6, 1):
        interpretation = "unlocked" if value == 0 else "locked"
        status = "documented_windows_7_server_2008_r2_reversed_behavior"
    else:
        interpretation = "locked" if value == 0 else "unlocked"
        status = "documented_current_mapping"
    return {
        "value": value,
        "hex": f"0x{unsigned:08X}",
        "interpretation": interpretation,
        "interpretation_status": status,
        "meaning": "Session lock-state flag; not a bitmask.",
    }


def decode_client_address(
    provider_value: Any, protocol_type: int | None
) -> dict[str, Any]:
    if protocol_type == 0:
        raw = None
        if isinstance(provider_value, dict):
            raw = provider_value.get("Address")
        raw_bytes = _bytes_from_provider(raw)
        return {
            "address_family_value": (
                provider_value.get("AddressFamily")
                if isinstance(provider_value, dict)
                else None
            ),
            "address_family_label": (
                ADDRESS_FAMILY_LABELS.get(
                    provider_value.get("AddressFamily"), "unknown_address_family"
                )
                if isinstance(provider_value, dict)
                else None
            ),
            "raw_bytes_hex": raw_bytes.hex() if raw_bytes is not None else None,
            "decoded_address": None,
            "status": "not_applicable_console_protocol",
        }
    if not isinstance(provider_value, dict):
        return {
            "address_family_value": None,
            "address_family_label": None,
            "raw_bytes_hex": None,
            "decoded_address": None,
            "status": "unavailable",
        }
    family = provider_value.get("AddressFamily")
    raw_bytes = _bytes_from_provider(provider_value.get("Address"))
    result = {
        "address_family_value": family if isinstance(family, int) else None,
        "address_family_label": (
            ADDRESS_FAMILY_LABELS.get(family, "unknown_address_family")
            if isinstance(family, int)
            else None
        ),
        "raw_bytes_hex": raw_bytes.hex() if raw_bytes is not None else None,
        "decoded_address": None,
        "status": "raw_bytes_only",
    }
    if raw_bytes is None:
        result["status"] = "malformed_address_buffer"
    elif family == socket.AF_INET and len(raw_bytes) == 20:
        result["decoded_address"] = str(ipaddress.IPv4Address(raw_bytes[2:6]))
        result["status"] = "decoded_ipv4_documented_offset"
    elif family == socket.AF_INET6 and len(raw_bytes) == 20:
        result["decoded_address"] = str(ipaddress.IPv6Address(raw_bytes[:16]))
        result["status"] = "decoded_ipv6_documented_layout"
    elif family == 0:
        result["status"] = "address_family_unspecified"
    return result


def _bytes_from_provider(value: Any) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, (tuple, list)) and all(
        isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255
        for item in value
    ):
        return bytes(value)
    return None


def _wide_array(value: Any) -> str:
    return "".join(value).split("\x00", 1)[0]


class WTSINFO(ctypes.Structure):
    _fields_ = [
        ("State", ctypes.c_uint32),
        ("SessionId", ctypes.c_uint32),
        ("IncomingBytes", ctypes.c_uint32),
        ("OutgoingBytes", ctypes.c_uint32),
        ("IncomingFrames", ctypes.c_uint32),
        ("OutgoingFrames", ctypes.c_uint32),
        ("IncomingCompressedBytes", ctypes.c_uint32),
        ("OutgoingCompressedBytes", ctypes.c_uint32),
        ("WinStationName", ctypes.c_wchar * WINSTATIONNAME_LENGTH),
        ("Domain", ctypes.c_wchar * DOMAIN_LENGTH),
        ("UserName", ctypes.c_wchar * (USERNAME_LENGTH + 1)),
        ("ConnectTime", ctypes.c_int64),
        ("DisconnectTime", ctypes.c_int64),
        ("LastInputTime", ctypes.c_int64),
        ("LogonTime", ctypes.c_int64),
        ("CurrentTime", ctypes.c_int64),
    ]


class WTSINFOEX_LEVEL1W(ctypes.Structure):
    _fields_ = [
        ("SessionId", ctypes.c_uint32),
        ("SessionState", ctypes.c_int32),
        ("SessionFlags", ctypes.c_int32),
        ("WinStationName", ctypes.c_wchar * (WINSTATIONNAME_LENGTH + 1)),
        ("UserName", ctypes.c_wchar * (USERNAME_LENGTH + 1)),
        ("DomainName", ctypes.c_wchar * (DOMAIN_LENGTH + 1)),
        ("LogonTime", ctypes.c_int64),
        ("ConnectTime", ctypes.c_int64),
        ("DisconnectTime", ctypes.c_int64),
        ("LastInputTime", ctypes.c_int64),
        ("CurrentTime", ctypes.c_int64),
        ("IncomingBytes", ctypes.c_uint32),
        ("OutgoingBytes", ctypes.c_uint32),
        ("IncomingFrames", ctypes.c_uint32),
        ("OutgoingFrames", ctypes.c_uint32),
        ("IncomingCompressedBytes", ctypes.c_uint32),
        ("OutgoingCompressedBytes", ctypes.c_uint32),
    ]


class WTSINFOEX_LEVEL_W(ctypes.Union):
    _fields_ = [("WTSInfoExLevel1", WTSINFOEX_LEVEL1W)]


class WTSINFOEXW(ctypes.Structure):
    _fields_ = [("Level", ctypes.c_uint32), ("Data", WTSINFOEX_LEVEL_W)]


def decode_wts_info(data: bytes) -> dict[str, Any]:
    if len(data) < ctypes.sizeof(WTSINFO):
        raise ValueError(
            f"WTSSessionInfo buffer is {len(data)} bytes; expected at least {ctypes.sizeof(WTSINFO)}."
        )
    info = WTSINFO.from_buffer_copy(data)
    return {
        "session_id": info.SessionId,
        "connection_state_value": info.State,
        "win_station_name": _wide_array(info.WinStationName),
        "domain_name": _wide_array(info.Domain),
        "username": _wide_array(info.UserName),
        "times": {
            "connect_time": normalize_filetime(info.ConnectTime),
            "disconnect_time": normalize_filetime(info.DisconnectTime),
            "last_input_time": normalize_filetime(info.LastInputTime),
            "logon_time": normalize_filetime(info.LogonTime),
            "provider_current_time": normalize_filetime(info.CurrentTime),
        },
        "traffic_counters": _traffic_counters(info),
        "structure_size": ctypes.sizeof(WTSINFO),
        "buffer_size": len(data),
    }


def decode_wts_info_ex(
    data: bytes, windows_version: tuple[int, int, int] | None
) -> dict[str, Any]:
    if len(data) < ctypes.sizeof(WTSINFOEXW):
        raise ValueError(
            f"WTSSessionInfoEx buffer is {len(data)} bytes; expected at least {ctypes.sizeof(WTSINFOEXW)}."
        )
    info = WTSINFOEXW.from_buffer_copy(data)
    if info.Level != 1:
        raise ValueError(f"Unsupported WTSINFOEX level: {info.Level}.")
    level = info.Data.WTSInfoExLevel1
    raw_flags = level.SessionFlags
    return {
        "level": info.Level,
        "session_id": level.SessionId,
        "connection_state_value": level.SessionState,
        "session_flags": interpret_session_flags(raw_flags, windows_version),
        "win_station_name": _wide_array(level.WinStationName),
        "username": _wide_array(level.UserName),
        "domain_name": _wide_array(level.DomainName),
        "times": {
            "logon_time": normalize_filetime(level.LogonTime),
            "connect_time": normalize_filetime(level.ConnectTime),
            "disconnect_time": normalize_filetime(level.DisconnectTime),
            "last_input_time": normalize_filetime(level.LastInputTime),
            "provider_current_time": normalize_filetime(level.CurrentTime),
        },
        "traffic_counters": _traffic_counters(level),
        "structure_size": ctypes.sizeof(WTSINFOEXW),
        "buffer_size": len(data),
    }


def _traffic_counters(source: Any) -> dict[str, Any]:
    return {
        "incoming_bytes_uncompressed": {
            "value": source.IncomingBytes,
            "unit": "bytes",
            "meaning": "Uncompressed RDP data from client to server since connection.",
        },
        "outgoing_bytes_uncompressed": {
            "value": source.OutgoingBytes,
            "unit": "bytes",
            "meaning": "Uncompressed RDP data from server to client since connection.",
        },
        "incoming_frames": {
            "value": source.IncomingFrames,
            "unit": "frames",
            "meaning": "RDP frames from client to server since connection.",
        },
        "outgoing_frames": {
            "value": source.OutgoingFrames,
            "unit": "frames",
            "meaning": "RDP frames from server to client since connection.",
        },
        "incoming_bytes_compressed": {
            "value": source.IncomingCompressedBytes,
            "unit": "bytes",
            "meaning": "Compressed RDP data from client to server since connection.",
        },
        "outgoing_bytes_compressed": {
            "value": source.OutgoingCompressedBytes,
            "unit": "bytes",
            "meaning": "Compressed RDP data from server to client since connection.",
        },
    }


def derive_idle_duration(times: dict[str, Any], observed_at_utc: str) -> dict[str, Any]:
    current = times.get("provider_current_time", {})
    last_input = times.get("last_input_time", {})
    current_ticks = current.get("raw_100ns")
    last_input_ticks = last_input.get("raw_100ns")
    duration = None
    status = "unavailable_timestamp"
    if current.get("status") == "zero_sentinel" or last_input.get("status") == "zero_sentinel":
        status = "zero_sentinel"
    elif current.get("status") != "available" or last_input.get("status") != "available":
        status = "invalid_or_unavailable_timestamp"
    elif isinstance(current_ticks, int) and isinstance(last_input_ticks, int):
        if _filetime_ticks_are_after(current_ticks, observed_at_utc) or _filetime_ticks_are_after(
            last_input_ticks, observed_at_utc
        ):
            status = "future_provider_timestamp"
        elif current_ticks < last_input_ticks:
            status = "inconsistent_provider_timestamps"
        else:
            duration = (current_ticks - last_input_ticks) / 10_000_000
            status = "derived"
    return {
        "duration_seconds": duration,
        "status": status,
        "source": "WTSSessionInfoEx/WTSSessionInfo LastInputTime and CurrentTime FILETIME values",
        "observed_at_utc": observed_at_utc,
        "observed_at_local": local_time_from_utc(observed_at_utc),
    }


def _filetime_ticks_are_after(value: int, timestamp_utc: str) -> bool:
    try:
        observed = datetime.fromisoformat(timestamp_utc.replace("Z", "+00:00"))
    except (OverflowError, ValueError):
        return True
    if observed.utcoffset() is None:
        return True
    elapsed = observed.astimezone(timezone.utc) - FILETIME_EPOCH
    observed_ticks = (
        (elapsed.days * 86_400 + elapsed.seconds) * 10_000_000
        + elapsed.microseconds * 10
    )
    # ISO observations retain microseconds; compare both values at that precision.
    return (value // 10) * 10 > observed_ticks


def _windows_version() -> tuple[int, int, int] | None:
    if sys.platform != "win32":
        return None
    version = sys.getwindowsversion()
    return version.major, version.minor, version.build


class WindowsWtsProvider:
    """Read-only WTS provider: pywin32 for supported queries, ctypes for raw structs."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OSError("A42 requires Windows.")
        import win32ts

        self._win32ts = win32ts
        self._wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
        self._wtsapi32.WTSQuerySessionInformationW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self._wtsapi32.WTSQuerySessionInformationW.restype = ctypes.c_int
        self._wtsapi32.WTSFreeMemory.argtypes = [ctypes.c_void_p]
        self._wtsapi32.WTSFreeMemory.restype = None

    def enumerate_sessions(self) -> list[dict[str, Any]]:
        return list(self._win32ts.WTSEnumerateSessions())

    def active_console_session_id(self) -> int | None:
        value = self._win32ts.WTSGetActiveConsoleSessionId()
        if value in (WTS_ACTIVE_CONSOLE_SESSION_ID_NONE, -1):
            return None
        return value

    def query_session_information(self, session_id: int, info_class: int) -> Any:
        if info_class == WTS_SESSION_INFO:
            raw = self._query_native(session_id, info_class)
            return decode_wts_info(raw)
        if info_class == WTS_SESSION_INFO_EX:
            raw = self._query_native(session_id, info_class)
            return decode_wts_info_ex(raw, _windows_version())
        return self._win32ts.WTSQuerySessionInformation(
            None, session_id, info_class
        )

    def _query_native(self, session_id: int, info_class: int) -> bytes:
        buffer = ctypes.c_void_p()
        returned = ctypes.c_uint32()
        try:
            ctypes.set_last_error(0)
            succeeded = self._wtsapi32.WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE,
                session_id,
                info_class,
                ctypes.byref(buffer),
                ctypes.byref(returned),
            )
            if not succeeded:
                code = ctypes.get_last_error()
                raise OSError(code, ctypes.FormatError(code))
            if not buffer.value:
                raise ValueError("WTS query succeeded with a null information buffer.")
            expected = (
                ctypes.sizeof(WTSINFO)
                if info_class == WTS_SESSION_INFO
                else ctypes.sizeof(WTSINFOEXW)
            )
            if returned.value < expected:
                raise ValueError(
                    f"WTS information buffer has {returned.value} bytes; expected at least {expected}."
                )
            return ctypes.string_at(buffer, returned.value)
        finally:
            self._wtsapi32.WTSFreeMemory(buffer)


class WindowsLsaProvider:
    """Read current authentication sessions through pywin32 LSA wrappers."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OSError("LSA session enumeration requires Windows.")
        import win32security

        self._win32security = win32security

    def enumerate_logon_sessions(self) -> list[Any]:
        return list(self._win32security.LsaEnumerateLogonSessions())

    def query_logon_session(self, logon_id: Any) -> dict[str, Any]:
        result = self._win32security.LsaGetLogonSessionData(logon_id)
        if not isinstance(result, dict):
            raise ValueError("LsaGetLogonSessionData returned a non-mapping result.")
        return result

    def sid_to_string(self, sid: Any) -> str:
        return self._win32security.ConvertSidToStringSid(sid)


class WindowsSecurityEventProvider:
    """Read retained Security logon events using the documented Windows Event API."""

    BATCH_SIZE = 64
    QUERY_FLAGS = 0x1 | 0x100
    RENDER_EVENT_XML = 1

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OSError("Windows Security event collection requires Windows.")
        self._wevtapi = ctypes.WinDLL("wevtapi", use_last_error=True)
        self._wevtapi.EvtQuery.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        self._wevtapi.EvtQuery.restype = ctypes.c_void_p
        self._wevtapi.EvtNext.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self._wevtapi.EvtNext.restype = ctypes.c_int
        self._wevtapi.EvtRender.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self._wevtapi.EvtRender.restype = ctypes.c_int
        self._wevtapi.EvtClose.argtypes = [ctypes.c_void_p]
        self._wevtapi.EvtClose.restype = ctypes.c_int

    def collect_security_events(self) -> dict[str, Any]:
        event_ids = " or ".join(
            f"EventID={event_id}" for event_id in HISTORICAL_EVENT_IDS
        )
        xpath = f"*[System[({event_ids})]]"
        query = self._wevtapi.EvtQuery(
            None, "Security", xpath, self.QUERY_FLAGS
        )
        if not query:
            code = ctypes.get_last_error()
            raise OSError(code, ctypes.FormatError(code))

        records: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        complete = True
        try:
            while True:
                handles = (ctypes.c_void_p * self.BATCH_SIZE)()
                returned = ctypes.c_uint32()
                ctypes.set_last_error(0)
                succeeded = self._wevtapi.EvtNext(
                    query,
                    self.BATCH_SIZE,
                    handles,
                    0,
                    0,
                    ctypes.byref(returned),
                )
                if not succeeded:
                    code = ctypes.get_last_error()
                    if code == ERROR_NO_MORE_ITEMS:
                        break
                    complete = False
                    errors.append(
                        {
                            "category": "security_event_query_failure",
                            "operation": "EvtNext",
                            "native_code": code,
                            "message": ctypes.FormatError(code),
                        }
                    )
                    break
                if returned.value == 0 or returned.value > self.BATCH_SIZE:
                    complete = False
                    errors.append(
                        {
                            "category": "malformed_security_event_result",
                            "operation": "EvtNext",
                            "message": "Event API returned an invalid batch count.",
                            "returned_count": returned.value,
                        }
                    )
                    break
                for index in range(returned.value):
                    event_handle = handles[index]
                    try:
                        xml = self._render_xml(event_handle)
                        records.append(_parse_security_event_xml(xml))
                    except Exception as exc:
                        complete = False
                        records.append(
                            {
                                "event_metadata": {},
                                "event_data": [],
                                "user_data_xml": None,
                                "raw_xml": None,
                                "event_type_label": None,
                                "record_status": "partial",
                                "errors": [
                                    _error_record(
                                        exc, operation="EvtRender/EvtRenderEventXml"
                                    )
                                ],
                            }
                        )
                    finally:
                        if event_handle:
                            self._close_handle(
                                event_handle, errors, operation="EvtClose(event)"
                            )
        finally:
            self._close_handle(query, errors, operation="EvtClose(query)")
        if errors:
            complete = False
        return {
            "records": records,
            "enumeration_complete": complete,
            "errors": errors,
            "query": {
                "channel": "Security",
                "event_ids": list(HISTORICAL_EVENT_IDS),
                "event_labels": HISTORICAL_EVENT_LABELS,
                "direction": "forward_chronological",
                "time_range": "all matching records retained in the local Security channel",
            },
        }

    def _render_xml(self, event_handle: ctypes.c_void_p) -> str:
        buffer_size = ctypes.c_uint32()
        property_count = ctypes.c_uint32()
        ctypes.set_last_error(0)
        succeeded = self._wevtapi.EvtRender(
            None,
            event_handle,
            self.RENDER_EVENT_XML,
            0,
            None,
            ctypes.byref(buffer_size),
            ctypes.byref(property_count),
        )
        if succeeded or ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER:
            code = ctypes.get_last_error()
            raise OSError(code, ctypes.FormatError(code))
        if buffer_size.value < ctypes.sizeof(ctypes.c_wchar):
            raise ValueError("EvtRender reported an invalid XML buffer size.")
        buffer = ctypes.create_unicode_buffer(
            (buffer_size.value + ctypes.sizeof(ctypes.c_wchar) - 1)
            // ctypes.sizeof(ctypes.c_wchar)
        )
        ctypes.set_last_error(0)
        succeeded = self._wevtapi.EvtRender(
            None,
            event_handle,
            self.RENDER_EVENT_XML,
            buffer_size.value,
            ctypes.cast(buffer, ctypes.c_void_p),
            ctypes.byref(buffer_size),
            ctypes.byref(property_count),
        )
        if not succeeded:
            code = ctypes.get_last_error()
            raise OSError(code, ctypes.FormatError(code))
        return buffer.value

    def _close_handle(
        self,
        handle: ctypes.c_void_p,
        errors: list[dict[str, Any]],
        *,
        operation: str,
    ) -> None:
        ctypes.set_last_error(0)
        if not self._wevtapi.EvtClose(handle):
            code = ctypes.get_last_error()
            errors.append(
                {
                    "category": "event_handle_release_failure",
                    "operation": operation,
                    "native_code": code,
                    "message": ctypes.FormatError(code),
                }
            )


def _xml_tag(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _parse_security_event_xml(xml: str) -> dict[str, Any]:
    root = ET.fromstring(xml)
    system = next((item for item in root if _xml_tag(item) == "System"), None)
    if system is None:
        raise ValueError("Rendered event XML has no System element.")
    system_data: dict[str, Any] = {}
    event_data: list[dict[str, Any]] = []
    user_data_xml: str | None = None
    for element in system:
        tag = _xml_tag(element)
        if tag == "Provider":
            system_data["provider"] = dict(element.attrib)
        elif tag == "EventID":
            try:
                system_data["event_id"] = int(element.text or "")
            except ValueError:
                system_data["event_id"] = element.text
            if element.attrib:
                system_data["event_id_attributes"] = dict(element.attrib)
        elif tag == "TimeCreated":
            system_data["time_created"] = dict(element.attrib)
            raw_time = element.attrib.get("SystemTime")
            try:
                parsed_time = datetime.fromisoformat(
                    (raw_time or "").replace("Z", "+00:00")
                )
                if parsed_time.utcoffset() is None:
                    raise ValueError("Event SystemTime has no UTC offset.")
                event_time_utc = parsed_time.astimezone(timezone.utc).isoformat(
                    timespec="microseconds"
                ).replace("+00:00", "Z")
                system_data["time_created_utc"] = event_time_utc
                system_data["time_created_local"] = local_time_from_utc(
                    event_time_utc
                )
                system_data["time_created_status"] = "available"
            except ValueError:
                system_data["time_created_utc"] = None
                system_data["time_created_local"] = None
                system_data["time_created_status"] = "invalid_provider_timestamp"
        elif tag == "Correlation":
            system_data["correlation"] = dict(element.attrib)
        elif tag == "Execution":
            system_data["execution"] = dict(element.attrib)
        elif tag == "Security":
            system_data["security"] = dict(element.attrib)
        else:
            system_data[tag[0].lower() + tag[1:]] = element.text
    for element in root:
        tag = _xml_tag(element)
        if tag == "EventData":
            for item in element:
                event_data.append(
                    {
                        "name": item.attrib.get("Name"),
                        "attributes": dict(item.attrib),
                        "value": item.text or "",
                    }
                )
        elif tag == "UserData":
            user_data_xml = ET.tostring(element, encoding="unicode")
    event_id = system_data.get("event_id")
    return {
        "event_metadata": system_data,
        "event_type_label": HISTORICAL_EVENT_LABELS.get(
            event_id, "unknown_security_event"
        )
        if isinstance(event_id, int)
        else None,
        "event_data": event_data,
        "user_data_xml": user_data_xml,
        "raw_xml": xml,
        "record_status": "success",
        "errors": [],
    }


QUERY_CLASSES = [
    (WTS_USER_NAME, "WTSUserName"),
    (WTS_DOMAIN_NAME, "WTSDomainName"),
    (WTS_WIN_STATION_NAME, "WTSWinStationName"),
    (WTS_CONNECT_STATE, "WTSConnectState"),
    (WTS_CLIENT_NAME, "WTSClientName"),
    (WTS_CLIENT_ADDRESS, "WTSClientAddress"),
    (WTS_CLIENT_PROTOCOL_TYPE, "WTSClientProtocolType"),
    (WTS_CLIENT_BUILD_NUMBER, "WTSClientBuildNumber"),
    (WTS_CLIENT_PRODUCT_ID, "WTSClientProductId"),
    (WTS_CLIENT_HARDWARE_ID, "WTSClientHardwareId"),
    (WTS_CLIENT_DISPLAY, "WTSClientDisplay"),
    (WTS_SESSION_INFO, "WTSSessionInfo"),
    (WTS_SESSION_INFO_EX, "WTSSessionInfoEx"),
    (WTS_IS_REMOTE_SESSION, "WTSIsRemoteSession"),
]


def _field(value: Any, *, empty_is_absent: bool = False) -> dict[str, Any]:
    if value is None:
        return {"value": None, "status": "unavailable"}
    if empty_is_absent and value == "":
        return {"value": "", "status": "absent"}
    return {"value": value, "status": "available"}


def _class_available_for_version(
    info_class: int, version: tuple[int, int, int] | None
) -> bool:
    if info_class == WTS_SESSION_INFO:
        return version is None or version >= (6, 0, 6001)
    if info_class == WTS_SESSION_INFO_EX:
        return version is None or version >= (6, 1, 0)
    return True


def _parse_session_record(
    raw: Any, *, observed_at_utc: str
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if not isinstance(raw, dict):
        return None, {
            "category": "malformed_provider_record",
            "message": "WTSEnumerateSessions returned a non-mapping record.",
        }
    session_id = raw.get("SessionId")
    state = raw.get("State")
    station = raw.get("WinStationName")
    if (
        not isinstance(session_id, int)
        or isinstance(session_id, bool)
        or session_id < 0
    ):
        return None, {
            "category": "malformed_provider_record",
            "message": "Session entry has no valid session ID and cannot be retained.",
        }
    if not isinstance(state, int) or isinstance(state, bool):
        state_error = {
            "category": "malformed_provider_data",
            "operation": "WTSEnumerateSessions",
            "message": "Session state was not an integer.",
        }
        state = None
    else:
        state_error = None
    if station is not None and not isinstance(station, str):
        station_error = {
            "category": "malformed_provider_data",
            "operation": "WTSEnumerateSessions",
            "message": "Station name was not a string.",
        }
        station = None
    else:
        station_error = None
    record_errors = [item for item in (state_error, station_error) if item is not None]
    return (
        {
            "session_id": session_id,
            "win_station_name": station,
            "connection_state_value": state,
            "connection_state_label": CONNECT_STATE_LABELS.get(
                state, "unknown_provider_state"
            ),
            "observed_at_utc": observed_at_utc,
            "observed_at_local": local_time_from_utc(observed_at_utc),
            "_provider_errors": record_errors,
        },
        None,
    )


def _normalize_session(
    provider: Any,
    enumerated: dict[str, Any],
    *,
    active_console_session_id: int | None,
    active_console_status: str,
    observed_at_utc: str,
    windows_version: tuple[int, int, int] | None,
) -> dict[str, Any]:
    session_id = enumerated["session_id"]
    errors: list[dict[str, Any]] = enumerated.pop("_provider_errors", [])
    values: dict[str, Any] = {}
    query_status: dict[str, Any] = {}
    for info_class, class_name in QUERY_CLASSES:
        if not _class_available_for_version(info_class, windows_version):
            query_status[class_name] = {
                "status": "not_applicable",
                "reason": "Information class is not documented for this Windows version.",
            }
            continue
        try:
            value = provider.query_session_information(
                session_id, info_class
            )
            expected_type = _expected_value_type(info_class)
            if expected_type is not None and not isinstance(value, expected_type):
                raise TypeError(
                    f"{class_name} returned {type(value).__name__}; expected "
                    f"{expected_type.__name__}."
                )
            if info_class in (
                WTS_CONNECT_STATE,
                WTS_CLIENT_BUILD_NUMBER,
                WTS_CLIENT_PRODUCT_ID,
                WTS_CLIENT_HARDWARE_ID,
                WTS_CLIENT_PROTOCOL_TYPE,
            ) and isinstance(value, bool):
                raise TypeError(f"{class_name} returned a boolean, not an integer.")
            if info_class == WTS_CLIENT_DISPLAY and not all(
                isinstance(value.get(key), int)
                and not isinstance(value.get(key), bool)
                for key in (
                    "HorizontalResolution",
                    "VerticalResolution",
                    "ColorDepth",
                )
            ):
                raise TypeError("WTSClientDisplay returned malformed fields.")
            if info_class == WTS_CLIENT_ADDRESS and (
                not isinstance(value.get("AddressFamily"), int)
                or _bytes_from_provider(value.get("Address")) is None
            ):
                raise TypeError("WTSClientAddress returned malformed fields.")
            values[class_name] = value
            query_status[class_name] = {"status": "available"}
        except Exception as exc:
            error = _error_record(
                exc,
                operation=f"WTSQuerySessionInformation({session_id}, {class_name})",
            )
            query_status[class_name] = {
                "status": error["category"],
                "error": error,
            }
            errors.append(error)

    username = values.get("WTSUserName")
    domain = values.get("WTSDomainName")
    username = username if isinstance(username, str) else None
    domain = domain if isinstance(domain, str) else None
    user_status = (
        "inaccessible"
        if query_status["WTSUserName"]["status"] in {
            "access_denied",
            "provider_failure",
            "session_disappeared",
        }
        else "absent"
        if username in (None, "")
        else "available"
    )
    qualified = (
        f"{domain}\\{username}"
        if domain not in (None, "") and username not in (None, "")
        else username
        if username not in (None, "")
        else None
    )

    protocol = values.get("WTSClientProtocolType")
    protocol = protocol if isinstance(protocol, int) and not isinstance(protocol, bool) else None
    queried_state = values.get("WTSConnectState")
    queried_state = queried_state if isinstance(queried_state, int) and not isinstance(queried_state, bool) else None
    state_from_enumeration = enumerated.get("connection_state_value")
    state_discrepancy = (
        queried_state is not None
        and state_from_enumeration is not None
        and queried_state != state_from_enumeration
    )
    if state_discrepancy:
        errors.append(
            {
                "category": "provider_state_changed_during_collection",
                "message": "Session connection state differed between enumeration and per-session query.",
                "enumerated_state": state_from_enumeration,
                "queried_state": queried_state,
            }
        )

    address = decode_client_address(values.get("WTSClientAddress"), protocol)
    display = values.get("WTSClientDisplay")
    if isinstance(display, dict):
        display = {
            key: display.get(key)
            for key in ("HorizontalResolution", "VerticalResolution", "ColorDepth")
        }
    else:
        display = None

    session_info = values.get("WTSSessionInfo")
    session_info_ex = values.get("WTSSessionInfoEx")
    extended = session_info_ex if isinstance(session_info_ex, dict) else session_info
    times = extended.get("times", {}) if isinstance(extended, dict) else {}
    identity = {
        **enumerated,
        "provider": "pywin32 win32ts.WTSEnumerateSessions",
        "matches_active_physical_console_session": (
            session_id == active_console_session_id
            if active_console_session_id is not None
            else None
        ),
        "active_console_comparison_status": (
            "compared"
            if active_console_session_id is not None
            else active_console_status
        ),
        "query_connection_state_value": queried_state,
        "query_connection_state_label": CONNECT_STATE_LABELS.get(
            queried_state, "unknown_provider_state"
        )
        if queried_state is not None
        else None,
        "state_changed_during_collection": state_discrepancy,
    }
    user_context = {
        "username": _field(username, empty_is_absent=True),
        "domain_name": _field(domain, empty_is_absent=True),
        "qualified_username": qualified,
        "status": user_status,
    }
    client_context = {
        "client_name": _field(values.get("WTSClientName"), empty_is_absent=True),
        "protocol_type_value": protocol,
        "protocol_type_label": PROTOCOL_LABELS.get(
            protocol, "unknown_provider_protocol"
        )
        if protocol is not None
        else None,
        "address": address,
        "client_build_number": _field(values.get("WTSClientBuildNumber")),
        "product_identifier": _field(values.get("WTSClientProductId")),
        "hardware_identifier": {
            **_field(values.get("WTSClientHardwareId")),
            "meaning": "Reserved for future use; documented API returns zero.",
        },
        "display": display,
        "is_remote_session": _field(values.get("WTSIsRemoteSession")),
    }
    extended_information = {
        "wts_session_info": session_info,
        "wts_session_info_ex": session_info_ex,
        "preferred_source": (
            "WTSSessionInfoEx"
            if isinstance(session_info_ex, dict)
            else "WTSSessionInfo"
            if isinstance(session_info, dict)
            else None
        ),
        "idle_duration": derive_idle_duration(times, observed_at_utc),
        "session_flags": (
            session_info_ex.get("session_flags")
            if isinstance(session_info_ex, dict)
            else None
        ),
    }
    has_information_error = any(
        status.get("status")
        in {
            "access_denied",
            "unsupported_information_class",
            "session_disappeared",
            "provider_failure",
        }
        for status in query_status.values()
    )
    return {
        "session_identity": identity,
        "user_context": user_context,
        "client_context": client_context,
        "extended_information": extended_information,
        "information_class_status": query_status,
        "record_status": "partial" if has_information_error else "success",
        "errors": errors,
    }


def _expected_value_type(info_class: int) -> type | tuple[type, ...] | None:
    if info_class in (
        WTS_USER_NAME,
        WTS_DOMAIN_NAME,
        WTS_WIN_STATION_NAME,
        WTS_CLIENT_NAME,
    ):
        return str
    if info_class in (
        WTS_CONNECT_STATE,
        WTS_CLIENT_BUILD_NUMBER,
        WTS_CLIENT_PRODUCT_ID,
        WTS_CLIENT_HARDWARE_ID,
        WTS_CLIENT_PROTOCOL_TYPE,
    ):
        return int
    if info_class in (WTS_CLIENT_ADDRESS, WTS_CLIENT_DISPLAY):
        return dict
    if info_class == WTS_IS_REMOTE_SESSION:
        return bool
    if info_class in (WTS_SESSION_INFO, WTS_SESSION_INFO_EX):
        return dict
    return None


def _lsa_json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {
            str(key): _lsa_json_value(item)
            for key, item in value.items()
            if not any(
                blocked in str(key).casefold()
                for blocked in ("password", "credential", "token", "secret")
            )
        }
    if isinstance(value, (list, tuple)):
        return [_lsa_json_value(item) for item in value]
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _lsa_timestamp(value: Any) -> dict[str, Any]:
    if not isinstance(value, datetime):
        return {
            "provider_value": _lsa_json_value(value),
            "utc": None,
            "local": None,
            "status": "invalid_or_unavailable",
        }
    if value.year == 1601 and value.month == 1 and value.day == 1:
        return {
            "provider_value": value.isoformat(),
            "utc": None,
            "local": None,
            "status": "zero_sentinel",
        }
    if value.utcoffset() is None:
        return {
            "provider_value": value.isoformat(),
            "utc": None,
            "local": None,
            "status": "timezone_missing",
        }
    try:
        utc_value = value.astimezone(timezone.utc)
        utc_string = utc_value.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
    except (OverflowError, ValueError):
        return {
            "provider_value": value.isoformat(),
            "utc": None,
            "local": None,
            "status": "out_of_range",
        }
    return {
        "provider_value": value.isoformat(),
        "utc": utc_string,
        "local": local_time_from_utc(utc_string),
        "status": "available",
    }


def _normalize_lsa_record(
    provider: Any, enumerated_logon_id: Any
) -> dict[str, Any]:
    if not isinstance(enumerated_logon_id, int) or isinstance(
        enumerated_logon_id, bool
    ):
        return {
            "authentication_session_identity": {
                "authentication_luid_value": _lsa_json_value(enumerated_logon_id),
                "authentication_luid_hex": None,
                "identifier_type": "LSA authentication LUID; not a WTS session ID",
            },
            "user_context": None,
            "logon_context": None,
            "record_status": "partial",
            "errors": [
                {
                    "category": "malformed_lsa_session_id",
                    "message": "LsaEnumerateLogonSessions returned a non-integer LUID.",
                }
            ],
        }
    luid = enumerated_logon_id & 0xFFFFFFFFFFFFFFFF
    identity = {
        "authentication_luid_value": enumerated_logon_id,
        "authentication_luid_hex": f"0x{luid:016X}",
        "identifier_type": "LSA authentication LUID; not a WTS session ID",
    }
    try:
        data = provider.query_logon_session(enumerated_logon_id)
    except Exception as exc:
        return {
            "authentication_session_identity": identity,
            "user_context": None,
            "logon_context": None,
            "record_status": "partial",
            "errors": [_error_record(exc, operation="LsaGetLogonSessionData")],
        }

    errors: list[dict[str, Any]] = []
    returned_luid = data.get("LogonId")
    if isinstance(returned_luid, int) and (returned_luid & 0xFFFFFFFFFFFFFFFF) != luid:
        errors.append(
            {
                "category": "lsa_identifier_mismatch",
                "operation": "LsaGetLogonSessionData",
                "enumerated_luid_hex": identity["authentication_luid_hex"],
                "returned_luid_hex": f"0x{returned_luid & 0xFFFFFFFFFFFFFFFF:016X}",
            }
        )
    sid_value = data.get("Sid")
    sid_string = None
    if sid_value is not None:
        try:
            sid_string = provider.sid_to_string(sid_value)
        except Exception as exc:
            errors.append(_error_record(exc, operation="ConvertSidToStringSid"))
            sid_string = _lsa_json_value(sid_value)

    primary_fields = {
        "LogonId",
        "UserName",
        "LogonDomain",
        "AuthenticationPackage",
        "LogonType",
        "Session",
        "Sid",
        "LogonTime",
        "LogoffTime",
        "KickOffTime",
        "LogonServer",
        "DnsDomainName",
        "Upn",
    }
    other_fields = {
        key: _lsa_json_value(value)
        for key, value in data.items()
        if key not in primary_fields
        and not any(
            blocked in str(key).casefold()
            for blocked in ("password", "credential", "token", "secret")
        )
    }
    logon_type = data.get("LogonType")
    user_context = {
        "username": _field(data.get("UserName"), empty_is_absent=True),
        "domain_name": _field(data.get("LogonDomain"), empty_is_absent=True),
        "sid": _field(sid_string),
        "upn": _field(data.get("Upn"), empty_is_absent=True),
    }
    logon_context = {
        "authentication_package": _field(
            data.get("AuthenticationPackage"), empty_is_absent=True
        ),
        "logon_type_value": logon_type,
        "logon_type_label": LOGON_TYPE_LABELS.get(
            logon_type, "unknown_logon_type"
        )
        if isinstance(logon_type, int) and not isinstance(logon_type, bool)
        else None,
        "terminal_services_session_id": _field(data.get("Session")),
        "logon_server": _field(data.get("LogonServer"), empty_is_absent=True),
        "dns_domain_name": _field(
            data.get("DnsDomainName"), empty_is_absent=True
        ),
        "logon_time": _lsa_timestamp(data.get("LogonTime")),
        "logoff_time": _lsa_timestamp(data.get("LogoffTime")),
        "kickoff_time": _lsa_timestamp(data.get("KickOffTime")),
        "additional_noncredential_provider_fields": other_fields,
    }
    return {
        "authentication_session_identity": identity,
        "user_context": user_context,
        "logon_context": logon_context,
        "record_status": "partial" if errors else "success",
        "errors": errors,
    }


def _collect_lsa_sessions(provider: Any) -> dict[str, Any]:
    try:
        logon_ids = provider.enumerate_logon_sessions()
    except Exception as exc:
        return {
            "status": "failed",
            "enumeration_complete": False,
            "record_count": 0,
            "sessions": [],
            "errors": [_error_record(exc, operation="LsaEnumerateLogonSessions")],
        }
    if not isinstance(logon_ids, (list, tuple)):
        return {
            "status": "failed",
            "enumeration_complete": False,
            "record_count": 0,
            "sessions": [],
            "errors": [
                {
                    "category": "malformed_lsa_enumeration",
                    "operation": "LsaEnumerateLogonSessions",
                    "message": "LSA provider returned a non-sequence result.",
                }
            ],
        }
    sessions = [
        _normalize_lsa_record(provider, logon_id) for logon_id in logon_ids
    ]
    errors = [
        {
            "category": "lsa_session_record_error",
            "authentication_luid_hex": session[
                "authentication_session_identity"
            ]["authentication_luid_hex"],
            "detail": error,
        }
        for session in sessions
        for error in session["errors"]
    ]
    status = (
        "partial"
        if errors or any(session["record_status"] != "success" for session in sessions)
        else "success"
    )
    return {
        "status": status,
        "enumeration_complete": True,
        "record_count": len(sessions),
        "sessions": sessions,
        "errors": errors,
    }


def _collect_historical_events(provider: Any) -> dict[str, Any]:
    try:
        result = provider.collect_security_events()
    except Exception as exc:
        return {
            "status": "failed",
            "enumeration_complete": False,
            "record_count": 0,
            "events": [],
            "query": {
                "channel": "Security",
                "event_ids": list(HISTORICAL_EVENT_IDS),
                "time_range": "all retained matching events",
            },
            "errors": [
                _error_record(exc, operation="Security event-log query")
            ],
        }
    if not isinstance(result, dict) or not isinstance(result.get("records"), list):
        return {
            "status": "failed",
            "enumeration_complete": False,
            "record_count": 0,
            "events": [],
            "query": {
                "channel": "Security",
                "event_ids": list(HISTORICAL_EVENT_IDS),
                "time_range": "all retained matching events",
            },
            "errors": [
                {
                    "category": "malformed_security_event_result",
                    "message": "Security event provider returned an invalid result.",
                }
            ],
        }
    events = result["records"]
    errors = result.get("errors", [])
    if not isinstance(errors, list):
        errors = [
            {
                "category": "malformed_security_event_result",
                "message": "Security event provider errors were not a list.",
            }
        ]
    complete = result.get("enumeration_complete") is True
    if not complete and not errors:
        errors.append(
            {
                "category": "incomplete_security_event_enumeration",
                "message": "Event provider did not confirm complete enumeration.",
            }
        )
    return {
        "status": (
            "success"
            if complete
            and not errors
            and all(event.get("record_status") == "success" for event in events)
            else "partial"
        ),
        "enumeration_complete": complete,
        "record_count": len(events),
        "events": events,
        "query": result.get(
            "query",
            {
                "channel": "Security",
                "event_ids": list(HISTORICAL_EVENT_IDS),
                "time_range": "all retained matching events",
            },
        ),
        "errors": errors,
    }


def build_inventory(
    *,
    provider: Any | None = None,
    lsa_provider: Any | None = None,
    event_provider: Any | None = None,
    now_provider: Callable[[], str] = utc_now,
    version_provider: Callable[[], tuple[int, int, int] | None] = _windows_version,
) -> dict[str, Any]:
    started = now_provider()
    errors: list[dict[str, Any]] = []
    version = version_provider()
    wts_errors: list[dict[str, Any]] = []
    active_console_id: int | None = None
    active_console_status = "not_queried"
    sessions: list[dict[str, Any]] = []
    try:
        provider = provider or WindowsWtsProvider()
        raw_sessions = provider.enumerate_sessions()
    except Exception as exc:
        raw_sessions = None
        wts_errors.append(_error_record(exc, operation="WTSEnumerateSessions"))
    enumeration_complete = isinstance(raw_sessions, (list, tuple))
    if raw_sessions is not None and not enumeration_complete:
        wts_errors.append(
            {
                "category": "malformed_enumeration_result",
                "operation": "WTSEnumerateSessions",
                "message": "Provider did not return a sequence of session records.",
            }
        )
    if enumeration_complete:
        try:
            active_console_id = provider.active_console_session_id()
            active_console_status = (
                "available"
                if active_console_id is not None
                else "no_active_console_session"
            )
        except Exception as exc:
            active_console_status = "query_failed"
            wts_errors.append(
                _error_record(exc, operation="WTSGetActiveConsoleSessionId")
            )
        if active_console_id is not None and (
            not isinstance(active_console_id, int)
            or isinstance(active_console_id, bool)
            or active_console_id < 0
        ):
            wts_errors.append(
                {
                    "category": "malformed_provider_value",
                    "operation": "WTSGetActiveConsoleSessionId",
                    "message": "Active console session identifier was not a valid integer.",
                }
            )
            active_console_id = None
            active_console_status = "malformed_provider_value"
        for raw in raw_sessions:
            observed = now_provider()
            enumerated, parse_error = _parse_session_record(
                raw, observed_at_utc=observed
            )
            if parse_error:
                wts_errors.append(parse_error)
                enumeration_complete = False
                continue
            record = _normalize_session(
                provider,
                enumerated,
                active_console_session_id=active_console_id,
                active_console_status=active_console_status,
                observed_at_utc=observed,
                windows_version=version,
            )
            observation_completed = now_provider()
            record["session_identity"]["observed_at_utc"] = observation_completed
            record["session_identity"]["observed_at_local"] = local_time_from_utc(
                observation_completed
            )
            extended = record["extended_information"]
            preferred = extended["wts_session_info_ex"] or extended["wts_session_info"]
            extended["idle_duration"] = derive_idle_duration(
                preferred.get("times", {}) if isinstance(preferred, dict) else {},
                observation_completed,
            )
            sessions.append(record)
            wts_errors.extend(
                {
                    "category": "session_record_error",
                    "session_id": enumerated["session_id"],
                    "detail": error,
                }
                for error in record["errors"]
            )
    wts_status = (
        "failed"
        if raw_sessions is None
        else "partial"
        if wts_errors or not enumeration_complete
        or any(record["record_status"] != "success" for record in sessions)
        else "success"
    )

    lsa_started = now_provider()
    try:
        lsa_provider = lsa_provider or WindowsLsaProvider()
        lsa_collection = _collect_lsa_sessions(lsa_provider)
    except Exception as exc:
        lsa_collection = {
            "status": "failed",
            "enumeration_complete": False,
            "record_count": 0,
            "sessions": [],
            "errors": [_error_record(exc, operation="LSA provider initialization")],
        }
    lsa_ended = now_provider()
    lsa_collection["observed_at_utc"] = lsa_ended
    lsa_collection["observed_at_local"] = local_time_from_utc(lsa_ended)

    event_started = now_provider()
    try:
        event_provider = event_provider or WindowsSecurityEventProvider()
        event_collection = _collect_historical_events(event_provider)
    except Exception as exc:
        event_collection = {
            "status": "failed",
            "enumeration_complete": False,
            "record_count": 0,
            "events": [],
            "query": {
                "channel": "Security",
                "event_ids": list(HISTORICAL_EVENT_IDS),
                "time_range": "all retained matching events",
            },
            "errors": [
                _error_record(exc, operation="Security event provider initialization")
            ],
        }
    event_ended = now_provider()
    event_collection["collection_started_at_utc"] = event_started
    event_collection["collection_ended_at_utc"] = event_ended
    event_collection["collection_started_at_local"] = local_time_from_utc(
        event_started
    )
    event_collection["collection_ended_at_local"] = local_time_from_utc(
        event_ended
    )

    source_statuses = (
        wts_status,
        lsa_collection["status"],
        event_collection["status"],
    )
    if all(source_status == "failed" for source_status in source_statuses):
        status = "failed"
    elif any(source_status != "success" for source_status in source_statuses):
        status = "partial"
    else:
        status = "success"
    errors.extend(
        {"source": "current_wts_sessions", **error} for error in wts_errors
    )
    errors.extend(
        {"source": "current_lsa_sessions", **error}
        for error in lsa_collection["errors"]
    )
    errors.extend(
        {"source": "historical_security_events", **error}
        for error in event_collection["errors"]
    )
    ended = now_provider()
    record_counts = {
        "current_wts_sessions": len(sessions),
        "current_lsa_authentication_sessions": lsa_collection["record_count"],
        "historical_security_events": event_collection["record_count"],
    }
    return {
        "artifact_id": ARTIFACT_ID,
        "local_time_basis": LOCAL_TIME_BASIS,
        "collection_started_at_utc": started,
        "collection_started_at_local": local_time_from_utc(started),
        "collection_ended_at_utc": ended,
        "collection_ended_at_local": local_time_from_utc(ended),
        "scope": (
            "current local WTS sessions, current local LSA authentication sessions, "
            "and all matching historical logon/logoff events retained in the local Security log"
        ),
        "status": status,
        "providers": [
            {
                "name": "pywin32 win32ts.WTSEnumerateSessions",
                "role": "local WTS session enumeration",
            },
            {
                "name": "pywin32 win32ts.WTSQuerySessionInformation",
                "role": "individual documented WTS information classes",
                "information_classes": [
                    {"value": value, "name": name}
                    for value, name in QUERY_CLASSES
                    if value not in (WTS_SESSION_INFO, WTS_SESSION_INFO_EX)
                ],
            },
            {
                "name": "pywin32 win32ts.WTSGetActiveConsoleSessionId",
                "role": "active physical-console session identification",
            },
            {
                "name": "ctypes WTSQuerySessionInformationW/WTSFreeMemory",
                "role": "WTSINFO and WTSINFOEXW structures not decoded by installed pywin32",
                "information_classes": [
                    {"value": WTS_SESSION_INFO, "name": "WTSSessionInfo"},
                    {"value": WTS_SESSION_INFO_EX, "name": "WTSSessionInfoEx"},
                ],
            },
            {
                "name": "pywin32 win32security.LsaEnumerateLogonSessions",
                "role": "current local LSA authentication-session identifiers",
            },
            {
                "name": "pywin32 win32security.LsaGetLogonSessionData",
                "role": "current local LSA authentication-session details",
            },
            {
                "name": "ctypes wevtapi EvtQuery/EvtNext/EvtRender/EvtClose",
                "role": "retained historical local Security logon/logoff events",
                "event_ids": list(HISTORICAL_EVENT_IDS),
            },
        ],
        "windows_version": (
            {"major": version[0], "minor": version[1], "build": version[2]}
            if version is not None
            else None
        ),
        "enumeration_complete": enumeration_complete,
        "current_wts_status": wts_status,
        "active_console_session_id": active_console_id,
        "active_console_status": active_console_status,
        "current_lsa_sessions": lsa_collection,
        "historical_security_events": event_collection,
        "record_counts": record_counts,
        "record_count": sum(record_counts.values()),
        "sessions": sessions,
        "errors": errors,
        "limitations": _limitations(),
    }


def _limitations() -> list[str]:
    return [
        "Current WTS sessions, current LSA authentication sessions, and retained matching local Security log events are separate inventories with different identifiers and coverage.",
        "Historical events include only the selected logon/session event IDs still retained in the local Security channel; cleared, overwritten, unaudited, or inaccessible events cannot be recovered.",
        "A failed logon event is an authentication attempt, not an established session; event fields and correlation identifiers vary by event ID and Windows version.",
        "WTS session IDs may be reused and are not LSA authentication LUIDs or historical event identifiers.",
        "Each source is queried at a different time; the combined report is not an atomic snapshot.",
        "A disconnected session is not necessarily logged off, and an active state does not prove a person is using the keyboard.",
        "Client names and addresses are provider-reported metadata and do not prove authenticated device identity or a public Internet address.",
        "Client-address decoding is limited to documented AF_INET and AF_INET6 WTS_CLIENT_ADDRESS layouts; console protocol addresses are not interpreted as remote endpoints.",
        "Query permissions, audit policy, Security log retention, and operating-system/provider support can limit visible sessions or returned fields, even when launched elevated.",
        "LSA session enumeration reports currently existing authentication sessions; it is not historical. The Security event log is the historical source and reflects configured auditing and retention only.",
        "LSA provider fields containing password, credential, token, or secret data are deliberately excluded; no credentials or user tokens are requested.",
        "Traffic counters are session-level cumulative RDP metadata, not per-connection details or packet contents.",
    ]


def _format_json(value: Any, indent: int = 0) -> str:
    prefix = " " * indent
    if isinstance(value, dict):
        if not value:
            return "{}"
        entries = [
            f"{' ' * (indent + 2)}{json.dumps(str(key), ensure_ascii=False)}: "
            f"{_format_json(item, indent + 2)}"
            for key, item in value.items()
        ]
        return "{\n" + ",\n".join(entries) + "\n" + prefix + "}"
    if isinstance(value, list):
        if not value:
            return "[]"
        separator = ",\n\n" if all(isinstance(item, dict) for item in value) else ",\n"
        entries = [
            " " * (indent + 2) + _format_json(item, indent + 2)
            for item in value
        ]
        return "[\n" + separator.join(entries) + "\n" + prefix + "]"
    return json.dumps(value, ensure_ascii=False)


def _write_json(path: Path, document: dict[str, Any], overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = (_format_json(document) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
            temporary.unlink()
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _default_output_path(directory: Path = DEFAULT_OUTPUT_DIRECTORY) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    return directory / f"Logon Sessions-{stamp}.json"


def collect_logon_sessions(
    output_path: str | os.PathLike[str],
    *,
    overwrite: bool = False,
    provider: Any | None = None,
    lsa_provider: Any | None = None,
    event_provider: Any | None = None,
) -> dict[str, Any]:
    path = Path(output_path).expanduser().resolve()
    if path.exists() and path.is_dir():
        path = _default_output_path(path)
    if path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing JSON output: {path}")
    result = build_inventory(
        provider=provider,
        lsa_provider=lsa_provider,
        event_provider=event_provider,
    )
    result["output_path"] = str(path)
    _write_json(path, result, overwrite)
    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only local WTS and LSA session snapshot plus retained "
            "Security logon/session events."
        )
    )
    parser.add_argument(
        "--output",
        help="Destination JSON file or existing directory. Omit to prompt/use A42 folder.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacement of an existing JSON file.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    if args.output:
        output_path = Path(args.output.strip().strip('"'))
    elif sys.stdin.isatty():
        try:
            default = _default_output_path()
            response = input(
                f"Output JSON file or existing directory (press Enter for {default}): "
            ).strip().strip('"')
        except (EOFError, KeyboardInterrupt) as exc:
            print(f"A42 collection was not started: {exc}", file=sys.stderr)
            return EXIT_FAILURE
        output_path = Path(response) if response else default
    else:
        output_path = _default_output_path()
    try:
        result = collect_logon_sessions(output_path, overwrite=args.overwrite)
    except Exception as exc:
        print(f"A42 collection failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    print(
        "A42 collection "
        f"{result['status']}: {result['record_counts']['current_wts_sessions']} "
        "WTS sessions, "
        f"{result['record_counts']['current_lsa_authentication_sessions']} "
        "current LSA sessions, and "
        f"{result['record_counts']['historical_security_events']} historical events; "
        f"JSON: {result['output_path']}"
    )
    return {
        "success": EXIT_SUCCESS,
        "partial": EXIT_PARTIAL,
        "failed": EXIT_FAILURE,
    }.get(result["status"], EXIT_FAILURE)


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
