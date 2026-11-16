"""Read-only A23 inventory of Windows driver services and loaded modules."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import re
import stat
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

ARTIFACT_ID = "A23"
EXIT_SUCCESS = 0
EXIT_PARTIAL = 1
EXIT_FAILURE = 2

ERROR_ACCESS_DENIED = 5
ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_INVALID_PARAMETER = 87
ERROR_MORE_DATA = 234
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_MARKED_FOR_DELETE = 1072
ERROR_RESOURCE_DATA_NOT_FOUND = 1812
ERROR_RESOURCE_TYPE_NOT_FOUND = 1813
ERROR_RESOURCE_NAME_NOT_FOUND = 1814

SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_ENUMERATE_SERVICE = 0x0004
SERVICE_QUERY_CONFIG = 0x0001
SERVICE_QUERY_STATUS = 0x0004
SERVICE_DRIVER = 0x0000000B
SERVICE_RECOGNIZER_DRIVER = 0x00000008
SERVICE_STATE_ALL = 0x0003
SC_ENUM_PROCESS_INFO = 0

SERVICE_CONFIG_DESCRIPTION = 1
SERVICE_CONFIG_FAILURE_ACTIONS = 2
SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 3
SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4
SERVICE_CONFIG_SERVICE_SID_INFO = 5
SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 6
SERVICE_CONFIG_PRESHUTDOWN_INFO = 7
SERVICE_CONFIG_TRIGGER_INFO = 8
SERVICE_CONFIG_PREFERRED_NODE = 9
SERVICE_CONFIG_LAUNCH_PROTECTED = 12

SERVICE_TYPE_BITS = {
    0x00000001: "SERVICE_KERNEL_DRIVER",
    0x00000002: "SERVICE_FILE_SYSTEM_DRIVER",
    0x00000004: "SERVICE_ADAPTER_RESERVED",
    0x00000008: "SERVICE_RECOGNIZER_DRIVER",
    0x00000010: "SERVICE_WIN32_OWN_PROCESS",
    0x00000020: "SERVICE_WIN32_SHARE_PROCESS",
    0x00000100: "SERVICE_INTERACTIVE_PROCESS",
    0x00000200: "SERVICE_USER_SERVICE",
    0x00000400: "SERVICE_USERSERVICE_INSTANCE",
    0x00000800: "SERVICE_PKG_SERVICE",
}
SERVICE_STATE_LABELS = {
    1: "SERVICE_STOPPED",
    2: "SERVICE_START_PENDING",
    3: "SERVICE_STOP_PENDING",
    4: "SERVICE_RUNNING",
    5: "SERVICE_CONTINUE_PENDING",
    6: "SERVICE_PAUSE_PENDING",
    7: "SERVICE_PAUSED",
}
START_TYPE_LABELS = {
    0: "SERVICE_BOOT_START",
    1: "SERVICE_SYSTEM_START",
    2: "SERVICE_AUTO_START",
    3: "SERVICE_DEMAND_START",
    4: "SERVICE_DISABLED",
}
ERROR_CONTROL_LABELS = {
    0: "SERVICE_ERROR_IGNORE",
    1: "SERVICE_ERROR_NORMAL",
    2: "SERVICE_ERROR_SEVERE",
    3: "SERVICE_ERROR_CRITICAL",
}
CONTROL_BITS = {
    0x0001: "SERVICE_ACCEPT_STOP",
    0x0002: "SERVICE_ACCEPT_PAUSE_CONTINUE",
    0x0004: "SERVICE_ACCEPT_SHUTDOWN",
    0x0008: "SERVICE_ACCEPT_PARAMCHANGE",
    0x0010: "SERVICE_ACCEPT_NETBINDCHANGE",
    0x0020: "SERVICE_ACCEPT_HARDWAREPROFILECHANGE",
    0x0040: "SERVICE_ACCEPT_POWEREVENT",
    0x0080: "SERVICE_ACCEPT_SESSIONCHANGE",
    0x0100: "SERVICE_ACCEPT_PRESHUTDOWN",
    0x0200: "SERVICE_ACCEPT_TIMECHANGE",
    0x0400: "SERVICE_ACCEPT_TRIGGEREVENT",
    0x0800: "SERVICE_ACCEPT_USER_LOGOFF",
    0x1000: "SERVICE_ACCEPT_LOWRESOURCES",
    0x2000: "SERVICE_ACCEPT_SYSTEMLOWRESOURCES",
}
SERVICE_FLAG_BITS = {0x0001: "SERVICE_RUNS_IN_SYSTEM_PROCESS"}
SERVICE_SID_TYPE_LABELS = {
    0: "SERVICE_SID_TYPE_NONE",
    1: "SERVICE_SID_TYPE_UNRESTRICTED",
    3: "SERVICE_SID_TYPE_RESTRICTED",
}
TRIGGER_TYPE_LABELS = {
    1: "SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL",
    2: "SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY",
    3: "SERVICE_TRIGGER_TYPE_DOMAIN_JOIN",
    4: "SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT",
    5: "SERVICE_TRIGGER_TYPE_GROUP_POLICY",
    6: "SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT",
    20: "SERVICE_TRIGGER_TYPE_CUSTOM",
}
TRIGGER_ACTION_LABELS = {
    1: "SERVICE_TRIGGER_ACTION_SERVICE_START",
    2: "SERVICE_TRIGGER_ACTION_SERVICE_STOP",
}
TRIGGER_DATA_TYPE_LABELS = {
    1: "SERVICE_TRIGGER_DATA_TYPE_BINARY",
    2: "SERVICE_TRIGGER_DATA_TYPE_STRING",
    3: "SERVICE_TRIGGER_DATA_TYPE_LEVEL",
    4: "SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY",
    5: "SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL",
}
FAILURE_ACTION_LABELS = {
    0: "SC_ACTION_NONE",
    1: "SC_ACTION_RESTART",
    2: "SC_ACTION_REBOOT",
    3: "SC_ACTION_RUN_COMMAND",
}
LAUNCH_PROTECTION_LABELS = {
    0: "SERVICE_LAUNCH_PROTECTED_NONE",
    1: "SERVICE_LAUNCH_PROTECTED_WINDOWS",
    2: "SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT",
    3: "SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT",
}
CONFIGURATION_LEVELS = {
    "description": SERVICE_CONFIG_DESCRIPTION,
    "failure_actions": SERVICE_CONFIG_FAILURE_ACTIONS,
    "delayed_auto_start": SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
    "failure_actions_on_non_crash": SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
    "service_sid_type": SERVICE_CONFIG_SERVICE_SID_INFO,
    "required_privileges": SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
    "preshutdown_timeout_ms": SERVICE_CONFIG_PRESHUTDOWN_INFO,
    "trigger_info": SERVICE_CONFIG_TRIGGER_INFO,
    "preferred_node": SERVICE_CONFIG_PREFERRED_NODE,
    "launch_protection": SERVICE_CONFIG_LAUNCH_PROTECTED,
}
OPTIONAL_CONFIG_ERRORS = {
    ERROR_INVALID_PARAMETER,
    50,   # ERROR_NOT_SUPPORTED
    120,  # ERROR_CALL_NOT_IMPLEMENTED
    124,  # ERROR_INVALID_LEVEL
}
MAX_ENUM_BUFFER = 256 * 1024
MAX_CONFIG_BUFFER = 1024 * 1024
MAX_PSAPI_MODULES = 65536
MAX_PSAPI_STRING = 32768


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
        "collection_started_at_utc": started.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        ),
        "collection_ended_at_utc": ended.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        ),
        "collection_started_at_local": started.astimezone().isoformat(
            timespec="microseconds"
        ),
        "collection_ended_at_local": ended.astimezone().isoformat(
            timespec="microseconds"
        ),
        "collection_time_zone_id": timezone_id,
        "collection_time_zone_id_source": timezone_id_source,
        "collection_time_zone_id_error": timezone_id_error,
        "collection_clock_adjusted": clock_adjusted,
    }


def numeric_value(value: Any, labels: dict[int, str]) -> dict[str, Any]:
    number = int(value)
    return {"value": number, "label": labels.get(number, f"UNKNOWN_{number}")}


def flags_value(value: Any, known_bits: dict[int, str]) -> dict[str, Any]:
    number = int(value)
    labels = [label for bit, label in known_bits.items() if number & bit]
    known_mask = 0
    for bit in known_bits:
        known_mask |= bit
    return {
        "value": number,
        "labels": labels,
        "unknown_bits": number & ~known_mask,
    }


def classify_error(exc: BaseException) -> dict[str, Any]:
    code = getattr(exc, "winerror", None)
    if code is None and getattr(exc, "args", None):
        first = exc.args[0]
        if isinstance(first, int):
            code = first
    if code == ERROR_ACCESS_DENIED:
        category = "access_denied"
    elif code in {ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE}:
        category = "disappeared"
    elif code in {ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND}:
        category = "not_found"
    elif code in OPTIONAL_CONFIG_ERRORS:
        category = "unsupported"
    elif code in {ERROR_RESOURCE_DATA_NOT_FOUND, ERROR_RESOURCE_TYPE_NOT_FOUND,
                  ERROR_RESOURCE_NAME_NOT_FOUND}:
        category = "version_resource_not_present"
    else:
        category = "provider_api_failure"
    return {
        "category": category,
        "winerror": code,
        "exception_type": type(exc).__name__,
        "message": str(exc),
    }


def paginate_service_pages(
    read_page: Callable[
        [int, int], tuple[bool, int, int, int, list[dict[str, Any]]]
    ],
    initial_buffer_size: int = 64 * 1024,
    maximum_buffer_size: int = MAX_ENUM_BUFFER,
) -> tuple[list[dict[str, Any]], bool, list[dict[str, Any]]]:
    """Read all EnumServicesStatusEx pages while retaining returned partial rows."""
    records: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    resume_handle = 0
    buffer_size = initial_buffer_size
    page_count = 0
    while page_count < 10000:
        page_count += 1
        previous_resume = resume_handle
        try:
            success, error_code, bytes_needed, next_resume, page = read_page(
                buffer_size, resume_handle
            )
        except Exception as exc:
            errors.append(classify_error(exc))
            return records, False, errors
        records.extend(page)
        resume_handle = next_resume
        if success:
            return records, True, errors
        if error_code != ERROR_MORE_DATA:
            errors.append(
                {
                    "category": "provider_api_failure",
                    "winerror": error_code,
                    "message": (
                        "EnumServicesStatusExW failed with Win32 error "
                        f"{error_code}."
                    ),
                }
            )
            return records, False, errors
        if resume_handle == previous_resume and not page:
            if buffer_size >= maximum_buffer_size:
                errors.append(
                    {
                        "category": "provider_api_failure",
                        "winerror": ERROR_MORE_DATA,
                        "message": (
                            "Driver-service enumeration made no progress at "
                            "the maximum buffer size."
                        ),
                    }
                )
                return records, False, errors
            buffer_size = min(
                maximum_buffer_size,
                max(buffer_size * 2, bytes_needed),
            )
        else:
            buffer_size = min(
                maximum_buffer_size,
                max(initial_buffer_size, bytes_needed),
            )
    errors.append(
        {
            "category": "provider_api_failure",
            "winerror": None,
            "message": "Driver-service enumeration exceeded the page safety limit.",
        }
    )
    return records, False, errors


class _ServiceStatusProcess(ctypes.Structure):
    _fields_ = [
        ("service_type", ctypes.c_uint32),
        ("current_state", ctypes.c_uint32),
        ("controls_accepted", ctypes.c_uint32),
        ("win32_exit_code", ctypes.c_uint32),
        ("service_specific_exit_code", ctypes.c_uint32),
        ("checkpoint", ctypes.c_uint32),
        ("wait_hint", ctypes.c_uint32),
        ("process_id", ctypes.c_uint32),
        ("service_flags", ctypes.c_uint32),
    ]


class _EnumServiceStatusProcess(ctypes.Structure):
    _fields_ = [
        ("service_name", ctypes.c_void_p),
        ("display_name", ctypes.c_void_p),
        ("status", _ServiceStatusProcess),
    ]


class _ServiceDescription(ctypes.Structure):
    _fields_ = [("description", ctypes.c_void_p)]


class _ServiceFailureAction(ctypes.Structure):
    _fields_ = [("action_type", ctypes.c_uint32), ("delay_ms", ctypes.c_uint32)]


class _ServiceFailureActions(ctypes.Structure):
    _fields_ = [
        ("reset_period_seconds", ctypes.c_uint32),
        ("reboot_message", ctypes.c_void_p),
        ("command", ctypes.c_void_p),
        ("action_count", ctypes.c_uint32),
        ("actions", ctypes.POINTER(_ServiceFailureAction)),
    ]


class _ServiceDwordInfo(ctypes.Structure):
    _fields_ = [("value", ctypes.c_uint32)]


class _Guid(ctypes.Structure):
    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    ]


class _ServiceTriggerDataItem(ctypes.Structure):
    _fields_ = [
        ("data_type", ctypes.c_uint32),
        ("data_size", ctypes.c_uint32),
        ("data", ctypes.c_void_p),
    ]


class _ServiceTrigger(ctypes.Structure):
    _fields_ = [
        ("trigger_type", ctypes.c_uint32),
        ("action", ctypes.c_uint32),
        ("subtype", ctypes.POINTER(_Guid)),
        ("data_item_count", ctypes.c_uint32),
        ("data_items", ctypes.POINTER(_ServiceTriggerDataItem)),
    ]


class _ServiceTriggerInfo(ctypes.Structure):
    _fields_ = [
        ("trigger_count", ctypes.c_uint32),
        ("triggers", ctypes.POINTER(_ServiceTrigger)),
        ("reserved", ctypes.c_void_p),
    ]


class _PreferredNodeInfo(ctypes.Structure):
    _fields_ = [
        ("preferred_node", ctypes.c_uint16),
        ("delete_preference", ctypes.c_ubyte),
    ]


def _read_buffer_wstring(
    pointer: int | None, buffer: ctypes.Array[Any], buffer_size: int
) -> str | None:
    if not pointer:
        return None
    base = ctypes.addressof(buffer)
    end = base + buffer_size
    address = int(pointer)
    if address < base or address >= end:
        raise ValueError("A Windows API string pointer was outside its result buffer.")
    char_count = (end - address) // ctypes.sizeof(ctypes.c_wchar)
    wide = ctypes.cast(address, ctypes.POINTER(ctypes.c_wchar))
    for index in range(char_count):
        if wide[index] == "\0":
            return ctypes.wstring_at(address, index)
    raise ValueError("A Windows API string was not terminated inside its result buffer.")


def _read_multisz(
    pointer: int | None, buffer: ctypes.Array[Any], buffer_size: int
) -> list[str] | None:
    if not pointer:
        return None
    base = ctypes.addressof(buffer)
    end = base + buffer_size
    address = int(pointer)
    if address < base or address >= end:
        raise ValueError("A Windows API MULTI_SZ pointer was outside its result buffer.")
    char_count = (end - address) // ctypes.sizeof(ctypes.c_wchar)
    wide = ctypes.cast(address, ctypes.POINTER(ctypes.c_wchar))
    result: list[str] = []
    current: list[str] = []
    for index in range(char_count):
        character = wide[index]
        if character == "\0":
            if not current:
                return result
            result.append("".join(current))
            current = []
        else:
            current.append(character)
    raise ValueError("A Windows API MULTI_SZ was not terminated inside its result buffer.")


def _pointer_in_buffer(pointer: int, buffer: ctypes.Array[Any], size: int, length: int) -> bool:
    base = ctypes.addressof(buffer)
    return base <= pointer and pointer + length <= base + size


def _format_guid(value: _Guid) -> str:
    data = ctypes.string_at(ctypes.byref(value), ctypes.sizeof(value))
    import uuid

    return str(uuid.UUID(bytes_le=data))


def _normalise_config2_buffer(
    level: int, buffer: ctypes.Array[Any], buffer_size: int
) -> Any:
    if level == SERVICE_CONFIG_DESCRIPTION:
        value = ctypes.cast(buffer, ctypes.POINTER(_ServiceDescription)).contents
        return _read_buffer_wstring(value.description, buffer, buffer_size)
    if level == SERVICE_CONFIG_FAILURE_ACTIONS:
        value = ctypes.cast(buffer, ctypes.POINTER(_ServiceFailureActions)).contents
        if value.action_count > 4096:
            raise ValueError("Failure-action count exceeded the safety limit.")
        action_bytes = value.action_count * ctypes.sizeof(_ServiceFailureAction)
        if value.action_count and (
            not value.actions
            or not _pointer_in_buffer(
                ctypes.addressof(value.actions.contents),
                buffer,
                buffer_size,
                action_bytes,
            )
        ):
            raise ValueError("Failure-action array was outside its result buffer.")
        return {
            "reset_period_seconds": int(value.reset_period_seconds),
            "reboot_message": _read_buffer_wstring(
                value.reboot_message, buffer, buffer_size
            ),
            "command": _read_buffer_wstring(value.command, buffer, buffer_size),
            "actions": [
                {
                    "type": numeric_value(item.action_type, FAILURE_ACTION_LABELS),
                    "delay_ms": int(item.delay_ms),
                }
                for item in (
                    value.actions[index] for index in range(value.action_count)
                )
            ],
        }
    if level in {
        SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
        SERVICE_CONFIG_SERVICE_SID_INFO,
        SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
        SERVICE_CONFIG_PRESHUTDOWN_INFO,
    }:
        if level == SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO:
            pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value
            return _read_multisz(pointer, buffer, buffer_size)
        number = ctypes.cast(buffer, ctypes.POINTER(_ServiceDwordInfo)).contents.value
        if level in {
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
        }:
            return bool(number)
        if level == SERVICE_CONFIG_SERVICE_SID_INFO:
            return numeric_value(number, SERVICE_SID_TYPE_LABELS)
        return int(number)
    if level == SERVICE_CONFIG_TRIGGER_INFO:
        info = ctypes.cast(buffer, ctypes.POINTER(_ServiceTriggerInfo)).contents
        if info.trigger_count > 4096:
            raise ValueError("Trigger count exceeded the safety limit.")
        trigger_bytes = info.trigger_count * ctypes.sizeof(_ServiceTrigger)
        if info.trigger_count and (
            not info.triggers
            or not _pointer_in_buffer(
                ctypes.addressof(info.triggers.contents),
                buffer,
                buffer_size,
                trigger_bytes,
            )
        ):
            raise ValueError("Trigger array was outside its result buffer.")
        triggers: list[dict[str, Any]] = []
        for index in range(info.trigger_count):
            trigger = info.triggers[index]
            if trigger.data_item_count > 4096:
                raise ValueError("Trigger data-item count exceeded the safety limit.")
            data_bytes = (
                trigger.data_item_count * ctypes.sizeof(_ServiceTriggerDataItem)
            )
            if trigger.data_item_count and (
                not trigger.data_items
                or not _pointer_in_buffer(
                    ctypes.addressof(trigger.data_items.contents),
                    buffer,
                    buffer_size,
                    data_bytes,
                )
            ):
                raise ValueError("Trigger data array was outside its result buffer.")
            subtype = None
            if trigger.subtype:
                subtype_address = ctypes.addressof(trigger.subtype.contents)
                if not _pointer_in_buffer(
                    subtype_address, buffer, buffer_size, ctypes.sizeof(_Guid)
                ):
                    raise ValueError("Trigger subtype GUID was outside its result buffer.")
                subtype = _format_guid(trigger.subtype.contents)
            data_items: list[dict[str, Any]] = []
            for item_index in range(trigger.data_item_count):
                item = trigger.data_items[item_index]
                if item.data_size > MAX_CONFIG_BUFFER:
                    raise ValueError("Trigger data item exceeded the safety limit.")
                raw = b""
                if item.data_size:
                    if not item.data or not _pointer_in_buffer(
                        int(item.data), buffer, buffer_size, item.data_size
                    ):
                        raise ValueError(
                            "Trigger data pointer was outside its result buffer."
                        )
                    raw = ctypes.string_at(item.data, item.data_size)
                data_items.append(
                    {
                        "data_type": numeric_value(
                            item.data_type, TRIGGER_DATA_TYPE_LABELS
                        ),
                        "data_size_bytes": int(item.data_size),
                        "data_hex": raw.hex(),
                    }
                )
            triggers.append(
                {
                    "trigger_type": numeric_value(
                        trigger.trigger_type, TRIGGER_TYPE_LABELS
                    ),
                    "action": numeric_value(trigger.action, TRIGGER_ACTION_LABELS),
                    "subtype_guid": subtype,
                    "data_items": data_items,
                }
            )
        return {"trigger_count": int(info.trigger_count), "triggers": triggers}
    if level == SERVICE_CONFIG_PREFERRED_NODE:
        info = ctypes.cast(buffer, ctypes.POINTER(_PreferredNodeInfo)).contents
        return {
            "preferred_node": int(info.preferred_node),
            "delete_preference": bool(info.delete_preference),
        }
    if level == SERVICE_CONFIG_LAUNCH_PROTECTED:
        number = ctypes.cast(buffer, ctypes.POINTER(_ServiceDwordInfo)).contents.value
        return numeric_value(number, LAUNCH_PROTECTION_LABELS)
    raise ValueError(f"Unsupported QueryServiceConfig2 information level: {level}")


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return str(value)


class WindowsScmProvider:
    """SCM adapter using documented service-enumeration and query APIs."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("A23 collection requires Windows.")
        import win32service

        self.win32service = win32service
        self.advapi32 = ctypes.WinDLL("Advapi32", use_last_error=True)
        self.advapi32.EnumServicesStatusExW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_wchar_p,
        ]
        self.advapi32.EnumServicesStatusExW.restype = ctypes.c_int
        self.advapi32.QueryServiceConfig2W.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self.advapi32.QueryServiceConfig2W.restype = ctypes.c_int
        rights = SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT
        self.scm = win32service.OpenSCManager(None, None, rights)

    def close(self) -> None:
        if self.scm is not None:
            scm, self.scm = self.scm, None
            self.win32service.CloseServiceHandle(scm)

    def _read_enum_page(
        self, service_type_filter: int, buffer_size: int, resume_handle: int
    ) -> tuple[bool, int, int, int, list[dict[str, Any]]]:
        buffer = ctypes.create_string_buffer(buffer_size)
        bytes_needed = ctypes.c_uint32()
        services_returned = ctypes.c_uint32()
        resume = ctypes.c_uint32(resume_handle)
        ctypes.set_last_error(0)
        succeeded = self.advapi32.EnumServicesStatusExW(
            ctypes.c_void_p(int(self.scm.handle)),
            SC_ENUM_PROCESS_INFO,
            service_type_filter,
            SERVICE_STATE_ALL,
            ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
            buffer_size,
            ctypes.byref(bytes_needed),
            ctypes.byref(services_returned),
            ctypes.byref(resume),
            None,
        )
        error_code = 0 if succeeded else ctypes.get_last_error()
        records: list[dict[str, Any]] = []
        base = ctypes.addressof(buffer)
        record_size = ctypes.sizeof(_EnumServiceStatusProcess)
        if services_returned.value * record_size > buffer_size:
            raise ValueError("SCM returned more records than fit in the enumeration buffer.")
        entries = ctypes.cast(
            buffer, ctypes.POINTER(_EnumServiceStatusProcess)
        )
        for index in range(services_returned.value):
            address = base + index * record_size
            if not _pointer_in_buffer(address, buffer, buffer_size, record_size):
                raise ValueError("SCM record was outside the enumeration buffer.")
            entry = entries[index]
            status = entry.status
            records.append(
                {
                    "service_name": _read_buffer_wstring(
                        entry.service_name, buffer, buffer_size
                    ),
                    "display_name": _read_buffer_wstring(
                        entry.display_name, buffer, buffer_size
                    ),
                    "service_type": int(status.service_type),
                    "current_state": int(status.current_state),
                    "controls_accepted": int(status.controls_accepted),
                    "win32_exit_code": int(status.win32_exit_code),
                    "service_specific_exit_code": int(
                        status.service_specific_exit_code
                    ),
                    "checkpoint": int(status.checkpoint),
                    "wait_hint_ms": int(status.wait_hint),
                    "process_id": int(status.process_id),
                    "service_flags": int(status.service_flags),
                }
            )
        return (
            bool(succeeded),
            int(error_code),
            int(bytes_needed.value),
            int(resume.value),
            records,
        )

    def enumerate_services(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        filters = [
            ("SERVICE_DRIVER", SERVICE_DRIVER),
            ("SERVICE_RECOGNIZER_DRIVER", SERVICE_RECOGNIZER_DRIVER),
        ]
        by_name: dict[str, dict[str, Any]] = {}
        filter_results: list[dict[str, Any]] = []
        for filter_name, filter_value in filters:
            records, complete, errors = paginate_service_pages(
                lambda size, resume: self._read_enum_page(
                    filter_value, size, resume
                )
            )
            for record in records:
                key = record["service_name"].casefold()
                existing = by_name.get(key)
                if existing is None:
                    record["enumeration_type_filters"] = [filter_name]
                    by_name[key] = record
                elif filter_name not in existing["enumeration_type_filters"]:
                    existing["enumeration_type_filters"].append(filter_name)
            filter_results.append(
                {
                    "service_type_filter": filter_name,
                    "service_type_filter_value": filter_value,
                    "status": "success" if complete else "partial",
                    "enumeration_complete": complete,
                    "records_returned": len(records),
                    "errors": errors,
                }
            )
        complete = all(item["enumeration_complete"] for item in filter_results)
        return list(by_name.values()), {
            "provider": "Windows Service Control Manager",
            "api": "EnumServicesStatusExW",
            "attempted": True,
            "status": "success" if complete else "partial",
            "enumeration_complete": complete,
            "service_state_filter": "SERVICE_STATE_ALL",
            "service_type_filters": filter_results,
            "records_returned": len(by_name),
            "errors": [
                error
                for item in filter_results
                for error in item["errors"]
            ],
        }

    def _query_config2(self, service: Any, level: int) -> Any:
        needed = ctypes.c_uint32()
        ctypes.set_last_error(0)
        first_ok = self.advapi32.QueryServiceConfig2W(
            ctypes.c_void_p(int(service.handle)),
            level,
            None,
            0,
            ctypes.byref(needed),
        )
        first_error = 0 if first_ok else ctypes.get_last_error()
        if first_ok:
            raise OSError(
                "QueryServiceConfig2W unexpectedly succeeded with a null output buffer."
            )
        if first_error not in {ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA}:
            error = OSError(first_error, ctypes.FormatError(first_error))
            setattr(error, "query_phase", "buffer_size_probe")
            raise error
        buffer_size = max(needed.value, 1)
        while buffer_size <= MAX_CONFIG_BUFFER:
            buffer = ctypes.create_string_buffer(buffer_size)
            ctypes.set_last_error(0)
            succeeded = self.advapi32.QueryServiceConfig2W(
                ctypes.c_void_p(int(service.handle)),
                level,
                ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
                buffer_size,
                ctypes.byref(needed),
            )
            if succeeded:
                return _normalise_config2_buffer(level, buffer, buffer_size)
            error_code = ctypes.get_last_error()
            if error_code not in {ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA}:
                error = OSError(error_code, ctypes.FormatError(error_code))
                setattr(error, "query_phase", "buffer_read")
                raise error
            next_size = max(int(needed.value), buffer_size * 2)
            if next_size <= buffer_size:
                break
            buffer_size = next_size
        raise OSError(
            ERROR_INSUFFICIENT_BUFFER,
            "QueryServiceConfig2W exceeded the 1 MiB safety limit.",
        )

    def query_service(self, service_name: str) -> dict[str, Any]:
        record: dict[str, Any] = {
            "status": None,
            "configuration": None,
            "extended_configuration": {},
            "errors": [],
        }
        service = None
        try:
            service = self.win32service.OpenService(
                self.scm,
                service_name,
                SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
            )
        except Exception as exc:
            record["errors"].append(
                {"field": "open_service", **classify_error(exc)}
            )
            return record
        try:
            try:
                raw_status = self.win32service.QueryServiceStatusEx(service)
                record["status"] = {
                    "service_type": int(raw_status["ServiceType"]),
                    "current_state": int(raw_status["CurrentState"]),
                    "controls_accepted": int(raw_status["ControlsAccepted"]),
                    "win32_exit_code": int(raw_status["Win32ExitCode"]),
                    "service_specific_exit_code": int(
                        raw_status["ServiceSpecificExitCode"]
                    ),
                    "checkpoint": int(raw_status["CheckPoint"]),
                    "wait_hint_ms": int(raw_status["WaitHint"]),
                    "process_id": int(raw_status["ProcessId"]),
                    "service_flags": int(raw_status["ServiceFlags"]),
                }
            except Exception as exc:
                record["errors"].append(
                    {"field": "status", **classify_error(exc)}
                )
            try:
                config = self.win32service.QueryServiceConfig(service)
                if len(config) < 9:
                    raise ValueError(
                        "QueryServiceConfig returned fewer than nine fields."
                    )
                (
                    service_type,
                    start_type,
                    error_control,
                    binary_path,
                    load_order_group,
                    tag_id,
                    dependencies,
                    service_account,
                    config_display_name,
                ) = config[:9]
                record["configuration"] = {
                    "service_type": int(service_type),
                    "start_type": int(start_type),
                    "error_control": int(error_control),
                    "binary_path_command": binary_path,
                    "load_order_group": load_order_group,
                    "tag_id": tag_id,
                    "dependencies": (
                        list(dependencies) if dependencies is not None else None
                    ),
                    "configured_account": service_account,
                    "display_name_from_configuration": config_display_name,
                }
            except Exception as exc:
                record["errors"].append(
                    {"field": "configuration", **classify_error(exc)}
                )
            for field_name, level in CONFIGURATION_LEVELS.items():
                try:
                    value = self._query_config2(service, level)
                    status = (
                        "not_configured"
                        if value is None or value == []
                        else "available"
                    )
                    record["extended_configuration"][field_name] = {
                        "status": status,
                        "value": _json_safe(value),
                    }
                except Exception as exc:
                    error = classify_error(exc)
                    if (
                        field_name == "preferred_node"
                        and error["winerror"] == ERROR_INVALID_PARAMETER
                    ):
                        error["diagnostic"] = {
                            "api": "QueryServiceConfig2W",
                            "information_level": SERVICE_CONFIG_PREFERRED_NODE,
                            "information_level_name": "SERVICE_CONFIG_PREFERRED_NODE",
                            "failed_call": getattr(exc, "query_phase", None),
                            "structure": (
                                "_PreferredNodeInfo contains a USHORT preferred "
                                "node followed by a one-byte BOOLEAN delete flag; "
                                "it is decoded only after QueryServiceConfig2W succeeds."
                            ),
                            "interpretation": (
                                "Windows returned ERROR_INVALID_PARAMETER from "
                                "the QueryServiceConfig2W request. This excludes "
                                "the post-call structure decoder as the source, "
                                "but this error alone does not establish whether "
                                "the service or provider rejects this information "
                                "level."
                            ),
                        }
                    field_status = (
                        "unsupported"
                        if error["category"] == "unsupported"
                        else "query_failed"
                    )
                    record["extended_configuration"][field_name] = {
                        "status": field_status,
                        "value": None,
                    }
                    record["errors"].append(
                        {"field": field_name, **error}
                    )
        finally:
            try:
                self.win32service.CloseServiceHandle(service)
            except Exception as exc:
                record["errors"].append(
                    {"field": "close_service_handle", **classify_error(exc)}
                )
        return record


def _query_dos_device(device_name: str) -> list[str]:
    if os.name != "nt":
        return []
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel32.QueryDosDeviceW
    query.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    query.restype = ctypes.c_uint32
    size = 1024
    while size <= 65536:
        buffer = ctypes.create_unicode_buffer(size)
        ctypes.set_last_error(0)
        length = query(device_name, buffer, size)
        if length:
            return [item for item in buffer[:length].split("\0") if item]
        error_code = ctypes.get_last_error()
        if error_code != ERROR_INSUFFICIENT_BUFFER:
            return []
        size *= 2
    return []


def _dos_device_mappings() -> dict[str, list[str]]:
    mappings: dict[str, list[str]] = {}
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        device = f"{letter}:"
        targets = _query_dos_device(device)
        if targets:
            mappings[device] = targets
    return mappings


def _extract_image_candidate(original_path: str) -> str:
    value = original_path.strip()
    if value.startswith('"'):
        closing = value.find('"', 1)
        if closing > 0:
            return value[1:closing]
    extension = re.search(r"(?i)\.(?:sys|dll|exe)(?=\s|$)", value)
    if extension:
        return value[: extension.end()]
    return value


def _expand_windows_environment(value: str, environ: dict[str, str]) -> str:
    folded = {name.casefold(): content for name, content in environ.items()}
    return re.sub(
        r"%([^%]+)%",
        lambda match: folded.get(match.group(1).casefold(), match.group(0)),
        value,
    )


def resolve_driver_path(
    original_path: str | None,
    environ: dict[str, str] | None = None,
    system_root: str | None = None,
    dos_device_map: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Resolve known Windows image-path forms without guessing device mappings."""
    if not original_path or not original_path.strip():
        return {
            "status": "not_configured",
            "method": None,
            "candidate_path": None,
            "reason": "No original image path was returned.",
        }
    env = os.environ if environ is None else environ
    system_root = system_root or env.get("SystemRoot") or env.get("windir")
    raw_candidate = _extract_image_candidate(original_path)
    if raw_candidate.casefold().startswith("\\\\?\\unc\\") or (
        raw_candidate.startswith("\\\\")
        and not re.match(r"(?i)^\\\\\?\\[a-z]:\\", raw_candidate)
    ):
        return {
            "status": "network_path_not_inspected",
            "method": None,
            "candidate_path": None,
            "reason": "UNC/network paths are not inspected.",
        }
    if raw_candidate.casefold().startswith("\\\\?\\"):
        if re.match(r"(?i)^\\\\\?\\[a-z]:\\", raw_candidate):
            return {
                "status": "resolved",
                "method": "extended_local_path",
                "candidate_path": _expand_windows_environment(raw_candidate, env),
                "reason": None,
            }
        return {
            "status": "unresolved",
            "method": None,
            "candidate_path": None,
            "reason": "Unsupported Windows extended/device path form.",
        }

    candidate = raw_candidate
    method = "absolute_dos_path"
    if candidate.casefold().startswith("\\systemroot\\"):
        if not system_root:
            return {
                "status": "unresolved",
                "method": None,
                "candidate_path": None,
                "reason": "SystemRoot is unavailable for the \\SystemRoot path.",
            }
        candidate = os.path.join(system_root, candidate[len("\\SystemRoot\\"):])
        method = "systemroot_mapping"

    candidate = _expand_windows_environment(candidate, env)
    if "%" in candidate:
        return {
            "status": "unresolved",
            "method": None,
            "candidate_path": None,
            "reason": "An environment variable in the image path was not resolved.",
        }

    mappings = dos_device_map if dos_device_map is not None else _dos_device_mappings()
    if candidate.casefold().startswith("\\??\\"):
        native = candidate[4:]
        drive_match = re.match(r"(?i)^([a-z]:)(\\.*)?$", native)
        if drive_match:
            drive = drive_match.group(1).upper()
            if drive not in {key.upper() for key in mappings}:
                return {
                    "status": "unresolved",
                    "method": None,
                    "candidate_path": None,
                    "reason": (
                        f"QueryDosDevice did not confirm a mapping for {drive}."
                    ),
                }
            candidate = drive + (drive_match.group(2) or "\\")
            method = "query_dos_device_verified_nt_dos_path"
        elif native.casefold().startswith("unc\\"):
            return {
                "status": "network_path_not_inspected",
                "method": None,
                "candidate_path": None,
                "reason": "Native UNC/network paths are not inspected.",
            }
        else:
            candidate = "\\" + native.lstrip("\\")

    if candidate.casefold().startswith("\\device\\"):
        matches: list[tuple[int, str, str]] = []
        for drive, targets in mappings.items():
            for target in targets:
                target_normalized = target.rstrip("\\")
                if candidate.casefold().startswith(
                    target_normalized.casefold() + "\\"
                ):
                    matches.append(
                        (len(target_normalized), drive, candidate[len(target_normalized):])
                    )
        if not matches:
            return {
                "status": "unresolved",
                "method": None,
                "candidate_path": None,
                "reason": "No QueryDosDevice drive mapping matched the device path.",
            }
        _, drive, suffix = max(matches)
        candidate = drive + suffix
        method = "query_dos_device_reverse_mapping"

    drive, tail = os.path.splitdrive(candidate)
    if not drive or not tail.startswith(("\\", "/")):
        return {
            "status": "unresolved",
            "method": None,
            "candidate_path": None,
            "reason": "The image path is relative or uses an unsupported device form.",
        }
    if drive.startswith("\\\\"):
        return {
            "status": "network_path_not_inspected",
            "method": None,
            "candidate_path": None,
            "reason": "UNC/network paths are not inspected.",
        }
    return {
        "status": "resolved",
        "method": method,
        "candidate_path": os.path.normpath(candidate),
        "reason": None,
    }


def _version_text(high: int, low: int) -> str:
    return ".".join(
        str(part)
        for part in (
            (high >> 16) & 0xFFFF,
            high & 0xFFFF,
            (low >> 16) & 0xFFFF,
            low & 0xFFFF,
        )
    )


def _read_version_info(path: str) -> dict[str, Any]:
    try:
        import win32api
    except ImportError as exc:
        return {
            "status": "dependency_unavailable",
            "string_resources_status": "not_checked",
            "file_version": None,
            "product_version": None,
            "company_name": None,
            "product_name": None,
            "original_filename": None,
            "string_errors": [],
            "error": classify_error(exc),
        }
    try:
        fixed = win32api.GetFileVersionInfo(path, "\\")
    except Exception as exc:
        error = classify_error(exc)
        if error["category"] == "version_resource_not_present":
            status = "not_present"
            error_value = None
        else:
            status = "query_failed"
            error_value = error
        return {
            "status": status,
            "string_resources_status": (
                "not_present"
                if status == "not_present"
                else "not_checked"
            ),
            "file_version": None,
            "product_version": None,
            "company_name": None,
            "product_name": None,
            "original_filename": None,
            "string_errors": [],
            "error": error_value,
        }
    translations: Iterable[tuple[int, int]] = ()
    string_errors: list[dict[str, Any]] = []
    try:
        queried_translations = win32api.GetFileVersionInfo(
            path, r"\VarFileInfo\Translation"
        )
        if isinstance(queried_translations, (tuple, list)):
            translations = queried_translations
    except Exception as exc:
        error = classify_error(exc)
        if error["category"] != "version_resource_not_present":
            string_errors.append({"field": "translations", **error})
    strings: dict[str, str | None] = {
        "company_name": None,
        "product_name": None,
        "original_filename": None,
    }
    for language, code_page in translations:
        for output_name, resource_name in (
            ("company_name", "CompanyName"),
            ("product_name", "ProductName"),
            ("original_filename", "OriginalFilename"),
        ):
            if strings[output_name] is not None:
                continue
            query = (
                rf"\StringFileInfo\{int(language):04x}{int(code_page):04x}"
                rf"\{resource_name}"
            )
            try:
                strings[output_name] = win32api.GetFileVersionInfo(path, query)
            except Exception as exc:
                error = classify_error(exc)
                if error["category"] != "version_resource_not_present":
                    string_errors.append({"field": output_name, **error})
    string_resources_status = (
        "available"
        if any(value is not None for value in strings.values())
        else "query_failed"
        if string_errors
        else "not_present"
    )
    return {
        "status": "available",
        "string_resources_status": string_resources_status,
        "file_version": _version_text(
            int(fixed.get("FileVersionMS", 0)) & 0xFFFFFFFF,
            int(fixed.get("FileVersionLS", 0)) & 0xFFFFFFFF,
        ),
        "product_version": _version_text(
            int(fixed.get("ProductVersionMS", 0)) & 0xFFFFFFFF,
            int(fixed.get("ProductVersionLS", 0)) & 0xFFFFFFFF,
        ),
        **strings,
        "string_errors": string_errors,
        "error": None,
    }


def inspect_binary(original_path: str | None) -> dict[str, Any]:
    resolution = resolve_driver_path(original_path)
    result: dict[str, Any] = {
        "original_path": original_path,
        "path_resolution": resolution,
        "filesystem_status": "not_checked",
        "exists": None,
        "accessible": None,
        "is_regular_file": None,
        "size_bytes": None,
        "creation_time_utc": None,
        "creation_time_source": None,
        "last_write_time_utc": None,
        "last_access_time_utc": None,
        "version_info": {
            "status": "not_checked",
            "file_version": None,
            "product_version": None,
            "company_name": None,
            "product_name": None,
            "original_filename": None,
            "string_resources_status": "not_checked",
            "string_errors": [],
            "error": None,
        },
        "errors": [],
    }
    if original_path is None or not original_path.strip():
        result["version_info"]["status"] = "not_applicable"
    if resolution["status"] != "resolved":
        result["filesystem_status"] = resolution["status"]
        return result
    candidate = resolution["candidate_path"]
    try:
        info = os.stat(candidate)
    except FileNotFoundError as exc:
        result["filesystem_status"] = "not_found"
        result["exists"] = False
        result["accessible"] = False
        result["errors"].append(
            {"field": "filesystem_metadata", **classify_error(exc)}
        )
        return result
    except PermissionError as exc:
        result["filesystem_status"] = "access_denied"
        result["exists"] = None
        result["accessible"] = False
        result["errors"].append(
            {"field": "filesystem_metadata", **classify_error(exc)}
        )
        return result
    except OSError as exc:
        result["filesystem_status"] = "query_failed"
        result["errors"].append(
            {"field": "filesystem_metadata", **classify_error(exc)}
        )
        return result

    is_file = stat.S_ISREG(info.st_mode)
    result.update(
        {
            "filesystem_status": "available" if is_file else "not_regular_file",
            "exists": True,
            "accessible": True,
            "is_regular_file": is_file,
            "size_bytes": int(info.st_size) if is_file else None,
            "last_write_time_utc": datetime.fromtimestamp(
                info.st_mtime, timezone.utc
            ).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "last_access_time_utc": datetime.fromtimestamp(
                info.st_atime, timezone.utc
            ).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        }
    )
    if not is_file:
        result["version_info"]["status"] = "not_applicable"
    birth_time = getattr(info, "st_birthtime", None)
    if birth_time is not None:
        creation_time_source = "st_birthtime"
        creation_time = birth_time
    else:
        creation_time = getattr(info, "st_ctime", None)
        creation_time_source = (
            "st_ctime_windows_creation_time"
            if os.name == "nt"
            else "st_ctime_fallback"
        )
    result["creation_time_source"] = (
        creation_time_source if creation_time is not None else None
    )
    result["creation_time_utc"] = (
        datetime.fromtimestamp(creation_time, timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
        if creation_time is not None
        else None
    )
    if is_file:
        result["version_info"] = _read_version_info(candidate)
        if result["version_info"]["status"] == "query_failed":
            result["errors"].append(
                {
                    "field": "version_info",
                    **result["version_info"]["error"],
                }
            )
        result["errors"].extend(
            {"field": "version_info", **error}
            for error in result["version_info"]["string_errors"]
        )
    return result


def _set_debug_privilege() -> tuple[Any | None, Any | None, dict[str, Any]]:
    """Enable SeDebugPrivilege in this process token when present; caller restores it."""
    token = None
    original_attributes = None
    try:
        import win32api
        import win32con
        import win32security

        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32con.TOKEN_QUERY | win32con.TOKEN_ADJUST_PRIVILEGES,
        )
        luid = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")
        privileges = win32security.GetTokenInformation(
            token, win32security.TokenPrivileges
        )
        original_attributes = next(
            (attributes for privilege_luid, attributes in privileges
             if privilege_luid == luid),
            None,
        )
        if original_attributes is None:
            return token, None, {
                "status": "not_assigned",
                "enabled_by_collector": False,
                "message": "SeDebugPrivilege is not present in this process token.",
            }
        if original_attributes & win32con.SE_PRIVILEGE_ENABLED:
            return token, None, {
                "status": "already_enabled",
                "enabled_by_collector": False,
                "message": None,
            }
        win32security.AdjustTokenPrivileges(
            token,
            False,
            [(luid, original_attributes | win32con.SE_PRIVILEGE_ENABLED)],
        )
        updated_privileges = win32security.GetTokenInformation(
            token, win32security.TokenPrivileges
        )
        enabled_attributes = next(
            (
                attributes
                for privilege_luid, attributes in updated_privileges
                if privilege_luid == luid
            ),
            None,
        )
        if (
            enabled_attributes is None
            or not enabled_attributes & win32con.SE_PRIVILEGE_ENABLED
        ):
            return token, original_attributes, {
                "status": "not_assigned",
                "enabled_by_collector": False,
                "message": "Windows did not assign SeDebugPrivilege to the token.",
            }
        return token, original_attributes, {
            "status": "enabled",
            "enabled_by_collector": True,
            "message": None,
        }
    except Exception as exc:
        return token, original_attributes, {
            "status": "unavailable",
            "enabled_by_collector": False,
            "message": str(exc),
            "error": classify_error(exc),
        }


def _restore_debug_privilege(token: Any, original_attributes: Any) -> None:
    if original_attributes is None:
        return
    import win32security

    luid = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")
    win32security.AdjustTokenPrivileges(
        token, False, [(luid, original_attributes)]
    )


class WindowsPsapiProvider:
    """PSAPI adapter for loaded kernel/device-driver module visibility."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("A23 loaded-module enumeration requires Windows.")
        self.psapi = ctypes.WinDLL("Psapi", use_last_error=True)
        self.psapi.EnumDeviceDrivers.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self.psapi.EnumDeviceDrivers.restype = ctypes.c_int
        self.psapi.GetDeviceDriverBaseNameW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        self.psapi.GetDeviceDriverBaseNameW.restype = ctypes.c_uint32
        self.psapi.GetDeviceDriverFileNameW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        self.psapi.GetDeviceDriverFileNameW.restype = ctypes.c_uint32

    def _enumerate_addresses(self) -> tuple[list[int | None], dict[str, Any]]:
        capacity = 256
        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        while capacity <= MAX_PSAPI_MODULES:
            addresses = (ctypes.c_void_p * capacity)()
            bytes_needed = ctypes.c_uint32()
            ctypes.set_last_error(0)
            succeeded = self.psapi.EnumDeviceDrivers(
                addresses,
                ctypes.sizeof(addresses),
                ctypes.byref(bytes_needed),
            )
            error_code = 0 if succeeded else ctypes.get_last_error()
            required_count = (
                (int(bytes_needed.value) + pointer_size - 1) // pointer_size
            )
            if required_count > capacity:
                capacity = max(capacity * 2, required_count)
                continue
            if not succeeded:
                if error_code in {ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA}:
                    capacity = max(capacity * 2, required_count)
                    continue
                return [], {
                    "status": "failed",
                    "enumeration_complete": False,
                    "enumerated_count": 0,
                    "error": {
                        "provider": "PSAPI.EnumDeviceDrivers",
                        "winerror": error_code,
                        "message": ctypes.FormatError(error_code),
                    },
                }
            count = min(required_count, capacity)
            return [addresses[index] for index in range(count)], {
                "status": "success",
                "enumeration_complete": True,
                "enumerated_count": count,
                "error": None,
            }
        return [], {
            "status": "partial",
            "enumeration_complete": False,
            "enumerated_count": 0,
            "error": {
                "provider": "PSAPI.EnumDeviceDrivers",
                "winerror": ERROR_INSUFFICIENT_BUFFER,
                "message": "Loaded-module list exceeded the 65536-entry safety limit.",
            },
        }

    def _query_string(
        self, function: Any, address: int, field_name: str
    ) -> tuple[str | None, dict[str, Any] | None]:
        size = 512
        while size <= MAX_PSAPI_STRING:
            buffer = ctypes.create_unicode_buffer(size)
            ctypes.set_last_error(0)
            length = function(ctypes.c_void_p(address), buffer, size)
            if not length:
                error_code = ctypes.get_last_error()
                return None, {
                    "field": field_name,
                    "category": (
                        "provider_api_failure" if error_code else "unavailable"
                    ),
                    "winerror": error_code or None,
                    "message": (
                        ctypes.FormatError(error_code)
                        if error_code
                        else f"PSAPI could not return {field_name}."
                    ),
                }
            if length < size - 1:
                return buffer.value, None
            size *= 2
        return None, {
            "field": field_name,
            "category": "truncated",
            "winerror": None,
            "message": f"PSAPI {field_name} exceeded the string safety limit.",
        }

    def enumerate_modules(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        observed = utc_now()
        token = None
        original_attributes = None
        privilege = {
            "status": "not_attempted",
            "enabled_by_collector": False,
            "message": None,
        }
        warnings: list[dict[str, Any]] = []
        cleanup_errors: list[dict[str, Any]] = []
        outcome: dict[str, Any] | None = None
        try:
            token, original_attributes, privilege = _set_debug_privilege()
        except Exception as exc:
            warnings.append(
                {"field": "SeDebugPrivilege", **classify_error(exc)}
            )
        try:
            addresses, enumeration = self._enumerate_addresses()
            if enumeration["status"] == "failed":
                error = enumeration["error"]
                outcome = {
                    "provider": "PSAPI",
                    "api": "EnumDeviceDrivers, GetDeviceDriverBaseNameW, "
                    "GetDeviceDriverFileNameW",
                    "attempted": True,
                    "status": "failed",
                    "enumeration_complete": False,
                    "enumerated_count": 0,
                    "observation_time_utc": observed,
                    "debug_privilege": privilege,
                    "errors": [error],
                    "warnings": warnings,
                }
                return [], outcome
            modules: list[dict[str, Any]] = []
            for index, raw_address in enumerate(addresses):
                address = int(raw_address) if raw_address else None
                module_errors: list[dict[str, Any]] = []
                basename = None
                original_path = None
                if address is None:
                    module_errors.append(
                        {
                            "field": "base_address",
                            "category": "unusable_address",
                            "winerror": None,
                            "message": (
                                "EnumDeviceDrivers returned a null address; "
                                "module names and paths cannot be queried."
                            ),
                        }
                    )
                else:
                    basename, error = self._query_string(
                        self.psapi.GetDeviceDriverBaseNameW,
                        address,
                        "module_basename",
                    )
                    if error:
                        module_errors.append(error)
                    original_path, error = self._query_string(
                        self.psapi.GetDeviceDriverFileNameW,
                        address,
                        "original_module_path",
                    )
                    if error:
                        module_errors.append(error)
                modules.append(
                    {
                        "module_index": index,
                        "module_basename": basename,
                        "original_module_path": original_path,
                        "base_address": hex(address) if address is not None else None,
                        "provider": "PSAPI",
                        "observation_time_utc": observed,
                        "errors": module_errors,
                    }
                )
            null_addresses = sum(
                module["base_address"] is None for module in modules
            )
            errors = [
                error
                for module in modules
                for error in module["errors"]
            ]
            complete = bool(enumeration["enumeration_complete"]) and not null_addresses
            if not enumeration["enumeration_complete"]:
                errors.append(enumeration["error"])
            outcome = {
                "provider": "PSAPI",
                "api": "EnumDeviceDrivers, GetDeviceDriverBaseNameW, "
                "GetDeviceDriverFileNameW",
                "attempted": True,
                "status": "success" if complete and not errors else "partial",
                "enumeration_complete": complete,
                "enumerated_count": len(modules),
                "unusable_address_count": null_addresses,
                "observation_time_utc": observed,
                "debug_privilege": privilege,
                "errors": errors,
                "warnings": warnings,
            }
            return modules, outcome
        except Exception as exc:
            outcome = {
                "provider": "PSAPI",
                "api": "EnumDeviceDrivers, GetDeviceDriverBaseNameW, "
                "GetDeviceDriverFileNameW",
                "attempted": True,
                "status": "failed",
                "enumeration_complete": False,
                "enumerated_count": 0,
                "observation_time_utc": observed,
                "debug_privilege": privilege,
                "errors": [classify_error(exc)],
                "warnings": warnings,
            }
            return [], outcome
        finally:
            if token is not None:
                try:
                    _restore_debug_privilege(token, original_attributes)
                except Exception as exc:
                    error = (
                        {"field": "restore_SeDebugPrivilege", **classify_error(exc)}
                    )
                    warnings.append(error)
                    cleanup_errors.append(error)
                try:
                    import win32api

                    win32api.CloseHandle(token)
                except Exception as exc:
                    error = (
                        {"field": "close_process_token", **classify_error(exc)}
                    )
                    warnings.append(error)
                    cleanup_errors.append(error)
            if outcome is not None and cleanup_errors:
                outcome["errors"].extend(cleanup_errors)
                if outcome["status"] == "success":
                    outcome["status"] = "partial"


def _status_record(
    values: dict[str, Any], observed_at: str, source: str
) -> dict[str, Any]:
    return {
        "observation_time_utc": observed_at,
        "source": source,
        "service_type_flags": flags_value(
            values["service_type"], SERVICE_TYPE_BITS
        ),
        "current_state": numeric_value(
            values["current_state"], SERVICE_STATE_LABELS
        ),
        "controls_accepted": flags_value(
            values["controls_accepted"], CONTROL_BITS
        ),
        "win32_exit_code": values["win32_exit_code"],
        "service_specific_exit_code": values["service_specific_exit_code"],
        "checkpoint": values["checkpoint"],
        "wait_hint_ms": values["wait_hint_ms"],
        "process_id": values["process_id"],
        "service_flags": flags_value(values["service_flags"], SERVICE_FLAG_BITS),
    }


def _empty_query_result() -> dict[str, Any]:
    return {
        "status": None,
        "configuration": None,
        "extended_configuration": {},
        "errors": [],
    }


def _correlate(
    services: list[dict[str, Any]], modules: list[dict[str, Any]]
) -> dict[str, Any]:
    service_paths: dict[str, list[dict[str, Any]]] = defaultdict(list)
    module_paths: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for service in services:
        path = service["binary_metadata"]["path_resolution"].get("candidate_path")
        if (
            service["binary_metadata"]["path_resolution"]["status"] == "resolved"
            and path
        ):
            service_paths[os.path.normcase(os.path.normpath(path))].append(service)
    for module in modules:
        path = module["binary_metadata"]["path_resolution"].get("candidate_path")
        if (
            module["binary_metadata"]["path_resolution"]["status"] == "resolved"
            and path
        ):
            module_paths[os.path.normcase(os.path.normpath(path))].append(module)
    matches: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    for path in sorted(service_paths.keys() & module_paths.keys()):
        service_group = service_paths[path]
        module_group = module_paths[path]
        if len(service_group) == 1 and len(module_group) == 1:
            cardinality = "one_to_one"
        elif len(service_group) > 1 and len(module_group) > 1:
            cardinality = "many_to_many"
        elif len(service_group) > 1:
            cardinality = "many_to_one"
        else:
            cardinality = "one_to_many"
        match = {
            "normalized_path": path,
            "service_names": [
                item["identity"]["service_name"] for item in service_group
            ],
            "module_indexes": [item["module_index"] for item in module_group],
            "match_cardinality": cardinality,
            "confidence": "high",
            "basis": "Exact case-insensitive normalized resolved filesystem path.",
        }
        matches.append(match)
        if cardinality != "one_to_one":
            ambiguous.append(match)
    matched_service_names = {
        name for match in matches for name in match["service_names"]
    }
    matched_module_indexes = {
        index for match in matches for index in match["module_indexes"]
    }
    return {
        "method": "exact_resolved_path_only",
        "matches": matches,
        "ambiguous_matches": ambiguous,
        "unmatched_service_names": [
            item["identity"]["service_name"]
            for item in services
            if item["identity"]["service_name"] not in matched_service_names
        ],
        "unmatched_module_indexes": [
            item["module_index"]
            for item in modules
            if item["module_index"] not in matched_module_indexes
        ],
        "limitations": [
            "Basename-only matching is never used.",
            "Unresolved device paths and paths with no exact match remain unmatched.",
            "A match is a path association at collection time, not proof that the "
            "service caused a module to load.",
        ],
    }


def collect_drivers(
    scm_provider: Any | None = None,
    module_provider: Any | None = None,
    binary_inspector: Callable[[str | None], dict[str, Any]] = inspect_binary,
) -> dict[str, Any]:
    """Collect installed driver services and loaded driver modules independently."""
    started = utc_now()
    services: list[dict[str, Any]] = []
    modules: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    limitations = [
        "SCM enumeration covers kernel and file-system driver service types plus "
        "the documented recognizer-driver type, across all service states.",
        "SERVICE_ADAPTER (0x4) is reserved and is not included as an installed "
        "driver service type.",
        "EnumServicesStatusEx can silently omit services the caller cannot query "
        "for status; Windows does not return names or a count for omitted services.",
        "PSAPI visibility is limited to modules exposed by EnumDeviceDrivers. "
        "It does not guarantee detection of hidden drivers or every kernel component.",
        "A configured service, a running service, and a loaded module are distinct "
        "observations; not every module maps to one service.",
        "CIM Win32_SystemDriver is not queried by the collector; use the documented "
        "manual comparison procedure in the README as an independent reference.",
        "File version resources are descriptive metadata, not proof of authenticity. "
        "Authenticode verification is not implemented.",
        "File timestamps describe current filesystem metadata, not installation or "
        "driver-load times.",
        "Collection is a live observation; service and module state can change while "
        "the collector runs.",
    ]
    providers: dict[str, Any] = {
        "installed_driver_services": {
            "provider": "Windows Service Control Manager",
            "apis": [
                "OpenSCManager",
                "EnumServicesStatusExW",
                "CloseServiceHandle",
            ],
            "attempted": True,
            "status": "failed",
            "enumeration_complete": False,
            "errors": [],
        },
        "driver_metadata_collection": {
            "provider": "Windows Service Control Manager, PSAPI, and filesystem",
            "apis": [
                "OpenService",
                "QueryServiceStatusEx",
                "QueryServiceConfig",
                "QueryServiceConfig2W",
                "CloseServiceHandle",
                "filesystem stat",
                "file version resource queries",
            ],
            "attempted": False,
            "status": "not_attempted",
            "collection_complete": False,
            "records_attempted": 0,
            "records_with_errors": 0,
            "errors": [],
        },
        "loaded_driver_modules": {
            "provider": "PSAPI",
            "apis": [
                "EnumDeviceDrivers",
                "GetDeviceDriverBaseNameW",
                "GetDeviceDriverFileNameW",
            ],
            "attempted": True,
            "status": "failed",
            "enumeration_complete": False,
            "errors": [],
        },
    }
    scm = scm_provider
    created_scm = scm is None
    raw_services: list[dict[str, Any]] = []
    enumeration_returned = False
    try:
        if scm is None:
            scm = WindowsScmProvider()
        raw_services, scm_outcome = scm.enumerate_services()
        enumeration_returned = True
        providers["installed_driver_services"].update(scm_outcome)
        metadata_provider = providers["driver_metadata_collection"]
        metadata_provider["attempted"] = True
        for item in raw_services:
            metadata_provider["records_attempted"] += 1
            name = item.get("service_name")
            record_errors: list[dict[str, Any]] = []
            if not name:
                record_errors.append(
                    {
                        "field": "service_name",
                        "category": "malformed_provider_record",
                        "message": "SCM enumeration returned a record without a service name.",
                    }
                )
                name = f"<unnamed-{len(services)}>"
            queried = _empty_query_result()
            try:
                queried = scm.query_service(name)
                record_errors.extend(queried.get("errors", []))
            except Exception as exc:
                record_errors.append(
                    {"field": "service_query", **classify_error(exc)}
                )
            enum_status = {
                "service_type": item.get("service_type", 0),
                "current_state": item.get("current_state", 0),
                "controls_accepted": item.get("controls_accepted", 0),
                "win32_exit_code": item.get("win32_exit_code"),
                "service_specific_exit_code": item.get(
                    "service_specific_exit_code"
                ),
                "checkpoint": item.get("checkpoint"),
                "wait_hint_ms": item.get("wait_hint_ms"),
                "process_id": item.get("process_id"),
                "service_flags": item.get("service_flags", 0),
            }
            status_values = queried.get("status") or enum_status
            status_observed = utc_now()
            status_source = (
                "QueryServiceStatusEx"
                if queried.get("status") is not None
                else "EnumServicesStatusExW snapshot"
            )
            configuration = queried.get("configuration")
            if configuration is None:
                configuration_record = {
                    "service_type_flags": None,
                    "start_type": None,
                    "error_control": None,
                    "binary_path_command": None,
                    "load_order_group": None,
                    "tag_id": None,
                    "dependencies": None,
                    "configured_account": None,
                    "display_name_from_configuration": None,
                    "extended": queried.get("extended_configuration", {}),
                }
            else:
                config_record = dict(configuration)
                service_type = config_record.pop("service_type", None)
                start_type = config_record.pop("start_type", None)
                error_control = config_record.pop("error_control", None)
                configuration_record = {
                    "service_type_flags": (
                        flags_value(service_type, SERVICE_TYPE_BITS)
                        if service_type is not None
                        else None
                    ),
                    "start_type": (
                        numeric_value(start_type, START_TYPE_LABELS)
                        if start_type is not None
                        else None
                    ),
                    "error_control": (
                        numeric_value(error_control, ERROR_CONTROL_LABELS)
                        if error_control is not None
                        else None
                    ),
                    **config_record,
                    "extended": queried.get("extended_configuration", {}),
                }
            binary_path = (
                configuration.get("binary_path_command")
                if configuration is not None
                else None
            )
            try:
                binary_metadata = binary_inspector(binary_path)
            except Exception as exc:
                binary_metadata = {
                    "original_path": binary_path,
                    "path_resolution": {
                        "status": "query_failed",
                        "method": None,
                        "candidate_path": None,
                        "reason": str(exc),
                    },
                    "filesystem_status": "query_failed",
                    "errors": [classify_error(exc)],
                }
            record_errors.extend(binary_metadata.get("errors", []))
            reportable_metadata_errors = [
                error
                for error in record_errors
                if error.get("category")
                not in {"unsupported", "version_resource_not_present"}
            ]
            if record_errors:
                metadata_provider["records_with_errors"] += 1
            metadata_provider["errors"].extend(
                {"service_name": name, **error}
                for error in reportable_metadata_errors
            )
            services.append(
                {
                    "identity": {
                        "service_name": name,
                        "display_name": item.get("display_name"),
                        "description": (
                            queried.get("extended_configuration", {})
                            .get("description", {})
                            .get("value")
                        ),
                        "enumerated_service_type_flags": flags_value(
                            item.get("service_type", 0), SERVICE_TYPE_BITS
                        ),
                    },
                    "status": _status_record(
                        status_values, status_observed, status_source
                    ),
                    "configuration": configuration_record,
                    "binary_metadata": binary_metadata,
                    "enumeration_type_filters": item.get(
                        "enumeration_type_filters", []
                    ),
                    "errors": record_errors,
                }
            )
    except Exception as exc:
        error = {"provider": "SCM", **classify_error(exc)}
        if not enumeration_returned:
            providers["installed_driver_services"].update(
                {
                    "status": "failed",
                    "enumeration_complete": False,
                    "errors": [error],
                }
            )
        else:
            providers["driver_metadata_collection"]["errors"].append(error)
        errors.append(error)
    finally:
        if scm is not None and created_scm:
            try:
                scm.close()
            except Exception as exc:
                error = {"provider": "SCM", **classify_error(exc)}
                providers["installed_driver_services"]["errors"].append(error)
                errors.append(error)

    psapi = module_provider
    created_psapi = psapi is None
    try:
        if psapi is None:
            psapi = WindowsPsapiProvider()
        modules, psapi_outcome = psapi.enumerate_modules()
        providers["loaded_driver_modules"].update(psapi_outcome)
        for module in modules:
            metadata_provider = providers["driver_metadata_collection"]
            metadata_provider["attempted"] = True
            metadata_provider["records_attempted"] += 1
            try:
                binary_metadata = binary_inspector(
                    module.get("original_module_path")
                )
            except Exception as exc:
                binary_metadata = {
                    "original_path": module.get("original_module_path"),
                    "path_resolution": {
                        "status": "query_failed",
                        "method": None,
                        "candidate_path": None,
                        "reason": str(exc),
                    },
                    "filesystem_status": "query_failed",
                    "errors": [classify_error(exc)],
                }
            module["binary_metadata"] = binary_metadata
            module.setdefault("errors", []).extend(
                binary_metadata.get("errors", [])
            )
            module_metadata_errors = binary_metadata.get("errors", [])
            if module_metadata_errors:
                metadata_provider["records_with_errors"] += 1
                metadata_provider["errors"].extend(
                    {
                        "module_index": module.get("module_index"),
                        **error,
                    }
                    for error in module_metadata_errors
                    if error.get("category")
                    not in {"unsupported", "version_resource_not_present"}
                )
    except Exception as exc:
        error = {"provider": "PSAPI", **classify_error(exc)}
        providers["loaded_driver_modules"].update(
            {
                "status": "failed",
                "enumeration_complete": False,
                "errors": [error],
            }
        )
        errors.append(error)
    finally:
        if psapi is not None and created_psapi:
            try:
                close = getattr(psapi, "close", None)
                if close is not None:
                    close()
            except Exception as exc:
                error = {"provider": "PSAPI", **classify_error(exc)}
                providers["loaded_driver_modules"]["errors"].append(error)
                errors.append(error)

    metadata_provider = providers["driver_metadata_collection"]
    if (
        metadata_provider["attempted"]
        and metadata_provider["status"] == "not_attempted"
    ):
        metadata_provider["status"] = (
            "partial" if metadata_provider["errors"] else "success"
        )
        metadata_provider["collection_complete"] = not metadata_provider["errors"]

    for provider_name in (
        "installed_driver_services",
        "driver_metadata_collection",
        "loaded_driver_modules",
    ):
        provider_errors = providers[provider_name].get("errors", [])
        for error in provider_errors:
            if error not in errors:
                errors.append({"provider": provider_name, **error})
    correlation = _correlate(services, modules)
    record_errors = [
        error
        for record in services + modules
        for error in record.get("errors", [])
        if error.get("category") != "unsupported"
        and error.get("category") != "version_resource_not_present"
    ]
    scm_status = providers["installed_driver_services"]["status"]
    required_scm_failure = scm_status == "failed" and not services
    incomplete = any(
        providers[name]["status"] != "success"
        for name in (
            "installed_driver_services",
            "driver_metadata_collection",
            "loaded_driver_modules",
        )
    )
    if required_scm_failure:
        overall_status = "failed"
    elif incomplete or errors or record_errors:
        overall_status = "partial"
    else:
        overall_status = "success"
    timestamps = _collection_time_metadata(started, utc_now())
    return {
        "artifact_id": ARTIFACT_ID,
        **timestamps,
        "status": overall_status,
        "runtime": {
            "operating_system": platform.platform(),
            "windows_release": platform.release() if os.name == "nt" else None,
            "python_version": sys.version.split()[0],
            "python_architecture_bits": ctypes.sizeof(ctypes.c_void_p) * 8,
        },
        "providers": providers,
        "coverage": {
            "installed_driver_services_complete": providers[
                "installed_driver_services"
            ].get("enumeration_complete", False),
            "loaded_driver_modules_complete": providers[
                "loaded_driver_modules"
            ].get("enumeration_complete", False),
            "hidden_drivers_detected": False,
            "meaning": (
                "Completeness is limited to records visible to the documented "
                "providers at observation time."
            ),
        },
        "installed_driver_services": services,
        "loaded_driver_modules": modules,
        "correlation": correlation,
        "counts": {
            "installed_driver_services": len(services),
            "loaded_driver_modules": len(modules),
            "correlated_paths": len(correlation["matches"]),
            "ambiguous_correlations": len(correlation["ambiguous_matches"]),
            "unmatched_driver_services": len(
                correlation["unmatched_service_names"]
            ),
            "unmatched_loaded_modules": len(
                correlation["unmatched_module_indexes"]
            ),
            "records_with_errors": sum(
                bool(record.get("errors")) for record in services + modules
            ),
            "overall_errors": len(errors),
        },
        "errors": errors,
        "limitations": limitations,
    }


def write_json(
    output_path: str | Path, document: dict[str, Any], overwrite: bool = False
) -> Path:
    destination = Path(output_path).expanduser().resolve()
    if destination.is_dir():
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
        destination = destination / f"Drivers-{timestamp}.json"
    if not destination.parent.is_dir():
        raise FileNotFoundError(
            f"Output parent directory does not exist: {destination.parent}"
        )
    payload = (_serialize_json(document) + "\n").encode("utf-8")
    if not overwrite:
        descriptor = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
        except Exception as write_error:
            try:
                destination.unlink()
            except FileNotFoundError:
                pass
            except OSError as cleanup_error:
                raise OSError(
                    f"JSON writing failed ({write_error}) and the incomplete "
                    f"destination could not be removed ({cleanup_error})."
                ) from write_error
            raise
        return destination
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return destination


def _serialize_json(document: dict[str, Any]) -> str:
    serialized = json.dumps(document, ensure_ascii=False, indent=2)
    for field_name in ("installed_driver_services", "loaded_driver_modules"):
        marker = f'"{field_name}": ['
        field_start = serialized.find(marker)
        if field_start < 0:
            continue
        array_start = field_start + len(marker) - 1
        depth = 0
        in_string = False
        escaped = False
        array_end = None
        for index in range(array_start, len(serialized)):
            character = serialized[index]
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
                continue
            if character == '"':
                in_string = True
            elif character == "[":
                depth += 1
            elif character == "]":
                depth -= 1
                if depth == 0:
                    array_end = index
                    break
        if array_end is None:
            raise ValueError(f"Could not locate the end of JSON array {field_name!r}.")
        array_text = serialized[array_start : array_end + 1]
        serialized = (
            serialized[:array_start]
            + re.sub(r"(?m)^    },\n(?=    \{)", "    },\n\n", array_text)
            + serialized[array_end + 1 :]
        )
    return serialized


def default_output_path() -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    return Path(__file__).resolve().parent / f"Drivers-{timestamp}.json"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only A23 installed-driver and loaded-module inventory."
    )
    parser.add_argument(
        "--output",
        help="Destination JSON file or existing directory (default: A23 folder).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly permit replacing an existing JSON file.",
    )
    return parser


def _prompt_output() -> str | None:
    entered = input(
        "Enter a JSON file path or existing folder (press Enter to save in A23): "
    ).strip()
    return entered or None


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    raw_args = list(sys.argv[1:] if argv is None else argv)
    try:
        args = parser.parse_args(raw_args)
        output_value = args.output
        if not raw_args and sys.stdin.isatty():
            output_value = _prompt_output()
        if output_value is not None and not output_value.strip():
            print("An output path cannot be blank.", file=sys.stderr)
            return EXIT_FAILURE
        document = collect_drivers()
        output = write_json(
            output_value if output_value is not None else default_output_path(),
            document,
            overwrite=args.overwrite,
        )
    except KeyboardInterrupt:
        print("A23 collection cancelled before completion.", file=sys.stderr)
        return EXIT_FAILURE
    except FileExistsError as exc:
        print(f"Output already exists; use --overwrite to replace it: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except (OSError, ValueError) as exc:
        print(f"A23 collection/output failure: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except Exception as exc:
        print(f"A23 unexpected collection/output failure: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    print(
        f"A23 {document['status']}: "
        f"{document['counts']['installed_driver_services']} installed driver "
        f"services, {document['counts']['loaded_driver_modules']} loaded modules "
        f"saved to {output}"
    )
    return {
        "success": EXIT_SUCCESS,
        "partial": EXIT_PARTIAL,
        "failed": EXIT_FAILURE,
    }[document["status"]]


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
