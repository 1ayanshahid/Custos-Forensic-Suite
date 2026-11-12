"""Read-only Windows Service Control Manager inventory collector for artifact A06."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import struct
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ARTIFACT_ID = "A06"
EXIT_SUCCESS = 0
EXIT_PARTIAL = 1
EXIT_FAILURE = 2

ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87
ERROR_INVALID_LEVEL = 124
ERROR_MORE_DATA = 234
ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_MARKED_FOR_DELETE = 1072
ERROR_NOT_SUPPORTED = 50
ERROR_CALL_NOT_IMPLEMENTED = 120
ERROR_INSUFFICIENT_BUFFER = 122

SERVICE_QUERY_CONFIG = 0x0001
SERVICE_QUERY_STATUS = 0x0004
READ_CONTROL = 0x00020000
SC_MANAGER_ENUMERATE_SERVICE = 0x0004
SERVICE_WIN32 = 0x0030
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
SERVICE_SID_TYPE_LABELS = {
    0: "SERVICE_SID_TYPE_NONE",
    1: "SERVICE_SID_TYPE_UNRESTRICTED",
    3: "SERVICE_SID_TYPE_RESTRICTED",
}
SERVICE_FLAG_BITS = {0x0001: "SERVICE_RUNS_IN_SYSTEM_PROCESS"}
SERVICE_TYPE_BITS = {
    0x00000001: "SERVICE_KERNEL_DRIVER",
    0x00000002: "SERVICE_FILE_SYSTEM_DRIVER",
    0x00000008: "SERVICE_RECOGNIZER_DRIVER",
    0x00000010: "SERVICE_WIN32_OWN_PROCESS",
    0x00000020: "SERVICE_WIN32_SHARE_PROCESS",
    0x00000100: "SERVICE_INTERACTIVE_PROCESS",
    0x00000200: "SERVICE_USER_SERVICE",
    0x00000400: "SERVICE_USERSERVICE_INSTANCE",
    0x00000800: "SERVICE_PKG_SERVICE",
}
ACE_TYPE_LABELS = {
    0: "ACCESS_ALLOWED_ACE",
    1: "ACCESS_DENIED_ACE",
    2: "SYSTEM_AUDIT_ACE",
    3: "SYSTEM_ALARM_ACE",
    4: "ACCESS_ALLOWED_COMPOUND_ACE",
    5: "ACCESS_ALLOWED_OBJECT_ACE",
    6: "ACCESS_DENIED_OBJECT_ACE",
    7: "SYSTEM_AUDIT_OBJECT_ACE",
    8: "SYSTEM_ALARM_OBJECT_ACE",
    9: "ACCESS_ALLOWED_CALLBACK_ACE",
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
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


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
        "collection_ended_at_utc": ended.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        ),
        "collection_started_at_local": started.astimezone().isoformat(),
        "collection_ended_at_local": ended.astimezone().isoformat(),
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
    return {"value": number, "labels": labels, "unknown_bits": number & ~known_mask}


def classify_error(exc: BaseException) -> dict[str, Any]:
    code = getattr(exc, "winerror", None)
    if code is None and getattr(exc, "args", None):
        first = exc.args[0]
        if isinstance(first, int):
            code = first
    if code == ERROR_ACCESS_DENIED:
        category = "access_denied"
    elif code in {ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE}:
        category = "service_disappeared"
    elif code in {
        ERROR_INVALID_LEVEL,
        ERROR_NOT_SUPPORTED,
        ERROR_CALL_NOT_IMPLEMENTED,
    }:
        category = "unsupported_configuration_class"
    else:
        category = "provider_api_failure"
    return {
        "category": category,
        "winerror": code,
        "message": str(exc),
        "exception_type": type(exc).__name__,
    }


def _get_advapi32() -> Any:
    if os.name != "nt":
        raise OSError("A06 collection requires Windows.")
    return ctypes.WinDLL("Advapi32", use_last_error=True)


def paginate_service_pages(
    read_page: Callable[[int, int], tuple[bool, int, int, int, list[dict[str, Any]]]],
    initial_buffer_size: int = 64 * 1024,
    maximum_buffer_size: int = 256 * 1024,
) -> tuple[list[dict[str, Any]], bool, list[dict[str, Any]]]:
    """Consume EnumServicesStatusEx pages, preserving partial pages and resume state."""
    services: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    resume_handle = 0
    buffer_size = initial_buffer_size
    while True:
        prior_resume = resume_handle
        try:
            success, error_code, bytes_needed, next_resume, page = read_page(
                buffer_size, resume_handle
            )
        except Exception as exc:
            errors.append(classify_error(exc))
            return services, False, errors
        services.extend(page)
        resume_handle = next_resume
        if success:
            return services, True, errors
        if error_code != ERROR_MORE_DATA:
            errors.append(
                {
                    "category": "provider_api_failure",
                    "winerror": error_code,
                    "message": f"EnumServicesStatusExW failed with Win32 error {error_code}.",
                }
            )
            return services, False, errors
        if resume_handle == prior_resume and not page:
            if buffer_size >= maximum_buffer_size:
                errors.append(
                    {
                        "category": "provider_api_failure",
                        "winerror": ERROR_MORE_DATA,
                        "message": "Enumeration made no progress at the maximum buffer size.",
                    }
                )
                return services, False, errors
            buffer_size = min(maximum_buffer_size, max(buffer_size * 2, bytes_needed))
        else:
            buffer_size = min(maximum_buffer_size, max(initial_buffer_size, bytes_needed))


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
    _fields_ = [("preferred_node", ctypes.c_uint16), ("delete", ctypes.c_ubyte)]


class WindowsServiceApi:
    """Thin read-only adapter around pywin32 and documented native SCM APIs."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("A06 collection requires Windows.")
        import win32security
        import win32service

        self.win32security = win32security
        self.win32service = win32service
        self.advapi32 = _get_advapi32()
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

    def enumerate_services(self) -> tuple[list[dict[str, Any]], bool, list[dict[str, Any]]]:
        scm = self.win32service.OpenSCManager(
            None, None, self.win32service.SC_MANAGER_ENUMERATE_SERVICE
        )

        def read_page(
            buffer_size: int, resume_handle: int
        ) -> tuple[bool, int, int, int, list[dict[str, Any]]]:
            buffer = ctypes.create_string_buffer(buffer_size)
            bytes_needed = ctypes.c_uint32()
            services_returned = ctypes.c_uint32()
            resume = ctypes.c_uint32(resume_handle)
            ctypes.set_last_error(0)
            result = self.advapi32.EnumServicesStatusExW(
                ctypes.c_void_p(int(scm.handle)),
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
                buffer_size,
                ctypes.byref(bytes_needed),
                ctypes.byref(services_returned),
                ctypes.byref(resume),
                None,
            )
            error_code = 0 if result else ctypes.get_last_error()
            page: list[dict[str, Any]] = []
            records = ctypes.cast(
                buffer, ctypes.POINTER(_EnumServiceStatusProcess)
            )
            for index in range(services_returned.value):
                entry = records[index]
                state = entry.status
                page.append(
                    {
                        "service_name": ctypes.wstring_at(entry.service_name),
                        "display_name": ctypes.wstring_at(entry.display_name),
                        "service_type": state.service_type,
                        "current_state": state.current_state,
                        "controls_accepted": state.controls_accepted,
                        "win32_exit_code": state.win32_exit_code,
                        "service_specific_exit_code": state.service_specific_exit_code,
                        "checkpoint": state.checkpoint,
                        "wait_hint": state.wait_hint,
                        "process_id": state.process_id,
                        "service_flags": state.service_flags,
                    }
                )
            return (
                bool(result),
                error_code,
                bytes_needed.value,
                resume.value,
                page,
            )

        try:
            return paginate_service_pages(read_page)
        finally:
            self.win32service.CloseServiceHandle(scm)

    def _open_service(self, name: str, access: int) -> Any:
        scm = self.win32service.OpenSCManager(
            None, None, self.win32service.SC_MANAGER_CONNECT
        )
        try:
            return self.win32service.OpenService(scm, name, access)
        finally:
            self.win32service.CloseServiceHandle(scm)

    def query_status(self, name: str) -> dict[str, Any]:
        handle = self._open_service(name, SERVICE_QUERY_STATUS)
        try:
            return self.win32service.QueryServiceStatusEx(handle)
        finally:
            self.win32service.CloseServiceHandle(handle)

    def query_basic_config(self, name: str) -> tuple[Any, ...]:
        handle = self._open_service(name, SERVICE_QUERY_CONFIG)
        try:
            return self.win32service.QueryServiceConfig(handle)
        finally:
            self.win32service.CloseServiceHandle(handle)

    def query_config2(self, name: str, level: int) -> Any:
        handle = self._open_service(name, SERVICE_QUERY_CONFIG)
        try:
            if level in {
                SERVICE_CONFIG_DESCRIPTION,
                SERVICE_CONFIG_FAILURE_ACTIONS,
                SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                SERVICE_CONFIG_SERVICE_SID_INFO,
                SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
                SERVICE_CONFIG_PRESHUTDOWN_INFO,
            }:
                return self.win32service.QueryServiceConfig2(handle, level)
            return self._query_native_config2(handle, level)
        finally:
            self.win32service.CloseServiceHandle(handle)

    def _query_native_config2(self, handle: Any, level: int) -> Any:
        buffer = ctypes.create_string_buffer(8192)
        needed = ctypes.c_uint32()
        ctypes.set_last_error(0)
        result = self.advapi32.QueryServiceConfig2W(
            ctypes.c_void_p(int(handle.handle)),
            level,
            ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
            len(buffer),
            ctypes.byref(needed),
        )
        if not result:
            code = ctypes.get_last_error()
            raise OSError(code, ctypes.FormatError(code))
        if level == SERVICE_CONFIG_TRIGGER_INFO:
            info = ctypes.cast(
                buffer, ctypes.POINTER(_ServiceTriggerInfo)
            ).contents
            triggers = []
            for index in range(info.trigger_count):
                trigger = info.triggers[index]
                subtype = None
                if trigger.subtype:
                    subtype = str(
                        uuid.UUID(bytes_le=ctypes.string_at(trigger.subtype, 16))
                    )
                items = []
                for item_index in range(trigger.data_item_count):
                    item = trigger.data_items[item_index]
                    raw = (
                        ctypes.string_at(item.data, item.data_size)
                        if item.data and item.data_size
                        else b""
                    )
                    data = {
                        "data_type": numeric_value(
                            item.data_type, TRIGGER_DATA_TYPE_LABELS
                        ),
                        "data_hex": raw.hex(),
                    }
                    if item.data_type == 2:
                        data["string_value"] = raw.decode(
                            "utf-16-le", errors="replace"
                        ).rstrip("\x00")
                    items.append(data)
                triggers.append(
                    {
                        "trigger_type": numeric_value(
                            trigger.trigger_type, TRIGGER_TYPE_LABELS
                        ),
                        "action": numeric_value(trigger.action, TRIGGER_ACTION_LABELS),
                        "subtype_guid": subtype,
                        "data_items": items,
                    }
                )
            return {"trigger_count": info.trigger_count, "triggers": triggers}
        if level == SERVICE_CONFIG_PREFERRED_NODE:
            item = ctypes.cast(
                buffer, ctypes.POINTER(_PreferredNodeInfo)
            ).contents
            return {
                "preferred_node": item.preferred_node,
                "delete_preference": bool(item.delete),
            }
        if level == SERVICE_CONFIG_LAUNCH_PROTECTED:
            value = struct.unpack_from("<I", buffer.raw)[0]
            return numeric_value(value, LAUNCH_PROTECTION_LABELS)
        raise ValueError(f"Unknown QueryServiceConfig2 level: {level}")

    def query_security(self, name: str) -> dict[str, Any]:
        handle = self._open_service(name, READ_CONTROL)
        try:
            info = (
                self.win32security.OWNER_SECURITY_INFORMATION
                | self.win32security.GROUP_SECURITY_INFORMATION
                | self.win32security.DACL_SECURITY_INFORMATION
            )
            descriptor = self.win32service.QueryServiceObjectSecurity(handle, info)
        finally:
            self.win32service.CloseServiceHandle(handle)
        owner = descriptor.GetSecurityDescriptorOwner()
        group = descriptor.GetSecurityDescriptorGroup()
        dacl = descriptor.GetSecurityDescriptorDacl()
        security_control, _revision = descriptor.GetSecurityDescriptorControl()
        dacl_present = bool(security_control & 0x0004)
        errors = []
        try:
            sddl = self.win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
                descriptor, self.win32security.SDDL_REVISION_1, info
            )
        except Exception as exc:
            sddl = None
            errors.append({"field": "sddl", **classify_error(exc)})
        acl_entries = None
        if dacl is not None:
            try:
                ace_count = dacl.GetAceCount()
                acl_entries = []
            except Exception as exc:
                errors.append({"field": "dacl_aces", **classify_error(exc)})
                acl_entries = None
                ace_count = 0
            for index in range(ace_count):
                try:
                    ace = dacl.GetAce(index)
                    if len(ace) < 3:
                        raise ValueError("The ACE decoder returned an incomplete record.")
                    header, mask, sid = ace[:3]
                    ace_header = list(header)
                    ace_type = int(header[0])
                except Exception as exc:
                    errors.append(
                        {
                            "field": f"dacl_aces[{index}]",
                            **classify_error(exc),
                        }
                    )
                    acl_entries.append(
                        {"ace_index": index, "decode_status": "failed"}
                    )
                    continue
                try:
                    trustee_sid = self.win32security.ConvertSidToStringSid(sid)
                except Exception as exc:
                    trustee_sid = None
                    errors.append(
                        {
                            "field": f"dacl_aces[{index}].trustee_sid",
                            **classify_error(exc),
                        }
                    )
                acl_entries.append(
                    {
                        "ace_index": index,
                        "ace_header": ace_header,
                        "ace_type": {
                            "value": ace_type,
                            "label": ACE_TYPE_LABELS.get(ace_type, "UNKNOWN_ACE_TYPE"),
                        },
                        "access_mask": mask,
                        "trustee_sid": trustee_sid,
                    }
                )
        try:
            owner_sid = (
                self.win32security.ConvertSidToStringSid(owner) if owner else None
            )
        except Exception as exc:
            owner_sid = None
            errors.append({"field": "owner_sid", **classify_error(exc)})
        try:
            group_sid = (
                self.win32security.ConvertSidToStringSid(group) if group else None
            )
        except Exception as exc:
            group_sid = None
            errors.append({"field": "group_sid", **classify_error(exc)})
        return {
            "owner_sid": owner_sid,
            "group_sid": group_sid,
            "dacl_present": dacl_present,
            "dacl_is_null": dacl_present and dacl is None,
            "dacl_aces": acl_entries,
            "sddl": sddl,
            "sacl_requested": False,
            "errors": errors,
        }

    def query_service_dll(self, name: str) -> dict[str, Any]:
        import winreg

        key_path = (
            rf"SYSTEM\CurrentControlSet\Services\{name}\Parameters"
        )
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ
        ) as key:
            value, value_type = winreg.QueryValueEx(key, "ServiceDll")
        value_encoding = None
        if isinstance(value, bytes):
            value = value.hex()
            value_encoding = "hex"
        return {
            "source": rf"HKLM\{key_path}\ServiceDll",
            "registry_type": value_type,
            "value": value,
            "value_encoding": value_encoding,
            "meaning": "Configured ServiceDll; not proof that the DLL is currently loaded.",
        }


def _field_error(errors: list[dict[str, Any]], field: str, exc: BaseException) -> None:
    item = classify_error(exc)
    item["field"] = field
    errors.append(item)


def _query_extended(
    api: Any, service_name: str, level: int, field_name: str,
    errors: list[dict[str, Any]], limitations: list[str],
) -> Any:
    try:
        return api.query_config2(service_name, level)
    except Exception as exc:
        item = classify_error(exc)
        item["field"] = field_name
        if item["category"] == "unsupported_configuration_class" or item.get(
            "winerror"
        ) == ERROR_INVALID_PARAMETER:
            item["category"] = "unsupported"
            if (
                field_name == "preferred_node"
                and item.get("winerror") == ERROR_INVALID_PARAMETER
            ):
                item["diagnostic"] = (
                    "QueryServiceConfig2W was called with "
                    "SERVICE_CONFIG_PREFERRED_NODE (dwInfoLevel=9). The A06 native "
                    "query passes SERVICE_QUERY_CONFIG access and an 8192-byte "
                    "output buffer; _PreferredNodeInfo is decoded only after the "
                    "API succeeds. ERROR_INVALID_PARAMETER therefore comes from "
                    "the Windows query call, not from response decoding. The error "
                    "code does not identify whether this service or the Windows "
                    "provider rejects that information level."
                )
            limitation = (
                f"{field_name} returned ERROR_INVALID_PARAMETER (87) from "
                "QueryServiceConfig2W for SERVICE_CONFIG_PREFERRED_NODE (9); "
                "the error does not identify why this service/provider rejected "
                "the request."
                if field_name == "preferred_node"
                and item.get("winerror") == ERROR_INVALID_PARAMETER
                else (
                    f"{field_name} is unsupported by this Windows version/provider "
                    f"(Win32 error {item.get('winerror')})."
                )
            )
            if limitation not in limitations:
                limitations.append(limitation)
        errors.append(item)
        return None


def _normalise_failure_actions(value: Any) -> Any:
    if value is None:
        return None
    result = dict(value)
    actions = result.get("Actions")
    if actions is not None:
        result["Actions"] = [
            {
                "type": numeric_value(action_type, FAILURE_ACTION_LABELS),
                "delay_ms": int(delay),
            }
            for action_type, delay in actions
        ]
    return result


def collect_services(api: Any | None = None) -> dict[str, Any]:
    started = utc_now()
    errors: list[dict[str, Any]] = []
    limitations = [
        "Only SERVICE_WIN32 own-process and shared-process services are enumerated; "
        "kernel and file-system driver services are assigned to A23.",
        "EnumServicesStatusEx may silently omit entries the caller cannot query "
        "for service status; the API does not report names or a count for omitted entries.",
        "SACL/audit-policy information is not requested. No ACCESS_SYSTEM_SECURITY "
        "right or additional privilege is used.",
        "Service status is a time-specific observation; configured service account "
        "does not establish the identity of a running process token.",
        "Services may change state or disappear during acquisition; shared PIDs are "
        "expected, and PID 0 can be valid for a stopped service.",
        "Configured binary command strings are preserved verbatim and are not "
        "treated as a resolved executable path.",
    ]
    if api is None:
        try:
            api = WindowsServiceApi()
        except Exception as exc:
            errors.append({"category": "provider_api_failure", **classify_error(exc)})
            timestamps = _collection_time_metadata(started, utc_now())
            return {
                "artifact_id": ARTIFACT_ID,
                "collection_start_utc": started,
                "collection_end_utc": timestamps["collection_ended_at_utc"],
                "collection_start_local": timestamps["collection_started_at_local"],
                "collection_end_local": timestamps["collection_ended_at_local"],
                "collection_time_zone_id": timestamps["collection_time_zone_id"],
                "collection_time_zone_id_source": timestamps[
                    "collection_time_zone_id_source"
                ],
                "collection_time_zone_id_error": timestamps[
                    "collection_time_zone_id_error"
                ],
                "collection_clock_adjusted": timestamps["collection_clock_adjusted"],
                "status": "failed",
                "provider": _provider_information(),
                "enumeration": {"complete": False, "service_type_filter": "SERVICE_WIN32"},
                "record_count": 0,
                "services": [],
                "errors": errors,
                "limitations": limitations,
            }

    try:
        enumerated, complete, enumeration_errors = api.enumerate_services()
        errors.extend(enumeration_errors)
    except Exception as exc:
        enumerated, complete = [], False
        errors.append({"category": "provider_api_failure", **classify_error(exc)})

    services: list[dict[str, Any]] = []

    for item in enumerated:
        name = item["service_name"]
        service_errors: list[dict[str, Any]] = []
        status_observed = utc_now()
        try:
            current_status = api.query_status(name)
            status = {
                "observation_time_utc": status_observed,
                "source": "QueryServiceStatusEx(SC_STATUS_PROCESS_INFO)",
                "service_type": flags_value(
                    current_status["ServiceType"], SERVICE_TYPE_BITS
                ),
                "current_state": numeric_value(
                    current_status["CurrentState"], SERVICE_STATE_LABELS
                ),
                "controls_accepted": flags_value(
                    current_status["ControlsAccepted"], CONTROL_BITS
                ),
                "win32_exit_code": int(current_status["Win32ExitCode"]),
                "service_specific_exit_code": int(
                    current_status["ServiceSpecificExitCode"]
                ),
                "checkpoint": int(current_status["CheckPoint"]),
                "wait_hint_ms": int(current_status["WaitHint"]),
                "process_id": int(current_status["ProcessId"]),
                "service_flags": flags_value(
                    current_status["ServiceFlags"], SERVICE_FLAG_BITS
                ),
            }
        except Exception as exc:
            status = {
                "observation_time_utc": status_observed,
                "source": "EnumServicesStatusExW snapshot",
                "service_type": flags_value(item["service_type"], SERVICE_TYPE_BITS),
                "current_state": numeric_value(
                    item["current_state"], SERVICE_STATE_LABELS
                ),
                "controls_accepted": flags_value(
                    item["controls_accepted"], CONTROL_BITS
                ),
                "win32_exit_code": int(item["win32_exit_code"]),
                "service_specific_exit_code": int(
                    item["service_specific_exit_code"]
                ),
                "checkpoint": int(item["checkpoint"]),
                "wait_hint_ms": int(item["wait_hint"]),
                "process_id": int(item["process_id"]),
                "service_flags": flags_value(item["service_flags"], SERVICE_FLAG_BITS),
            }
            _field_error(service_errors, "status", exc)

        basic_config = None
        try:
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
            ) = api.query_basic_config(name)
            basic_config = {
                "service_type": flags_value(service_type, SERVICE_TYPE_BITS),
                "start_type": numeric_value(start_type, START_TYPE_LABELS),
                "error_control": numeric_value(error_control, ERROR_CONTROL_LABELS),
                "binary_path_command": binary_path,
                "load_order_group": load_order_group,
                "tag_id": tag_id,
                "dependencies": list(dependencies) if dependencies is not None else None,
                "configured_service_account": service_account,
                "display_name_from_configuration": config_display_name,
            }
        except Exception as exc:
            _field_error(service_errors, "basic_configuration", exc)
            basic_config = {
                "service_type": None,
                "start_type": None,
                "error_control": None,
                "binary_path_command": None,
                "load_order_group": None,
                "tag_id": None,
                "dependencies": None,
                "configured_service_account": None,
                "display_name_from_configuration": None,
            }

        description = _query_extended(
            api, name, SERVICE_CONFIG_DESCRIPTION, "description",
            service_errors, limitations,
        )
        service_sid_type = _query_extended(
            api, name, SERVICE_CONFIG_SERVICE_SID_INFO,
            "service_sid_type", service_errors, limitations,
        )
        ext = {
            "delayed_auto_start": _query_extended(
                api, name, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                "delayed_auto_start", service_errors, limitations,
            ),
            "failure_actions": _normalise_failure_actions(_query_extended(
                api, name, SERVICE_CONFIG_FAILURE_ACTIONS,
                "failure_actions", service_errors, limitations,
            )),
            "failure_actions_on_non_crash": _query_extended(
                api, name, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                "failure_actions_on_non_crash", service_errors, limitations,
            ),
            "service_sid_type": (
                numeric_value(service_sid_type, SERVICE_SID_TYPE_LABELS)
                if service_sid_type is not None
                else None
            ),
            "required_privileges": _query_extended(
                api, name, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
                "required_privileges", service_errors, limitations,
            ),
            "preshutdown_timeout_ms": _query_extended(
                api, name, SERVICE_CONFIG_PRESHUTDOWN_INFO,
                "preshutdown_timeout_ms", service_errors, limitations,
            ),
            "trigger_info": _query_extended(
                api, name, SERVICE_CONFIG_TRIGGER_INFO,
                "trigger_info", service_errors, limitations,
            ),
            "preferred_node": _query_extended(
                api, name, SERVICE_CONFIG_PREFERRED_NODE,
                "preferred_node", service_errors, limitations,
            ),
            "launch_protection": _query_extended(
                api, name, SERVICE_CONFIG_LAUNCH_PROTECTED,
                "launch_protection", service_errors, limitations,
            ),
        }
        try:
            security = api.query_security(name)
            for security_error in security.pop("errors", []):
                service_errors.append(security_error)
        except Exception as exc:
            security = {
                "owner_sid": None,
                "group_sid": None,
                "dacl_present": None,
                "dacl_aces": None,
                "sddl": None,
                "sacl_requested": False,
            }
            _field_error(service_errors, "security_descriptor", exc)
        try:
            enrichment = {"service_dll": api.query_service_dll(name)}
        except FileNotFoundError:
            enrichment = {"service_dll": None, "service_dll_availability": "not_configured"}
        except Exception as exc:
            enrichment = {"service_dll": None}
            _field_error(service_errors, "registry_service_dll", exc)
        services.append(
            {
                "identity": {
                    "service_name": name,
                    "display_name": item["display_name"],
                    "description": description,
                },
                "status": status,
                "configuration": {
                    **(basic_config or {}),
                    "extended": ext,
                },
                "security": security,
                "enrichment": enrichment,
                "errors": service_errors,
            }
        )
    errors_count = sum(
        any(error.get("category") != "unsupported" for error in service["errors"])
        for service in services
    )
    if not complete and not services:
        result_status = "failed"
    elif not complete or errors_count or errors:
        result_status = "partial"
    else:
        result_status = "success"
    timestamps = _collection_time_metadata(started, utc_now())
    return {
        "artifact_id": ARTIFACT_ID,
        "collection_start_utc": started,
        "collection_end_utc": timestamps["collection_ended_at_utc"],
        "collection_start_local": timestamps["collection_started_at_local"],
        "collection_end_local": timestamps["collection_ended_at_local"],
        "collection_time_zone_id": timestamps["collection_time_zone_id"],
        "collection_time_zone_id_source": timestamps["collection_time_zone_id_source"],
        "collection_time_zone_id_error": timestamps["collection_time_zone_id_error"],
        "collection_clock_adjusted": timestamps["collection_clock_adjusted"],
        "status": result_status,
        "provider": _provider_information(),
        "enumeration": {
            "complete": bool(complete),
            "service_type_filter": "SERVICE_WIN32",
            "state_filter": "SERVICE_STATE_ALL",
            "driver_services_included": False,
            "enumerated_record_count": len(services),
        },
        "record_count": len(services),
        "services": services,
        "errors": errors,
        "limitations": sorted(set(limitations)),
    }


def _provider_information() -> dict[str, Any]:
    return {
        "operating_system": platform.platform(),
        "windows_release": platform.release() if os.name == "nt" else None,
        "windows_version": platform.version() if os.name == "nt" else None,
        "python_version": sys.version.split()[0],
        "python_architecture": platform.architecture()[0],
        "provider": "Windows Service Control Manager (SCM)",
        "pywin32_version": _pywin32_version(),
        "native_api": "Advapi32 EnumServicesStatusExW and QueryServiceConfig2W",
    }


def _pywin32_version() -> str | None:
    try:
        from importlib.metadata import version

        return version("pywin32")
    except Exception:
        return None


def write_json(output_path: str | Path, document: dict[str, Any], overwrite: bool) -> Path:
    destination = Path(output_path).expanduser().resolve()
    if destination.is_dir():
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
        destination = destination / f"Services-{timestamp}.json"
    if not destination.parent.is_dir():
        raise FileNotFoundError(f"Output directory does not exist: {destination.parent}")
    formatted = json.dumps(document, ensure_ascii=False, indent=2).splitlines()
    output_lines: list[str] = []
    in_services = False
    for line in formatted:
        output_lines.append(line)
        if line == '  "services": [':
            in_services = True
        elif in_services and line == "  ],":
            in_services = False
        elif in_services and line == "    },":
            output_lines.append("")
    payload = ("\n".join(output_lines) + "\n").encode("utf-8")
    if not overwrite:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(destination, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
        except Exception:
            try:
                destination.unlink()
            except OSError:
                pass
            raise
        return destination

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return destination


def default_output_path() -> Path:
    return output_path_in_directory(Path(__file__).resolve().parent)


def output_path_in_directory(directory: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    return directory / f"Services-{timestamp}.json"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only A06 inventory of Win32 Windows services."
    )
    parser.add_argument("--output", help="Destination JSON file path.")
    parser.add_argument(
        "--overwrite", action="store_true",
        help="Explicitly allow replacing an existing output file.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.output is not None and not args.output.strip():
        print("An output JSON path is required; collection was not started.", file=sys.stderr)
        return EXIT_FAILURE
    try:
        document = collect_services()
        output_path = args.output if args.output is not None else default_output_path()
        output = write_json(output_path, document, args.overwrite)
    except FileExistsError as exc:
        print(f"Output already exists; use --overwrite to replace it: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except Exception as exc:
        print(f"A06 collection/output failure: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    print(
        f"A06 {document['status']}: {document['record_count']} services saved to {output}"
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
