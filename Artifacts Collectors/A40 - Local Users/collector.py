"""Read-only local Windows user inventory (artifact A40)."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

ARTIFACT_ID = "A40"
EXIT_SUCCESS = 0
EXIT_PARTIAL = 1
EXIT_FAILURE = 2
DEFAULT_OUTPUT_DIRECTORY = Path(__file__).resolve().parent / "Local Users_Output"
NETUSERENUM_LEVEL = 3
NETUSERENUM_FALLBACK_LEVEL = 0
NETUSERGETINFO_PRIMARY_LEVEL = 4
NETUSERGETINFO_FALLBACK_LEVELS = (3, 2)
NETUSERGETINFO_SID_LEVEL = 23
FILTER_NORMAL_ACCOUNT = 2
MAX_PREFERRED_LENGTH = -1
ERROR_MORE_DATA = 234
ERROR_INVALID_LEVEL = 124
NERR_USER_NOT_FOUND = 2221
TIMEQ_FOREVER = 0xFFFFFFFF

FLAG_DEFINITIONS = {
    0x00000001: "script",
    0x00000002: "account_disabled",
    0x00000008: "home_directory_required",
    0x00000010: "locked_out",
    0x00000020: "password_not_required",
    0x00000040: "password_cannot_be_changed",
    0x00000080: "reversible_encryption_allowed",
    0x00000100: "temporary_duplicate_account",
    0x00000200: "normal_account",
    0x00000800: "interdomain_trust_account",
    0x00001000: "workstation_trust_account",
    0x00002000: "server_trust_account",
    0x00010000: "password_never_expires",
    0x00020000: "mns_logon_account",
    0x00040000: "smartcard_required",
    0x00080000: "trusted_for_delegation",
    0x00100000: "not_delegated",
    0x00200000: "des_key_only",
    0x00400000: "kerberos_preauthentication_not_required",
    0x00800000: "password_expired",
    0x01000000: "trusted_to_authenticate_for_delegation",
}
KNOWN_FLAGS_MASK = 0
for _known_flag in FLAG_DEFINITIONS:
    KNOWN_FLAGS_MASK |= _known_flag
PRIVILEGE_LABELS = {0: "guest", 1: "user", 2: "administrator"}
SID_TYPE_LABELS = {
    1: "user",
    2: "group",
    3: "domain",
    4: "alias",
    5: "well_known_group",
    6: "deleted_account",
    7: "invalid",
    8: "unknown",
    9: "computer",
    10: "label",
}

POWERSHELL_LOCAL_USER_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$toUtc = {
    param($value)
    if ($null -eq $value) { return $null }
    if ($value -is [datetime]) {
        return $value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    }
    return $null
}
try {
    $records = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
        $user = $_
        [ordered]@{
            name = [string]$user.Name
            sid = if ($null -ne $user.SID) { [string]$user.SID.Value } else { $null }
            enabled = if ($null -ne $user.Enabled) { [bool]$user.Enabled } else { $null }
            full_name = if ($null -ne $user.FullName) { [string]$user.FullName } else { $null }
            description = if ($null -ne $user.Description) { [string]$user.Description } else { $null }
            principal_source = if ($null -ne $user.PrincipalSource) { [string]$user.PrincipalSource } else { $null }
            user_may_change_password = if ($null -ne $user.UserMayChangePassword) { [bool]$user.UserMayChangePassword } else { $null }
            password_required = if ($null -ne $user.PasswordRequired) { [bool]$user.PasswordRequired } else { $null }
            password_never_expires = if ($null -eq $user.PasswordExpires) { $true } else { $false }
            password_last_set_utc = & $toUtc $user.PasswordLastSet
            password_expires_utc = & $toUtc $user.PasswordExpires
            last_logon_utc = & $toUtc $user.LastLogon
            account_expires_utc = & $toUtc $user.AccountExpires
        }
    })
    ConvertTo-Json -InputObject ([ordered]@{ accounts = $records }) -Compress -Depth 4
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
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
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _local_timezone_id() -> tuple[str | None, str | None]:
    if sys.platform != "win32":
        return None, "Windows timezone registry is unavailable on this platform."
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
            0,
            winreg.KEY_READ,
        ) as key:
            value = winreg.QueryValueEx(key, "TimeZoneKeyName")[0]
        return (value, None) if isinstance(value, str) and value else (
            None,
            "TimeZoneKeyName is empty or malformed.",
        )
    except (ImportError, OSError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _timestamp_fields(started_at_utc: str, ended_at_utc: str) -> dict[str, Any]:
    started = datetime.fromisoformat(started_at_utc.replace("Z", "+00:00"))
    ended = datetime.fromisoformat(ended_at_utc.replace("Z", "+00:00"))
    adjusted = ended < started
    if adjusted:
        ended = started
    timezone_id, timezone_error = _local_timezone_id()
    return {
        "collection_started_at_utc": started.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z"),
        "collection_ended_at_utc": ended.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z"),
        "collection_started_at_local": started.astimezone().isoformat(
            timespec="microseconds"
        ),
        "collection_ended_at_local": ended.astimezone().isoformat(
            timespec="microseconds"
        ),
        "collection_time_zone_id": timezone_id,
        "collection_time_zone_id_error": timezone_error,
        "collection_clock_adjusted": adjusted,
    }


def _error_record(exc: BaseException, *, operation: str) -> dict[str, Any]:
    code = getattr(exc, "winerror", None)
    if code is None and exc.args and isinstance(exc.args[0], int):
        code = exc.args[0]
    if code == 5:
        category = "access_denied"
    elif code == NERR_USER_NOT_FOUND:
        category = "account_disappeared"
    elif code in {ERROR_INVALID_LEVEL, 124}:
        category = "unsupported_information_level"
    else:
        category = "provider_failure"
    return {
        "operation": operation,
        "category": category,
        "type": type(exc).__name__,
        "winerror": code,
        "message": str(exc),
    }


class PyWin32NetApi:
    """Thin adapter around the installed pywin32 NetAPI and SID functions."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OSError("A40 requires Windows.")
        try:
            import win32api
            import win32net
            import win32security
        except ImportError as exc:
            raise RuntimeError(
                "pywin32 is required. Install it manually into the project venv."
            ) from exc
        self._win32api = win32api
        self._win32net = win32net
        self._win32security = win32security

    def computer_name(self) -> str:
        return self._win32api.GetComputerName()

    def user_enum(
        self, level: int, filter_value: int, preferred_length: int, resume: int
    ) -> tuple[list[dict[str, Any]], int, int]:
        return self._win32net.NetUserEnum(
            None, level, filter_value, preferred_length, resume
        )

    def user_get_info(self, username: str, level: int) -> dict[str, Any]:
        return self._win32net.NetUserGetInfo(None, username, level)

    def user_modals_get(self) -> dict[str, Any]:
        return self._win32net.NetUserModalsGet(None, 0)

    def lookup_account_name(self, computer_name: str, username: str) -> tuple[Any, str, int]:
        return self._win32security.LookupAccountName(computer_name, username)

    def sid_to_string(self, sid: Any) -> str:
        return self._win32security.ConvertSidToStringSid(sid)

    def lookup_account_sid(self, sid: Any) -> tuple[str, str, int]:
        return self._win32security.LookupAccountSid(None, sid)

    def sid_type_labels(self) -> dict[int, str]:
        labels: dict[int, str] = {}
        for name, label in (
            ("SidTypeUser", "user"),
            ("SidTypeGroup", "group"),
            ("SidTypeDomain", "domain"),
            ("SidTypeAlias", "alias"),
            ("SidTypeWellKnownGroup", "well_known_group"),
            ("SidTypeDeletedAccount", "deleted_account"),
            ("SidTypeInvalid", "invalid"),
            ("SidTypeUnknown", "unknown"),
            ("SidTypeComputer", "computer"),
            ("SidTypeLabel", "label"),
        ):
            value = getattr(self._win32security, name, None)
            if isinstance(value, int):
                labels[value] = label
        return labels or SID_TYPE_LABELS.copy()


def detect_local_account_scope() -> dict[str, Any]:
    """Read ProductType to prevent treating a domain controller's AD as local SAM."""
    if sys.platform != "win32":
        return {
            "status": "unsupported",
            "product_type": None,
            "classification": None,
            "error": "A40 is supported only on Windows.",
        }
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\ProductOptions",
            0,
            winreg.KEY_READ,
        ) as key:
            product_type = winreg.QueryValueEx(key, "ProductType")[0]
    except (ImportError, OSError) as exc:
        return {
            "status": "failed",
            "product_type": None,
            "classification": None,
            "error": _error_record(exc, operation="read_local_computer_role"),
        }
    if not isinstance(product_type, str):
        return {
            "status": "failed",
            "product_type": None,
            "classification": None,
            "error": {
                "operation": "read_local_computer_role",
                "category": "invalid_provider_value",
                "message": "ProductType is not a string.",
            },
        }
    classification = {
        "WinNT": "workstation",
        "ServerNT": "member_or_standalone_server",
        "LanmanNT": "domain_controller",
    }.get(product_type)
    if classification is None:
        return {
            "status": "failed",
            "product_type": product_type,
            "classification": None,
            "error": {
                "operation": "read_local_computer_role",
                "category": "unsupported_product_type",
                "message": f"Unrecognized Windows ProductType: {product_type}",
            },
        }
    return {
        "status": "domain_controller" if classification == "domain_controller" else "success",
        "product_type": product_type,
        "classification": classification,
        "registry_path": (
            r"HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType"
        ),
        "error": None,
    }


def _normalize_page_result(result: Any) -> tuple[list[Any], int, int]:
    if not isinstance(result, tuple) or len(result) != 3:
        raise TypeError(
            "pywin32 NetUserEnum must return (entries, total_entries, resume_handle)."
        )
    entries, total, resume = result
    if not isinstance(entries, (list, tuple)):
        raise TypeError("NetUserEnum entries are not a list or tuple.")
    if not isinstance(total, int) or not isinstance(resume, int):
        raise TypeError("NetUserEnum total/resume values are not integers.")
    return list(entries), total, resume


def enumerate_netapi_users(
    api: Any,
    *,
    preferred_length: int = MAX_PREFERRED_LENGTH,
) -> dict[str, Any]:
    """Enumerate local normal-user accounts until the resume handle is zero."""
    entries: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    pages: list[dict[str, Any]] = []
    levels_tried: list[int] = []
    level = NETUSERENUM_LEVEL
    resume = 0
    seen_resumes = {resume}
    while True:
        levels_tried.append(level)
        try:
            raw_result = api.user_enum(
                level, FILTER_NORMAL_ACCOUNT, preferred_length, resume
            )
        except Exception as exc:
            error = _error_record(exc, operation=f"NetUserEnum(level={level})")
            if (
                not entries
                and level == NETUSERENUM_LEVEL
                and error["category"] == "unsupported_information_level"
            ):
                warnings.append(
                    {
                        **error,
                        "category": "unsupported_information_level_fallback",
                    }
                )
                level = NETUSERENUM_FALLBACK_LEVEL
                resume = 0
                seen_resumes = {0}
                continue
            errors.append(error)
            return {
                "status": "partial" if entries else "failed",
                "complete": False,
                "entries": entries,
                "pages": pages,
                "levels_tried": list(dict.fromkeys(levels_tried)),
                "error": errors,
                "warnings": warnings,
                "last_resume_handle": resume,
            }
        try:
            page_entries, total, next_resume = _normalize_page_result(raw_result)
        except (TypeError, ValueError) as exc:
            errors.append(_error_record(exc, operation="validate_NetUserEnum_result"))
            return {
                "status": "partial" if entries else "failed",
                "complete": False,
                "entries": entries,
                "pages": pages,
                "levels_tried": list(dict.fromkeys(levels_tried)),
                "error": errors,
                "warnings": warnings,
                "last_resume_handle": resume,
            }
        pages.append(
            {
                "information_level": level,
                "entries_read": len(page_entries),
                "total_entries_hint": total,
                "resume_handle": next_resume,
            }
        )
        entries.extend(item for item in page_entries if isinstance(item, dict))
        malformed = sum(not isinstance(item, dict) for item in page_entries)
        if malformed:
            errors.append(
                {
                    "operation": f"NetUserEnum(level={level})",
                    "category": "unexpected_provider_record",
                    "count": malformed,
                    "message": "Non-mapping user entries were excluded; inventory may be incomplete.",
                }
            )
        if next_resume == 0:
            return {
                "status": "partial" if errors else "success",
                "complete": not errors,
                "entries": entries,
                "pages": pages,
                "levels_tried": list(dict.fromkeys(levels_tried)),
                "error": errors,
                "warnings": warnings,
                "last_resume_handle": 0,
            }
        if next_resume == resume or next_resume in seen_resumes:
            errors.append(
                {
                    "operation": f"NetUserEnum(level={level})",
                    "category": "pagination_no_progress",
                    "message": "NetUserEnum returned a repeated resume handle; stopped to avoid an infinite loop.",
                }
            )
            return {
                "status": "partial" if entries else "failed",
                "complete": False,
                "entries": entries,
                "pages": pages,
                "levels_tried": list(dict.fromkeys(levels_tried)),
                "error": errors,
                "warnings": warnings,
                "last_resume_handle": next_resume,
            }
        seen_resumes.add(next_resume)
        resume = next_resume


def read_local_users_supplemental(
    *,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Read safe local-account properties from Get-LocalUser for reconciliation."""
    if sys.platform != "win32":
        return {
            "status": "unsupported",
            "accounts": [],
            "error": "Get-LocalUser is available only on Windows.",
            "provider": "PowerShell Microsoft.PowerShell.LocalAccounts",
        }
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    powershell = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not powershell.is_file():
        return {
            "status": "unsupported",
            "accounts": [],
            "error": f"Windows PowerShell was not found at {powershell}.",
            "provider": "PowerShell Microsoft.PowerShell.LocalAccounts",
        }
    try:
        result = subprocess.run(
            [
                str(powershell),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                POWERSHELL_LOCAL_USER_SCRIPT,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "failed",
            "accounts": [],
            "error": {
                "category": "provider_timeout",
                "type": type(exc).__name__,
                "message": f"Get-LocalUser exceeded {timeout_seconds} seconds.",
            },
            "provider": "PowerShell Microsoft.PowerShell.LocalAccounts",
        }
    except OSError as exc:
        return {
            "status": "failed",
            "accounts": [],
            "error": _error_record(exc, operation="Get-LocalUser"),
            "provider": "PowerShell Microsoft.PowerShell.LocalAccounts",
        }
    if result.returncode != 0:
        return {
            "status": "unsupported",
            "accounts": [],
            "error": {
                "category": "provider_unavailable",
                "return_code": result.returncode,
                "message": (result.stderr or "Get-LocalUser failed.").strip(),
            },
            "provider": "PowerShell Microsoft.PowerShell.LocalAccounts",
        }
    try:
        payload = json.loads(result.stdout)
        if not isinstance(payload, dict) or not isinstance(payload.get("accounts"), list):
            raise ValueError("Get-LocalUser JSON does not contain an accounts array.")
        accounts = payload["accounts"]
        if not all(isinstance(item, dict) for item in accounts):
            raise ValueError("Get-LocalUser JSON contains a non-object account.")
    except (json.JSONDecodeError, ValueError) as exc:
        return {
            "status": "failed",
            "accounts": [],
            "error": {
                "category": "invalid_structured_output",
                "type": type(exc).__name__,
                "message": str(exc),
            },
            "provider": "PowerShell Microsoft.PowerShell.LocalAccounts",
        }
    safe_accounts = [
        {key: item.get(key) for key in SUPPLEMENTAL_FIELDS}
        for item in accounts
    ]
    return {
        "status": "success",
        "accounts": safe_accounts,
        "error": None,
        "provider": "PowerShell Microsoft.PowerShell.LocalAccounts",
        "information": (
            "Supplemental, explicitly allowlisted Get-LocalUser properties; "
            "not a replacement for NetUserEnum."
        ),
    }


SUPPLEMENTAL_FIELDS = (
    "name",
    "sid",
    "enabled",
    "full_name",
    "description",
    "principal_source",
    "user_may_change_password",
    "password_required",
    "password_never_expires",
    "password_last_set_utc",
    "password_expires_utc",
    "last_logon_utc",
    "account_expires_utc",
)


def _read_field(record: dict[str, Any], *keys: str) -> tuple[Any, bool]:
    for key in keys:
        if key in record:
            return record[key], True
    return None, False


def classify_builtin_sid(sid: str | None) -> dict[str, Any]:
    if not sid:
        return {"status": "unresolved", "classification": None, "rid": None}
    match = re.fullmatch(r"S-1-5-21-\d+-\d+-\d+-(\d+)", sid, flags=re.IGNORECASE)
    if not match:
        return {
            "status": "not_a_local_account_sid_shape",
            "classification": None,
            "rid": None,
        }
    rid = int(match.group(1))
    labels = {
        500: "built_in_administrator_identity",
        501: "built_in_guest_identity",
    }
    return {
        "status": "classified" if rid in labels else "not_a_recognized_builtin_rid",
        "classification": labels.get(rid),
        "rid": rid,
    }


def _epoch_timestamp(raw_value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(raw_value, int) or isinstance(raw_value, bool):
        return {
            "raw": raw_value if isinstance(raw_value, (str, int, float, bool)) else None,
            "utc": None,
            "status": "unsupported_value",
        }
    if raw_value == 0 and field in {"last_logon", "last_logoff"}:
        return {"raw": 0, "utc": None, "status": "zero_not_recorded"}
    if field == "account_expires" and raw_value in {TIMEQ_FOREVER, -1}:
        return {"raw": raw_value, "utc": None, "status": "never"}
    try:
        converted = datetime.fromtimestamp(raw_value, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return {"raw": raw_value, "utc": None, "status": "invalid_timestamp"}
    return {
        "raw": raw_value,
        "utc": converted.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "status": "available",
    }


def _is_all_bits_set_sentinel(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value in {
        TIMEQ_FOREVER,
        -1,
    }


def _string_field(
    source: dict[str, Any],
    *provider_names: str,
) -> tuple[Any, str]:
    value, present = _read_field(source, *provider_names)
    if not present:
        return None, "unavailable"
    if value is None:
        return None, "null_value"
    if isinstance(value, str):
        return value, "available"
    return None, "unsupported_value"


def _logon_hours(value: Any, units_per_week: Any) -> tuple[dict[str, Any] | None, str]:
    if value is None:
        return None, "null_value"
    try:
        if isinstance(value, (bytes, bytearray, memoryview)):
            bitmap = bytes(value)
        elif isinstance(value, (list, tuple)) and all(
            isinstance(item, int) and 0 <= item <= 255 for item in value
        ):
            bitmap = bytes(value)
        else:
            return None, "unsupported_value"
    except (TypeError, ValueError):
        return None, "unsupported_value"
    return {
        "bitmap_hex": bitmap.hex(),
        "byte_length": len(bitmap),
        "units_per_week": units_per_week
        if isinstance(units_per_week, int) and not isinstance(units_per_week, bool)
        else None,
        "decoding": "not_performed; bit ordering/time semantics are not inferred",
    }, "available"


def _password_time_fields(
    password_age_seconds: Any,
    observed_at_utc: str,
    flags: int | None,
    password_expired_value: Any,
    max_password_age_seconds: Any,
) -> dict[str, Any]:
    never_expires = (
        bool(flags & 0x00010000) if flags is not None else None
    )
    age_valid = isinstance(password_age_seconds, int) and not isinstance(
        password_age_seconds, bool
    ) and password_age_seconds >= 0
    last_set = None
    last_set_status = "unavailable"
    if age_valid:
        observed = datetime.fromisoformat(observed_at_utc.replace("Z", "+00:00"))
        last_set = (observed - timedelta(seconds=password_age_seconds)).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
        last_set_status = "derived_from_password_age"

    expired: bool | None
    if isinstance(password_expired_value, bool):
        expired = password_expired_value
    elif isinstance(password_expired_value, int) and password_expired_value in (0, 1):
        expired = bool(password_expired_value)
    elif flags is not None:
        expired = bool(flags & 0x00800000)
    else:
        expired = None

    if never_expires is True:
        expires_utc = None
        expiry_status = "never"
    elif (
        last_set is not None
        and isinstance(max_password_age_seconds, int)
        and not isinstance(max_password_age_seconds, bool)
    ):
        if _is_all_bits_set_sentinel(max_password_age_seconds):
            expires_utc = None
            expiry_status = "policy_never"
        else:
            last_set_dt = datetime.fromisoformat(last_set.replace("Z", "+00:00"))
            expires_utc = (
                last_set_dt + timedelta(seconds=max_password_age_seconds)
            ).isoformat(timespec="microseconds").replace("+00:00", "Z")
            expiry_status = "derived_from_local_password_policy"
    else:
        expires_utc = None
        expiry_status = "unavailable"
    return {
        "password_never_expires": never_expires,
        "password_expired": expired,
        "password_last_set_utc_derived": last_set,
        "password_last_set_derivation_status": last_set_status,
        "password_last_set_observed_at_utc": observed_at_utc if age_valid else None,
        "password_last_set_uncertainty": (
            "Derived from provider password age at query time; not a directly stored timestamp."
            if age_valid
            else None
        ),
        "password_expires_utc_derived": expires_utc,
        "password_expiration_status": expiry_status,
    }


def normalize_account(
    username: str,
    sources: Iterable[tuple[str, dict[str, Any], int]],
    *,
    api: Any,
    computer_name: str,
    observed_at_utc: str,
    max_password_age_seconds: Any,
    initial_sid: str | None = None,
    initial_sid_source: str | None = None,
    supplemental: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an allowlisted account record from provider levels."""
    sources = list(sources)
    errors: list[dict[str, Any]] = []
    field_status: dict[str, str] = {}
    provider_levels: dict[str, int] = {}
    merged: dict[str, Any] = {}
    for provider_name, record, level in sources:
        provider_levels[provider_name] = level
        for key, value in record.items():
            if key.casefold() not in {"password", "usri2_password", "usri3_password", "usri4_password"}:
                merged[key] = value

    def get_string(output_name: str, *keys: str) -> Any:
        value, status = _string_field(merged, *keys)
        field_status[output_name] = status
        if status == "unsupported_value":
            errors.append(
                {
                    "field": output_name,
                    "category": "unexpected_provider_type",
                    "message": "Provider returned a non-string value for a string field.",
                }
            )
        return value

    name_value, name_present = _read_field(merged, "name", "usri3_name", "usri2_name")
    normalized_name = name_value if isinstance(name_value, str) and name_value else username
    field_status["username"] = "available" if normalized_name else (
        "unsupported_value" if name_present else "unavailable"
    )
    for provider_name, record, _ in sources:
        field_status[f"{provider_name}_record"] = "available"

    flags_value, flags_present = _read_field(merged, "flags", "usri3_flags", "usri2_flags")
    flags = flags_value if isinstance(flags_value, int) and not isinstance(flags_value, bool) else None
    field_status["account_flags"] = (
        "available" if flags is not None else "unsupported_value" if flags_present else "unavailable"
    )
    if flags_present and flags is None:
        errors.append(
            {
                "field": "account_flags",
                "category": "unexpected_provider_type",
                "message": "Provider returned a non-integer account flags value.",
            }
        )
    known_flag_names = (
        [label for mask, label in FLAG_DEFINITIONS.items() if flags & mask]
        if flags is not None
        else None
    )
    flag_interpretations: dict[str, bool | None] = {
        "enabled": not bool(flags & 0x00000002) if flags is not None else None,
        "disabled": bool(flags & 0x00000002) if flags is not None else None,
        "locked_out": bool(flags & 0x00000010) if flags is not None else None,
        "password_required": not bool(flags & 0x00000020) if flags is not None else None,
        "password_cannot_be_changed": bool(flags & 0x00000040) if flags is not None else None,
        "password_never_expires": bool(flags & 0x00010000) if flags is not None else None,
        "password_expired": bool(flags & 0x00800000) if flags is not None else None,
        "unknown_bits": flags & ~KNOWN_FLAGS_MASK if flags is not None else None,
    }
    field_status["flag_interpretations"] = "available" if flags is not None else "unavailable"

    def get_numeric(output_name: str, *keys: str) -> Any:
        value, present = _read_field(merged, *keys)
        if not present:
            field_status[output_name] = "unavailable"
            return None
        if isinstance(value, int) and not isinstance(value, bool):
            field_status[output_name] = "available"
            return value
        if value is None:
            field_status[output_name] = "null_value"
            return None
        field_status[output_name] = "unsupported_value"
        errors.append(
            {
                "field": output_name,
                "category": "unexpected_provider_type",
                "message": "Provider returned a non-integer value.",
            }
        )
        return None

    password_age = get_numeric("password_age_seconds", "password_age", "usri3_password_age", "usri2_password_age")
    primary_group_id = get_numeric("primary_group_id", "primary_group_id", "usri3_primary_group_id")
    user_id = get_numeric("provider_user_id", "user_id", "usri3_user_id")
    privilege = get_numeric("privilege_level", "priv", "usri3_priv", "usri2_priv")
    if privilege is None:
        privilege_label = None
    else:
        privilege_label = PRIVILEGE_LABELS.get(privilege, "unknown_provider_value")
    acct_expires_value, acct_expires_present = _read_field(merged, "acct_expires", "usri3_acct_expires", "usri2_acct_expires")
    acct_expires = _epoch_timestamp(acct_expires_value, field="account_expires") if acct_expires_present else {
        "raw": None,
        "utc": None,
        "status": "unavailable",
    }
    field_status["account_expiration"] = acct_expires["status"]
    last_logon_raw = get_numeric("last_logon_raw", "last_logon", "usri3_last_logon", "usri2_last_logon")
    last_logoff_raw = get_numeric("last_logoff_raw", "last_logoff", "usri3_last_logoff", "usri2_last_logoff")
    last_logon = _epoch_timestamp(last_logon_raw, field="last_logon") if last_logon_raw is not None else {
        "raw": None,
        "utc": None,
        "status": field_status["last_logon_raw"],
    }
    last_logoff = _epoch_timestamp(last_logoff_raw, field="last_logoff") if last_logoff_raw is not None else {
        "raw": None,
        "utc": None,
        "status": field_status["last_logoff_raw"],
    }
    field_status["last_logon"] = last_logon["status"]
    field_status["last_logoff"] = last_logoff["status"]

    strings = {
        "full_name": ("full_name", "usri3_full_name", "usri2_full_name"),
        "description": ("comment", "usri3_comment", "usri2_comment"),
        "user_comment": ("usr_comment", "usri3_usr_comment", "usri2_usr_comment"),
        "home_directory": ("home_dir", "usri3_home_dir", "usri2_home_dir"),
        "home_drive": ("home_dir_drive", "usri3_home_dir_drive"),
        "profile_path": ("profile", "usri3_profile"),
        "logon_script_path": ("script_path", "usri3_script_path", "usri2_script_path"),
        "permitted_workstations": ("workstations", "usri3_workstations", "usri2_workstations"),
        "logon_server": ("logon_server", "usri3_logon_server", "usri2_logon_server"),
    }
    string_fields = {
        name: get_string(name, *keys)
        for name, keys in strings.items()
    }
    units_per_week = get_numeric("logon_hours_units_per_week", "units_per_week", "usri3_units_per_week", "usri2_units_per_week")
    logon_hours_value, logon_hours_present = _read_field(merged, "logon_hours", "usri3_logon_hours", "usri2_logon_hours")
    logon_hours, logon_hours_status = _logon_hours(logon_hours_value, units_per_week)
    field_status["logon_hours"] = logon_hours_status if logon_hours_present else "unavailable"
    if logon_hours_status == "unsupported_value":
        errors.append(
            {
                "field": "logon_hours",
                "category": "unexpected_provider_type",
                "message": "Logon-hours bitmap had an unsupported representation.",
            }
        )

    sid = initial_sid
    sid_source = initial_sid_source if sid else None
    sid_lookup: dict[str, Any]
    sid_object = None
    provider_sid, provider_sid_present = _read_field(
        merged, "user_sid", "usri4_user_sid"
    )
    if provider_sid_present and provider_sid is not None:
        try:
            sid_object = provider_sid
            resolved_provider_sid = api.sid_to_string(provider_sid)
            if sid and sid.casefold() != resolved_provider_sid.casefold():
                errors.append(
                    {
                        "field": "sid",
                        "category": "sid_changed_during_collection",
                        "message": "The SID resolved before enrichment differs from the SID returned by NetUserGetInfo level 4; the initial identity SID is retained and both values are reported.",
                        "initial_sid": sid,
                        "enrichment_sid": resolved_provider_sid,
                    }
                )
                sid_lookup = {
                    "status": "mismatch",
                    "source": sid_source,
                    "enrichment_source": "NetUserGetInfo(level=4).user_sid",
                    "initial_sid": sid,
                    "enrichment_sid": resolved_provider_sid,
                    "error": None,
                }
                sid_object = None
            else:
                sid = resolved_provider_sid
                sid_source = "NetUserGetInfo(level=4).user_sid"
                sid_lookup = {"status": "resolved", "source": sid_source, "error": None}
        except Exception as exc:
            sid_lookup = {
                "status": "unresolved",
                "source": "NetUserGetInfo(level=4).user_sid",
                "error": _error_record(exc, operation="convert_provider_sid"),
            }
            errors.append(sid_lookup["error"])
    elif sid:
        sid_lookup = {
            "status": "resolved",
            "source": sid_source,
            "error": None,
        }
    else:
        try:
            sid_object, _, _ = api.lookup_account_name(
                computer_name, normalized_name
            )
            sid = api.sid_to_string(sid_object)
            sid_source = "win32security.LookupAccountName against local computer"
            sid_lookup = {"status": "resolved", "source": sid_source, "error": None}
        except Exception as exc:
            sid_lookup = {
                "status": "unresolved",
                "source": "win32security.LookupAccountName against local computer",
                "error": _error_record(exc, operation="resolve_local_account_sid"),
            }
            errors.append(sid_lookup["error"])
    field_status["sid"] = (
        sid_lookup["status"]
        if sid_lookup["status"] == "mismatch"
        else "available" if sid
        else sid_lookup["status"]
    )
    if sid_object is not None:
        try:
            _, resolved_domain, resolved_type = api.lookup_account_sid(sid_object)
            sid_type_map = api.sid_type_labels()
            sid_lookup["resolved_domain"] = resolved_domain
            sid_lookup["resolved_type"] = sid_type_map.get(
                resolved_type, "unknown_provider_value"
            )
        except Exception as exc:
            sid_lookup["reverse_lookup_error"] = _error_record(
                exc, operation="LookupAccountSid"
            )
    builtin = classify_builtin_sid(sid)

    supplemental_fields: dict[str, Any] = {}
    if supplemental:
        for key in SUPPLEMENTAL_FIELDS:
            value = supplemental.get(key)
            if value is not None:
                supplemental_fields[key] = value
        if sid is None and isinstance(supplemental.get("sid"), str):
            sid = supplemental["sid"]
            sid_source = "Get-LocalUser"
            sid_lookup = {"status": "resolved", "source": sid_source, "error": None}
            field_status["sid"] = "available"
            builtin = classify_builtin_sid(sid)
        supplemental_mappings = {
            "full_name": "full_name",
            "description": "description",
        }
        for output_name, supplemental_name in supplemental_mappings.items():
            if string_fields[output_name] is None and supplemental_fields.get(supplemental_name) is not None:
                string_fields[output_name] = supplemental_fields[supplemental_name]
                field_status[output_name] = "supplemental_provider"
        for flag_name, supplemental_name in (
            ("enabled", "enabled"),
            ("password_required", "password_required"),
        ):
            if flag_interpretations[flag_name] is None and isinstance(
                supplemental_fields.get(supplemental_name), bool
            ):
                flag_interpretations[flag_name] = supplemental_fields[supplemental_name]
                field_status[flag_name] = "supplemental_provider"

    password_expired_value, _ = _read_field(merged, "password_expired", "usri3_password_expired")
    password_metadata = _password_time_fields(
        password_age,
        observed_at_utc,
        flags,
        password_expired_value,
        max_password_age_seconds,
    )
    if supplemental_fields:
        for field_name in (
            "password_last_set_utc",
            "password_expires_utc",
            "last_logon_utc",
            "account_expires_utc",
        ):
            if supplemental_fields.get(field_name) is not None:
                password_metadata.setdefault("supplemental_timestamps", {})[field_name] = supplemental_fields[field_name]
                field_status[field_name] = "supplemental_provider_direct_timestamp"
            else:
                field_status[field_name] = "unavailable"
        ps_never_expires = supplemental_fields.get("password_never_expires")
        if isinstance(ps_never_expires, bool):
            password_metadata["password_never_expires_supplemental"] = ps_never_expires

    auth_flags = get_numeric("auth_flags", "auth_flags", "usri3_auth_flags", "usri2_auth_flags")
    bad_password_count = get_numeric("bad_password_count", "bad_pw_count", "usri3_bad_pw_count", "usri2_bad_pw_count")
    logon_count = get_numeric("logon_count", "num_logons", "usri3_num_logons", "usri2_num_logons")
    bad_password_count_status = (
        "unknown_sentinel" if _is_all_bits_set_sentinel(bad_password_count) else field_status["bad_password_count"]
    )
    logon_count_status = (
        "unknown_sentinel" if _is_all_bits_set_sentinel(logon_count) else field_status["logon_count"]
    )
    country_code = get_numeric("country_code", "country_code", "usri3_country_code", "usri2_country_code")
    code_page = get_numeric("code_page", "code_page", "usri3_code_page", "usri2_code_page")
    max_storage = get_numeric("max_storage_bytes", "max_storage", "usri3_max_storage", "usri2_max_storage")
    if _is_all_bits_set_sentinel(max_storage):
        max_storage_value = None
        field_status["max_storage_bytes"] = "unlimited_sentinel"
    else:
        max_storage_value = max_storage

    return {
        "username": normalized_name,
        "sid": sid,
        "sid_source": sid_source,
        "sid_resolution": sid_lookup,
        "builtin_account": builtin,
        "principal_source": supplemental_fields.get("principal_source"),
        "account_flags": flags,
        "account_flag_names": known_flag_names,
        "unknown_account_flag_bits": flag_interpretations["unknown_bits"],
        "enabled": flag_interpretations["enabled"],
        "disabled": flag_interpretations["disabled"],
        "locked_out": flag_interpretations["locked_out"],
        "password_required": flag_interpretations["password_required"],
        "password_cannot_be_changed": flag_interpretations["password_cannot_be_changed"],
        "supplemental_account_settings": {
            key: supplemental_fields[key]
            for key in (
                "enabled",
                "user_may_change_password",
                "password_required",
                "password_never_expires",
            )
            if supplemental_fields.get(key) is not None
        },
        "password_never_expires": password_metadata["password_never_expires"],
        "password_expired": password_metadata["password_expired"],
        "password_age_seconds": password_age,
        "password_last_set_utc_derived": password_metadata["password_last_set_utc_derived"],
        "password_last_set_derivation_status": password_metadata["password_last_set_derivation_status"],
        "password_last_set_observed_at_utc": password_metadata["password_last_set_observed_at_utc"],
        "password_last_set_uncertainty": password_metadata["password_last_set_uncertainty"],
        "password_expires_utc_derived": password_metadata["password_expires_utc_derived"],
        "password_expiration_status": password_metadata["password_expiration_status"],
        "supplemental_timestamps": password_metadata.get("supplemental_timestamps", {}),
        "password_never_expires_supplemental": password_metadata.get("password_never_expires_supplemental"),
        "account_expiration": acct_expires,
        "privilege_level": privilege,
        "privilege_classification": (
            privilege_label
            if privilege_label is not None
            else supplemental_fields.get("privilege_classification")
        ),
        "primary_group_id": primary_group_id,
        "provider_user_id": user_id,
        **string_fields,
        "last_logon": last_logon,
        "last_logoff": last_logoff,
        "logon_hours": logon_hours,
        "logon_hours_units_per_week": units_per_week,
        "auth_flags": auth_flags,
        "bad_password_count": bad_password_count,
        "bad_password_count_status": bad_password_count_status,
        "logon_count": logon_count,
        "logon_count_status": logon_count_status,
        "country_code": country_code,
        "code_page": code_page,
        "max_storage_bytes": max_storage_value,
        "information_levels_used": provider_levels,
        "sources": list(dict.fromkeys(item[0] for item in sources))
        + (["Get-LocalUser"] if supplemental else []),
        "observed_at_utc": observed_at_utc,
        "errors": errors,
    }


def _supplemental_key(account: dict[str, Any]) -> str:
    sid = account.get("sid")
    return f"sid:{sid.casefold()}" if isinstance(sid, str) and sid else ""


def _merge_account_sets(
    primary_records: list[dict[str, Any]],
    supplemental_records: list[dict[str, Any]],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any] | None]], list[dict[str, Any]]]:
    merged = [(record, None) for record in primary_records]
    discrepancies: list[dict[str, Any]] = []
    sid_indices: dict[str, list[int]] = {}
    for index, (record, _) in enumerate(merged):
        key = _supplemental_key(record)
        if key:
            sid_indices.setdefault(key, []).append(index)
    matched_primary: set[int] = set()
    for supplement in supplemental_records:
        key = _supplemental_key(supplement)
        index = next(
            (
                candidate
                for candidate in sid_indices.get(key, [])
                if candidate not in matched_primary
            ),
            None,
        ) if key else None
        if index is not None:
            merged[index] = (merged[index][0], supplement)
            matched_primary.add(index)
            continue
        username = supplement.get("name")
        if not isinstance(username, str) or not username:
            discrepancies.append(
                {
                    "category": "supplemental_record_missing_username",
                    "message": "Get-LocalUser returned an account without a usable name; it was retained as an error, not serialized as an account.",
                }
            )
            continue
        candidate = {
            "username": username,
            "sid": supplement.get("sid"),
            "account_flags": None,
            "account_flag_names": None,
            "enabled": supplement.get("enabled"),
            "disabled": (
                not supplement["enabled"]
                if isinstance(supplement.get("enabled"), bool)
                else None
            ),
            "locked_out": None,
            "password_required": supplement.get("password_required"),
            "password_cannot_be_changed": (
                not supplement["user_may_change_password"]
                if isinstance(supplement.get("user_may_change_password"), bool)
                else None
            ),
            "password_never_expires": supplement.get("password_never_expires"),
            "password_expired": None,
            "password_age_seconds": None,
            "password_last_set_utc_derived": None,
            "password_last_set_derivation_status": "unavailable",
            "password_last_set_observed_at_utc": None,
            "password_last_set_uncertainty": None,
            "password_expires_utc_derived": None,
            "password_expiration_status": "unavailable",
            "supplemental_timestamps": {
                key: supplement.get(key)
                for key in (
                    "password_last_set_utc",
                    "password_expires_utc",
                    "last_logon_utc",
                    "account_expires_utc",
                )
                if supplement.get(key) is not None
            },
            "password_never_expires_supplemental": supplement.get("password_never_expires"),
            "account_expiration": {
                "raw": None,
                "utc": supplement.get("account_expires_utc"),
                "status": "supplemental_provider_direct_value"
                if supplement.get("account_expires_utc") is not None
                else "unavailable",
            },
            "privilege_level": None,
            "privilege_classification": None,
            "primary_group_id": None,
            "provider_user_id": None,
            "full_name": supplement.get("full_name"),
            "description": supplement.get("description"),
            "user_comment": None,
            "home_directory": None,
            "home_drive": None,
            "profile_path": None,
            "logon_script_path": None,
            "permitted_workstations": None,
            "logon_server": None,
            "last_logon": {
                "raw": None,
                "utc": supplement.get("last_logon_utc"),
                "status": "supplemental_provider_direct_value"
                if supplement.get("last_logon_utc") is not None
                else "unavailable",
            },
            "last_logoff": {"raw": None, "utc": None, "status": "unavailable"},
            "logon_hours": None,
            "logon_hours_units_per_week": None,
            "auth_flags": None,
            "bad_password_count": None,
            "bad_password_count_status": "unavailable",
            "logon_count": None,
            "logon_count_status": "unavailable",
            "country_code": None,
            "code_page": None,
            "max_storage_bytes": None,
            "information_levels_used": {},
            "sources": ["Get-LocalUser supplemental account"],
            "observed_at_utc": utc_now(),
            "errors": [],
        }
        if isinstance(candidate["sid"], str):
            candidate["sid_source"] = "Get-LocalUser"
            candidate["sid_resolution"] = {
                "status": "resolved",
                "source": "Get-LocalUser",
                "error": None,
            }
        else:
            candidate["sid_source"] = None
            candidate["sid_resolution"] = {
                "status": "unresolved",
                "source": "Get-LocalUser",
                "error": None,
            }
        candidate["builtin_account"] = classify_builtin_sid(candidate["sid"])
        candidate["principal_source"] = supplement.get("principal_source")
        candidate["supplemental_account_settings"] = {
            setting: supplement[setting]
            for setting in (
                "enabled",
                "user_may_change_password",
                "password_required",
                "password_never_expires",
            )
            if supplement.get(setting) is not None
        }
        merged.append((candidate, supplement))
        index = len(merged) - 1
        discrepancies.append(
            {
                "category": "provider_account_set_mismatch",
                "username": username,
                "sid": candidate["sid"],
                "message": "Account was returned by Get-LocalUser but not by the completed NetUserEnum pages; supplemental record retained and inventory marked partial.",
            }
        )
    return merged, discrepancies


def _compare_account_sets(
    primary_records: list[dict[str, Any]],
    supplemental_records: list[dict[str, Any]],
) -> dict[str, Any]:
    by_sid: dict[str, list[int]] = {}
    for index, record in enumerate(supplemental_records):
        sid = record.get("sid")
        if isinstance(sid, str) and sid:
            by_sid.setdefault(sid.casefold(), []).append(index)
    matched_supplemental: set[int] = set()
    netapi_only: list[dict[str, Any]] = []
    for record in primary_records:
        sid = record.get("sid")
        name = record.get("username")
        candidates = (
            by_sid.get(sid.casefold(), [])
            if isinstance(sid, str) and sid
            else []
        )
        match = next(
            (index for index in candidates if index not in matched_supplemental),
            None,
        )
        if match is None:
            netapi_only.append({"username": name, "sid": sid})
        else:
            matched_supplemental.add(match)
    supplemental_only = [
        {
            "username": record.get("name"),
            "sid": record.get("sid"),
        }
        for index, record in enumerate(supplemental_records)
        if index not in matched_supplemental
    ]
    return {
        "status": "match"
        if not netapi_only and not supplemental_only
        else "mismatch",
        "netapi_only_count": len(netapi_only),
        "get_local_user_only_count": len(supplemental_only),
        "netapi_only_accounts": netapi_only,
        "get_local_user_only_accounts": supplemental_only,
        "username_fallback_match_count": 0,
    }


def build_inventory(
    *,
    api: Any,
    scope_provider: Callable[[], dict[str, Any]] = detect_local_account_scope,
    supplemental_provider: Callable[[], dict[str, Any]] = read_local_users_supplemental,
    now_provider: Callable[[], str] = utc_now,
    preferred_length: int = MAX_PREFERRED_LENGTH,
) -> dict[str, Any]:
    started = now_provider()
    scope = scope_provider()
    errors: list[dict[str, Any]] = []
    if scope.get("status") == "domain_controller":
        ended = now_provider()
        return {
            "artifact_id": ARTIFACT_ID,
            **_timestamp_fields(started, ended),
            "scope": {
                "target": "local computer",
                "account_database": "Active Directory on a domain controller",
                "computer_role": scope,
            },
            "status": "failed",
            "providers": [],
            "enumeration_complete": False,
            "account_count": 0,
            "accounts": [],
            "errors": [
                {
                    "category": "domain_controller_scope_unsupported",
                    "message": "A40 does not enumerate domain accounts. No NetUserEnum query was run.",
                }
            ],
            "limitations": ["Local-user collection is not supported on a domain controller."],
        }
    if scope.get("status") != "success":
        ended = now_provider()
        return {
            "artifact_id": ARTIFACT_ID,
            **_timestamp_fields(started, ended),
            "scope": {"target": "local computer", "computer_role": scope},
            "status": "failed",
            "providers": [],
            "enumeration_complete": False,
            "account_count": 0,
            "accounts": [],
            "errors": [
                {
                    "category": "local_scope_unverified",
                    "message": "Could not verify that this machine has a supported local account database.",
                    "detail": scope.get("error"),
                }
            ],
            "limitations": [],
        }

    computer_name = api.computer_name()
    enumeration = enumerate_netapi_users(api, preferred_length=preferred_length)
    errors.extend(enumeration["error"])
    warnings = list(enumeration.get("warnings", []))
    modal_info: dict[str, Any] | None = None
    modal_error: dict[str, Any] | None = None
    try:
        modal_info = api.user_modals_get()
    except Exception as exc:
        modal_error = _error_record(exc, operation="NetUserModalsGet(level=0)")
        errors.append(modal_error)
    max_password_age = (
        modal_info.get("max_passwd_age")
        if isinstance(modal_info, dict)
        else None
    )

    supplemental = supplemental_provider()
    supplemental_status = supplemental.get("status", "failed")
    if supplemental_status == "failed" and supplemental.get("error"):
        errors.append(
            {
                "category": "supplemental_provider_failed",
                "provider": supplemental.get("provider"),
                "error": supplemental.get("error"),
            }
        )
    if supplemental_status not in {"success", "unsupported", "failed"}:
        errors.append(
            {
                "category": "invalid_supplemental_provider_status",
                "message": f"Unexpected supplemental provider status: {supplemental_status}",
            }
        )
        supplemental_status = "failed"
        supplemental = {"accounts": [], "status": supplemental_status}
    supplemental_records = supplemental.get("accounts", [])
    if not isinstance(supplemental_records, list):
        errors.append(
            {
                "category": "invalid_supplemental_provider_result",
                "message": "Supplemental account records were not a list.",
            }
        )
        supplemental_records = []

    observed_accounts: list[dict[str, Any]] = []
    for enum_record in enumeration["entries"]:
        username = enum_record.get("name", enum_record.get("usri3_name"))
        if not isinstance(username, str) or not username:
            errors.append(
                {
                    "category": "enumerated_record_missing_username",
                    "message": "A NetUserEnum record did not include a usable account name.",
                }
            )
            continue
        observed_accounts.append(
            normalize_account(
                username,
                [("NetUserEnum", enum_record, NETUSERENUM_LEVEL)],
                api=api,
                computer_name=computer_name,
                observed_at_utc=now_provider(),
                max_password_age_seconds=max_password_age,
            )
        )

    combined, discrepancies = _merge_account_sets(
        observed_accounts,
        [
            item
            for item in supplemental_records
            if isinstance(item, dict)
        ],
    )
    errors.extend(discrepancies)
    accounts: list[dict[str, Any]] = []
    for account, supplemental_record in combined:
        username = account.get("username")
        if not isinstance(username, str) or not username:
            accounts.append(account)
            continue
        sources: list[tuple[str, dict[str, Any], int]] = []
        primary_record = next(
            (
                item
                for item in enumeration["entries"]
                if str(item.get("name", item.get("usri3_name", ""))).casefold()
                == username.casefold()
            ),
            None,
        )
        if primary_record is not None:
            sources.append(("NetUserEnum", primary_record, NETUSERENUM_LEVEL))
        details_error: dict[str, Any] | None = None
        details_warning: dict[str, Any] | None = None
        detail_failures: list[dict[str, Any]] = []
        for information_level in (
            NETUSERGETINFO_PRIMARY_LEVEL,
            *NETUSERGETINFO_FALLBACK_LEVELS,
        ):
            try:
                detail_record = api.user_get_info(username, information_level)
                if not isinstance(detail_record, dict):
                    raise TypeError("NetUserGetInfo did not return a mapping.")
            except Exception as detail_exc:
                detail_failures.append(
                    _error_record(
                        detail_exc,
                        operation=f"NetUserGetInfo(level={information_level})",
                    )
                )
                continue
            sources.append(("NetUserGetInfo", detail_record, information_level))
            if detail_failures:
                if all(
                    item["category"] == "unsupported_information_level"
                    for item in detail_failures
                ):
                    details_warning = {
                        "category": "unsupported_information_level_fallback",
                        "message": "A more comprehensive NetUserGetInfo level was unsupported; a lower supported level succeeded.",
                        "attempts": detail_failures,
                    }
                else:
                    details_error = {
                        "category": "account_enrichment_fallback_after_provider_error",
                        "attempts": detail_failures,
                    }
            break
        if not sources or sources[-1][0] != "NetUserGetInfo":
            details_error = {
                "category": "account_enrichment_failed",
                "attempts": detail_failures,
            }
        initial_sid = account.get("sid")
        if sources:
            enriched = normalize_account(
                username,
                sources,
                api=api,
                computer_name=computer_name,
                observed_at_utc=now_provider(),
                max_password_age_seconds=max_password_age,
                initial_sid=initial_sid if isinstance(initial_sid, str) else None,
                initial_sid_source=account.get("sid_source"),
                supplemental=supplemental_record,
            )
            enriched["errors"].extend(account.get("errors", []))
            if details_error:
                enriched["errors"].append(details_error)
                errors.append(
                    {
                        "category": "account_enrichment_failed_or_fallback_used",
                        "username": username,
                        "detail": details_error,
                    }
                )
            if details_warning:
                warnings.append({"username": username, **details_warning})
            accounts.append(enriched)
        else:
            account.setdefault("errors", []).append(
                details_error
                or {
                    "category": "account_enrichment_unavailable",
                    "message": "No NetUserGetInfo information was available.",
                }
            )
            errors.append(
                {
                    "category": "account_enrichment_failed",
                    "username": username,
                    "detail": details_error,
                }
            )
            accounts.append(account)

    if enumeration["complete"] and not enumeration["entries"]:
        errors.append(
            {
                "category": "empty_primary_enumeration",
                "message": "NetUserEnum completed without accounts; an empty local-user inventory is not treated as verified.",
            }
        )
    if supplemental_status == "success":
        valid_supplemental_records = [
            item for item in supplemental_records if isinstance(item, dict)
        ]
        provider_consistency = _compare_account_sets(
            observed_accounts,
            valid_supplemental_records,
        )
        if not observed_accounts and valid_supplemental_records:
            warnings.append(
                {
                    "category": "unresolved_empty_netapi_enumeration",
                    "message": (
                        "NetUserEnum returned no accounts while Get-LocalUser "
                        "returned accounts; this is an unresolved provider "
                        "discrepancy, and the available evidence does not "
                        "establish a cause."
                    ),
                    "netuserenum_filter": FILTER_NORMAL_ACCOUNT,
                    "netuserenum_filter_meaning": (
                        "normal user accounts; trust/machine account classes "
                        "are excluded"
                    ),
                    "information_levels_tried": enumeration["levels_tried"],
                    "pages": enumeration["pages"],
                    "enumeration_status": enumeration["status"],
                    "enumeration_complete": enumeration["complete"],
                    "resume_handle": enumeration["last_resume_handle"],
                    "get_local_user_account_count": len(valid_supplemental_records),
                }
            )
        if provider_consistency["status"] == "mismatch":
            errors.append(
                {
                    "category": "provider_account_set_mismatch",
                    "message": "NetUserEnum and Get-LocalUser returned different account sets; all supplemental-only accounts were retained and inventory is partial.",
                    "netapi_only_count": provider_consistency["netapi_only_count"],
                    "get_local_user_only_count": provider_consistency["get_local_user_only_count"],
                }
            )
    else:
        provider_consistency = {
            "status": "not_compared",
            "reason": supplemental.get("error"),
        }
    primary_complete = bool(enumeration["complete"])
    enumeration_complete = (
        primary_complete
        and bool(enumeration["entries"])
        and provider_consistency["status"] in {"match", "not_compared"}
    )
    if not primary_complete and enumeration["status"] == "failed":
        status = "failed" if not accounts else "partial"
    elif (
        not primary_complete
        or provider_consistency["status"] == "mismatch"
        or any(account.get("errors") for account in accounts)
        or modal_error
        or (supplemental_status == "failed")
        or not enumeration["entries"]
    ):
        status = "partial"
    else:
        status = "success"

    ended = now_provider()
    providers = [
        {
            "name": "pywin32 win32net.NetUserEnum",
            "role": "primary local account enumeration",
            "information_levels_tried": enumeration["levels_tried"],
            "filter": FILTER_NORMAL_ACCOUNT,
            "filter_meaning": "normal user accounts; trust/machine account classes are excluded",
            "preferred_maximum_length": preferred_length,
            "pages": enumeration["pages"],
            "status": enumeration["status"],
            "complete": primary_complete,
            "resume_handle": enumeration["last_resume_handle"],
        },
        {
            "name": "pywin32 win32net.NetUserGetInfo",
            "role": "per-account details",
            "information_levels": [
                NETUSERGETINFO_PRIMARY_LEVEL,
                *NETUSERGETINFO_FALLBACK_LEVELS,
            ],
            "sid_resolution": "pywin32 win32security.LookupAccountName against the local computer",
        },
        {
            "name": "pywin32 win32net.NetUserModalsGet",
            "role": "local password-policy maximum age used only for an explicitly marked expiry estimate",
            "information_level": 0,
            "status": "success" if modal_info is not None else "failed",
            "error": modal_error,
        },
        {
            "name": supplemental.get(
                "provider", "PowerShell Microsoft.PowerShell.LocalAccounts"
            ),
            "role": "independent cross-check and supplemental account source; never silently replaces NetAPI",
            "status": supplemental_status,
            "account_count": len(supplemental_records),
            "error": supplemental.get("error"),
        },
    ]
    return {
        "artifact_id": ARTIFACT_ID,
        **_timestamp_fields(started, ended),
        "scope": {
            "target": "local computer",
            "computer_name": computer_name,
            "account_database": "local SAM; domain accounts and active sessions are out of scope",
            "computer_role": scope,
        },
        "status": status,
        "providers": providers,
        "enumeration_complete": enumeration_complete,
        "primary_enumeration_complete": primary_complete,
        "provider_consistency": provider_consistency,
        "account_count": len(accounts),
        "accounts": accounts,
        "password_policy": (
            {
                "source": "NetUserModalsGet(level=0)",
                "maximum_password_age_seconds": max_password_age,
                "maximum_password_age_status": (
                    "never" if _is_all_bits_set_sentinel(max_password_age) else "available"
                )
                if isinstance(max_password_age, int)
                else "unavailable",
            }
            if modal_info is not None
            else {"source": "NetUserModalsGet(level=0)", "status": "unavailable"}
        ),
        "errors": errors,
        "warnings": warnings,
        "limitations": [
            "No passwords, password hashes, credential material, tokens, SAM/SECURITY hives, or LSASS memory are collected.",
            "NetUserEnum is the primary provider. Get-LocalUser is an independent, explicitly identified supplemental provider; disagreements are preserved and make the result partial.",
            "A domain controller is rejected because its security database is Active Directory rather than the local SAM.",
            "NetUserEnum FILTER_NORMAL_ACCOUNT intentionally excludes trust and machine account classes.",
            "Password last-set time is derived from the provider age and query observation time; it is not a directly returned stored timestamp.",
            "Password expiration is estimated only when NetUserModalsGet returns a finite maximum age; account expiration is separate.",
            "Last logon/logoff zero values are preserved as not recorded and are not converted to the Unix epoch.",
            "Logon-hours bitmaps are preserved in hexadecimal and not decoded into a weekly schedule.",
            "Account records can change during collection; NetAPI account-not-found errors are retained with the affected record.",
        ],
    }


def _write_json(path: Path, document: dict[str, Any], overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing JSON output: {path}")
    content = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
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


def collect_local_users(
    output_path: str | os.PathLike[str],
    *,
    overwrite: bool = False,
    api: Any | None = None,
    scope_provider: Callable[[], dict[str, Any]] = detect_local_account_scope,
    supplemental_provider: Callable[[], dict[str, Any]] = read_local_users_supplemental,
    now_provider: Callable[[], str] = utc_now,
    preferred_length: int = MAX_PREFERRED_LENGTH,
) -> dict[str, Any]:
    path = Path(output_path).expanduser().resolve()
    if path.exists() and path.is_dir():
        path = _default_output_path(path)
    if path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing JSON output: {path}")
    if api is None:
        api = PyWin32NetApi()
    result = build_inventory(
        api=api,
        scope_provider=scope_provider,
        supplemental_provider=supplemental_provider,
        now_provider=now_provider,
        preferred_length=preferred_length,
    )
    result["output_path"] = str(path)
    _write_json(path, result, overwrite)
    return result


def _default_output_path(directory: Path = DEFAULT_OUTPUT_DIRECTORY) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    return directory / f"Local Users-{timestamp}.json"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only inventory of local Windows user accounts."
    )
    parser.add_argument(
        "--output",
        help="Destination JSON file or existing folder. If omitted, prompts or uses the A40 artifact folder.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacing an existing JSON output file.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    args = _build_parser().parse_args(arguments)
    if args.output:
        output_path = Path(args.output.strip().strip('"'))
    elif sys.stdin.isatty():
        try:
            response = input(
                f"Output JSON file path (press Enter for {_default_output_path()}): "
            ).strip().strip('"')
        except (EOFError, KeyboardInterrupt) as exc:
            print(f"A40 collection was not started: {exc}", file=sys.stderr)
            return EXIT_FAILURE
        output_path = Path(response) if response else _default_output_path()
    else:
        output_path = _default_output_path()
    try:
        result = collect_local_users(output_path, overwrite=args.overwrite)
    except Exception as exc:
        print(f"A40 collection failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    print(
        f"A40 collection {result['status']}: {result['account_count']} accounts; "
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
