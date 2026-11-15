"""Read-only collector for modern Windows Recycle Bin contents (artifact A18)."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import re
import shutil
import stat
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from ctypes import wintypes

ARTIFACT_ID = "A18"
EXIT_SUCCESS = 0
EXIT_PARTIAL = 1
EXIT_FAILURE = 2
SID_PATTERN = re.compile(r"S-\d+(?:-\d+)+", re.IGNORECASE)
VOLUME_PATTERN = re.compile(r"([A-Za-z])(?::\\?)?")
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
MAX_COPY_DEPTH = 128


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
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _normalize_utc_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            field_path = f"{path}.{key}"
            if key.endswith("_utc") and isinstance(item, str):
                match = re.search(r"(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$", item)
                if match is None:
                    raise ValueError(f"{field_path} must include a timezone offset.")
                precision = len(match.group(1) or "")
                if precision > 6:
                    raise ValueError(f"{field_path} exceeds supported microsecond precision.")
                parsed = datetime.fromisoformat(
                    item[:-1] + "+00:00" if item.endswith("Z") else item
                )
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    raise ValueError(f"{field_path} must be timezone-aware.")
                normalized = parsed.astimezone(timezone.utc)
                result = (
                    f"{normalized.year:04d}-{normalized.month:02d}-{normalized.day:02d}"
                    f"T{normalized.hour:02d}:{normalized.minute:02d}:{normalized.second:02d}"
                )
                if precision:
                    result += f".{normalized.microsecond:06d}"[: precision + 1]
                value[key] = result + "+00:00"
            else:
                _normalize_utc_fields(item, field_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _normalize_utc_fields(item, f"{path}[{index}]")


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
        "collection_started_at_utc": started.isoformat(timespec="microseconds"),
        "collection_ended_at_utc": ended.isoformat(timespec="microseconds"),
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


def validate_volume(value: str) -> str:
    match = VOLUME_PATTERN.fullmatch(value.strip())
    if not match:
        raise ValueError(f"Invalid local drive letter: {value!r}")
    return f"{match.group(1).upper()}:\\"


def validate_scope(volumes: Iterable[str]) -> list[str]:
    normalized_volumes = list(dict.fromkeys(validate_volume(item) for item in volumes))
    if not normalized_volumes:
        raise ValueError("Select at least one local source volume.")
    return normalized_volumes


def parse_i_file(data: bytes) -> dict[str, Any]:
    """Parse verified $I versions 1 and 2 without discarding input bytes."""
    result: dict[str, Any] = {
        "version": None,
        "format_name": None,
        "parse_status": "malformed",
        "original_size_bytes": None,
        "deletion_time_filetime_100ns": None,
        "deletion_time_utc": None,
        "deletion_time_local": None,
        "deletion_time_100ns_remainder": None,
        "original_path": None,
        "warnings": [],
    }
    if len(data) < 8:
        result["warnings"].append("Metadata is shorter than the 8-byte version field.")
        return result

    version = int.from_bytes(data[0:8], "little", signed=False)
    result["version"] = version
    if version not in (1, 2):
        result["parse_status"] = "unsupported"
        result["warnings"].append(f"Unsupported modern $I version {version}.")
        return result

    result["format_name"] = "Vista-layout-v1" if version == 1 else "Windows-10-layout-v2"
    fixed_length = 24 if version == 1 else 28
    if len(data) < fixed_length:
        result["warnings"].append(
            f"Metadata is truncated before the version {version} fixed fields end."
        )
        return result

    anomalous_v1 = version == 1 and len(data) == 543
    if version == 1 and len(data) not in (544, 543):
        result["warnings"].append(
            f"Version 1 metadata has {len(data)} bytes; the documented fixed size is 544."
        )

    size_end = 15 if anomalous_v1 else 16
    size_bytes = data[8:size_end]
    if len(size_bytes) == 8 and not anomalous_v1:
        result["original_size_bytes"] = int.from_bytes(size_bytes, "little")
    elif anomalous_v1:
        result["warnings"].append(
            "Observed 543-byte version 1 variant; original size is withheld because "
            "the maintained parser treats its 56-bit size as unreliable."
        )
    else:
        result["warnings"].append("Original-size field is incomplete.")

    time_offset = 15 if anomalous_v1 else 16
    ticks = int.from_bytes(data[time_offset : time_offset + 8], "little", signed=False)
    result["deletion_time_filetime_100ns"] = ticks
    result["deletion_time_100ns_remainder"] = ticks % 10
    try:
        deletion_time = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=ticks // 10
        )
        result["deletion_time_utc"] = deletion_time.isoformat(timespec="microseconds")
        result["deletion_time_local"] = deletion_time.astimezone().isoformat(
            timespec="microseconds"
        )
        current_utc = datetime.now(timezone.utc)
        if deletion_time.year < 2007 or deletion_time > current_utc + timedelta(days=366):
            result["warnings"].append(
                "FILETIME converts successfully but is suspicious for a modern Recycle Bin record."
            )
    except (OverflowError, ValueError):
        result["deletion_time_utc"] = None
        result["warnings"].append("FILETIME is outside the supported UTC datetime range.")

    if version == 1:
        path_offset = 23 if anomalous_v1 else 24
        expected_path_bytes = 520
        available_path = data[path_offset:]
        path_data = available_path[:expected_path_bytes]
        if len(available_path) != expected_path_bytes:
            result["warnings"].append(
                f"Version 1 UTF-16 path area is incomplete or has extra bytes "
                f"({len(available_path)} available; {expected_path_bytes} expected)."
            )
    else:
        char_count = int.from_bytes(data[24:28], "little")
        expected_path_bytes = char_count * 2
        path_offset = 28
        if expected_path_bytes > len(data) - path_offset:
            result["warnings"].append(
                "Version 2 UTF-16 path length exceeds the bytes present in the metadata."
            )
            path_data = data[path_offset:]
        else:
            path_data = data[path_offset : path_offset + expected_path_bytes]
            if path_offset + expected_path_bytes != len(data):
                result["warnings"].append(
                    "Version 2 metadata has bytes beyond its declared UTF-16 path."
                )

    terminator = next(
        (index for index in range(0, len(path_data) - 1, 2)
         if path_data[index : index + 2] == b"\x00\x00"),
        len(path_data) - (len(path_data) % 2),
    )
    path_bytes = path_data[:terminator]
    path_complete = (
        (version == 1 and len(path_data) == expected_path_bytes)
        or (
            version == 2
            and expected_path_bytes <= len(data) - path_offset
            and len(path_data) == expected_path_bytes
        )
    )
    try:
        decoded_path = path_bytes.decode("utf-16le", errors="strict")
        if path_complete:
            result["original_path"] = decoded_path
        else:
            result["warnings"].append("Original path is withheld because its field is truncated.")
    except UnicodeDecodeError:
        result["warnings"].append("Original path contains malformed UTF-16LE.")

    if result["warnings"]:
        result["parse_status"] = "partial"
    else:
        result["parse_status"] = "parsed"
    return result


def pair_items(names: Iterable[str]) -> list[dict[str, str | None]]:
    """Pair generated names only within the supplied single SID directory."""
    entries: dict[str, list[str]] = {"i": [], "r": []}
    for name in names:
        if len(name) >= 2 and name[:2].casefold() in ("$i", "$r"):
            entries["i" if name[1].casefold() == "i" else "r"].append(name)
    r_by_suffix: dict[str, list[str]] = {}
    for name in entries["r"]:
        r_by_suffix.setdefault(name[2:].casefold(), []).append(name)
    consumed_r: set[str] = set()
    pairs: list[dict[str, str | None]] = []
    for i_name in sorted(entries["i"], key=str.casefold):
        matches = r_by_suffix.get(i_name[2:].casefold(), [])
        if len(matches) == 1:
            r_name = matches[0]
            consumed_r.add(r_name)
            status = "paired"
        elif len(matches) > 1:
            r_name = None
            status = "ambiguous"
        else:
            r_name = None
            status = "i_only"
        pairs.append(
            {"i_filename": i_name, "r_filename": r_name, "pairing_status": status}
        )
    for r_name in sorted(entries["r"], key=str.casefold):
        if r_name not in consumed_r:
            pairs.append(
                {"i_filename": None, "r_filename": r_name, "pairing_status": "r_only"}
            )
    return pairs


def _is_reparse(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def filesystem_metadata(path: Path) -> dict[str, Any]:
    info = path.lstat()
    if _is_reparse(info) or stat.S_ISLNK(info.st_mode):
        kind = "reparse_point"
    elif stat.S_ISDIR(info.st_mode):
        kind = "directory"
    elif stat.S_ISREG(info.st_mode):
        kind = "file"
    else:
        kind = "other"

    def iso_time(value: float | None) -> str | None:
        if value is None:
            return None
        try:
            return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="microseconds")
        except (OverflowError, OSError, ValueError):
            return None

    return {
        "kind": kind,
        "reparse_point": kind == "reparse_point",
        "size_bytes": info.st_size,
        "creation_time_utc": iso_time(getattr(info, "st_birthtime", None) or (
            info.st_ctime if os.name == "nt" else None
        )),
        "last_write_time_utc": iso_time(info.st_mtime),
        "last_access_time_utc": iso_time(info.st_atime),
        "device_id": info.st_dev,
        "file_id": getattr(info, "st_ino", None),
    }


def _error(
    stage: str, message: str, path: Path | str | None = None, exc: BaseException | None = None
) -> dict[str, Any]:
    winerror = getattr(exc, "winerror", None) if exc is not None else None
    return {
        "stage": stage,
        "source_path": str(path) if path is not None else None,
        "exception_type": type(exc).__name__ if exc is not None else None,
        "winerror": winerror,
        "message": message,
    }


def _account_name_for_sid(sid_name: str) -> dict[str, Any]:
    result = {"resolved_account_name": None, "account_resolution": "unresolved_local_only"}
    if os.name != "nt":
        result["account_resolution"] = "not_available_off_windows"
        return result
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    convert_sid = advapi.ConvertStringSidToSidW
    lookup = advapi.LookupAccountSidW
    free = ctypes.WinDLL("kernel32", use_last_error=True).LocalFree
    sid_pointer = ctypes.c_void_p()
    convert_sid.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    convert_sid.restype = ctypes.c_int
    lookup.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_ulong),
    ]
    lookup.restype = ctypes.c_int
    free.argtypes = [ctypes.c_void_p]
    free.restype = ctypes.c_void_p
    if not convert_sid(sid_name, ctypes.byref(sid_pointer)):
        result["account_resolution"] = "invalid_sid"
        return result
    try:
        name_size = ctypes.c_ulong(0)
        domain_size = ctypes.c_ulong(0)
        use = ctypes.c_ulong(0)
        lookup(
            ".",
            sid_pointer,
            None,
            ctypes.byref(name_size),
            None,
            ctypes.byref(domain_size),
            ctypes.byref(use),
        )
        error = ctypes.get_last_error()
        if error != 122 or not name_size.value:
            return result
        name = ctypes.create_unicode_buffer(name_size.value)
        domain = ctypes.create_unicode_buffer(max(domain_size.value, 1))
        if not lookup(
            ".",
            sid_pointer,
            name,
            ctypes.byref(name_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(use),
        ):
            return result
        account_name = name.value
        result["resolved_account_name"] = (
            f"{domain.value}\\{account_name}" if domain.value else account_name
        )
        result["account_resolution"] = "local_computer_lookup"
        return result
    finally:
        free(sid_pointer)


def _is_local_volume(root: str) -> bool:
    if os.name != "nt":
        return True
    get_drive_type = ctypes.WinDLL("kernel32", use_last_error=True).GetDriveTypeW
    get_drive_type.argtypes = [wintypes.LPCWSTR]
    get_drive_type.restype = wintypes.UINT
    drive_type = get_drive_type(root)
    return drive_type in (DRIVE_REMOVABLE, DRIVE_FIXED)


def _discover_local_volumes() -> list[str]:
    if os.name != "nt":
        raise OSError("Automatic A18 drive discovery requires Windows.")
    get_logical_drives = ctypes.WinDLL("kernel32", use_last_error=True).GetLogicalDrives
    get_logical_drives.argtypes = []
    get_logical_drives.restype = wintypes.DWORD
    drive_mask = get_logical_drives()
    if not drive_mask:
        error = ctypes.get_last_error()
        if error:
            raise ctypes.WinError(error)
        return []

    volumes = []
    for index in range(26):
        if not drive_mask & (1 << index):
            continue
        volume = f"{chr(ord('A') + index)}:\\"
        if not _is_local_volume(volume):
            continue
        try:
            Path(volume).stat()
        except OSError as exc:
            print(
                f"Skipping unavailable local drive {volume[:2]}: {exc}",
                file=sys.stderr,
            )
            continue
        volumes.append(volume)
    return volumes


def _within(child: Path, parent: Path) -> bool:
    try:
        child.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def validate_output_destination(output_dir: str | Path, source_roots: Iterable[Path]) -> Path:
    destination = Path(output_dir).expanduser().resolve()
    if not destination.is_dir():
        raise NotADirectoryError(f"Output destination must be an existing directory: {destination}")
    for source_tree in source_roots:
        if _within(destination, source_tree):
            raise ValueError(
                f"Output destination is inside a selected source Recycle Bin tree: {source_tree}"
            )
    return destination


def _windows_io_path(path: Path) -> str:
    value = os.fspath(path)
    if os.name != "nt":
        return value
    if value.startswith("\\\\?\\"):
        return value
    absolute = os.path.abspath(value)
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


def _copy_file(
    source: Path, destination: Path, overwrite: bool, errors: list[dict[str, Any]], stage: str
) -> tuple[str, int | None]:
    try:
        source_before = source.lstat()
        if _is_reparse(source_before) or stat.S_ISLNK(source_before.st_mode):
            raise OSError("Refusing to follow a source reparse point.")
        if not stat.S_ISREG(source_before.st_mode):
            raise OSError("Source is not a regular file.")
        io_destination = Path(_windows_io_path(destination))
        io_destination.parent.mkdir(parents=True, exist_ok=True)
        if io_destination.exists() and not overwrite:
            raise FileExistsError(f"Destination already exists: {destination}")
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        io_temporary = Path(_windows_io_path(temporary))
        try:
            with source.open("rb") as source_stream:
                opened_info = os.fstat(source_stream.fileno())
                if (
                    _is_reparse(opened_info)
                    or opened_info.st_dev != source_before.st_dev
                    or opened_info.st_ino != source_before.st_ino
                ):
                    raise OSError("Source changed to a different or reparse target before opening.")
                with io_temporary.open("xb") as output_stream:
                    shutil.copyfileobj(source_stream, output_stream, length=1024 * 1024)
                    output_stream.flush()
                    os.fsync(output_stream.fileno())
            source_after = source.lstat()
            changed = (
                source_before.st_size != source_after.st_size
                or source_before.st_mtime_ns != source_after.st_mtime_ns
                or source_before.st_ino != source_after.st_ino
            )
            if io_destination.exists() and not overwrite:
                raise FileExistsError(f"Destination already exists: {destination}")
            os.replace(io_temporary, io_destination)
            if changed:
                errors.append(
                    _error(stage, "Source changed while being copied; copied bytes may be partial.", source)
                )
                return "partial", io_destination.stat().st_size
            return "copied", io_destination.stat().st_size
        finally:
            try:
                io_temporary.unlink()
            except FileNotFoundError:
                pass
    except OSError as exc:
        errors.append(_error(stage, str(exc), source, exc))
        return "failed", None


def _copy_tree(
    source: Path,
    destination: Path,
    overwrite: bool,
    errors: list[dict[str, Any]],
    seen: set[tuple[int, int]],
    depth: int = 0,
) -> dict[str, Any]:
    summary = {"status": "copied", "files": 0, "directories": 0, "bytes": 0}
    try:
        info = source.lstat()
        if _is_reparse(info) or stat.S_ISLNK(info.st_mode):
            raise OSError("Refusing to traverse a source reparse point.")
        if not stat.S_ISDIR(info.st_mode):
            summary["status"], size = _copy_file(source, destination, overwrite, errors, "content_copy")
            if size is not None:
                summary["files"], summary["bytes"] = 1, size
            return summary
        if depth >= MAX_COPY_DEPTH:
            raise OSError(f"Directory traversal exceeded maximum depth {MAX_COPY_DEPTH}.")
        identity = (info.st_dev, info.st_ino)
        if identity in seen:
            raise OSError("Directory identity was already visited; refusing a possible loop.")
        seen.add(identity)
        if destination.exists() and not destination.is_dir():
            raise FileExistsError(f"Directory destination conflicts with a file: {destination}")
        if destination.exists() and not overwrite:
            raise FileExistsError(f"Directory destination already exists: {destination}")
        destination.mkdir(parents=True, exist_ok=True)
        summary["directories"] = 1
        with os.scandir(source) as children:
            child_entries = sorted(list(children), key=lambda item: item.name.casefold())
        scanned_info = source.lstat()
        if (
            _is_reparse(scanned_info)
            or scanned_info.st_dev != info.st_dev
            or scanned_info.st_ino != info.st_ino
        ):
            raise OSError("Source directory changed during enumeration; traversal stopped.")
        for child in child_entries:
            child_source = Path(child.path)
            child_destination = destination / child.name
            child_summary = _copy_tree(
                child_source, child_destination, overwrite, errors, seen, depth + 1
            )
            summary["files"] += child_summary["files"]
            summary["directories"] += child_summary["directories"]
            summary["bytes"] += child_summary["bytes"]
            if child_summary["status"] != "copied":
                summary["status"] = "partial"
        after = source.lstat()
        if info.st_mtime_ns != after.st_mtime_ns or info.st_ino != after.st_ino:
            errors.append(_error("content_copy", "Directory changed during traversal.", source))
            summary["status"] = "partial"
    except OSError as exc:
        errors.append(_error("content_copy", str(exc), source, exc))
        summary["status"] = "failed" if summary["files"] == 0 else "partial"
    return summary


def _copy_metadata(
    source: Path, output: Path, overwrite: bool, entry_errors: list[dict[str, Any]]
) -> tuple[str, str | None]:
    status, _size = _copy_file(source, output, overwrite, entry_errors, "metadata_preservation")
    return status, str(output) if status in ("copied", "partial") else None


def _read_metadata(source: Path) -> tuple[bytes | None, dict[str, Any] | None]:
    try:
        info = source.lstat()
        if _is_reparse(info) or stat.S_ISLNK(info.st_mode):
            raise OSError("Refusing to read metadata through a reparse point.")
        if not stat.S_ISREG(info.st_mode):
            raise OSError("Metadata source is not a regular file.")
        return source.read_bytes(), None
    except OSError as exc:
        return None, _error("metadata_read", str(exc), source, exc)


def _entry_base(volume: str, sid: str, root: Path) -> dict[str, Any]:
    identity = _account_name_for_sid(sid)
    return {
        "source_volume": volume,
        "recycle_bin_root": str(root),
        "sid_folder_name": sid,
        **identity,
        "collection_observed_at_utc": utc_now(),
    }


def _enumerate_sid(
    volume: str,
    sid: str,
    sid_root: Path,
    output_root: Path,
    content_requested: bool,
    overwrite: bool,
    result: dict[str, Any],
) -> None:
    scope_path = sid_root / sid
    scope_output = output_root / f"volume-{volume[0]}" / sid
    try:
        bin_root_info = sid_root.lstat()
        if _is_reparse(bin_root_info) or not stat.S_ISDIR(bin_root_info.st_mode):
            raise OSError("Refusing to enumerate a non-directory or reparse Recycle Bin root.")
        directory_before = scope_path.lstat()
        if _is_reparse(directory_before) or stat.S_ISLNK(directory_before.st_mode):
            raise OSError("Refusing to enumerate a SID reparse point.")
        if not stat.S_ISDIR(directory_before.st_mode):
            raise NotADirectoryError(f"SID location is not a directory: {scope_path}")
        with os.scandir(scope_path) as iterator:
            names = [item.name for item in iterator]
        directory_after = scope_path.lstat()
        if (
            directory_before.st_dev != directory_after.st_dev
            or directory_before.st_ino != directory_after.st_ino
        ):
            result["enumeration"]["complete"] = False
            result["errors"].append(
                _error("enumeration", "SID directory changed while being enumerated.", scope_path)
            )
    except FileNotFoundError:
        result["enumeration"]["locations"].append(
            {"path": str(scope_path), "status": "not_present", "complete": True}
        )
        return
    except OSError as exc:
        result["enumeration"]["locations"].append(
            {"path": str(scope_path), "status": "inaccessible", "complete": False}
        )
        result["enumeration"]["complete"] = False
        result["errors"].append(_error("enumeration", str(exc), scope_path, exc))
        return

    result["enumeration"]["locations"].append(
        {"path": str(scope_path), "status": "enumerated", "complete": True}
    )
    classified_names = {
        name.casefold() for name in names
        if len(name) >= 2 and name[:2].casefold() in ("$i", "$r")
    }
    for pairing in pair_items(names):
        i_name = pairing["i_filename"]
        r_name = pairing["r_filename"]
        i_source = scope_path / i_name if i_name else None
        r_source = scope_path / r_name if r_name else None
        entry = _entry_base(volume, sid, sid_root)
        entry.update(
            {
                "i_filename": i_name,
                "i_source_path": str(i_source) if i_source else None,
                "i_output_path": None,
                "r_filename": r_name,
                "r_source_path": str(r_source) if r_source else None,
                "pairing_status": pairing["pairing_status"],
                "i_format_version": None,
                "metadata_parse_status": "not_applicable" if i_source is None else "unreadable",
                "original_path": None,
                "original_size_bytes": None,
                "deletion_time_filetime_100ns": None,
                "deletion_time_utc": None,
                "deletion_time_local": None,
                "deletion_time_100ns_remainder": None,
                "i_file_size_bytes": None,
                "i_filesystem_metadata": None,
                "r_item_type": "missing" if r_source is None else "inaccessible",
                "r_filesystem_metadata": None,
                "observed_content_size_bytes": None,
                "content_copy_status": "not_requested" if not content_requested else "not_started",
                "content_output_path": None,
                "content_copy_summary": None,
                "parse_warnings": [],
                "errors": [],
                "collection_observed_at_utc": utc_now(),
            }
        )
        result["entries"].append(entry)
        if pairing["pairing_status"] == "ambiguous":
            entry["errors"].append(
                _error("pairing", "Multiple $R items have this generated-name suffix.", scope_path)
            )

        if i_source is not None:
            try:
                i_meta = filesystem_metadata(i_source)
                entry["i_filesystem_metadata"] = i_meta
                entry["i_file_size_bytes"] = i_meta["size_bytes"]
            except OSError as exc:
                entry["errors"].append(_error("metadata_stat", str(exc), i_source, exc))
            preserved_path = scope_output / "metadata" / i_name
            entry["metadata_preservation_status"], entry["i_output_path"] = _copy_metadata(
                i_source, preserved_path, overwrite, entry["errors"]
            )
            parse_source = Path(entry["i_output_path"]) if entry["i_output_path"] else i_source
            raw, read_error = _read_metadata(parse_source)
            if read_error:
                entry["errors"].append(read_error)
            elif raw is not None:
                parsed = parse_i_file(raw)
                entry["i_format_version"] = parsed["version"]
                entry["metadata_parse_status"] = parsed["parse_status"]
                entry["original_path"] = parsed["original_path"]
                entry["original_size_bytes"] = parsed["original_size_bytes"]
                entry["deletion_time_filetime_100ns"] = parsed["deletion_time_filetime_100ns"]
                entry["deletion_time_utc"] = parsed["deletion_time_utc"]
                entry["deletion_time_local"] = parsed["deletion_time_local"]
                entry["deletion_time_100ns_remainder"] = parsed[
                    "deletion_time_100ns_remainder"
                ]
                entry["parse_warnings"] = parsed["warnings"]
        else:
            entry["metadata_preservation_status"] = "not_applicable"

        if r_source is not None:
            try:
                r_meta = filesystem_metadata(r_source)
                entry["r_filesystem_metadata"] = r_meta
                entry["r_item_type"] = r_meta["kind"]
                if r_meta["kind"] == "file":
                    entry["observed_content_size_bytes"] = r_meta["size_bytes"]
            except FileNotFoundError as exc:
                entry["r_item_type"] = "missing"
                entry["errors"].append(_error("content_stat", str(exc), r_source, exc))
            except OSError as exc:
                entry["r_item_type"] = "inaccessible"
                entry["errors"].append(_error("content_stat", str(exc), r_source, exc))
            if content_requested:
                if entry["r_item_type"] == "missing":
                    entry["content_copy_status"] = "missing"
                elif entry["r_item_type"] == "reparse_point":
                    entry["content_copy_status"] = "skipped_reparse_point"
                elif entry["r_item_type"] == "inaccessible":
                    entry["content_copy_status"] = "inaccessible"
                else:
                    destination = scope_output / "content" / r_name
                    entry["content_output_path"] = str(destination)
                    if entry["r_item_type"] == "directory":
                        copied = _copy_tree(r_source, destination, overwrite, entry["errors"], set())
                        entry["content_copy_summary"] = copied
                        entry["content_copy_status"] = copied["status"]
                        entry["observed_content_size_bytes"] = None
                    elif entry["r_item_type"] == "file":
                        status, observed = _copy_file(
                            r_source, destination, overwrite, entry["errors"], "content_copy"
                        )
                        entry["content_copy_status"] = status
                        entry["content_copy_summary"] = {
                            "files": 1 if observed is not None else 0,
                            "directories": 0,
                            "bytes": observed or 0,
                            "status": status,
                        }
                    else:
                        entry["content_copy_status"] = "unsupported_item_type"
        elif content_requested:
            entry["content_copy_status"] = "missing"

    for name in names:
        if name.casefold() in classified_names:
            continue
        source = scope_path / name
        try:
            metadata = filesystem_metadata(source)
            result["unclassified_items"].append(
                {
                    "source_volume": volume,
                    "sid_folder_name": sid,
                    "scope_location": str(scope_path),
                    "source_path": str(source),
                    "filesystem_metadata": metadata,
                    "reason": "Item in SID folder does not have a $I or $R generated name.",
                    "error": None,
                }
            )
        except OSError as exc:
            result["unclassified_items"].append(
                {
                    "source_volume": volume,
                    "sid_folder_name": sid,
                    "scope_location": str(scope_path),
                    "source_path": str(source),
                    "filesystem_metadata": None,
                    "reason": "Unclassified item could not be inspected.",
                    "error": _error("metadata_stat", str(exc), source, exc),
                }
            )


def _enumerate_legacy(
    volume: str, output_root: Path, overwrite: bool,
    result: dict[str, Any]
) -> None:
    for legacy_name in ("RECYCLER", "RECYCLED"):
        legacy_root = Path(volume) / legacy_name
        try:
            root_info = legacy_root.lstat()
            if _is_reparse(root_info) or not stat.S_ISDIR(root_info.st_mode):
                raise OSError("Refusing to enumerate a non-directory or reparse legacy root.")
            with os.scandir(legacy_root) as iterator:
                children = list(iterator)
        except FileNotFoundError:
            continue
        except OSError as exc:
            result["enumeration"]["complete"] = False
            result["enumeration"]["locations"].append(
                {"path": str(legacy_root), "status": "inaccessible", "complete": False}
            )
            result["errors"].append(_error("legacy_enumeration", str(exc), legacy_root, exc))
            continue
        result["enumeration"]["locations"].append(
            {"path": str(legacy_root), "status": "enumerated", "complete": True}
        )
        for child in children:
            candidate = Path(child.path)
            try:
                candidate_info = candidate.lstat()
                if _is_reparse(candidate_info) or stat.S_ISLNK(candidate_info.st_mode):
                    result["unclassified_items"].append(
                        {
                            "source_volume": volume,
                            "sid_folder_name": child.name if SID_PATTERN.fullmatch(child.name) else None,
                            "scope_location": str(legacy_root),
                            "source_path": str(candidate),
                            "filesystem_metadata": filesystem_metadata(candidate),
                            "reason": "Legacy reparse point was not followed.",
                            "error": None,
                        }
                    )
                    continue
                if child.is_dir(follow_symlinks=False):
                    with os.scandir(candidate) as items:
                        indexes = [
                            Path(item.path) for item in items
                            if item.name.casefold() in ("info", "info2")
                        ]
                    result["enumeration"]["locations"].append(
                        {"path": str(candidate), "status": "enumerated", "complete": True}
                    )
                elif child.name.casefold() in ("info", "info2"):
                    indexes = [candidate]
                else:
                    continue
            except OSError as exc:
                result["enumeration"]["complete"] = False
                result["enumeration"]["locations"].append(
                    {"path": str(candidate), "status": "inaccessible", "complete": False}
                )
                result["errors"].append(_error("legacy_enumeration", str(exc), candidate, exc))
                continue
            for index_path in indexes:
                item = {
                    "source_volume": volume,
                    "legacy_root": str(legacy_root),
                    "sid_folder_name": child.name if SID_PATTERN.fullmatch(child.name) else None,
                    "source_path": str(index_path),
                    "filename": index_path.name,
                    "format": "legacy_INFO" if index_path.name.casefold() == "info" else "legacy_INFO2",
                    "parse_status": "unsupported",
                    "reason": "Legacy INFO/INFO2 is a different format and is not parsed by this collector.",
                    "filesystem_metadata": None,
                    "output_path": None,
                    "preservation_status": "not_started",
                    "errors": [],
                }
                try:
                    item["filesystem_metadata"] = filesystem_metadata(index_path)
                    safe_root = re.sub(r"[^A-Za-z0-9_-]", "_", child.name)
                    destination = (
                        output_root / f"volume-{volume[0]}" / "legacy_metadata"
                        / legacy_name / safe_root / index_path.name
                    )
                    item["preservation_status"], item["output_path"] = _copy_metadata(
                        index_path, destination, overwrite, item["errors"]
                    )
                except OSError as exc:
                    item["errors"].append(_error("legacy_metadata", str(exc), index_path, exc))
                result["unsupported_items"].append(item)


def _volume_sid_folders(volume: str, roots: tuple[str, ...], result: dict[str, Any]) -> list[str]:
    found: dict[str, str] = {}
    for relative in roots:
        root = Path(volume) / relative
        try:
            root_info = root.lstat()
            if _is_reparse(root_info) or not stat.S_ISDIR(root_info.st_mode):
                raise OSError("Refusing to enumerate a non-directory or reparse bin root.")
            with os.scandir(root) as iterator:
                children = list(iterator)
        except FileNotFoundError:
            result["enumeration"]["locations"].append(
                {"path": str(root), "status": "not_present", "complete": True}
            )
            continue
        except OSError as exc:
            result["enumeration"]["complete"] = False
            result["enumeration"]["locations"].append(
                {"path": str(root), "status": "inaccessible", "complete": False}
            )
            result["errors"].append(_error("sid_enumeration", str(exc), root, exc))
            continue
        result["enumeration"]["locations"].append(
            {"path": str(root), "status": "enumerated", "complete": True}
        )
        for child in children:
            if not SID_PATTERN.fullmatch(child.name):
                path = Path(child.path)
                try:
                    metadata = filesystem_metadata(path)
                    reason = "Non-SID item at an enumerated Recycle Bin root."
                    error = None
                except OSError as exc:
                    metadata = None
                    reason = "Non-SID item at an enumerated root could not be inspected."
                    error = _error("sid_stat", str(exc), path, exc)
                result["unclassified_items"].append(
                    {
                        "source_volume": volume,
                        "sid_folder_name": None,
                        "scope_location": str(root),
                        "source_path": str(path),
                        "filesystem_metadata": metadata,
                        "reason": reason,
                        "error": error,
                    }
                )
                continue
            try:
                child_path = Path(child.path)
                child_info = child_path.lstat()
                if _is_reparse(child_info) or stat.S_ISLNK(child_info.st_mode):
                    result["unclassified_items"].append(
                        {
                            "source_volume": volume,
                            "sid_folder_name": child.name,
                            "scope_location": str(root),
                            "source_path": str(child_path),
                            "filesystem_metadata": filesystem_metadata(child_path),
                            "reason": "SID-named reparse point was not followed.",
                            "error": None,
                        }
                    )
                    continue
                if child.is_dir(follow_symlinks=False):
                    found.setdefault(child.name.casefold(), child.name)
                else:
                    result["unclassified_items"].append(
                        {
                            "source_volume": volume,
                            "sid_folder_name": child.name,
                            "scope_location": str(root),
                            "source_path": str(child_path),
                            "filesystem_metadata": filesystem_metadata(child_path),
                            "reason": "SID-named item is not a directory and was not traversed.",
                            "error": None,
                        }
                    )
            except OSError as exc:
                result["enumeration"]["complete"] = False
                result["errors"].append(
                    _error("sid_stat", str(exc), Path(child.path), exc)
                )
    return sorted(found.values(), key=str.casefold)


def _prepare_output(output_dir: str | Path, volumes: list[str]) -> tuple[Path, Path]:
    source_trees = [(Path(volume) / "$Recycle.Bin").resolve(strict=False) for volume in volumes]
    destination = validate_output_destination(output_dir, source_trees)
    run_name = "A18-RecycleBin-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    run_root = destination / run_name
    run_root.mkdir(exist_ok=False)
    return destination, run_root


def collect_recycle_bin(
    volumes: Iterable[str],
    output_dir: str | Path | None = None,
    collect_content: bool = False,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Collect selected Recycle Bin metadata and optionally corresponding $R items."""
    selected_volumes = validate_scope(volumes)
    destination = (
        Path(output_dir).expanduser()
        if output_dir is not None
        else Path(__file__).resolve().parent
    )
    for volume in selected_volumes:
        if not _is_local_volume(volume):
            raise ValueError(f"Selected volume is not a local fixed/removable drive: {volume}")
        if not Path(volume).is_dir():
            raise FileNotFoundError(f"Selected volume is not accessible: {volume}")
    destination, run_root = _prepare_output(destination, selected_volumes)
    started = utc_now()
    timestamps = _collection_time_metadata(started, started)
    result: dict[str, Any] = {
        "artifact_id": ARTIFACT_ID,
        **timestamps,
        "status": "success",
        "cancelled": False,
        "acquisition_status": "success",
        "metadata_parsing_status": "complete",
        "content_copy_status": "not_requested" if not collect_content else "complete",
        "collection_mode": "metadata_plus_content" if collect_content else "metadata_only",
        "scope": {
            "selected_volumes": selected_volumes,
            "sid_scope": "all_accessible_sid_folders",
            "selected_sids": None,
            "output_destination": str(destination),
            "collection_output_root": str(run_root),
        },
        "enumeration": {"complete": True, "locations": []},
        "entries": [],
        "unsupported_items": [],
        "unclassified_items": [],
        "counts": {},
        "output_paths": {"collection_json": None},
        "errors": [],
        "limitations": [
            "Live Recycle Bin contents may change during collection; this is not a snapshot.",
            "Starting Python and reading live files can affect operating-system state and access times.",
            "Normal file copying does not preserve all NTFS ACLs, alternate data streams, compression, "
            "sparse allocation, EFS state, hard-link relationships, or exact filesystem structure.",
            "Directory entry size is not the total size of a directory's descendants.",
            "SID ownership context and deletion time do not prove which person performed a deletion.",
            "Items already emptied, permanently deleted, or deleted outside the Recycle Bin are out of scope.",
            "Reparse points are recorded and skipped; directory copying is bounded and skips links.",
        ],
    }

    try:
        for volume in selected_volumes:
            roots = ("$Recycle.Bin", "RECYCLER", "RECYCLED")
            volume_sids = _volume_sid_folders(volume, roots, result)
            modern_root = Path(volume) / "$Recycle.Bin"
            for sid in volume_sids:
                _enumerate_sid(
                    volume, sid, modern_root, run_root, collect_content, overwrite, result
                )
            _enumerate_legacy(volume, run_root, overwrite, result)
    except KeyboardInterrupt:
        result["cancelled"] = True
        result["enumeration"]["complete"] = False
        result["errors"].append(
            _error("collection", "Collection was cancelled by the operator.")
        )

    for entry in result["entries"]:
        if entry["metadata_parse_status"] in ("malformed", "unsupported", "partial"):
            result["metadata_parsing_status"] = "partial"
        if entry["metadata_preservation_status"] not in ("copied", "not_applicable"):
            result["acquisition_status"] = "partial"
        if entry["errors"]:
            result["acquisition_status"] = "partial"
        if collect_content and entry["content_copy_status"] not in ("copied", "not_requested"):
            result["content_copy_status"] = "partial"
    if result["unsupported_items"]:
        result["metadata_parsing_status"] = "partial"
        if collect_content:
            result["content_copy_status"] = "partial"
    if result["errors"] or not result["enumeration"]["complete"] or result["cancelled"]:
        result["acquisition_status"] = "partial"
        result["metadata_parsing_status"] = "partial"
        if collect_content:
            result["content_copy_status"] = "partial"
    if result["acquisition_status"] == "success" and result["metadata_parsing_status"] == "complete":
        result["status"] = "success"
    else:
        result["status"] = "partial"
    result["counts"] = {
        "entries": len(result["entries"]),
        "pairs": sum(item["pairing_status"] == "paired" for item in result["entries"]),
        "unpaired_entries": sum(
            item["pairing_status"] in ("i_only", "r_only")
            for item in result["entries"]
        ),
        "ambiguous_pairs": sum(
            item["pairing_status"] == "ambiguous" for item in result["entries"]
        ),
        "parse_failures": sum(
            item["metadata_parse_status"] in (
                "malformed", "unsupported", "partial", "unreadable"
            )
            for item in result["entries"]
        ),
        "copy_failures": sum(
            item["metadata_preservation_status"] in ("failed", "partial")
            or item["content_copy_status"] in ("failed", "partial", "inaccessible", "missing")
            for item in result["entries"]
        ) + sum(
            item["preservation_status"] in ("failed", "partial")
            for item in result["unsupported_items"]
        ),
        "unsupported_legacy_indexes": len(result["unsupported_items"]),
        "unclassified_items": len(result["unclassified_items"]),
    }
    result.update(_collection_time_metadata(started, utc_now()))
    if result["errors"] and not any(
        location["status"] == "enumerated"
        for location in result["enumeration"]["locations"]
    ):
        result["status"] = "failed"
        result["acquisition_status"] = "failed"
        if collect_content:
            result["content_copy_status"] = "failed"
    json_path = run_root / "Recycle Bin-collection.json"
    result["output_paths"]["collection_json"] = str(json_path)
    write_collection_json(json_path, result, overwrite=overwrite)
    return result


def write_collection_json(
    path: str | Path, document: dict[str, Any], overwrite: bool = False
) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _normalize_utc_fields(document)
    payload = (json.dumps(document, ensure_ascii=True, indent=2) + "\n").encode("utf-8")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Output already exists; use --overwrite to replace it: {destination}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        if destination.exists() and not overwrite:
            raise FileExistsError(f"Output already exists: {destination}")
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return destination


def _parse_arguments() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only A18 Windows Recycle Bin collector."
    )
    parser.add_argument("--volume", action="append", help="Selected local drive letter, e.g. D:. Repeatable.")
    parser.add_argument(
        "--output-dir",
        help="Existing output destination directory (default: this A18 artifact folder).",
    )
    parser.add_argument(
        "--collect-content",
        action="store_true",
        help="Explicitly copy corresponding $R items. Metadata-only is the default.",
    )
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing existing output files.")
    return parser


def _prompt_args() -> list[str]:
    volumes = _discover_local_volumes()
    if not volumes:
        raise ValueError("No accessible local fixed or removable drives were found.")
    print("A18 will collect from these local drives: " + ", ".join(
        volume[:2] for volume in volumes
    ))
    return [argument for volume in volumes for argument in ("--volume", volume[:2])]


def main(argv: list[str] | None = None) -> int:
    parser = _parse_arguments()
    raw_args = list(sys.argv[1:] if argv is None else argv)
    try:
        if not raw_args and sys.stdin.isatty():
            raw_args = _prompt_args()
        args = parser.parse_args(raw_args)
        if not args.volume:
            args.volume = _discover_local_volumes()
            if not args.volume:
                raise ValueError("No accessible local fixed or removable drives were found.")
        result = collect_recycle_bin(
            volumes=args.volume,
            output_dir=args.output_dir,
            collect_content=args.collect_content,
            overwrite=args.overwrite,
        )
    except KeyboardInterrupt:
        print("A18 cancelled before collection completed.", file=sys.stderr)
        return EXIT_FAILURE
    except SystemExit as exc:
        return int(exc.code)
    except (OSError, ValueError) as exc:
        print(f"A18 failed before collection: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    print(
        f"A18 {result['status']}: {result['counts']['entries']} entries; "
        f"result saved to {result['output_paths']['collection_json']}"
    )
    return {
        "success": EXIT_SUCCESS,
        "partial": EXIT_PARTIAL,
        "failed": EXIT_FAILURE,
    }[result["status"]]


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
            "A01", "A17", "A23", "A25", "A30", "A31",
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
    _normalize_utc_fields(report)
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
