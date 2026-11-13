"""Read-only wrapper for acquiring a local NTFS $MFT with RawCopy64."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ARTIFACT_ID = "A17"
ARTIFACT_NAME = "MFT"
RAW_COPY_NAME = "RawCopy64.exe"
RAW_COPY_VERSION = "1.0.0.22"
RAW_COPY_GIT_BLOB_SHA1 = "9f4430f36ca8dd5a5a36e411747eaafe2085ec95"
RAW_COPY_REVISION = "jschicht/RawCopy commit 0d8d690c0f0fe9d2c68c5fce02d26d0efa53459c"
FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
EXIT_SUCCESS = 0
EXIT_PARTIAL = 1
EXIT_FAILURE = 2


class _NtfsVolumeData(ctypes.Structure):
    _fields_ = [
        ("VolumeSerialNumber", ctypes.c_longlong),
        ("NumberSectors", ctypes.c_longlong),
        ("TotalClusters", ctypes.c_longlong),
        ("FreeClusters", ctypes.c_longlong),
        ("TotalReserved", ctypes.c_longlong),
        ("BytesPerSector", wintypes.DWORD),
        ("BytesPerCluster", wintypes.DWORD),
        ("BytesPerFileRecordSegment", wintypes.DWORD),
        ("ClustersPerFileRecordSegment", wintypes.DWORD),
        ("MftValidDataLength", ctypes.c_longlong),
        ("MftStartLcn", ctypes.c_longlong),
        ("Mft2StartLcn", ctypes.c_longlong),
        ("MftZoneStart", ctypes.c_longlong),
        ("MftZoneEnd", ctypes.c_longlong),
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


def validate_volume_spec(value: str) -> str:
    match = re.fullmatch(r"\s*([A-Za-z])(?::\\?)?\s*", value)
    if not match:
        raise ValueError("Source must be a local drive letter such as C or C:.")
    return f"{match.group(1).upper()}:\\"


def probe_volume(volume_root: str) -> dict[str, Any]:
    if os.name != "nt":
        raise OSError("A17 acquisition requires Windows.")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD,
    ]
    kernel32.GetVolumeInformationW.restype = wintypes.BOOL
    kernel32.GetDiskFreeSpaceExW.argtypes = [
        wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_ulonglong),
    ]
    kernel32.GetDiskFreeSpaceExW.restype = wintypes.BOOL
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.DeviceIoControl.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    kernel32.DeviceIoControl.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    label = ctypes.create_unicode_buffer(261)
    filesystem = ctypes.create_unicode_buffer(64)
    serial = wintypes.DWORD()
    max_component = wintypes.DWORD()
    filesystem_flags = wintypes.DWORD()
    if not kernel32.GetVolumeInformationW(
        volume_root, label, len(label), ctypes.byref(serial),
        ctypes.byref(max_component), ctypes.byref(filesystem_flags),
        filesystem, len(filesystem),
    ):
        error = ctypes.get_last_error()
        raise OSError(error, f"Cannot access volume {volume_root} (Win32 error {error}).")
    if filesystem.value.upper() != "NTFS":
        raise ValueError(f"Volume {volume_root} uses {filesystem.value!r}, not NTFS.")

    free_to_caller = ctypes.c_ulonglong()
    total_bytes = ctypes.c_ulonglong()
    total_free = ctypes.c_ulonglong()
    if not kernel32.GetDiskFreeSpaceExW(
        volume_root, ctypes.byref(free_to_caller),
        ctypes.byref(total_bytes), ctypes.byref(total_free),
    ):
        error = ctypes.get_last_error()
        raise OSError(error, f"Cannot query volume accessibility (Win32 error {error}).")

    device = rf"\\.\{volume_root[0]}:"
    handle = kernel32.CreateFileW(
        device, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None,
    )
    if handle == INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        raise OSError(error, f"Cannot open volume for read-only NTFS metadata (Win32 error {error}).")
    try:
        ntfs_data = _NtfsVolumeData()
        returned = wintypes.DWORD()
        if not kernel32.DeviceIoControl(
            handle, FSCTL_GET_NTFS_VOLUME_DATA, None, 0,
            ctypes.byref(ntfs_data), ctypes.sizeof(ntfs_data),
            ctypes.byref(returned), None,
        ):
            error = ctypes.get_last_error()
            raise OSError(error, f"Cannot query NTFS volume data (Win32 error {error}).")
    finally:
        kernel32.CloseHandle(handle)

    return {
        "volume_root": volume_root,
        "volume_label": label.value,
        "volume_serial_number": f"{serial.value:08X}",
        "filesystem": filesystem.value,
        "filesystem_flags": filesystem_flags.value,
        "maximum_component_length": max_component.value,
        "total_bytes": total_bytes.value,
        "free_bytes_available_to_caller": free_to_caller.value,
        "ntfs": {
            "bytes_per_sector": ntfs_data.BytesPerSector,
            "bytes_per_cluster": ntfs_data.BytesPerCluster,
            "bytes_per_file_record_segment": ntfs_data.BytesPerFileRecordSegment,
            "mft_valid_data_length_bytes": ntfs_data.MftValidDataLength,
            "mft_start_lcn": ntfs_data.MftStartLcn,
        },
    }


def _pe_file_version(path: Path) -> str | None:
    if os.name != "nt":
        return None
    version = ctypes.WinDLL("version", use_last_error=True)
    version.GetFileVersionInfoSizeW.argtypes = [
        wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD),
    ]
    version.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    version.GetFileVersionInfoW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    ]
    version.GetFileVersionInfoW.restype = wintypes.BOOL
    version.VerQueryValueW.argtypes = [
        ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT),
    ]
    version.VerQueryValueW.restype = wintypes.BOOL
    ignored = wintypes.DWORD()
    size = version.GetFileVersionInfoSizeW(str(path), ctypes.byref(ignored))
    if not size:
        return None
    data = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(str(path), 0, size, data):
        return None
    value = ctypes.c_void_p()
    length = wintypes.UINT()
    if not version.VerQueryValueW(data, "\\", ctypes.byref(value), ctypes.byref(length)):
        return None

    class _FixedFileInfo(ctypes.Structure):
        _fields_ = [
            ("dwSignature", wintypes.DWORD), ("dwStrucVersion", wintypes.DWORD),
            ("dwFileVersionMS", wintypes.DWORD), ("dwFileVersionLS", wintypes.DWORD),
            ("dwProductVersionMS", wintypes.DWORD), ("dwProductVersionLS", wintypes.DWORD),
            ("dwFileFlagsMask", wintypes.DWORD), ("dwFileFlags", wintypes.DWORD),
            ("dwFileOS", wintypes.DWORD), ("dwFileType", wintypes.DWORD),
            ("dwFileSubtype", wintypes.DWORD), ("dwFileDateMS", wintypes.DWORD),
            ("dwFileDateLS", wintypes.DWORD),
        ]

    info = ctypes.cast(value, ctypes.POINTER(_FixedFileInfo)).contents
    parts = (
        info.dwFileVersionMS >> 16, info.dwFileVersionMS & 0xFFFF,
        info.dwFileVersionLS >> 16, info.dwFileVersionLS & 0xFFFF,
    )
    return ".".join(str(part) for part in parts)


def inspect_rawcopy(path: Path) -> dict[str, Any]:
    with path.open("rb") as executable:
        if executable.read(2) != b"MZ":
            raise ValueError("RawCopy executable is not a valid PE image.")
        executable.seek(0x3C)
        pe_offset_data = executable.read(4)
        if len(pe_offset_data) != 4:
            raise ValueError("RawCopy executable has a truncated PE header.")
        pe_offset = int.from_bytes(pe_offset_data, "little")
        executable.seek(pe_offset)
        header = executable.read(6)
    if len(header) != 6 or header[:4] != b"PE\0\0":
        raise ValueError("RawCopy executable has an invalid PE header.")
    machine = int.from_bytes(header[4:6], "little")
    if machine != 0x8664:
        raise ValueError(f"RawCopy must be x64 PE (machine 0x8664); found 0x{machine:04X}.")
    version = _pe_file_version(path)
    if version != RAW_COPY_VERSION:
        raise ValueError(
            f"Expected RawCopy version {RAW_COPY_VERSION} in the PE version resource; "
            f"found {version or 'no version resource'}."
        )
    content_hash = hashlib.sha1()
    content_hash.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as executable:
        for block in iter(lambda: executable.read(1024 * 1024), b""):
            content_hash.update(block)
    if content_hash.hexdigest() != RAW_COPY_GIT_BLOB_SHA1:
        raise ValueError(
            "RawCopy executable does not match the pinned upstream RawCopy64.exe."
        )
    return {
        "file_version_resource": version,
        "pe_machine": f"0x{machine:04X}",
        "pinned_upstream_binary_match": True,
    }


def build_rawcopy_arguments(
    tool_path: Path, volume_root: str, output_dir: Path, mft_path: Path
) -> list[str]:
    return [
        str(tool_path),
        f"/FileNamePath:{volume_root[0]}:0",
        f"/OutputPath:{output_dir}",
        f"/OutputName:{mft_path.name}",
    ]


def _run_rawcopy(arguments: list[str], tool_path: Path) -> dict[str, Any]:
    process = subprocess.Popen(
        arguments,
        cwd=str(tool_path.parent),
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        stdout, stderr = process.communicate()
    except KeyboardInterrupt:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
        return {
            "exit_code": process.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "interrupted": True,
        }
    return {
        "exit_code": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "interrupted": False,
    }


def _check_mft_structure(
    path: Path, expected_length: int | None, record_size: int | None
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "exists": path.is_file(),
        "size_bytes": path.stat().st_size if path.is_file() else None,
        "record_size_bytes": record_size,
        "expected_mft_length_bytes": expected_length,
        "record_size_aligned": None,
        "expected_length_matches": None,
        "sampled_record_offsets": [],
        "sampled_file_signatures": 0,
        "sampled_records": 0,
        "record_zero_signature": None,
    }
    size = result["size_bytes"]
    if not size or not record_size or record_size <= 0:
        result["valid"] = False
        result["limitations"] = ["No nonempty artifact or NTFS record-size metadata was available."]
        return result

    result["record_size_aligned"] = size % record_size == 0
    if expected_length is not None:
        result["expected_length_matches"] = size == expected_length
    count = size // record_size
    indexes = sorted({0, count // 4, count // 2, (3 * count) // 4, count - 1})
    signatures = 0
    sample_info: list[dict[str, Any]] = []
    with path.open("rb") as stream:
        for index in indexes:
            stream.seek(index * record_size)
            signature = stream.read(4)
            rendered = signature.decode("ascii", errors="replace")
            is_mft_record = signature in (b"FILE", b"BAAD")
            signatures += int(is_mft_record)
            sample_info.append(
                {"record_index": index, "signature": rendered, "recognized": is_mft_record}
            )
            if index == 0:
                result["record_zero_signature"] = rendered
    result["sampled_record_offsets"] = sample_info
    result["sampled_file_signatures"] = signatures
    result["sampled_records"] = len(indexes)
    # Sampling is a plausibility check only; sparse/uninitialized slots need not be FILE records.
    result["valid"] = (
        result["record_size_aligned"]
        and result["record_zero_signature"] == "FILE"
        and signatures >= 1
        and result["expected_length_matches"] is not False
    )
    result["limitations"] = [
        "Bounded FILE/BAAD signature sampling checks plausibility, not full MFT integrity."
    ]
    return result


def _result_path(output_dir: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    return output_dir / f"MFT-collection-{timestamp}.json"


def _write_result(path: Path, document: dict[str, Any], overwrite: bool) -> None:
    payload = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    if not overwrite:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        return
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def collect_mft(
    source_volume: str,
    output_dir: str | Path,
    *,
    overwrite: bool = False,
    tool_path: str | Path | None = None,
    volume_probe: Callable[[str], dict[str, Any]] = probe_volume,
    runner: Callable[[list[str], Path], dict[str, Any]] = _run_rawcopy,
    tool_inspector: Callable[[Path], dict[str, Any]] = inspect_rawcopy,
) -> dict[str, Any]:
    started = utc_now()
    destination = Path(output_dir).expanduser().resolve()
    volume_root: str | None = None
    volume_info: dict[str, Any] | None = None
    mft_path: Path | None = None
    working_path: Path | None = None
    result_path: Path | None = None
    errors: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {"stdout": "", "stderr": ""}
    tool = Path(tool_path).resolve() if tool_path else Path(__file__).resolve().parent / RAW_COPY_NAME
    tool_metadata: dict[str, Any] = {}
    tool_exit_code: int | None = None
    validation: dict[str, Any] | None = None
    status = "failed"
    invocation: list[str] = []
    try:
        volume_root = validate_volume_spec(source_volume)
        if not destination.is_dir():
            raise FileNotFoundError(f"Output directory does not exist: {destination}")
        if not tool.is_file():
            raise FileNotFoundError(
                f"Acquisition tool not found: {tool}. Place verified RawCopy64.exe here."
            )
        tool_metadata = tool_inspector(tool)
        volume_info = volume_probe(volume_root)
        expected_length = volume_info["ntfs"]["mft_valid_data_length_bytes"]
        record_size = volume_info["ntfs"]["bytes_per_file_record_segment"]
        free_bytes = shutil.disk_usage(destination).free
        if expected_length > free_bytes:
            raise OSError(
                f"Destination has {free_bytes} free bytes; volume reports "
                f"{expected_length} MFT bytes."
            )

        final_mft_path = destination / f"MFT-MFT-{volume_root[0]}.bin"
        result_path = _result_path(destination)
        if final_mft_path.exists() and not overwrite:
            raise FileExistsError(
                f"Output already exists: {final_mft_path}; pass --overwrite to replace it."
            )
        working_path = destination / f".A17-MFT-{volume_root[0]}.acquire-{uuid.uuid4().hex}.tmp"
        invocation = build_rawcopy_arguments(tool, volume_root, destination, working_path)
        run_result = runner(invocation, tool)
        tool_exit_code = run_result["exit_code"]
        diagnostics = {
            "stdout": run_result.get("stdout", ""),
            "stderr": run_result.get("stderr", ""),
            "interrupted": run_result.get("interrupted", False),
        }
        exists = working_path.is_file()
        if exists:
            validation = _check_mft_structure(working_path, expected_length, record_size)
        if not exists:
            errors.append({"category": "missing_output", "message": "RawCopy did not produce the expected MFT output."})
        elif not validation or not validation["valid"]:
            errors.append({"category": "incomplete_or_invalid_output", "message": "Output failed one or more bounded structural plausibility checks."})
        if diagnostics["interrupted"]:
            errors.append({"category": "interrupted", "message": "Acquisition was interrupted; any output is incomplete."})
        if tool_exit_code != 0:
            errors.append({"category": "tool_failure", "message": f"RawCopy exited with code {tool_exit_code}."})
        if exists and validation and validation["valid"] and tool_exit_code == 0 and not errors:
            mft_path = final_mft_path
            if overwrite:
                os.replace(working_path, final_mft_path)
            else:
                os.rename(working_path, final_mft_path)
            working_path = None
            status = "success"
        elif exists:
            mft_path = destination / (
                f"MFT-MFT-{volume_root[0]}.partial-{datetime.now(timezone.utc):%Y%m%dT%H%M%S_%fZ}.bin"
            )
            os.replace(working_path, mft_path)
            working_path = None
            status = "partial"
        else:
            status = "failed"
    except (OSError, ValueError, KeyError) as exc:
        winerror = getattr(exc, "winerror", None)
        if winerror == 5:
            category = "access_denied"
        elif winerror in (21, 23, 1117):
            category = "volume_unavailable_or_locked"
        else:
            category = "collection_error"
        errors.append(
            {
                "category": category,
                "exception_type": type(exc).__name__,
                "winerror": winerror,
                "message": str(exc),
            }
        )
    except Exception as exc:
        errors.append(
            {
                "category": "unexpected_collection_error",
                "exception_type": type(exc).__name__,
                "message": str(exc),
            }
        )
    if working_path and working_path.is_file():
        partial_path = destination / (
            f"MFT-MFT-{source_volume[:1].upper()}.partial-{datetime.now(timezone.utc):%Y%m%dT%H%M%S_%fZ}.bin"
        )
        try:
            os.replace(working_path, partial_path)
            mft_path = partial_path
        except OSError as move_error:
            errors.append(
                {
                    "category": "partial_output_rename_failure",
                    "message": str(move_error),
                    "partial_output_path": str(working_path),
                }
            )

    timestamps = _collection_time_metadata(started, utc_now())
    existing_size = mft_path.stat().st_size if mft_path and mft_path.is_file() else None
    result_path = result_path or (_result_path(destination) if destination.is_dir() else None)
    document: dict[str, Any] = {
        "artifact_id": ARTIFACT_ID,
        "artifact_name": ARTIFACT_NAME,
        **timestamps,
        "acquisition_status": status,
        "parsing_status": "not_requested",
        "collection_host": {
            "operating_system": platform.platform(),
            "python_version": platform.python_version(),
            "python_architecture": platform.architecture()[0],
        },
        "source": {
            "volume_specification": source_volume,
            "volume": volume_info,
        },
        "acquisition_tool": {
            "name": "RawCopy64",
            "path": str(tool),
            **tool_metadata,
            "upstream_version_documented": RAW_COPY_VERSION,
            "upstream_source": "https://github.com/jschicht/RawCopy",
            "upstream_revision": RAW_COPY_REVISION,
            "acquisition_semantics": "Extracts NTFS file reference 0 ($MFT) using the tool's low-level NTFS reader; default attribute behavior is used.",
        },
        "invocation_arguments": invocation,
        "tool_exit_code": tool_exit_code,
        "output": {
            "mft_binary_path": str(mft_path) if mft_path else None,
            "mft_size_bytes": existing_size,
            "result_json_path": str(result_path) if result_path else None,
        },
        "diagnostics": diagnostics,
        "validation_checks": validation or {},
        "errors": errors,
        "limitations": [
            "RawCopy is a third-party low-level NTFS acquisition utility; its executable must be manually obtained and verified.",
            "A live volume may change during acquisition; this is not an atomic snapshot or hardware write-blocked acquisition.",
            "FILE/BAAD sampling and length comparison are plausibility checks, not a complete integrity proof.",
            "No parser was run. Raw MFT records, including deleted records, are not a parsed inventory or proof that file contents are recoverable.",
            "Only the MFT file reference is acquired; no file contents, alternate-stream contents, USN Journal, $LogFile, or other artifacts are collected.",
        ],
    }
    if destination.is_dir() and result_path:
        try:
            _write_result(result_path, document, overwrite=False)
        except OSError as exc:
            print(f"Could not write collection-result JSON: {exc}", file=sys.stderr)
            document["acquisition_status"] = "partial" if existing_size else "failed"
            document["errors"].append(
                {"category": "result_write_failure", "message": str(exc)}
            )
    return document


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Acquire a local NTFS $MFT using RawCopy64.")
    parser.add_argument("--source", help="Explicit local NTFS drive letter, e.g. C:.")
    parser.add_argument("--output-dir", help="Existing destination directory for binary and result JSON.")
    parser.add_argument("--tool", help="Path to a manually verified RawCopy64.exe.")
    parser.add_argument("--overwrite", action="store_true", help="Allow replacement of the fixed MFT binary output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    source = args.source
    output_dir = args.output_dir
    if source is None and sys.stdin.isatty():
        source = input("Source NTFS volume (for example C:): ").strip()
    if output_dir is None and sys.stdin.isatty():
        output_dir = input("Existing destination folder for MFT and result JSON: ").strip()
    if not source or not output_dir:
        print("Both --source and --output-dir are required when running non-interactively.", file=sys.stderr)
        return EXIT_FAILURE
    try:
        result = collect_mft(
            source,
            output_dir,
            overwrite=args.overwrite,
            tool_path=args.tool,
        )
    except Exception as exc:
        print(f"A17 failed: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    if result["acquisition_status"] == "failed":
        messages = [error["message"] for error in result["errors"]]
        print(
            "A17 failed: " + ("; ".join(messages) if messages else "no MFT output"),
            file=sys.stderr,
        )
    else:
        print(
            f"A17 {result['acquisition_status']}: "
            f"{result['output']['mft_binary_path'] or 'no MFT output'}"
        )
    return {
        "success": EXIT_SUCCESS,
        "partial": EXIT_PARTIAL,
        "failed": EXIT_FAILURE,
    }[result["acquisition_status"]]


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
