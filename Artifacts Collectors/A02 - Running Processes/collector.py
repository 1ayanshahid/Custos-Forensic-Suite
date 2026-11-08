"""Collect a read-only snapshot of Windows process metadata with psutil."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from ctypes import wintypes

try:
    import psutil
except ImportError as exc:
    raise SystemExit(
        "The A02 collector requires psutil. Install it in the project environment with: "
        '"E:\\FYP Custos Forensic Suite\\.venv\\Scripts\\python.exe" -m pip install psutil'
    ) from exc

PROCESS_FIELDS: tuple[tuple[str, Callable[[psutil.Process], Any]], ...] = (
    ("parent_pid", lambda process: process.ppid()),
    ("name", lambda process: process.name()),
    ("executable_path", lambda process: process.exe()),
    ("command_line", lambda process: process.cmdline()),
    ("username", lambda process: process.username()),
    ("status", lambda process: process.status()),
    ("thread_count", lambda process: process.num_threads()),
)


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


def _utc_now() -> str:
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


def _append_error(
    errors: list[dict[str, Any]],
    pid: int | None,
    field: str | None,
    error_type: str,
    message: str,
) -> None:
    errors.append(
        {
            "pid": pid,
            "field": field,
            "error_type": error_type,
            "message": message,
        }
    )


def _read_process_field(
    process: psutil.Process,
    pid: int,
    field: str,
    getter: Callable[[psutil.Process], Any],
    unavailable: dict[str, str],
    errors: list[dict[str, Any]],
) -> Any:
    try:
        value = getter(process)
    except psutil.ZombieProcess as exc:
        reason = "The process became a zombie while its metadata was being read."
        unavailable[field] = reason
        _append_error(errors, pid, field, "ZombieProcess", str(exc) or reason)
        return None
    except psutil.NoSuchProcess as exc:
        reason = "The process exited or its PID was reused during collection."
        unavailable[field] = reason
        _append_error(errors, pid, field, "NoSuchProcess", str(exc) or reason)
        return None
    except psutil.AccessDenied as exc:
        reason = "Windows denied access to this process field for the current token."
        unavailable[field] = reason
        _append_error(errors, pid, field, "AccessDenied", str(exc) or reason)
        return None
    except psutil.Error as exc:
        reason = f"psutil could not retrieve this field: {exc}"
        unavailable[field] = reason
        _append_error(errors, pid, field, type(exc).__name__, str(exc) or reason)
        return None

    if value is None:
        unavailable[field] = "psutil returned no value for this field."
    return value


def _collect_one_process(
    process: psutil.Process,
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    try:
        pid = int(process.pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error) as exc:
        _append_error(
            errors,
            None,
            "pid",
            type(exc).__name__,
            str(exc) or "Could not read the process ID.",
        )
        reason = "The process exited or access was denied before its PID could be read."
        return {
            "pid": None,
            "parent_pid": None,
            "name": None,
            "executable_path": None,
            "command_line": None,
            "username": None,
            "creation_time_utc": None,
            "status": None,
            "thread_count": None,
        }

    unavailable: dict[str, str] = {}
    record: dict[str, Any] = {"pid": pid}
    creation_time = _read_process_field(
        process,
        pid,
        "creation_time_utc",
        lambda item: item.create_time(),
        unavailable,
        errors,
    )
    if creation_time is None:
        record["creation_time_utc"] = None
    else:
        record["creation_time_utc"] = datetime.fromtimestamp(
            creation_time, timezone.utc
        ).isoformat()

    for field, getter in PROCESS_FIELDS:
        record[field] = _read_process_field(
            process,
            pid,
            field,
            getter,
            unavailable,
            errors,
        )

    return record


def _write_json(
    output_path: Path,
    document: dict[str, Any],
    overwrite: bool,
) -> None:
    if not output_path.parent.is_dir():
        raise FileNotFoundError(f"Output directory does not exist: {output_path.parent}")
    if not overwrite and os.path.lexists(output_path):
        raise FileExistsError(f"Refusing to overwrite existing output: {output_path}")

    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            dir=output_path.parent,
            delete=False,
        ) as temporary_file:
            temporary_path = temporary_file.name
            json.dump(document, temporary_file, ensure_ascii=True, indent=2)
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        if overwrite:
            os.replace(temporary_path, output_path)
        else:
            # On Windows, rename fails rather than replacing a destination created
            # concurrently after the preflight existence check.
            os.rename(temporary_path, output_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def collect_processes(
    output_path: str | os.PathLike[str],
    overwrite: bool = False,
) -> dict[str, Any]:
    """Collect process metadata and atomically save a UTF-8 JSON snapshot."""
    started_at = _utc_now()
    destination = Path(os.path.abspath(Path(output_path).expanduser()))
    if not overwrite and os.path.lexists(destination):
        raise FileExistsError(f"Refusing to overwrite existing output: {destination}")
    if not destination.parent.is_dir():
        raise FileNotFoundError(f"Output directory does not exist: {destination.parent}")

    processes: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    enumeration_failed = False
    iterator = iter(psutil.process_iter())
    while True:
        try:
            process = next(iterator)
        except StopIteration:
            break
        except psutil.Error as exc:
            _append_error(
                errors,
                None,
                "process_enumeration",
                type(exc).__name__,
                str(exc) or "psutil could not continue process enumeration.",
            )
            enumeration_failed = True
            break

        try:
            processes.append(_collect_one_process(process, errors))
        except psutil.Error as exc:
            try:
                pid = int(process.pid)
            except psutil.Error:
                pid = None
            _append_error(
                errors,
                pid,
                None,
                type(exc).__name__,
                str(exc) or "psutil could not collect this process record.",
            )

    finished_at = _utc_now()
    if enumeration_failed and not processes:
        outcome = "failed"
    elif errors:
        outcome = "partial"
    else:
        outcome = "completed"

    document: dict[str, Any] = {
        "schema_version": 1,
        "artifact": "A02 - Running Processes",
        "source": "Current Windows process table",
        "method": "Read-only psutil process enumeration",
        **_collection_time_metadata(started_at, finished_at),
        "outcome": outcome,
        "process_count": len(processes),
        "process_identity_note": (
            "Use PID together with creation_time_utc to distinguish a process "
            "from a later process that reuses the same PID."
        ),
        "limitations": [
            "This is a live snapshot; processes may start, exit, or change during enumeration.",
            "Unavailable process fields are null; reasons remain in collection_errors.",
            "Visibility depends on the current Windows token and security policy.",
            "Administrator elevation can improve visibility but does not bypass protected-process restrictions or guarantee access to every field.",
            "Collection does not terminate, suspend, or modify processes.",
        ],
        "collection_errors": errors,
        "processes": processes,
    }
    _write_json(destination, document, overwrite)
    return document


def _collect_thread_snapshot(
    output_path: str | os.PathLike[str],
    overwrite: bool = False,
    process_names: dict[int, str | None] | None = None,
) -> dict[str, Any]:
    started_at = _utc_now()
    destination = Path(os.path.abspath(Path(output_path).expanduser()))
    if not overwrite and os.path.lexists(destination):
        raise FileExistsError(f"Refusing to overwrite existing output: {destination}")
    if not destination.parent.is_dir():
        raise FileNotFoundError(f"Output directory does not exist: {destination.parent}")

    threads: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    field_error_counts: dict[tuple[str, str], int] = {}
    enumeration_failed = False

    if os.name != "nt":
        _append_error(
            errors,
            None,
            "thread_enumeration",
            "UnsupportedPlatform",
            "The Windows Toolhelp thread snapshot API is available only on Windows.",
        )
        enumeration_failed = True
    else:
        class FileTime(ctypes.Structure):
            _fields_ = [
                ("dwLowDateTime", wintypes.DWORD),
                ("dwHighDateTime", wintypes.DWORD),
            ]

        class ThreadEntry32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", wintypes.LONG),
                ("tpDeltaPri", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_snapshot = kernel32.CreateToolhelp32Snapshot
        create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        create_snapshot.restype = wintypes.HANDLE
        thread_first = kernel32.Thread32First
        thread_first.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
        thread_first.restype = wintypes.BOOL
        thread_next = kernel32.Thread32Next
        thread_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
        thread_next.restype = wintypes.BOOL
        open_thread = kernel32.OpenThread
        open_thread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_thread.restype = wintypes.HANDLE
        get_thread_priority = kernel32.GetThreadPriority
        get_thread_priority.argtypes = [wintypes.HANDLE]
        get_thread_priority.restype = wintypes.INT
        get_thread_times = kernel32.GetThreadTimes
        get_thread_times.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
        ]
        get_thread_times.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        set_last_error = kernel32.SetLastError
        set_last_error.argtypes = [wintypes.DWORD]
        set_last_error.restype = None

        invalid_handle = ctypes.c_void_p(-1).value
        snapshot = create_snapshot(0x00000004, 0)
        if snapshot == invalid_handle:
            error_code = ctypes.get_last_error()
            _append_error(
                errors,
                None,
                "thread_snapshot",
                "WindowsAPIError",
                f"CreateToolhelp32Snapshot failed with Windows error {error_code}.",
            )
            enumeration_failed = True
        else:
            def collect_thread_details(
                thread_id: int,
                owner_pid: int,
            ) -> dict[str, Any]:
                unavailable: dict[str, str] = {}
                owner_name = (
                    process_names.get(owner_pid)
                    if process_names is not None
                    else None
                )
                if owner_name is None:
                    unavailable["owning_process_name"] = (
                        "The process snapshot did not provide a name for this owner PID."
                    )

                priority: int | None = None
                creation_time_utc: str | None = None
                user_cpu_seconds: float | None = None
                kernel_cpu_seconds: float | None = None

                def record_error(field: str, error_code: int) -> None:
                    reason = (
                        f"Windows error {error_code} while querying the thread."
                    )
                    unavailable[field] = reason
                    key = (field, reason)
                    field_error_counts[key] = field_error_counts.get(key, 0) + 1

                thread_handle = open_thread(0x0040 | 0x0800, False, thread_id)
                if not thread_handle:
                    error_code = ctypes.get_last_error()
                    for field in (
                        "current_priority",
                        "creation_time_utc",
                        "user_cpu_time_seconds",
                        "kernel_cpu_time_seconds",
                    ):
                        record_error(field, error_code)
                else:
                    try:
                        set_last_error(0)
                        priority_value = int(get_thread_priority(thread_handle))
                        priority_error = ctypes.get_last_error()
                        if priority_value == 0x7FFFFFFF:
                            record_error("current_priority", priority_error)
                        else:
                            priority = priority_value

                        creation = FileTime()
                        exit_time = FileTime()
                        kernel_time = FileTime()
                        user_time = FileTime()
                        if get_thread_times(
                            thread_handle,
                            ctypes.byref(creation),
                            ctypes.byref(exit_time),
                            ctypes.byref(kernel_time),
                            ctypes.byref(user_time),
                        ):
                            creation_ticks = (
                                (creation.dwHighDateTime << 32)
                                | creation.dwLowDateTime
                            )
                            kernel_ticks = (
                                (kernel_time.dwHighDateTime << 32)
                                | kernel_time.dwLowDateTime
                            )
                            user_ticks = (
                                (user_time.dwHighDateTime << 32)
                                | user_time.dwLowDateTime
                            )
                            windows_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
                            creation_time_utc = (
                                windows_epoch
                                + timedelta(microseconds=creation_ticks / 10)
                            ).isoformat()
                            kernel_cpu_seconds = kernel_ticks / 10_000_000
                            user_cpu_seconds = user_ticks / 10_000_000
                        else:
                            error_code = ctypes.get_last_error()
                            for field in (
                                "creation_time_utc",
                                "user_cpu_time_seconds",
                                "kernel_cpu_time_seconds",
                            ):
                                record_error(field, error_code)
                    finally:
                        if not close_handle(thread_handle):
                            error_code = ctypes.get_last_error()
                            key = (
                                "thread_handle",
                                f"CloseHandle failed with Windows error {error_code}.",
                            )
                            field_error_counts[key] = field_error_counts.get(key, 0) + 1

                return {
                    "owning_process_name": owner_name,
                    "current_priority": priority,
                    "creation_time_utc": creation_time_utc,
                    "user_cpu_time_seconds": user_cpu_seconds,
                    "kernel_cpu_time_seconds": kernel_cpu_seconds,
                    "collection_status": (
                        "partial" if unavailable else "completed"
                    ),
                }

            try:
                entry = ThreadEntry32()
                entry.dwSize = ctypes.sizeof(ThreadEntry32)
                has_entry = bool(thread_first(snapshot, ctypes.byref(entry)))
                error_code = 0 if has_entry else ctypes.get_last_error()

                while has_entry:
                    thread_id = int(entry.th32ThreadID)
                    owner_pid = int(entry.th32OwnerProcessID)
                    thread_record: dict[str, Any] = {
                        "thread_id": thread_id,
                        "owner_process_id": owner_pid,
                        "base_priority": int(entry.tpBasePri),
                    }
                    thread_record.update(
                        collect_thread_details(thread_id, owner_pid)
                    )
                    threads.append(thread_record)
                    entry.dwSize = ctypes.sizeof(ThreadEntry32)
                    has_entry = bool(thread_next(snapshot, ctypes.byref(entry)))
                    error_code = 0 if has_entry else ctypes.get_last_error()

                if error_code not in (0, 18):
                    _append_error(
                        errors,
                        None,
                        "thread_enumeration",
                        "WindowsAPIError",
                        f"Thread32First/Thread32Next stopped with Windows error {error_code}.",
                    )
                    enumeration_failed = True
            finally:
                if not close_handle(snapshot):
                    _append_error(
                        errors,
                        None,
                        "snapshot_handle",
                        "WindowsAPIError",
                        "CloseHandle failed for the Toolhelp thread snapshot.",
                    )

    for (field, reason), count in sorted(field_error_counts.items()):
        _append_error(
            errors,
            None,
            field,
            "ThreadQueryError",
            f"{reason} Affected thread count: {count}.",
        )

    finished_at = _utc_now()
    if enumeration_failed and not threads:
        outcome = "failed"
    elif errors:
        outcome = "partial"
    else:
        outcome = "completed"

    document: dict[str, Any] = {
        "schema_version": 1,
        "artifact": "A02 - System-wide Thread Snapshot",
        "source": "Windows Toolhelp thread snapshot",
        "method": "Read-only CreateToolhelp32Snapshot with TH32CS_SNAPTHREAD",
        **_collection_time_metadata(started_at, finished_at),
        "outcome": outcome,
        "thread_count": len(threads),
        "thread_field_definitions": {
            "base_priority": "Base priority reported by THREADENTRY32, in Windows priority levels.",
            "current_priority": (
                "Relative thread priority returned by GetThreadPriority; this is "
                "not a guaranteed instantaneous scheduler priority."
            ),
            "creation_time_utc": "Thread creation timestamp converted from Windows FILETIME to UTC.",
            "user_cpu_time_seconds": "Cumulative thread CPU time in user mode, in seconds.",
            "kernel_cpu_time_seconds": "Cumulative thread CPU time in kernel mode, in seconds.",
            "owning_process_name": "Process name joined by owner_process_id from the separate process snapshot.",
        },
        "not_collected_fields": {
            "thread_state": (
                "Not collected: the selected documented Toolhelp and thread timing "
                "APIs do not provide a supported thread-state inventory."
            ),
            "wait_reason": (
                "Not collected: determining wait reason requires a system-information "
                "interface outside the documented APIs used by this collector."
            ),
            "start_address": (
                "Not collected: this collector does not use undocumented thread "
                "information classes to query a start address."
            ),
            "context_switch_count": (
                "Not collected: per-thread context-switch counters are not provided "
                "by the documented APIs used by this collector."
            ),
        },
        "limitations": [
            "This is a point-in-time system-wide thread inventory; threads can start or exit during collection.",
            "Current-priority, creation-time, and CPU-time fields are best-effort queries and can be denied or fail if a thread exits during collection.",
            "Unavailable thread values are null; reasons and affected counts are summarized in collection_errors rather than repeated in each thread record.",
            "CPU time is cumulative and is not an instantaneous utilization measurement.",
            "The Toolhelp snapshot does not identify whether a thread is executing in user mode or kernel mode.",
            "This output is not a separate inventory of kernel-only processes or kernel-mode threads.",
        ],
        "collection_errors": errors,
        "threads": threads,
    }
    _write_json(destination, document, overwrite)
    return document


def collect_thread_snapshot(
    output_path: str | os.PathLike[str],
    overwrite: bool = False,
    process_names: dict[int, str | None] | None = None,
) -> dict[str, Any]:
    """Collect and save a separate read-only Windows system-wide thread snapshot."""
    return _collect_thread_snapshot(output_path, overwrite, process_names)


def _default_threads_path(processes_path: Path) -> Path:
    return processes_path.with_name(
        f"{processes_path.stem}_threads{processes_path.suffix or '.json'}"
    )


def collect_process_and_thread_snapshots(
    output_path: str | os.PathLike[str],
    threads_output_path: str | os.PathLike[str] | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Save process and system-wide thread inventories to separate JSON files."""
    processes_destination = Path(os.path.abspath(Path(output_path).expanduser()))
    if processes_destination.is_dir():
        output_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        processes_destination = (
            processes_destination / f"processes_{output_stamp}.json"
        )
    threads_destination = (
        Path(os.path.abspath(Path(threads_output_path).expanduser()))
        if threads_output_path is not None
        else _default_threads_path(processes_destination)
    )
    if os.path.normcase(str(processes_destination)) == os.path.normcase(
        str(threads_destination)
    ):
        raise ValueError("Process and thread outputs must be different files.")
    if not overwrite:
        for destination in (processes_destination, threads_destination):
            if os.path.lexists(destination):
                raise FileExistsError(
                    f"Refusing to overwrite existing output: {destination}"
                )

    processes_document = collect_processes(processes_destination, overwrite)
    process_names = {
        int(record["pid"]): record.get("name")
        for record in processes_document["processes"]
        if record.get("pid") is not None
    }
    threads_document = collect_thread_snapshot(
        threads_destination,
        overwrite,
        process_names,
    )
    return {
        "processes": processes_document,
        "threads": threads_document,
        "processes_output": str(processes_destination),
        "threads_output": str(threads_destination),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Collect separate read-only Windows process and system-wide thread "
            "snapshots as JSON. The thread snapshot does not identify kernel-mode "
            "execution."
        )
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Destination path for the process UTF-8 JSON output",
    )
    parser.add_argument(
        "--threads-output",
        help=(
            "Destination for the separate thread JSON; by default, the process "
            "filename gets a _threads suffix"
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
        documents = collect_process_and_thread_snapshots(
            args.output,
            args.threads_output,
            overwrite=args.overwrite,
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"outcome": "failed", "error": str(exc)}), file=sys.stderr)
        return 2

    processes_document = documents["processes"]
    threads_document = documents["threads"]
    outcomes = (processes_document["outcome"], threads_document["outcome"])
    overall_outcome = (
        "completed" if all(outcome == "completed" for outcome in outcomes) else "partial"
    )
    print(
        json.dumps(
            {
                "outcome": overall_outcome,
                "processes_outcome": processes_document["outcome"],
                "process_count": processes_document["process_count"],
                "processes_output": documents["processes_output"],
                "threads_outcome": threads_document["outcome"],
                "thread_count": threads_document["thread_count"],
                "threads_output": documents["threads_output"],
                "collection_errors": (
                    len(processes_document["collection_errors"])
                    + len(threads_document["collection_errors"])
                ),
            },
            ensure_ascii=True,
        )
    )
    return 0 if overall_outcome == "completed" else 1


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
