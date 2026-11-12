
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Custos Forensic Suite
Artifact: A07 - Scheduled Tasks Enumeration
Version: 1.0.0
Platform: Windows 10/11 x64

Default case root:
    C:\\Custos\\Case001

Read-only collection:
- Scheduled task inventory and metadata
- Task XML definitions
- Task definition files from Windows task store
- Task Scheduler Operational EVTX log, if accessible
- SHA-256 hashes, verification records, and collection errors

Does not create, modify, enable, disable, or run scheduled tasks.
Requires an elevated terminal. launch.bat delegates to the workspace helper.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


MODULE = "A07_Scheduled_Tasks_Enumeration"
VERSION = "1.0.0"
DEFAULT_CASE_ROOT = Path(r"C:\Custos\Case001")
TASK_LOG = "Microsoft-Windows-TaskScheduler/Operational"
COMMAND_TIMEOUT = 300


def _canonical_integrity_report(report):
    # Isolated embedded implementation: collector globals cannot shadow its imports.
    _inline_namespace = {}
    exec('"""Canonical post-save integrity reports; never evidence of acquisition-time hashing."""\nimport hashlib\nimport os\nfrom datetime import datetime, timezone\nfrom pathlib import Path\n\n\ndef _long_path(path):\n    value = os.fspath(path)\n    if os.name != \'nt\':\n        return os.path.abspath(value)\n    if value.startswith(\'\\\\\\\\?\\\\\'):\n        return value\n    value = os.path.abspath(value)\n    if value.startswith(\'\\\\\\\\\'):\n        return \'\\\\\\\\?\\\\UNC\\\\\' + value[2:]\n    return \'\\\\\\\\?\\\\\' + value\n\n\ndef _now():\n    return datetime.now(timezone.utc).isoformat()\n\n\ndef _metadata(info):\n    return (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_dev, info.st_ino)\n\n\ndef _read_hash(path):\n    digest = hashlib.sha256()\n    with Path(_long_path(path)).open(\'rb\') as stream:\n        for chunk in iter(lambda: stream.read(1024 * 1024), b\'\'):\n            digest.update(chunk)\n    return digest.hexdigest()\n\n\ndef canonical_report(source):\n    root = Path(source[\'output_directory\']).resolve()\n    outputs = []\n    for original in source.get(\'outputs\', []):\n        entry = dict.fromkeys((\'path\', \'size_bytes\', \'sha256\', \'verification_sha256\',\n                              \'verification_status\', \'error\'))\n        entry[\'path\'] = original[\'path\']\n        entry[\'verification_status\'] = \'failed\'\n        try:\n            relative = Path(original[\'path\'])\n            if relative.is_absolute() or \'..\' in relative.parts:\n                raise ValueError(\'Saved output path is not a safe relative path\')\n            path = root / relative\n            before = Path(_long_path(path)).stat()\n            metadata = _metadata(before)\n            entry[\'size_bytes\'] = before.st_size\n            entry[\'sha256\'] = _read_hash(path)\n            if _metadata(Path(_long_path(path)).stat()) != metadata:\n                raise RuntimeError(\'Saved file metadata changed during first read\')\n            entry[\'verification_sha256\'] = _read_hash(path)\n            if _metadata(Path(_long_path(path)).stat()) != metadata:\n                raise RuntimeError(\'Saved file metadata changed during independent verification read\')\n            if entry[\'sha256\'] != entry[\'verification_sha256\']:\n                raise RuntimeError(\'Saved-file SHA-256 mismatch between independent reads\')\n            entry[\'verification_status\'] = \'verified\'\n        except (OSError, ValueError, RuntimeError) as exc:\n            entry[\'error\'] = str(exc)\n        outputs.append(entry)\n    failed = any(item[\'verification_status\'] == \'failed\' for item in outputs)\n    return {\n        \'schema_version\': 1,\n        \'artifact_name\': source.get(\'artifact_name\') or root.name.removesuffix(\'_Output\'),\n        \'collector\': source.get(\'collector\', \'collector.py\'),\n        \'hash_algorithm\': \'SHA-256\',\n        \'verification_status\': \'failed\' if failed else \'verified\' if outputs else \'not_run\',\n        \'verification_method\': \'Two independent reads of saved output files; SHA-256 comparison and size, mtime, ctime, device and file identity stability checks. Not acquisition-time hashing.\',\n        \'collection_status\': \'partial\' if failed and source.get(\'collection_exit_code\') == 0 else source.get(\'collection_status\'),\n        \'collection_exit_code\': 1 if failed and source.get(\'collection_exit_code\') == 0 else source.get(\'collection_exit_code\'),\n        \'output_directory\': str(root),\n        \'outputs\': sorted(outputs, key=lambda item: item[\'path\'].casefold()),        \'error\': source.get(\'error\'),\n        \'errors\': source.get(\'errors\', []),\n        \'generated_at_utc\': _now(),\n    }\n', _inline_namespace)
    report.setdefault('artifact_name', _inline_namespace['Path'](__file__).resolve().parent.name.split(' - ', 1)[1])
    canonical = _inline_namespace['canonical_report'](report)
    return canonical


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _windows_long_path(path):
    value = os.fspath(path)
    if os.name != "nt":
        return os.path.abspath(value)
    if value.startswith("\\\\?\\"):
        return value
    value = os.path.abspath(value)
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _display_path(path):
    value = os.fspath(path)
    if value.startswith("\\\\?\\UNC\\"):
        return "\\\\" + value[8:]
    if value.startswith("\\\\?\\"):
        return value[4:]
    return value


def _normal_path(path):
    return os.path.normcase(os.path.abspath(_display_path(path)))


def new_run_id():
    return (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "_"
        + uuid.uuid4().hex[:8]
    )


def is_admin():
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def sha256_file(path):
    digest = hashlib.sha256()
    path = Path(path)
    io_path = path if _report_key(path) is not None else Path(_windows_long_path(path))
    with _report_open(io_path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _report_open(path, "x", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def walk_exclusions():
    artifact_dir = Path(__file__).resolve().parent
    paths = (
        Path(__file__).resolve(),
        artifact_dir / "launch.bat",
        artifact_dir.parent / "setup_environment.bat",
        artifact_dir.parent.parent / "setup_environment.bat",
        artifact_dir.parent / "requirement_dev_log.txt",
        artifact_dir.parent.parent / ".custos-runtime",
        Path(sys.executable),
    )
    return {
        os.path.normcase(os.path.abspath(str(path)))
        for path in paths
    }


def output_overlaps_source(output_dir: Path, source_root: Path) -> bool:
    output = output_dir.resolve()
    source = source_root.resolve()
    return output == source or source in output.parents


def command_record(argv, timeout=COMMAND_TIMEOUT):
    """Execute without a shell and preserve the original output bytes."""
    record = {
        "argv": argv,
        "started_utc": utc_now(),
        "ended_utc": None,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "stdout_base64": "",
        "stderr_base64": "",
        "error": None,
        "duration_seconds": None,
    }

    started = time.monotonic()

    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            shell=False,
            check=False,
        )

        record["exit_code"] = result.returncode
        record["stdout"] = result.stdout.decode(
            "utf-8", errors="replace"
        )
        record["stderr"] = result.stderr.decode(
            "utf-8", errors="replace"
        )
        record["stdout_base64"] = base64.b64encode(
            result.stdout
        ).decode("ascii")
        record["stderr_base64"] = base64.b64encode(
            result.stderr
        ).decode("ascii")

    except subprocess.TimeoutExpired as exc:
        record["error"] = f"Command timed out after {timeout} seconds."

        stdout = exc.stdout or b""
        stderr = exc.stderr or b""

        if isinstance(stdout, str):
            stdout = stdout.encode("utf-8", errors="replace")
        if isinstance(stderr, str):
            stderr = stderr.encode("utf-8", errors="replace")

        record["stdout"] = stdout.decode("utf-8", errors="replace")
        record["stderr"] = stderr.decode("utf-8", errors="replace")
        record["stdout_base64"] = base64.b64encode(
            stdout
        ).decode("ascii")
        record["stderr_base64"] = base64.b64encode(
            stderr
        ).decode("ascii")

    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"

    record["ended_utc"] = utc_now()
    record["duration_seconds"] = round(
        time.monotonic() - started, 3
    )

    return record


def powershell_path():
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    candidate = (
        root
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )

    if candidate.exists():
        return str(candidate)

    return "powershell.exe"


def build_inventory_script():
    """
    PowerShell retrieves task metadata and exported task XML.
    JSON is emitted as a single object to simplify reliable parsing.
    """

    return r'''
$ErrorActionPreference = 'Continue'
$tasksOut = @()
$globalErrors = @()

try {
    Import-Module ScheduledTasks -ErrorAction Stop
    $allTasks = @(Get-ScheduledTask -ErrorAction Stop)

    foreach ($task in $allTasks) {
        $xml = $null
        $exportError = $null

        try {
            $xml = Export-ScheduledTask `
                -TaskName $task.TaskName `
                -TaskPath $task.TaskPath `
                -ErrorAction Stop
        }
        catch {
            $exportError = $_.Exception.Message
        }

        $actionsOut = @()

        foreach ($action in @($task.Actions)) {
            $actionsOut += [pscustomobject]@{
                ActionType = [string]$action.CimClass.CimClassName
                Execute = [string]$action.Execute
                Arguments = [string]$action.Arguments
                WorkingDirectory = [string]$action.WorkingDirectory
                ClassId = [string]$action.ClassId
                Data = [string]$action.Data
            }
        }

        $triggersOut = @()

        foreach ($trigger in @($task.Triggers)) {
            $triggersOut += [pscustomobject]@{
                TriggerType = [string]$trigger.CimClass.CimClassName
                Enabled = $trigger.Enabled
                StartBoundary = [string]$trigger.StartBoundary
                EndBoundary = [string]$trigger.EndBoundary
                ExecutionTimeLimit = [string]$trigger.ExecutionTimeLimit
                UserId = [string]$trigger.UserId
                Subscription = [string]$trigger.Subscription
                StateChange = [string]$trigger.StateChange
            }
        }

        $principal = $task.Principal
        $settings = $task.Settings

        $tasksOut += [pscustomobject]@{
            TaskName = [string]$task.TaskName
            TaskPath = [string]$task.TaskPath
            State = [string]$task.State
            Author = [string]$task.Author
            Description = [string]$task.Description
            URI = [string]$task.URI
            Source = [string]$task.Source
            Date = [string]$task.Date

            Principal = [pscustomobject]@{
                UserId = [string]$principal.UserId
                GroupId = [string]$principal.GroupId
                LogonType = [string]$principal.LogonType
                RunLevel = [string]$principal.RunLevel
                DisplayName = [string]$principal.DisplayName
            }

            Settings = [pscustomobject]@{
                Enabled = $settings.Enabled
                Hidden = $settings.Hidden
                AllowDemandStart = $settings.AllowDemandStart
                StartWhenAvailable = $settings.StartWhenAvailable
                RunOnlyIfIdle = $settings.RunOnlyIfIdle
                WakeToRun = $settings.WakeToRun
                ExecutionTimeLimit = [string]$settings.ExecutionTimeLimit
                MultipleInstances = [string]$settings.MultipleInstances
                Priority = $settings.Priority
            }

            Actions = @($actionsOut)
            Triggers = @($triggersOut)
            ExportedXml = [string]$xml
            ExportError = $exportError
        }
    }
}
catch {
    $globalErrors += $_.Exception.Message
}

$result = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    CollectionTimeLocal = (Get-Date).ToString('o')
    TaskCount = $tasksOut.Count
    GlobalErrors = @($globalErrors)
    Tasks = @($tasksOut)
}

$result | ConvertTo-Json -Depth 12 -Compress
'''


def copy_and_verify(source, destination):
    """Copy one file and compare source/acquired SHA-256 hashes."""
    source = Path(source)
    destination = Path(destination)
    source_io = Path(_windows_long_path(source))
    destination_io = Path(_windows_long_path(destination))

    record = {
        "source_path": _display_path(source),
        "destination_path": str(destination),
        "status": None,
        "source_sha256_before": None,
        "acquired_sha256": None,
        "source_sha256_after": None,
        "source_size_before": None,
        "source_size_after": None,
        "acquired_size": None,
        "source_changed_during_acquisition": None,
        "error": None,
    }

    try:
        before_stat = source_io.stat()
        record["source_size_before"] = before_stat.st_size
        record["source_sha256_before"] = sha256_file(source)

        destination_io.parent.mkdir(parents=True, exist_ok=True)
        if destination_io.exists():
            raise FileExistsError(f"Output collision: {destination}")
        with source_io.open("rb") as source_stream, destination_io.open("xb") as target_stream:
            shutil.copyfileobj(source_stream, target_stream)
        shutil.copystat(source_io, destination_io)

        record["acquired_size"] = destination_io.stat().st_size
        record["acquired_sha256"] = sha256_file(destination)

        try:
            after_stat = source_io.stat()
            record["source_size_after"] = after_stat.st_size
            record["source_sha256_after"] = sha256_file(source)

            record["source_changed_during_acquisition"] = (
                record["source_sha256_before"]
                != record["source_sha256_after"]
                or record["source_size_before"]
                != record["source_size_after"]
            )

        except OSError as exc:
            record["source_changed_during_acquisition"] = True
            record["error"] = (
                f"Source became unavailable after copy: {exc}"
            )

        if record["acquired_sha256"] != record["source_sha256_before"]:
            record["status"] = "VERIFICATION_FAILED"
        elif record["source_changed_during_acquisition"]:
            record["status"] = "SOURCE_CHANGED_OR_DISAPPEARED"
        else:
            record["status"] = "ACQUIRED_VERIFIED"

    except Exception as exc:
        record["status"] = "ACQUISITION_FAILED"
        record["error"] = f"{type(exc).__name__}: {exc}"

    return record


def main():
    parser = argparse.ArgumentParser(
        description="Custos A07 Scheduled Tasks Enumeration"
    )

    parser.add_argument(
        "--case-root",
        default=str(DEFAULT_CASE_ROOT),
        help=r"Case root (default: C:\Custos\Case001)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "Scheduled Tasks Enumeration_Output",
        help="Destination directory for all collected and generated files.",
    )

    parser.add_argument(
        "--skip-task-files",
        action="store_true",
        help="Skip copying the Windows task-definition files.",
    )

    parser.add_argument(
        "--skip-operational-log",
        action="store_true",
        help="Skip exporting the Task Scheduler Operational log.",
    )

    args = parser.parse_args()

    if os.name != "nt":
        print("[FATAL] This collector runs on Windows only.")
        return 2

    if not is_admin():
        print(
            "[FATAL] Administrator privileges are required. "
            "Open an elevated terminal and rerun."
        )
        return 2

    case_root = Path(args.case_root)
    output_dir = args.output_dir.expanduser().resolve()
    rid = new_run_id()
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    task_store = system_root / "System32" / "Tasks"
    if (
        not args.skip_task_files
        and task_store.is_dir()
        and output_overlaps_source(output_dir, task_store)
    ):
        print(
            "[FATAL] --output-dir is inside the recursively scanned task "
            f"store '{task_store}'. Select another destination; collection "
            "scope will not be narrowed.",
            file=sys.stderr,
        )
        return 2
    output_dir.mkdir(parents=True, exist_ok=True)
    files_dir = output_dir / "Scheduled Tasks Enumeration_Files"
    files_dir.mkdir(parents=True, exist_ok=True)

    evidence_root = files_dir
    derived_root = files_dir

    planned_outputs = [
        output_dir / f"Scheduled Tasks Enumeration_{rid}.json",
        derived_root / f"Scheduled Tasks Enumeration_Summary_{rid}.json",
    ]
    if not args.skip_operational_log:
        planned_outputs.append(
            evidence_root / "TaskScheduler_Operational.evtx"
        )
    collisions = [path for path in planned_outputs if path.exists()]
    if collisions:
        print(
            "[FATAL] Output collision; no files were overwritten: "
            + ", ".join(str(path) for path in collisions),
            file=sys.stderr,
        )
        return 2

    obsolete_stdout = evidence_root / "PowerShell_TaskInventory.stdout.bin"
    if obsolete_stdout.is_file():
        obsolete_stdout.unlink()

    errors = []
    commands = {}
    task_file_records = []
    acquired_files = []

    print(f"[INFO] {MODULE} v{VERSION}")
    print(f"[INFO] Run ID: {rid}")
    print(f"[INFO] Case root: {case_root}")

    inventory_command = [
        powershell_path(),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        build_inventory_script(),
    ]

    inventory_result = command_record(inventory_command)
    commands["scheduled_task_inventory"] = inventory_result

    inventory = {
        "module": MODULE,
        "version": VERSION,
        "artifact": "A07 - Scheduled Tasks Enumeration",
        "run_id": rid,
        "collected_utc": utc_now(),
        "computer_name": os.environ.get("COMPUTERNAME"),
        "collector_user": os.environ.get("USERNAME"),
        "case_root": str(case_root),
        "status": None,
        "inventory": None,
        "commands": commands,
        "task_definition_files": [],
        "task_scheduler_operational_log": None,
        "errors": errors,
        "limitations": [
            "Live-system collection is not atomic.",
            "Task metadata describes collection-time state; it does not prove execution.",
            "The Operational event log may be disabled, inaccessible, or have limited history.",
            "Task API output and task-store files are separate evidence sources.",
            "Access-denied, changing, or unavailable sources may make collection incomplete.",
            "This collector does not run or modify scheduled tasks.",
        ],
    }

    try:
        stdout = inventory_result["stdout"]

        if inventory_result["error"] or inventory_result["exit_code"] != 0:
            errors.append({
                "source": "scheduled_task_inventory",
                "error": inventory_result["error"]
                or inventory_result["stderr"]
                or f"PowerShell exit code {inventory_result['exit_code']}",
            })

        parsed = json.loads(stdout)

        if not isinstance(parsed, dict) or "Tasks" not in parsed:
            raise ValueError("PowerShell output has no Tasks array.")

        inventory["inventory"] = parsed

    except Exception as exc:
        errors.append({
            "source": "inventory_parse",
            "error": f"{type(exc).__name__}: {exc}",
        })
        inventory["inventory_raw_stdout_base64"] = (
            inventory_result["stdout_base64"]
        )

    # Acquire native task definition files.
    if not args.skip_task_files:
        system_root = Path(
            os.environ.get("SystemRoot", r"C:\Windows")
        )
        excluded_paths = walk_exclusions()

        if task_store.is_dir():
            long_task_store = Path(_windows_long_path(task_store))

            def record_task_walk_error(exc):
                errors.append({
                    "source": _display_path(getattr(exc, "filename", task_store)),
                    "error": f"{type(exc).__name__}: {exc}",
                })

            for root, dirs, files in os.walk(
                long_task_store,
                topdown=True,
                followlinks=False,
                onerror=record_task_walk_error,
            ):
                dirs[:] = [
                    name
                    for name in dirs
                    if (
                        not (Path(root) / name).is_symlink()
                        and _normal_path(Path(root) / name) not in excluded_paths
                    )
                ]

                for filename in files:
                    source = Path(root) / filename

                    try:
                        if os.path.normcase(
                            _normal_path(source)
                        ) in excluded_paths:
                            continue
                        if source.is_symlink() or not source.is_file():
                            continue

                        relative = source.relative_to(long_task_store)
                        destination = (
                            evidence_root
                            / "TaskDefinitionFiles"
                            / relative
                        )

                        record = copy_and_verify(source, destination)
                        task_file_records.append(record)

                        if record["status"] != "ACQUIRED_VERIFIED":
                            errors.append({
                                "source": _display_path(source),
                                "error": record.get("error")
                                or record["status"],
                            })

                    except Exception as exc:
                        errors.append({
                            "source": _display_path(source),
                            "error": f"{type(exc).__name__}: {exc}",
                        })

        else:
            errors.append({
                "source": str(task_store),
                "error": "Task-definition directory is unavailable.",
            })

    inventory["task_definition_files"] = task_file_records

    # Export the event log without enabling or changing it.
    log_record = {
        "channel": TASK_LOG,
        "status": None,
    }

    if not args.skip_operational_log:
        system_root = Path(
            os.environ.get("SystemRoot", r"C:\Windows")
        )
        wevtutil_path = system_root / "System32" / "wevtutil.exe"
        wevtutil = (
            str(wevtutil_path)
            if wevtutil_path.exists()
            else "wevtutil.exe"
        )

        evtx_path = evidence_root / "TaskScheduler_Operational.evtx"

        event_command = command_record([
            wevtutil,
            "epl",
            TASK_LOG,
            str(evtx_path),
            "/ow:false",
        ])

        commands["export_task_scheduler_operational_log"] = event_command

        if (
            event_command["exit_code"] == 0
            and evtx_path.is_file()
            and _report_stat(evtx_path).st_size > 0
        ):
            log_record.update({
                "status": "EXPORTED",
                "path": str(evtx_path),
                "size": _report_stat(evtx_path).st_size,
                "sha256": sha256_file(evtx_path),
            })

            acquired_files.append({
                "path": str(evtx_path),
                "sha256": log_record["sha256"],
                "size": log_record["size"],
                "role": "primary_event_log_evidence",
            })

        else:
            log_record["status"] = "EXPORT_FAILED_OR_UNAVAILABLE"
            log_record["error"] = (
                event_command["stderr"]
                or event_command["error"]
                or f"wevtutil exit code {event_command['exit_code']}"
            )

            errors.append({
                "source": TASK_LOG,
                "error": log_record["error"],
            })

    else:
        log_record["status"] = "SKIPPED_BY_ARGUMENT"

    inventory["task_scheduler_operational_log"] = log_record

    parsed_inventory = inventory.get("inventory")
    tasks = (
        parsed_inventory.get("Tasks", []) or []
        if isinstance(parsed_inventory, dict)
        else None
    )
    task_count = len(tasks) if isinstance(tasks, list) else None

    if isinstance(parsed_inventory, dict):
        for error_text in parsed_inventory.get("GlobalErrors", []) or []:
            errors.append({
                "source": "PowerShell_inventory",
                "error": error_text,
            })

        failed_xml_exports = sum(
            1 for task in tasks if task.get("ExportError")
        ) if isinstance(tasks, list) else 0
        if failed_xml_exports:
            errors.append({
                "source": "task_xml_export",
                "error": f"{failed_xml_exports} task XML export(s) failed.",
            })

    if task_count is None:
        task_enumeration_status = "SOURCE_UNAVAILABLE"
    elif (
        inventory_result["exit_code"] != 0
        or inventory_result["error"]
        or (
            isinstance(parsed_inventory, dict)
            and parsed_inventory.get("GlobalErrors")
        )
    ):
        task_enumeration_status = "PARTIAL"
    else:
        task_enumeration_status = "SUCCESS"

    if args.skip_task_files:
        task_file_copy_status = "SKIPPED_BY_ARGUMENT"
    elif not task_store.is_dir():
        task_file_copy_status = "SOURCE_UNAVAILABLE"
    elif (
        any(record["status"] != "ACQUIRED_VERIFIED" for record in task_file_records)
        or any(
            error.get("source") == str(task_store)
            or str(error.get("source", "")).startswith(_display_path(task_store))
            for error in errors
        )
    ):
        task_file_copy_status = "PARTIAL"
    elif task_file_records:
        task_file_copy_status = "SUCCESS"
    else:
        task_file_copy_status = "SOURCE_AVAILABLE_EMPTY"

    if task_file_copy_status == "PARTIAL":
        status = "PARTIAL"
    elif task_enumeration_status == "SOURCE_UNAVAILABLE":
        status = "SOURCE_UNAVAILABLE"
    elif (
        task_enumeration_status == "PARTIAL"
        or task_file_copy_status == "SOURCE_UNAVAILABLE"
        or errors
    ):
        status = "PARTIAL"
    elif task_count == 0 and not task_file_records:
        status = "SOURCE_AVAILABLE_EMPTY"
    else:
        status = "SUCCESS"

    inventory["task_enumeration_status"] = task_enumeration_status
    inventory["task_definition_file_copy_requested"] = not args.skip_task_files
    inventory["task_definition_file_copy_status"] = task_file_copy_status
    inventory["status"] = status

    # Store the inventory as primary evidence.
    inventory["errors"] = errors
    evidence_json = output_dir / f"Scheduled Tasks Enumeration_{rid}.json"

    try:
        write_json(evidence_json, inventory)

        acquired_files.append({
            "path": str(evidence_json),
            "sha256": sha256_file(evidence_json),
            "size": _report_stat(evidence_json).st_size,
            "role": "primary_inventory_evidence",
        })

    except Exception as exc:
        errors.append({
            "source": "evidence_json_write",
            "error": f"{type(exc).__name__}: {exc}",
        })

    # Re-hash acquired files after collection.
    verification_items = []
    verification_failed = False

    for item in acquired_files:
        path = Path(item["path"])

        try:
            observed_hash = sha256_file(path)
            observed_size = _report_stat(path).st_size

            verified = (
                observed_hash == item["sha256"]
                and observed_size == item["size"]
            )

            verification_items.append({
                "path": str(path),
                "expected_sha256": item["sha256"],
                "observed_sha256": observed_hash,
                "expected_size": item["size"],
                "observed_size": observed_size,
                "verified": verified,
                "role": item["role"],
            })

            if not verified:
                verification_failed = True

        except Exception as exc:
            verification_items.append({
                "path": str(path),
                "verified": False,
                "error": str(exc),
            })
            verification_failed = True

    status_before_verification = status
    if verification_failed:
        status = "VERIFICATION_FAILED"
    inventory["status"] = status
    if status != status_before_verification:
        write_json(evidence_json, inventory)
        evidence_item = next(
            item for item in acquired_files
            if item.get("path") == str(evidence_json)
        )
        evidence_item["sha256"] = sha256_file(evidence_json)
        evidence_item["size"] = _report_stat(evidence_json).st_size
        for verification_item in verification_items:
            if verification_item.get("path") == str(evidence_json):
                verification_item["expected_sha256"] = evidence_item["sha256"]
                verification_item["observed_sha256"] = sha256_file(evidence_json)
                verification_item["expected_size"] = evidence_item["size"]
                verification_item["observed_size"] = _report_stat(evidence_json).st_size
                verification_item["verified"] = (
                    verification_item["expected_sha256"]
                    == verification_item["observed_sha256"]
                    and verification_item["expected_size"]
                    == verification_item["observed_size"]
                )

    summary = {
        "module": MODULE,
        "version": VERSION,
        "artifact": "A07 - Scheduled Tasks Enumeration",
        "run_id": rid,
        "collected_utc": utc_now(),
        "computer_name": os.environ.get("COMPUTERNAME"),
        "case_root": str(case_root),
        "status": status,
        "task_count": task_count,
        "task_enumeration_status": task_enumeration_status,
        "task_definition_file_copy_requested": not args.skip_task_files,
        "task_definition_file_copy_status": task_file_copy_status,
        "task_definition_files_acquired": sum(
            1
            for record in task_file_records
            if record["status"] == "ACQUIRED_VERIFIED"
        ),
        "task_definition_file_errors": sum(
            1
            for record in task_file_records
            if record["status"] != "ACQUIRED_VERIFIED"
        ),
        "operational_log_status": log_record["status"],
        "error_count": len(errors),
        "evidence_json": str(evidence_json),
        "errors": errors,
        "limitations": inventory["limitations"],
    }

    write_json(
        derived_root / f"Scheduled Tasks Enumeration_Summary_{rid}.json",
        summary,
    )

    print(f"[INFO] Tasks enumerated: {task_count}")
    print(
        "[INFO] Task files acquired: "
        f"{summary['task_definition_files_acquired']}"
    )
    print(f"[INFO] Operational log: {log_record['status']}")
    print(f"[INFO] Errors: {len(errors)}")
    print(f"[INFO] Verification passed: {not verification_failed}")
    print(f"[INFO] Final status: {status}")
    print(f"[INFO] Evidence: {evidence_json}")
    print(f"[INFO] Summary: {derived_root / f'Scheduled Tasks Enumeration_Summary_{rid}.json'}")

    return 0 if status in ("SUCCESS", "SOURCE_AVAILABLE_EMPTY") else 1




# Legacy reporting streams stay in memory; acquired evidence still uses native IO.
_REPORT_MEMORY = {}

def _report_key(path):
    from pathlib import Path
    from fnmatch import fnmatchcase
    path = Path(path)
    if path.name.endswith('.tmp'):
        path = path.with_name(path.name[:-4])
    if any(part.casefold() in {'acquiredfiles', 'acquired', 'files', 'evidencefiles'} for part in path.parts[:-1]):
        return None
    return path if any(fnmatchcase(path.name.casefold(), pattern) for pattern in _REPORT_PATTERNS) else None

def _report_open(path, mode='r', *args, **kwargs):
    from pathlib import Path
    import io
    key = _report_key(path)
    if key is None:
        return Path(path).open(mode, *args, **kwargs)
    encoding = kwargs.get('encoding') or 'utf-8'
    binary = 'b' in mode
    if not any(flag in mode for flag in 'wax'):
        if key not in _REPORT_MEMORY:
            return Path(path).open(mode, *args, **kwargs)
        raw = _REPORT_MEMORY[key]
        return io.BytesIO(raw) if binary else io.StringIO(raw.decode(encoding))
    class ReportStream(io.BytesIO if binary else io.StringIO):
        _in_memory_report = True
        def close(self):
            if not self.closed:
                value = self.getvalue()
                _REPORT_MEMORY[key] = value if binary else value.encode(encoding)
            super().close()
    return ReportStream()

def _report_write_text(path, text, *args, **kwargs):
    with _report_open(path, 'w', *args, **kwargs) as stream:
        return stream.write(text)

def _report_replace(source, destination):
    import os
    if _report_key(destination) is None:
        return os.replace(source, destination)

def _report_stat(path):
    from pathlib import Path
    from types import SimpleNamespace
    key = _report_key(path)
    if key in _REPORT_MEMORY:
        return SimpleNamespace(st_size=len(_REPORT_MEMORY[key]), st_mtime=0, st_ctime=0, st_mtime_ns=0, st_ctime_ns=0)
    return Path(path).stat()

_REPORT_PATTERNS = ('*summary_*.json',)

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
    has_output = any(
        argument.partition("=")[0] in {
            "-o", "--out", "--output", "--output-dir", "--output-directory"
        }
        for argument in arguments
    )
    if not has_output:
        output_option = "--output-dir"
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
        arguments.extend((output_option, str(output_directory)))
        _integrity_sys.argv[:] = [_integrity_sys.argv[0], *arguments]

    def utc_now():
        return _integrity_datetime.datetime.now(
            _integrity_datetime.timezone.utc
        ).isoformat(timespec="microseconds").replace("+00:00", "Z")

    def long_path(path):
        value = _integrity_os.fspath(path)
        if _integrity_os.name != "nt":
            return _integrity_os.path.abspath(value)
        if value.startswith("\\\\?\\"):
            return value
        value = _integrity_os.path.abspath(value)
        if value.startswith("\\\\"):
            return "\\\\?\\UNC\\" + value[2:]
        return "\\\\?\\" + value

    def plain_path(path):
        value = _integrity_os.fspath(path)
        if value.startswith("\\\\?\\UNC\\"):
            return "\\\\" + value[8:]
        if value.startswith("\\\\?\\"):
            return value[4:]
        return value

    def snapshot(directory):
        if not _IntegrityPath(long_path(directory)).is_dir():
            return {}
        result = {}
        skipped = {".git", ".venv", "venv", "__pycache__", "output & validation"}
        def raise_walk_error(error):
            raise error
        for current, folders, filenames in _integrity_os.walk(
            long_path(directory), onerror=raise_walk_error
        ):
            folders[:] = [name for name in folders if name.casefold() not in skipped]
            for filename in filenames:
                path = _IntegrityPath(plain_path(current)) / filename
                io_path = _IntegrityPath(long_path(path))
                if io_path.is_symlink():
                    continue
                info = io_path.stat()
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

    manifest_path = output_root / f"{artifact_display_name}_Hash & Timestamp Report.json"
    if _IntegrityPath(long_path(manifest_path)).exists():
        raise FileExistsError(f"Existing report preserved; choose a fresh output directory: {manifest_path}")
    before = snapshot(output_root)
    _REPORT_MEMORY.clear()
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
        if result is None:
            result = 0
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
    consolidated_reports = {}
    report_paths = set()
    for path, raw in _REPORT_MEMORY.items():
        try:
            relative = path.resolve().relative_to(output_root)
        except ValueError:
            relative = _IntegrityPath(path.name)
        try:
            content = _integrity_json.loads(raw.decode("utf-8-sig")) if path.suffix.lower() == ".json" else raw.decode("utf-8-sig")
            content_encoding = "json" if path.suffix.lower() == ".json" else "utf-8"
        except (ValueError, UnicodeError):
            content = __import__("base64").b64encode(raw).decode("ascii")
            content_encoding = "base64"
        consolidated_reports[str(relative)] = {
            "original_path": str(relative), "sha256": _integrity_hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw), "content": content, "content_encoding": content_encoding,
        }
    outputs = []
    verification_errors = 0
    for path, metadata in snapshot(output_root).items():
        if path == manifest_path or path in report_paths or before.get(path) == metadata:
            continue
        try:
            io_path = _IntegrityPath(long_path(path))
            info = io_path.stat()
            current = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if current != metadata:
                raise RuntimeError(f"Output changed before SHA-256 calculation: {path}")
            digest = _integrity_hashlib.sha256()
            with io_path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            info = io_path.stat()
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
            "last_modified_utc": _integrity_datetime.datetime.fromtimestamp(info.st_mtime, _integrity_datetime.timezone.utc).isoformat(),
            "hash_timestamp_utc": utc_now(),
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
        "consolidated_reports": consolidated_reports,
    }
    if failure is not None and not isinstance(failure, SystemExit):
        report["error"] = {"type": type(failure).__name__, "message": str(failure)}

    if not _IntegrityPath(long_path(output_root)).is_dir() and result != 0:
        output_root = default_output_directory
        _IntegrityPath(long_path(output_root)).mkdir(parents=True, exist_ok=True)
        manifest_path = output_root / manifest_path.name
        report["output_directory"] = str(output_root)
        report["outputs"] = []
    else:
        _IntegrityPath(long_path(output_root)).mkdir(parents=True, exist_ok=True)
    temporary_path = manifest_path.with_name(
        f".{manifest_path.name}.{_integrity_secrets.token_hex(4)}.tmp"
    )
    report = _canonical_integrity_report(report)
    result = report["collection_exit_code"]
    try:
        with _IntegrityPath(long_path(temporary_path)).open(
            "x", encoding="utf-8", newline="\n"
        ) as stream:
            _integrity_json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            _integrity_os.fsync(stream.fileno())
        _integrity_os.replace(long_path(temporary_path), long_path(manifest_path))
    finally:
        _IntegrityPath(long_path(temporary_path)).unlink(missing_ok=True)
    if failure is not None:
        raise failure.with_traceback(failure.__traceback__)
    return result


if __name__ == "__main__":
    raise SystemExit(_run_with_integrity_manifest(main))
