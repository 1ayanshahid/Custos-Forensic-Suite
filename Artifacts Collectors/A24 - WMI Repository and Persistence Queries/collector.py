
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Custos Forensic Suite
Artifact: A24 - WMI Repository and Persistence Queries
Version: 1.0.0
Platform: Windows 10/11 x64

Default case root:
    C:\\Custos\\Case001

Collects:
- WMI namespace inventory
- __EventFilter instances
- Event consumer instances
- __FilterToConsumerBinding instances
- WMI repository directory metadata
- WMI-Activity Operational EVTX log, if accessible
- Raw command output, SHA-256 hashes, and verification records

Read-only collector. Does not repair or modify WMI.
Requires an elevated terminal. launch.bat delegates to the workspace helper.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


MODULE = "A24_WMI_Repository_Persistence"
VERSION = "1.0.0"
DEFAULT_CASE_ROOT = Path(r"C:\Custos\Case001")
WMI_ACTIVITY_LOG = "Microsoft-Windows-WMI-Activity/Operational"
COMMAND_TIMEOUT = 300


def _canonical_integrity_report(report):
    # Isolated embedded implementation: collector globals cannot shadow its imports.
    _inline_namespace = {}
    exec('"""Canonical post-save integrity reports; never evidence of acquisition-time hashing."""\nimport hashlib\nfrom datetime import datetime, timezone\nfrom pathlib import Path\n\n\ndef _now():\n    return datetime.now(timezone.utc).isoformat()\n\n\ndef _metadata(info):\n    return (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_dev, info.st_ino)\n\n\ndef _read_hash(path):\n    digest = hashlib.sha256()\n    with path.open(\'rb\') as stream:\n        for chunk in iter(lambda: stream.read(1024 * 1024), b\'\'):\n            digest.update(chunk)\n    return digest.hexdigest()\n\n\ndef canonical_report(source):\n    root = Path(source[\'output_directory\']).resolve()\n    outputs = []\n    for original in source.get(\'outputs\', []):\n        entry = dict.fromkeys((\'path\', \'size_bytes\', \'sha256\', \'verification_sha256\',\n                              \'verification_status\', \'error\'))\n        entry[\'path\'] = original[\'path\']\n        entry[\'verification_status\'] = \'failed\'\n        try:\n            path = (root / original[\'path\']).resolve()\n            path.relative_to(root)\n            before = path.stat()\n            metadata = _metadata(before)\n            entry[\'size_bytes\'] = before.st_size\n            entry[\'sha256\'] = _read_hash(path)\n            if _metadata(path.stat()) != metadata:\n                raise RuntimeError(\'Saved file metadata changed during first read\')\n            entry[\'verification_sha256\'] = _read_hash(path)\n            if _metadata(path.stat()) != metadata:\n                raise RuntimeError(\'Saved file metadata changed during independent verification read\')\n            if entry[\'sha256\'] != entry[\'verification_sha256\']:\n                raise RuntimeError(\'Saved-file SHA-256 mismatch between independent reads\')\n            entry[\'verification_status\'] = \'verified\'\n        except (OSError, ValueError, RuntimeError) as exc:\n            entry[\'error\'] = str(exc)\n        outputs.append(entry)\n    failed = any(item[\'verification_status\'] == \'failed\' for item in outputs)\n    return {\n        \'schema_version\': 1,\n        \'artifact_name\': source.get(\'artifact_name\') or root.name.removesuffix(\'_Output\'),\n        \'collector\': source.get(\'collector\', \'collector.py\'),\n        \'hash_algorithm\': \'SHA-256\',\n        \'verification_status\': \'failed\' if failed else \'verified\' if outputs else \'not_run\',\n        \'verification_method\': \'Two independent reads of saved output files; SHA-256 comparison and size, mtime, ctime, device and file identity stability checks. Not acquisition-time hashing.\',\n        \'collection_status\': \'partial\' if failed and source.get(\'collection_exit_code\') == 0 else source.get(\'collection_status\'),\n        \'collection_exit_code\': 1 if failed and source.get(\'collection_exit_code\') == 0 else source.get(\'collection_exit_code\'),\n        \'output_directory\': str(root),\n        \'outputs\': sorted(outputs, key=lambda item: item[\'path\'].casefold()),        \'error\': source.get(\'error\'),\n        \'errors\': source.get(\'errors\', []),\n        \'generated_at_utc\': _now(),\n    }\n', _inline_namespace)
    report.setdefault('artifact_name', _inline_namespace['Path'](__file__).resolve().parent.name.split(' - ', 1)[1])
    canonical = _inline_namespace['canonical_report'](report)
    return canonical


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def make_run_id():
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
    with _report_open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _report_open(path, "x", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def run_command(argv, timeout=COMMAND_TIMEOUT):
    """Run a command without a shell; retain output text and original bytes."""
    result = {
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
        completed = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            shell=False,
            check=False,
        )

        result["exit_code"] = completed.returncode
        result["stdout"] = completed.stdout.decode(
            "utf-8", errors="replace"
        )
        result["stderr"] = completed.stderr.decode(
            "utf-8", errors="replace"
        )
        result["stdout_base64"] = base64.b64encode(
            completed.stdout
        ).decode("ascii")
        result["stderr_base64"] = base64.b64encode(
            completed.stderr
        ).decode("ascii")

    except subprocess.TimeoutExpired as exc:
        result["error"] = f"TIMEOUT after {timeout} seconds"

        stdout = exc.stdout or b""
        stderr = exc.stderr or b""

        if isinstance(stdout, str):
            stdout = stdout.encode("utf-8", errors="replace")
        if isinstance(stderr, str):
            stderr = stderr.encode("utf-8", errors="replace")

        result["stdout"] = stdout.decode("utf-8", errors="replace")
        result["stderr"] = stderr.decode("utf-8", errors="replace")
        result["stdout_base64"] = base64.b64encode(
            stdout
        ).decode("ascii")
        result["stderr_base64"] = base64.b64encode(
            stderr
        ).decode("ascii")

    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["ended_utc"] = utc_now()
    result["duration_seconds"] = round(
        time.monotonic() - started, 3
    )
    return result


def powershell_path():
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    candidate = (
        root / "System32" / "WindowsPowerShell"
        / "v1.0" / "powershell.exe"
    )
    return str(candidate) if candidate.exists() else "powershell.exe"


def build_wmi_script():
    """
    Enumerate namespaces and WMI persistence classes.

    Query failures are recorded individually. A failed namespace query
    must not be interpreted as an empty namespace.
    """

    return r'''
$ErrorActionPreference = 'Continue'

$namespaceRecords = @()
$namespaceErrors = @()
$filterRecords = @()
$consumerRecords = @()
$bindingRecords = @()
$repositoryRecord = $null

# Walk namespaces from root, with a depth limit and a visited set.
$queue = @(
    [pscustomobject]@{ Name = 'root'; Depth = 0 }
)
$visited = @{}

while ($queue.Count -gt 0) {
    $current = $queue[0]
    if ($queue.Count -gt 1) {
        $queue = @($queue[1..($queue.Count - 1)])
    } else {
        $queue = @()
    }

    $ns = [string]$current.Name
    if ($visited.ContainsKey($ns.ToLowerInvariant())) {
        continue
    }
    $visited[$ns.ToLowerInvariant()] = $true

    $namespaceRecords += [pscustomobject]@{
        Namespace = $ns
        Depth = $current.Depth
        Status = 'ENUMERATED'
    }

    if ($current.Depth -ge 8) {
        continue
    }

    try {
        $children = @(
            Get-CimInstance -Namespace $ns -ClassName __Namespace `
                -ErrorAction Stop
        )

        foreach ($child in $children) {
            $childName = [string]$child.Name
            if ([string]::IsNullOrWhiteSpace($childName)) {
                continue
            }

            $nextName = if ($ns -eq 'root') {
                "root\$childName"
            } else {
                "$ns\$childName"
            }

            $queue += [pscustomobject]@{
                Name = $nextName
                Depth = $current.Depth + 1
            }
        }
    }
    catch {
        $namespaceErrors += [pscustomobject]@{
            Namespace = $ns
            Operation = 'EnumerateChildNamespaces'
            Error = $_.Exception.Message
        }
    }
}

# Query the standard WMI permanent-event subscription namespace.
$subscriptionNamespace = 'root\subscription'

$classes = @(
    @{
        Name = '__EventFilter'
        Target = 'Filter'
    },
    @{
        Name = '__FilterToConsumerBinding'
        Target = 'Binding'
    },
    @{
        Name = 'ActiveScriptEventConsumer'
        Target = 'Consumer'
    },
    @{
        Name = 'CommandLineEventConsumer'
        Target = 'Consumer'
    },
    @{
        Name = 'LogFileEventConsumer'
        Target = 'Consumer'
    },
    @{
        Name = 'NTEventLogEventConsumer'
        Target = 'Consumer'
    },
    @{
        Name = 'SMTPEventConsumer'
        Target = 'Consumer'
    }
)

foreach ($entry in $classes) {
    try {
        $instances = @(
            Get-CimInstance -Namespace $subscriptionNamespace `
                -ClassName $entry.Name -ErrorAction Stop
        )

        foreach ($instance in $instances) {
            # ConvertTo-Json-compatible property bag.
            $properties = [ordered]@{}
            foreach ($property in $instance.CimInstanceProperties) {
                try {
                    $properties[$property.Name] = $property.Value
                }
                catch {
                    $properties[$property.Name] = $null
                }
            }

            $record = [pscustomobject]@{
                Namespace = $subscriptionNamespace
                ClassName = $entry.Name
                Properties = [pscustomobject]$properties
            }

            switch ($entry.Target) {
                'Filter' {
                    $filterRecords += $record
                }
                'Binding' {
                    $bindingRecords += $record
                }
                'Consumer' {
                    $consumerRecords += $record
                }
            }
        }
    }
    catch {
        $namespaceErrors += [pscustomobject]@{
            Namespace = $subscriptionNamespace
            Operation = "QueryClass:$($entry.Name)"
            Error = $_.Exception.Message
        }
    }
}

# Record repository metadata only. Do not copy or repair live repository files.
$repositoryPath = Join-Path $env:windir 'System32\wbem\Repository'

try {
    $dir = Get-Item -LiteralPath $repositoryPath -ErrorAction Stop

    $repoFiles = @()
    try {
        foreach ($file in @(
            Get-ChildItem -LiteralPath $repositoryPath -File `
                -ErrorAction Stop
        )) {
            $repoFiles += [pscustomobject]@{
                Name = $file.Name
                FullName = $file.FullName
                Length = $file.Length
                CreationTimeUtc = $file.CreationTimeUtc.ToString('o')
                LastWriteTimeUtc = $file.LastWriteTimeUtc.ToString('o')
                Attributes = [string]$file.Attributes
            }
        }
    }
    catch {
        $namespaceErrors += [pscustomobject]@{
            Namespace = $repositoryPath
            Operation = 'ListRepositoryFiles'
            Error = $_.Exception.Message
        }
    }

    $repositoryRecord = [pscustomobject]@{
        Path = $dir.FullName
        Exists = $true
        Attributes = [string]$dir.Attributes
        CreationTimeUtc = $dir.CreationTimeUtc.ToString('o')
        LastWriteTimeUtc = $dir.LastWriteTimeUtc.ToString('o')
        Files = @($repoFiles)
    }
}
catch {
    $repositoryRecord = [pscustomobject]@{
        Path = $repositoryPath
        Exists = $false
        Error = $_.Exception.Message
        Files = @()
    }
}

$result = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    CollectionTimeLocal = (Get-Date).ToString('o')
    NamespaceCount = $namespaceRecords.Count
    EventFilterCount = $filterRecords.Count
    EventConsumerCount = $consumerRecords.Count
    BindingCount = $bindingRecords.Count
    Namespaces = @($namespaceRecords)
    NamespaceErrors = @($namespaceErrors)
    EventFilters = @($filterRecords)
    EventConsumers = @($consumerRecords)
    FilterToConsumerBindings = @($bindingRecords)
    RepositoryMetadata = $repositoryRecord
}

$result | ConvertTo-Json -Depth 15 -Compress
'''


def main():
    parser = argparse.ArgumentParser(
        description="Custos A24 WMI repository and persistence collector"
    )
    parser.add_argument(
        "--case-root",
        default=str(DEFAULT_CASE_ROOT),
        help=r"Case root (default: C:\Custos\Case001)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "WMI Repository and Persistence Queries_Output",
        help="Destination directory for all collected and generated files.",
    )
    parser.add_argument(
        "--skip-operational-log",
        action="store_true",
        help="Skip exporting the WMI-Activity Operational EVTX log.",
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
    files_root = output_dir / "WMI Repository and Persistence Queries_Files"
    rid = make_run_id()
    planned_outputs = [
        files_root / "WMI-Activity_Operational.evtx",
        output_dir / f"WMI Repository and Persistence Queries_Persistence_{rid}.json",
        files_root / f"WMI Repository and Persistence Queries_Summary_{rid}.json",
    ]
    collisions = [path for path in planned_outputs if path.exists()]
    if collisions:
        print(
            "[FATAL] Output collision; no files were overwritten: "
            + ", ".join(str(path) for path in collisions),
            file=sys.stderr,
        )
        return 2
    obsolete_stdout = files_root / "WMI_Inventory.stdout.bin"
    if obsolete_stdout.is_file():
        obsolete_stdout.unlink()

    evidence_root = files_root
    derived_root = files_root

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        files_root.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        print(f"[FATAL] Cannot create output directories: {exc}")
        return 2

    print(f"[INFO] {MODULE} v{VERSION}")
    print(f"[INFO] Run ID: {rid}")
    print(f"[INFO] Case root: {case_root}")

    errors = []
    commands = {}
    acquired_files = []

    command = [
        powershell_path(),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        build_wmi_script(),
    ]

    inventory_result = run_command(command)
    commands["wmi_inventory"] = inventory_result

    try:
        if inventory_result["error"] or inventory_result["exit_code"] != 0:
            errors.append({
                "source": "wmi_inventory_command",
                "error": inventory_result["error"]
                or inventory_result["stderr"]
                or f"PowerShell exit code {inventory_result['exit_code']}",
            })

        inventory = json.loads(inventory_result["stdout"])

        if not isinstance(inventory, dict):
            raise ValueError("PowerShell output was not a JSON object.")

    except Exception as exc:
        inventory = None
        errors.append({
            "source": "wmi_inventory_parse",
            "error": f"{type(exc).__name__}: {exc}",
        })

    # Export WMI-Activity Operational EVTX without enabling the channel.
    log_record = {
        "channel": WMI_ACTIVITY_LOG,
        "status": None,
    }

    if not args.skip_operational_log:
        system_root = Path(
            os.environ.get("SystemRoot", r"C:\Windows")
        )
        candidate = system_root / "System32" / "wevtutil.exe"
        wevtutil = str(candidate) if candidate.exists() else "wevtutil.exe"

        evtx_path = evidence_root / "WMI-Activity_Operational.evtx"

        event_result = run_command([
            wevtutil,
            "epl",
            WMI_ACTIVITY_LOG,
            str(evtx_path),
            "/ow:false",
        ])

        commands["export_wmi_activity_log"] = event_result

        if (
            event_result["exit_code"] == 0
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
                "size": log_record["size"],
                "sha256": log_record["sha256"],
                "role": "primary_event_log_evidence",
            })
        else:
            log_record["status"] = "EXPORT_FAILED_OR_UNAVAILABLE"
            log_record["error"] = (
                event_result["stderr"]
                or event_result["error"]
                or f"wevtutil exit code {event_result['exit_code']}"
            )
            errors.append({
                "source": WMI_ACTIVITY_LOG,
                "error": log_record["error"],
            })
    else:
        log_record["status"] = "SKIPPED_BY_ARGUMENT"

    # Write the structured inventory as primary evidence.
    evidence_json = output_dir / f"WMI Repository and Persistence Queries_Persistence_{rid}.json"

    evidence = {
        "module": MODULE,
        "version": VERSION,
        "artifact": "A24 - WMI Repository and Persistence Queries",
        "run_id": rid,
        "collected_utc": utc_now(),
        "computer_name": os.environ.get("COMPUTERNAME"),
        "collector_user": os.environ.get("USERNAME"),
        "case_root": str(case_root),
        "inventory": inventory,
        "wmi_activity_log": log_record,
        "commands": commands,
        "errors": errors,
        "limitations": [
            "Live WMI state can change during collection.",
            "A WMI subscription is not, by itself, proof of malicious activity.",
            "Only listed standard consumer classes are queried; custom provider behavior may require further investigation.",
            "Namespace enumeration is depth-limited and inaccessible namespaces are recorded as errors.",
            "Repository files are inventoried but not copied, repaired, or modified.",
            "The WMI-Activity log may be disabled, inaccessible, or have limited retention.",
            "Raw command output bytes are preserved, but command output is not a full disk image.",
            "SHA-256 verifies acquired-file integrity, not completeness or truth of the source data.",
        ],
    }

    try:
        with _report_open(evidence_json, "x", encoding="utf-8", newline="\n") as stream:
            json.dump(evidence, stream, ensure_ascii=False, indent=2)
            stream.write("\n")

        acquired_files.append({
            "path": str(evidence_json),
            "size": _report_stat(evidence_json).st_size,
            "sha256": sha256_file(evidence_json),
            "role": "primary_structured_evidence",
        })

    except Exception as exc:
        errors.append({
            "source": "evidence_json_write",
            "error": f"{type(exc).__name__}: {exc}",
        })

    # Verify files acquired by this run.
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
            verification_failed = True
            verification_items.append({
                "path": str(path),
                "verified": False,
                "error": str(exc),
            })

    namespace_errors = []
    filter_count = None
    consumer_count = None
    binding_count = None
    namespace_count = None

    if isinstance(inventory, dict):
        namespace_errors = inventory.get("NamespaceErrors", []) or []
        filter_count = inventory.get("EventFilterCount")
        consumer_count = inventory.get("EventConsumerCount")
        binding_count = inventory.get("BindingCount")
        namespace_count = inventory.get("NamespaceCount")

        for item in namespace_errors:
            errors.append({
                "source": item.get("Namespace", "WMI"),
                "operation": item.get("Operation"),
                "error": item.get("Error"),
            })

    if verification_failed:
        status = "VERIFICATION_FAILED"
    elif inventory is None or errors:
        status = "PARTIAL"
    elif (
        namespace_count == 0
        and filter_count == 0
        and consumer_count == 0
        and binding_count == 0
    ):
        status = "SOURCE_AVAILABLE_EMPTY"
    else:
        status = "SUCCESS"

    summary = {
        "module": MODULE,
        "version": VERSION,
        "artifact": "A24 - WMI Repository and Persistence Queries",
        "run_id": rid,
        "collected_utc": utc_now(),
        "computer_name": os.environ.get("COMPUTERNAME"),
        "case_root": str(case_root),
        "status": status,
        "namespace_count": namespace_count,
        "event_filter_count": filter_count,
        "event_consumer_count": consumer_count,
        "binding_count": binding_count,
        "namespace_error_count": len(namespace_errors),
        "error_count": len(errors),
        "wmi_activity_log_status": log_record["status"],
        "evidence_json": str(evidence_json),
        "errors": errors,
    }

    write_json(
        derived_root / f"WMI Repository and Persistence Queries_Summary_{rid}.json",
        summary,
    )

    print(f"[INFO] Namespaces: {namespace_count}")
    print(f"[INFO] Event filters: {filter_count}")
    print(f"[INFO] Event consumers: {consumer_count}")
    print(f"[INFO] Filter bindings: {binding_count}")
    print(f"[INFO] WMI Activity log: {log_record['status']}")
    print(f"[INFO] Errors: {len(errors)}")
    print(f"[INFO] Verification passed: {not verification_failed}")
    print(f"[INFO] Status: {status}")
    print(f"[INFO] Evidence: {evidence_json}")
    print(f"[INFO] Summary: {derived_root / f'WMI Repository and Persistence Queries_Summary_{rid}.json'}")

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

    manifest_path = output_root / f"{artifact_display_name}_Hash & Timestamp Report.json"
    if manifest_path.exists():
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
