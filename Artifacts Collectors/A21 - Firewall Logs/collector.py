from __future__ import annotations

import hashlib
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ARTIFACT_ID = "A21"
ARTIFACT_NAME = "Firewall Logs"


def _canonical_integrity_report(report):
    # Isolated embedded implementation: collector globals cannot shadow its imports.
    _inline_namespace = {}
    exec('"""Canonical post-save integrity reports; never evidence of acquisition-time hashing."""\nimport hashlib\nfrom datetime import datetime, timezone\nfrom pathlib import Path\n\n\ndef _now():\n    return datetime.now(timezone.utc).isoformat()\n\n\ndef _metadata(info):\n    return (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_dev, info.st_ino)\n\n\ndef _read_hash(path):\n    digest = hashlib.sha256()\n    with path.open(\'rb\') as stream:\n        for chunk in iter(lambda: stream.read(1024 * 1024), b\'\'):\n            digest.update(chunk)\n    return digest.hexdigest()\n\n\ndef canonical_report(source):\n    root = Path(source[\'output_directory\']).resolve()\n    outputs = []\n    for original in source.get(\'outputs\', []):\n        entry = dict.fromkeys((\'path\', \'size_bytes\', \'sha256\', \'verification_sha256\',\n                              \'verification_status\', \'error\'))\n        entry[\'path\'] = original[\'path\']\n        entry[\'verification_status\'] = \'failed\'\n        try:\n            path = (root / original[\'path\']).resolve()\n            path.relative_to(root)\n            before = path.stat()\n            metadata = _metadata(before)\n            entry[\'size_bytes\'] = before.st_size\n            entry[\'sha256\'] = _read_hash(path)\n            if _metadata(path.stat()) != metadata:\n                raise RuntimeError(\'Saved file metadata changed during first read\')\n            entry[\'verification_sha256\'] = _read_hash(path)\n            if _metadata(path.stat()) != metadata:\n                raise RuntimeError(\'Saved file metadata changed during independent verification read\')\n            if entry[\'sha256\'] != entry[\'verification_sha256\']:\n                raise RuntimeError(\'Saved-file SHA-256 mismatch between independent reads\')\n            entry[\'verification_status\'] = \'verified\'\n        except (OSError, ValueError, RuntimeError) as exc:\n            entry[\'error\'] = str(exc)\n        outputs.append(entry)\n    failed = any(item[\'verification_status\'] == \'failed\' for item in outputs)\n    return {\n        \'schema_version\': 1,\n        \'artifact_name\': source.get(\'artifact_name\') or root.name.removesuffix(\'_Output\'),\n        \'collector\': source.get(\'collector\', \'collector.py\'),\n        \'hash_algorithm\': \'SHA-256\',\n        \'verification_status\': \'failed\' if failed else \'verified\' if outputs else \'not_run\',\n        \'verification_method\': \'Two independent reads of saved output files; SHA-256 comparison and size, mtime, ctime, device and file identity stability checks. Not acquisition-time hashing.\',\n        \'collection_status\': \'partial\' if failed and source.get(\'collection_exit_code\') == 0 else source.get(\'collection_status\'),\n        \'collection_exit_code\': 1 if failed and source.get(\'collection_exit_code\') == 0 else source.get(\'collection_exit_code\'),\n        \'output_directory\': str(root),\n        \'outputs\': sorted(outputs, key=lambda item: item[\'path\'].casefold()),        \'error\': source.get(\'error\'),\n        \'errors\': source.get(\'errors\', []),\n        \'generated_at_utc\': _now(),\n    }\n', _inline_namespace)
    report.setdefault('artifact_name', _inline_namespace['Path'](__file__).resolve().parent.name.split(' - ', 1)[1])
    canonical = _inline_namespace['canonical_report'](report)
    return canonical


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    """Calculate SHA-256 of a file."""
    h = hashlib.sha256()

    with _report_open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)

    return h.hexdigest()


def discover_firewall_logs() -> list[dict[str, Any]]:
    """
    Enable firewall logging and get each profile's configured log file.

    Uses PowerShell to enable allowed and blocked traffic logging and
    inspect profiles. The actual evidence acquisition is performed by Python.
    """

    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "Set-NetFirewallProfile -Profile Domain,Private,Public "
            "-LogAllowed True -LogBlocked True -ErrorAction Stop; "
            "Get-NetFirewallProfile | "
            "Select-Object Name, Enabled, LogAllowed, LogBlocked, LogFileName | "
            "ConvertTo-Json -Compress"
        ),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except Exception as e:
        raise RuntimeError(f"Unable to execute firewall discovery: {e}") from e

    if result.returncode != 0:
        raise RuntimeError(
            "Unable to enable firewall logging or discover profiles: "
            f"{result.stderr.strip()}"
        )

    output = result.stdout.strip()

    if not output:
        return []

    data = json.loads(output)

    # PowerShell returns an object instead of an array when there is
    # only one profile.
    if isinstance(data, dict):
        data = [data]

    return data


def normalize_windows_path(path: str) -> Path:
    """
    Convert a Windows path returned by PowerShell into a Path.
    """
    path = path.strip().strip('"')

    # Environment variables are not normally expected here, but expanding
    # them makes the collector more robust.
    path = os.path.expandvars(path)

    return Path(path)


def copy_evidence(
    source: Path,
    evidence_dir: Path,
) -> tuple[Path, str]:
    """
    Copy the original firewall log into Custos evidence storage.

    Returns:
        destination path
        SHA-256 of the acquired copy
    """

    evidence_dir.mkdir(parents=True, exist_ok=True)

    destination = evidence_dir / source.name

    # Copy the file as bytes.
    if destination.exists():
        raise FileExistsError(f"Output collision: {destination}")
    with source.open("rb") as source_stream, destination.open("xb") as target_stream:
        shutil.copyfileobj(source_stream, target_stream)
    shutil.copystat(source, destination)

    # Hash the acquired evidence copy.
    digest = sha256_file(destination)

    return destination, digest


def read_firewall_log(path: Path) -> tuple[list[str], list[list[str]]]:
    """
    Parse a Windows Firewall text log.

    Windows Firewall logs are ASCII-compatible text files, but the
    live log can contain NUL-byte padding between the header and
    active log records.

    We remove NUL characters before parsing while leaving the
    original evidence file completely untouched.
    """

    # Read the acquired evidence as raw bytes.
    raw = path.read_bytes()

    # Decode as ASCII-compatible text.
    #
    # errors="replace" ensures that unexpected bytes do not cause
    # acquisition/parsing to crash.
    text = raw.decode(
        "ascii",
        errors="replace",
    )

    # Windows Firewall log can contain NUL-byte padding.
    # Remove NUL characters from the PARSING representation only.
    #
    # IMPORTANT:
    # The original evidence file is NOT modified.
    text = text.replace("\x00", "")

    fields: list[str] = []
    rows: list[list[str]] = []

    for raw_line in text.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        # --------------------------------------------------------
        # #Fields header
        # --------------------------------------------------------

        if line.startswith("#Fields:"):
            field_string = line[len("#Fields:"):].strip()
            fields = field_string.split()
            continue

        # --------------------------------------------------------
        # Other Windows Firewall comments
        # --------------------------------------------------------

        if line.startswith("#"):
            continue

        # --------------------------------------------------------
        # Do not parse data before discovering fields
        # --------------------------------------------------------

        if not fields:
            continue

        values = line.split()

        rows.append(values)

    return fields, rows


def normalize_rows(
    fields: list[str],
    rows: list[list[str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Convert firewall log rows into dictionaries.

    Malformed rows are preserved in a separate list rather than silently
    discarded.
    """

    records: list[dict[str, Any]] = []
    malformed: list[dict[str, Any]] = []

    for line_number, values in enumerate(rows, start=1):

        if len(values) != len(fields):
            malformed.append(
                {
                    "line_number": line_number,
                    "field_count": len(values),
                    "expected_field_count": len(fields),
                    "raw_values": values,
                    "reason": "field_count_mismatch",
                }
            )
            continue

        record = {}

        for field, value in zip(fields, values):
            # Windows Firewall logs commonly use "-" for unavailable data.
            record[field] = None if value == "-" else value

        records.append(record)

    return records, malformed


def collect_a21(output_root: str | Path) -> dict[str, Any]:
    """
    Main A21 Firewall Logs collector.

    Example:
        collect_a21(r"C:\\Custos\\Firewall Logs_Output")
    """

    acquisition_start = utc_now()

    case_root = Path(output_root).expanduser().resolve()

    evidence_dir = case_root / "Firewall Logs_Files"
    derived_dir = case_root

    evidence_dir.mkdir(parents=True, exist_ok=True)
    derived_dir.mkdir(parents=True, exist_ok=True)
    collisions = [
        path for path in (evidence_dir / "Firewall Logs_hash.json", derived_dir / "Firewall Logs.json")
        if path.exists()
    ]
    if collisions:
        raise FileExistsError(
            "Output collision; no files were overwritten: "
            + ", ".join(str(path) for path in collisions)
        )

    result: dict[str, Any] = {
        "artifact_id": ARTIFACT_ID,
        "artifact_name": ARTIFACT_NAME,
        "collector": "Custos-A21-Python",
        "acquisition_started": acquisition_start,
        "status": None,
        "source": {},
        "profiles": [],
        "evidence": {},
        "derived": {},
        "errors": [],
    }

    # ------------------------------------------------------------
    # 1. Discover configured firewall logging
    # ------------------------------------------------------------

    try:
        profiles = discover_firewall_logs()
        result["profiles"] = profiles

    except Exception as e:
        result["status"] = "ACCESS_DENIED_OR_DISCOVERY_FAILED"
        result["errors"].append(str(e))
        result["acquisition_completed"] = utc_now()

        return result

    # ------------------------------------------------------------
    # 2. Determine configured log paths
    # ------------------------------------------------------------

    discovered_paths: list[Path] = []

    for profile in profiles:

        log_path_string = profile.get("LogFileName")

        if not log_path_string:
            continue

        try:
            log_path = normalize_windows_path(log_path_string)

            if log_path not in discovered_paths:
                discovered_paths.append(log_path)

        except Exception as e:
            result["errors"].append(
                f"Invalid LogFileName: {log_path_string}: {e}"
            )

    if not discovered_paths:
        result["status"] = "SOURCE_NOT_CONFIGURED"
        result["acquisition_completed"] = utc_now()

        return result

    # ------------------------------------------------------------
    # 3. Collect each configured log
    # ------------------------------------------------------------

    collected_files = []

    for source in discovered_paths:

        source_info = {
            "path": str(source),
            "exists": source.exists(),
        }

        # Check whether the source actually exists.
        if not source.exists():
            source_info["status"] = "SOURCE_MISSING"
            result["source"] = source_info
            continue

        if not source.is_file():
            source_info["status"] = "SOURCE_NOT_A_FILE"
            result["source"] = source_info
            continue

        try:
            stat = _report_stat(source)

            source_info["size"] = stat.st_size
            source_info["modified_time"] = datetime.fromtimestamp(
                stat.st_mtime,
                timezone.utc,
            ).isoformat()

        except OSError as e:
            source_info["status"] = "STAT_FAILED"
            source_info["error"] = str(e)
            result["source"] = source_info
            continue

        # --------------------------------------------------------
        # 4. Preserve original evidence
        # --------------------------------------------------------

        try:
            destination, digest = copy_evidence(
                source,
                evidence_dir,
            )

        except PermissionError as e:
            source_info["status"] = "ACCESS_DENIED"
            source_info["error"] = str(e)
            result["source"] = source_info
            continue

        except Exception as e:
            source_info["status"] = "COLLECTION_FAILED"
            source_info["error"] = str(e)
            if isinstance(e, FileExistsError):
                result["errors"].append(str(e))
            result["source"] = source_info
            continue

        source_info["status"] = "COLLECTED"

        result["source"] = source_info

        collected_files.append(
            {
                "source_path": str(source),
                "evidence_path": str(destination),
                "sha256": digest,
                "size": _report_stat(destination).st_size,
            }
        )

    # ------------------------------------------------------------
    # 5. No evidence successfully acquired
    # ------------------------------------------------------------

    if not collected_files:

        result["status"] = "SOURCE_UNAVAILABLE"
        result["acquisition_completed"] = utc_now()

        return result

    # ------------------------------------------------------------
    # 6. Parse the acquired evidence
    # ------------------------------------------------------------

    all_records = []
    all_malformed = []
    parsed_files = []

    for evidence in collected_files:

        evidence_path = Path(evidence["evidence_path"])

        try:
            fields, rows = read_firewall_log(evidence_path)

            if not fields:
                result["errors"].append(
                    f"No #Fields header found in {evidence_path}"
                )

                parsed_files.append(
                    {
                        "path": str(evidence_path),
                        "status": "NO_FIELDS_HEADER",
                    }
                )

                continue

            records, malformed = normalize_rows(
                fields,
                rows,
            )

            for record in records:
                record["_source_file"] = str(evidence_path)

            all_records.extend(records)

            for item in malformed:
                item["_source_file"] = str(evidence_path)

            all_malformed.extend(malformed)

            parsed_files.append(
                {
                    "path": str(evidence_path),
                    "status": "PARSED",
                    "fields": fields,
                    "record_count": len(records),
                    "malformed_count": len(malformed),
                }
            )

        except Exception as e:
            result["errors"].append(
                f"Parsing failed for {evidence_path}: {e}"
            )

            parsed_files.append(
                {
                    "path": str(evidence_path),
                    "status": "PARSE_FAILED",
                    "error": str(e),
                }
            )

    # ------------------------------------------------------------
    # 7. Write SHA-256 manifest
    # ------------------------------------------------------------

    hash_manifest = {
        "artifact_id": ARTIFACT_ID,
        "artifact_name": ARTIFACT_NAME,
        "generated": utc_now(),
        "files": collected_files,
    }

    hash_path = evidence_dir / "Firewall Logs_hash.json"

    with _report_open(hash_path, "x", encoding="utf-8") as f:
        json.dump(
            hash_manifest,
            f,
            indent=2,
        )

    # ------------------------------------------------------------
    # 8. Write derived JSON
    # ------------------------------------------------------------

    derived = {
        "artifact_id": ARTIFACT_ID,
        "artifact_name": ARTIFACT_NAME,
        "source_type": "Windows Firewall text log",
        "generated": utc_now(),
        "source_evidence": collected_files,
        "parsed_files": parsed_files,
        "record_count": len(all_records),
        "malformed_record_count": len(all_malformed),
        "records": all_records,
        "malformed_records": all_malformed,
    }

    derived_path = derived_dir / "Firewall Logs.json"

    with _report_open(derived_path, "x", encoding="utf-8") as f:
        json.dump(
            derived,
            f,
            indent=2,
        )

    result["evidence"] = {
        "files": collected_files,
        "hash_manifest": str(hash_path),
    }

    result["derived"] = {
        "json": str(derived_path),
        "record_count": len(all_records),
        "malformed_record_count": len(all_malformed),
    }

    # ------------------------------------------------------------
    # 9. Final status
    # ------------------------------------------------------------

    if all_records:
        result["status"] = "SUCCESS"
    elif collected_files:
        result["status"] = "COLLECTED_BUT_NOT_PARSED"
    else:
        result["status"] = "SOURCE_UNAVAILABLE"

    result["acquisition_completed"] = utc_now()

    return result


# ================================================================
# CLI
# ================================================================



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

_REPORT_PATTERNS = ('firewall logs_hash.json',)

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



def main():
    parser = argparse.ArgumentParser(description="Custos A21 Firewall Logs collector")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "Firewall Logs_Output",
        help="Destination directory for all collected and generated files.",
    )
    args = parser.parse_args()
    args.output_dir.expanduser().resolve().mkdir(parents=True, exist_ok=True)
    try:
        result = collect_a21(args.output_dir)
    except FileExistsError as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        raise SystemExit(2)

    print(json.dumps(result, indent=2))
    if any("Output collision" in error for error in result["errors"]):
        raise SystemExit(2)
    return 0

if __name__ == "__main__":
    raise SystemExit(_run_with_integrity_manifest(main))
