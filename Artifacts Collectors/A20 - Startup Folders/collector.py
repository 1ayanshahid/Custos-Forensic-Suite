
#!/usr/bin/env python3
"""
Custos Forensic Suite
Artifact A20 - Windows Startup Folders
Version: 1.0.0

Acquires files from:
  1. All-users Startup folder
  2. Startup folders under Windows user profiles discovered from
     the Windows ProfileList registry key

Default case root:
  C:\\Custos\\Case001

Output:
  Directly in the selected --output-dir; copied files retain their original
  source-relative names under CommonStartup/User_<SID> source directories.

Requires Windows 10/11 and administrator privileges.
No parser is included. launch.bat delegates to the workspace helper.

Scope note:
This collects Startup-folder contents only. It does not enumerate every
Windows persistence mechanism, scheduled task, service, Run key, or policy.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import shutil
import sys
import uuid
import winreg

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ARTIFACT_ID = "A20"
VERSION = "1.0.0"

DEFAULT_CASE_ROOT = Path(r"C:\Custos\Case001")
COMMON_STARTUP = Path(
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

STARTUP_RELATIVE = Path(
    "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
)


def _canonical_integrity_report(report):
    # Isolated embedded implementation: collector globals cannot shadow its imports.
    _inline_namespace = {}
    exec('"""Canonical post-save integrity reports; never evidence of acquisition-time hashing."""\nimport hashlib\nfrom datetime import datetime, timezone\nfrom pathlib import Path\n\n\ndef _now():\n    return datetime.now(timezone.utc).isoformat()\n\n\ndef _metadata(info):\n    return (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_dev, info.st_ino)\n\n\ndef _read_hash(path):\n    digest = hashlib.sha256()\n    with path.open(\'rb\') as stream:\n        for chunk in iter(lambda: stream.read(1024 * 1024), b\'\'):\n            digest.update(chunk)\n    return digest.hexdigest()\n\n\ndef canonical_report(source):\n    root = Path(source[\'output_directory\']).resolve()\n    outputs = []\n    for original in source.get(\'outputs\', []):\n        entry = dict.fromkeys((\'path\', \'size_bytes\', \'sha256\', \'verification_sha256\',\n                              \'verification_status\', \'error\'))\n        entry[\'path\'] = original[\'path\']\n        entry[\'verification_status\'] = \'failed\'\n        try:\n            path = (root / original[\'path\']).resolve()\n            path.relative_to(root)\n            before = path.stat()\n            metadata = _metadata(before)\n            entry[\'size_bytes\'] = before.st_size\n            entry[\'sha256\'] = _read_hash(path)\n            if _metadata(path.stat()) != metadata:\n                raise RuntimeError(\'Saved file metadata changed during first read\')\n            entry[\'verification_sha256\'] = _read_hash(path)\n            if _metadata(path.stat()) != metadata:\n                raise RuntimeError(\'Saved file metadata changed during independent verification read\')\n            if entry[\'sha256\'] != entry[\'verification_sha256\']:\n                raise RuntimeError(\'Saved-file SHA-256 mismatch between independent reads\')\n            entry[\'verification_status\'] = \'verified\'\n        except (OSError, ValueError, RuntimeError) as exc:\n            entry[\'error\'] = str(exc)\n        outputs.append(entry)\n    failed = any(item[\'verification_status\'] == \'failed\' for item in outputs)\n    return {\n        \'schema_version\': 1,\n        \'artifact_name\': source.get(\'artifact_name\') or root.name.removesuffix(\'_Output\'),\n        \'collector\': source.get(\'collector\', \'collector.py\'),\n        \'hash_algorithm\': \'SHA-256\',\n        \'verification_status\': \'failed\' if failed else \'verified\' if outputs else \'not_run\',\n        \'verification_method\': \'Two independent reads of saved output files; SHA-256 comparison and size, mtime, ctime, device and file identity stability checks. Not acquisition-time hashing.\',\n        \'collection_status\': \'partial\' if failed and source.get(\'collection_exit_code\') == 0 else source.get(\'collection_status\'),\n        \'collection_exit_code\': 1 if failed and source.get(\'collection_exit_code\') == 0 else source.get(\'collection_exit_code\'),\n        \'output_directory\': str(root),\n        \'outputs\': sorted(outputs, key=lambda item: item[\'path\'].casefold()),        \'error\': source.get(\'error\'),\n        \'errors\': source.get(\'errors\', []),\n        \'generated_at_utc\': _now(),\n    }\n', _inline_namespace)
    report.setdefault('artifact_name', _inline_namespace['Path'](__file__).resolve().parent.name.split(' - ', 1)[1])
    canonical = _inline_namespace['canonical_report'](report)
    return canonical


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_administrator() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with _report_open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def walk_exclusions() -> set[str]:
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


def file_metadata(path: Path) -> dict[str, Any]:
    info = _report_stat(path)
    return {
        "size_bytes": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
        "atime_ns": info.st_atime_ns,
        "mtime_utc": datetime.fromtimestamp(
            info.st_mtime, timezone.utc
        ).isoformat(),
        "ctime_utc": datetime.fromtimestamp(
            info.st_ctime, timezone.utc
        ).isoformat(),
        "atime_utc": datetime.fromtimestamp(
            info.st_atime, timezone.utc
        ).isoformat(),
    }


def add_error(
    manifest: dict[str, Any],
    stage: str,
    path: str,
    exc: BaseException,
) -> None:
    manifest["errors"].append({
        "timestamp_utc": utc_now(),
        "stage": stage,
        "path": path,
        "error_type": type(exc).__name__,
        "error": str(exc),
    })


def discover_user_profiles(manifest: dict[str, Any]) -> list[dict[str, str]]:
    """Read local Windows profile paths from the ProfileList registry key."""
    profiles: list[dict[str, str]] = []
    key_path = (
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    )

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            key_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as root_key:
            count = winreg.QueryInfoKey(root_key)[0]

            for index in range(count):
                try:
                    sid = winreg.EnumKey(root_key, index)

                    with winreg.OpenKey(
                        root_key, sid, 0, winreg.KEY_READ
                    ) as profile_key:
                        value, _ = winreg.QueryValueEx(
                            profile_key, "ProfileImagePath"
                        )

                    expanded = os.path.expandvars(value)
                    profile_path = Path(expanded)

                    profiles.append({
                        "sid": sid,
                        "profile_path": str(profile_path),
                    })

                except OSError as exc:
                    add_error(
                        manifest,
                        "profile_registry_entry",
                        f"{key_path}\\{index}",
                        exc,
                    )

    except OSError as exc:
        add_error(manifest, "profile_registry", key_path, exc)

    # Avoid duplicate paths while preserving registry discovery order.
    unique: list[dict[str, str]] = []
    seen: set[str] = set()

    for profile in profiles:
        normalized = os.path.normcase(
            os.path.abspath(profile["profile_path"])
        )
        if normalized not in seen:
            seen.add(normalized)
            unique.append(profile)

    return unique


def build_source_list(
    manifest: dict[str, Any],
) -> list[dict[str, str]]:
    """Build the list of Startup folders to examine."""
    sources = [{
        "source_id": "CommonStartup",
        "scope": "all_users",
        "source_path": str(COMMON_STARTUP),
    }]

    for profile in discover_user_profiles(manifest):
        profile_path = Path(profile["profile_path"])
        startup_path = profile_path / STARTUP_RELATIVE

        sources.append({
            "source_id": "User_" + profile["sid"],
            "scope": "user",
            "sid": profile["sid"],
            "profile_path": str(profile_path),
            "source_path": str(startup_path),
        })

    return sources


def enumerate_source(
    source: dict[str, str],
    manifest: dict[str, Any],
    excluded_paths: set[str],
) -> list[Path]:
    """Enumerate files in one Startup folder without following symlinks."""
    root = Path(source["source_path"])
    source["exists"] = root.is_dir()
    source["enumeration_status"] = "NOT_STARTED"
    source["files_discovered"] = 0

    if not root.exists():
        source["enumeration_status"] = "SOURCE_MISSING"
        return []

    if not root.is_dir():
        source["enumeration_status"] = "NOT_A_DIRECTORY"
        return []

    if os.path.normcase(os.path.abspath(str(root))) in excluded_paths:
        source["enumeration_status"] = "OUTPUT_OR_TOOL_PATH_EXCLUDED"
        return []

    discovered: list[Path] = []
    enumeration_errors = 0

    def on_walk_error(exc: OSError) -> None:
        nonlocal enumeration_errors
        enumeration_errors += 1
        add_error(
            manifest,
            "directory_enumeration",
            str(getattr(exc, "filename", None) or root),
            exc,
        )

    for current, directories, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=on_walk_error,
    ):
        current_path = Path(current)
        safe_directories = []

        for dirname in directories:
            child = current_path / dirname
            try:
                if child.is_symlink():
                    manifest["skipped_paths"].append({
                        "path": str(child),
                        "reason": "Symbolic-link directory not followed",
                        "source_id": source["source_id"],
                    })
                elif os.path.normcase(
                    os.path.abspath(str(child))
                ) not in excluded_paths:
                    safe_directories.append(dirname)
            except OSError as exc:
                add_error(
                    manifest, "directory_check", str(child), exc
                )

        directories[:] = safe_directories

        for filename in filenames:
            candidate = current_path / filename

            try:
                if os.path.normcase(
                    os.path.abspath(str(candidate))
                ) in excluded_paths:
                    continue
                if candidate.is_symlink():
                    manifest["skipped_paths"].append({
                        "path": str(candidate),
                        "reason": "Symbolic-link file not acquired",
                        "source_id": source["source_id"],
                    })
                    continue

                if candidate.is_file():
                    discovered.append(candidate)

            except OSError as exc:
                add_error(
                    manifest, "file_check", str(candidate), exc
                )

    source["files_discovered"] = len(discovered)
    source["enumeration_status"] = (
        "ENUMERATED_WITH_ERRORS"
        if enumeration_errors
        else "ENUMERATED"
    )
    return discovered


def acquire_file(
    source_file: Path,
    source_root: Path,
    destination_root: Path,
    source_id: str,
    manifest: dict[str, Any],
) -> None:
    """Copy one file, calculate hashes, and record observed changes."""
    relative = source_file.relative_to(source_root)
    destination = destination_root / source_id / relative

    record: dict[str, Any] = {
        "source_id": source_id,
        "source_path": str(source_file),
        "relative_path": relative.as_posix(),
        "destination_path": str(destination),
        "status": "STARTED",
        "sha256_before": None,
        "sha256_copy": None,
        "sha256_after": None,
        "hash_verified": False,
        "source_changed_or_unstable": False,
        "errors": [],
    }
    manifest["files"].append(record)

    try:
        if source_file.is_symlink():
            raise OSError("Symbolic-link source skipped.")

        before_metadata = file_metadata(source_file)
        before_hash = sha256_file(source_file)

        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise FileExistsError(
                f"Output collision; existing file was not overwritten: {destination}"
            )
        with source_file.open("rb") as source_stream, destination.open("xb") as target_stream:
            shutil.copyfileobj(source_stream, target_stream)
        shutil.copystat(source_file, destination)

        copy_hash = sha256_file(destination)

        record["source_metadata_before"] = before_metadata
        record["sha256_before"] = before_hash
        record["sha256_copy"] = copy_hash
        record["copy_metadata"] = file_metadata(destination)
        record["hash_verified"] = before_hash == copy_hash

        try:
            after_metadata = file_metadata(source_file)
            after_hash = sha256_file(source_file)

            record["source_metadata_after"] = after_metadata
            record["sha256_after"] = after_hash

            record["source_changed_or_unstable"] = (
                before_hash != after_hash
                or before_metadata["size_bytes"]
                != after_metadata["size_bytes"]
                or before_metadata["mtime_ns"]
                != after_metadata["mtime_ns"]
            )

        except Exception as exc:
            record["source_changed_or_unstable"] = True
            record["errors"].append(
                "Source recheck failed: "
                f"{type(exc).__name__}: {exc}"
            )

        if not record["hash_verified"]:
            record["status"] = "HASH_MISMATCH"
        elif record["source_changed_or_unstable"]:
            record["status"] = "COPIED_SOURCE_UNSTABLE"
        else:
            record["status"] = "COPIED_VERIFIED"

    except Exception as exc:
        record["status"] = "FAILED"
        record["errors"].append(f"{type(exc).__name__}: {exc}")
        add_error(manifest, "file_acquisition", str(source_file), exc)

    record["finished_utc"] = utc_now()


def write_outputs(
    run_root: Path,
    manifest: dict[str, Any],
    inventory_path: Path,
) -> None:
    summary = {
        "source_folders_examined": len(manifest["sources"]),
        "source_folders_found": sum(
            source.get("exists", False) for source in manifest["sources"]
        ),
        "files_discovered": len(manifest["files"]),
        "files_copied": sum(
            item.get("copy_metadata") is not None
            for item in manifest["files"]
        ),
        "hash_verified": sum(
            item["hash_verified"] for item in manifest["files"]
        ),
        "failed_files": sum(
            item["status"] == "FAILED" for item in manifest["files"]
        ),
        "source_changed_or_unstable": sum(
            item["source_changed_or_unstable"]
            for item in manifest["files"]
        ),
        "bytes_copied": sum(
            item.get("copy_metadata", {}).get("size_bytes", 0)
            for item in manifest["files"]
        ),
        "errors_recorded": len(manifest["errors"]),
        "skipped_paths": len(manifest["skipped_paths"]),
    }
    manifest["summary"] = summary
    manifest["finished_utc"] = utc_now()

    if manifest["errors"] or summary["failed_files"]:
        manifest["result"] = "COMPLETED_WITH_ERRORS"
    elif summary["files_discovered"] == 0:
        manifest["result"] = "NO_FILES_DISCOVERED"
    elif summary["hash_verified"] != summary["files_copied"]:
        manifest["result"] = "COMPLETED_WITH_VERIFICATION_ISSUES"
    else:
        manifest["result"] = "COMPLETED"

    temporary = inventory_path.with_suffix(".json.tmp")
    with _report_open(temporary, "x", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
        stream.flush()
        None if getattr(stream, "_in_memory_report", False) else os.fsync(stream.fileno())
    _report_replace(temporary, inventory_path)

    print("\nAcquisition finished.")
    print("Result:", manifest["result"])
    print("Source folders examined:", summary["source_folders_examined"])
    print("Files discovered:", summary["files_discovered"])
    print("Files copied:", summary["files_copied"])
    print("SHA-256 verified:", summary["hash_verified"])
    print("Errors recorded:", summary["errors_recorded"])
    print("Artifact results:", inventory_path)


def main() -> int:
    if os.name != "nt":
        print("ERROR: This collector requires Windows.", file=sys.stderr)
        return 2

    if not is_administrator():
        print(
            "ERROR: Administrator privileges are required. "
            "Open an elevated PowerShell terminal.",
            file=sys.stderr,
        )
        return 3

    parser = argparse.ArgumentParser(
        description="Custos A20 Windows Startup Folders acquisition"
    )
    parser.add_argument(
        "--case-root",
        type=Path,
        default=DEFAULT_CASE_ROOT,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "Startup Folders_Output",
        help="Destination directory for all collected and generated files.",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Optional run identifier; generated if omitted.",
    )
    args = parser.parse_args()

    case_root = args.case_root.expanduser().resolve()
    run_id = args.run_id or (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "_" + uuid.uuid4().hex[:8]
    )

    run_root = args.output_dir.expanduser().resolve()
    files_root = run_root / "Startup Folders_Files"
    acquired_root = files_root

    try:
        run_root.mkdir(parents=True, exist_ok=True)
        files_root.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        print(f"ERROR: Cannot create output directory: {exc}", file=sys.stderr)
        return 4
    inventory_path = run_root / "Startup Folders_Inventory.json"
    temporary_path = inventory_path.with_suffix(".json.tmp")
    collisions = [
        path
        for path in (inventory_path, temporary_path)
        if path.exists()
    ]
    if collisions:
        print(
            "ERROR: Output collision; no files were overwritten: "
            + ", ".join(str(path) for path in collisions),
            file=sys.stderr,
        )
        return 4
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "artifact_id": ARTIFACT_ID,
        "artifact_name": "Windows Startup Folders",
        "collector_version": VERSION,
        "run_id": run_id,
        "started_utc": utc_now(),
        "finished_utc": None,
        "case_root": str(case_root),
        "run_directory": str(run_root),
        "acquired_files_directory": str(acquired_root),
        "system": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "windows_version": platform.version(),
            "python_version": sys.version,
            "administrator": True,
        },
        "timestamp_field_meanings": {
            "mtime_utc": "Filesystem-reported last content modification time.",
            "ctime_utc": (
                "On Windows with Python 3.12, file creation time, not Unix "
                "metadata-change time. For a copied file, this is typically "
                "when the copy was created."
            ),
            "atime_utc": (
                "Filesystem-reported last access time; reading a file during "
                "collection may update it."
            ),
            "utc": "The _utc values are ISO-8601 timestamps in UTC.",
            "nanosecond_fields": (
                "mtime_ns, ctime_ns, and atime_ns are integer filesystem "
                "timestamp values in nanoseconds, not UTC timestamps."
            ),
        },
        "sources": [],
        "files": [],
        "errors": [],
        "skipped_paths": [],
        "summary": {},
        "limitations": [
            "Startup folders are only one Windows persistence location.",
            "Profile discovery relies on the ProfileList registry key.",
            "Live acquisition is not an application-consistent snapshot.",
        ],
    }

    sources = build_source_list(manifest)
    manifest["sources"] = sources
    overlapping_sources = [
        source["source_path"]
        for source in sources
        if Path(source["source_path"]).is_dir()
        and output_overlaps_source(
            run_root, Path(source["source_path"])
        )
    ]
    if overlapping_sources:
        print(
            "ERROR: --output-dir is inside a recursively scanned Startup "
            "source. Select another destination; collection scope will not "
            "be narrowed. Overlapping source(s): "
            + ", ".join(overlapping_sources),
            file=sys.stderr,
        )
        return 4
    excluded_paths = walk_exclusions()

    print("Artifact: A20 - Windows Startup Folders")
    print("Case root:", case_root)
    print("Output:", run_root)
    print("Source folders to examine:", len(sources))

    for source in sources:
        root = Path(source["source_path"])
        print(f"\nExamining: {root}")

        if not root.is_dir():
            source["exists"] = False
            source["enumeration_status"] = "SOURCE_MISSING"
            print("  Source folder missing; recorded in inventory.")
            continue

        try:
            source_files = enumerate_source(source, manifest, excluded_paths)
        except Exception as exc:
            source["enumeration_status"] = "ENUMERATION_FAILED"
            add_error(
                manifest, "source_enumeration", source["source_path"], exc
            )
            continue

        for source_file in source_files:
            acquire_file(
                source_file=source_file,
                source_root=root,
                destination_root=acquired_root,
                source_id=source["source_id"],
                manifest=manifest,
            )

    write_outputs(run_root, manifest, inventory_path)

    if manifest["errors"]:
        return 10
    if not manifest["files"]:
        return 20
    return 0




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

_REPORT_PATTERNS = ()

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
