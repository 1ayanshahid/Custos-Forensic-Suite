
#!/usr/bin/env python3
"""
Custos Forensic Suite
Artifact: A22 - Installed Software
Version: 1.0.0

Acquisition-only collector for Windows 10/11 x64.
Requires an elevated Administrator session.
No parser is included. launch.bat delegates to the workspace helper.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import traceback
import uuid
import winreg

from datetime import datetime, timezone
from pathlib import Path


ARTIFACT = "A22"
ARTIFACT_NAME = "Installed Software"
VERSION = "1.0.0"
DEFAULT_CASE_ROOT = Path(r"C:\Custos\Case001")

UNINSTALL_PATH = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"

REGISTRY_VIEWS = [
    ("64-bit view", getattr(winreg, "KEY_WOW64_64KEY", 0x0100)),
    ("32-bit view", getattr(winreg, "KEY_WOW64_32KEY", 0x0200)),
]

SOFTWARE_FIELDS = [
    "DisplayName",
    "DisplayVersion",
    "Publisher",
    "InstallDate",
    "InstallLocation",
    "InstallSource",
    "UninstallString",
    "QuietUninstallString",
    "DisplayIcon",
    "URLInfoAbout",
    "URLUpdateInfo",
    "HelpLink",
    "Comments",
    "EstimatedSize",
    "WindowsInstaller",
    "SystemComponent",
    "ParentKeyName",
    "ParentDisplayName",
    "ReleaseType",
    "NoModify",
    "NoRepair",
    "Language",
]


def _canonical_integrity_report(report):
    # Isolated embedded implementation: collector globals cannot shadow its imports.
    _inline_namespace = {}
    exec('"""Canonical post-save integrity reports; never evidence of acquisition-time hashing."""\nimport hashlib\nfrom datetime import datetime, timezone\nfrom pathlib import Path\n\n\ndef _now():\n    return datetime.now(timezone.utc).isoformat()\n\n\ndef _metadata(info):\n    return (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_dev, info.st_ino)\n\n\ndef _read_hash(path):\n    digest = hashlib.sha256()\n    with path.open(\'rb\') as stream:\n        for chunk in iter(lambda: stream.read(1024 * 1024), b\'\'):\n            digest.update(chunk)\n    return digest.hexdigest()\n\n\ndef canonical_report(source):\n    root = Path(source[\'output_directory\']).resolve()\n    outputs = []\n    for original in source.get(\'outputs\', []):\n        entry = dict.fromkeys((\'path\', \'size_bytes\', \'sha256\', \'verification_sha256\',\n                              \'verification_status\', \'error\'))\n        entry[\'path\'] = original[\'path\']\n        entry[\'verification_status\'] = \'failed\'\n        try:\n            path = (root / original[\'path\']).resolve()\n            path.relative_to(root)\n            before = path.stat()\n            metadata = _metadata(before)\n            entry[\'size_bytes\'] = before.st_size\n            entry[\'sha256\'] = _read_hash(path)\n            if _metadata(path.stat()) != metadata:\n                raise RuntimeError(\'Saved file metadata changed during first read\')\n            entry[\'verification_sha256\'] = _read_hash(path)\n            if _metadata(path.stat()) != metadata:\n                raise RuntimeError(\'Saved file metadata changed during independent verification read\')\n            if entry[\'sha256\'] != entry[\'verification_sha256\']:\n                raise RuntimeError(\'Saved-file SHA-256 mismatch between independent reads\')\n            entry[\'verification_status\'] = \'verified\'\n        except (OSError, ValueError, RuntimeError) as exc:\n            entry[\'error\'] = str(exc)\n        outputs.append(entry)\n    failed = any(item[\'verification_status\'] == \'failed\' for item in outputs)\n    return {\n        \'schema_version\': 1,\n        \'artifact_name\': source.get(\'artifact_name\') or root.name.removesuffix(\'_Output\'),\n        \'collector\': source.get(\'collector\', \'collector.py\'),\n        \'hash_algorithm\': \'SHA-256\',\n        \'verification_status\': \'failed\' if failed else \'verified\' if outputs else \'not_run\',\n        \'verification_method\': \'Two independent reads of saved output files; SHA-256 comparison and size, mtime, ctime, device and file identity stability checks. Not acquisition-time hashing.\',\n        \'collection_status\': \'partial\' if failed and source.get(\'collection_exit_code\') == 0 else source.get(\'collection_status\'),\n        \'collection_exit_code\': 1 if failed and source.get(\'collection_exit_code\') == 0 else source.get(\'collection_exit_code\'),\n        \'output_directory\': str(root),\n        \'outputs\': sorted(outputs, key=lambda item: item[\'path\'].casefold()),        \'error\': source.get(\'error\'),\n        \'errors\': source.get(\'errors\', []),\n        \'generated_at_utc\': _now(),\n    }\n', _inline_namespace)
    report.setdefault('artifact_name', _inline_namespace['Path'](__file__).resolve().parent.name.split(' - ', 1)[1])
    canonical = _inline_namespace['canonical_report'](report)
    return canonical


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def sha256_file(path: Path):
    digest = hashlib.sha256()
    with _report_open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_safe(value):
    if isinstance(value, bytes):
        return {"type": "bytes", "hex": value.hex()}
    if isinstance(value, tuple):
        return [json_safe(item) for item in value]
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def registry_value(key, name):
    try:
        value, value_type = winreg.QueryValueEx(key, name)
        return json_safe(value), value_type, None
    except FileNotFoundError:
        return None, None, None
    except OSError as exc:
        return None, None, str(exc)


def list_subkeys(key):
    names = []
    errors = []
    index = 0

    while True:
        try:
            names.append(winreg.EnumKey(key, index))
            index += 1
        except OSError as exc:
            # ERROR_NO_MORE_ITEMS = 259
            if getattr(exc, "winerror", None) == 259:
                break
            # Some Python/Windows combinations expose the end of
            # enumeration as an OSError without a useful winerror.
            if isinstance(exc, WindowsErrorEndOfEnumeration):
                break
            errors.append(str(exc))
            break

    return names, errors


def current_user_sid():
    """Return the process token SID without inferring it from a profile path."""
    try:
        result = subprocess.run(
            ["whoami.exe", "/user", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
    except Exception:
        return None

    if result.returncode != 0:
        return None

    for row in csv.reader(result.stdout.splitlines()):
        for field in row:
            sid = field.strip().strip('"')
            if re.fullmatch(r"S-1-(?:\d+-)*\d+", sid, flags=re.IGNORECASE):
                return sid
    return None


def original_hive_probe(sid):
    try:
        with winreg.OpenKey(
            winreg.HKEY_USERS, sid, 0, winreg.KEY_READ
        ):
            return "LOADED", None
    except FileNotFoundError as exc:
        return "HIVE_NOT_LOADED", str(exc)
    except PermissionError as exc:
        return "ACCESS_DENIED", str(exc)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 5 or getattr(exc, "errno", None) == 13:
            return "ACCESS_DENIED", str(exc)
        return "HIVE_ACCESS_ERROR", str(exc)


class WindowsErrorEndOfEnumeration(Exception):
    """Compatibility placeholder; normal enumeration uses winerror 259."""


def registry_sources():
    sources = [
        {
            "label": "HKLM uninstall entries",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "hive_name": "HKEY_LOCAL_MACHINE",
            "path": UNINSTALL_PATH,
            "user_sid": None,
        },
    ]

    original_sid = os.environ.get("CUSTOS_ORIGINAL_SID", "").strip()
    token_sid = current_user_sid()
    original_is_alternate = bool(
        original_sid
        and (
            token_sid is None
            or original_sid.casefold() != token_sid.casefold()
        )
    )

    if original_is_alternate:
        if not re.fullmatch(r"S-1-(?:\d+-)*\d+", original_sid, flags=re.IGNORECASE):
            hive_status, hive_error = "INVALID_ORIGINAL_SID", "CUSTOS_ORIGINAL_SID is not a valid SID."
        else:
            hive_status, hive_error = original_hive_probe(original_sid)
        if hive_status == "LOADED":
            sources.append({
                "label": f"Original user hive {original_sid}",
                "hive": winreg.HKEY_USERS,
                "hive_name": "HKEY_USERS",
                "path": original_sid + "\\" + UNINSTALL_PATH,
                "user_sid": original_sid,
            })
        else:
            sources.append({
                "label": f"Original user hive {original_sid}",
                "hive": winreg.HKEY_USERS,
                "hive_name": "HKEY_USERS",
                "path": original_sid + "\\" + UNINSTALL_PATH,
                "user_sid": original_sid,
                "status_override": hive_status,
                "status_error": hive_error,
            })
    else:
        sources.append({
            "label": "HKCU uninstall entries (current token)",
            "hive": winreg.HKEY_CURRENT_USER,
            "hive_name": "HKEY_CURRENT_USER",
            "path": UNINSTALL_PATH,
            "user_sid": token_sid,
        })

    # Other currently loaded user hives. Hives are not loaded from disk:
    # this avoids changing system registry state during collection.
    try:
        with winreg.OpenKey(winreg.HKEY_USERS, "") as users_key:
            sids, _ = list_subkeys(users_key)

        for sid in sids:
            if sid.endswith("_Classes") or sid in (".DEFAULT",):
                continue
            if not sid.startswith("S-1-5-"):
                continue
            if original_is_alternate and sid.casefold() == original_sid.casefold():
                continue

            sources.append({
                "label": f"Loaded user hive {sid}",
                "hive": winreg.HKEY_USERS,
                "hive_name": "HKEY_USERS",
                "path": sid + "\\" + UNINSTALL_PATH,
                "user_sid": sid,
            })
    except OSError:
        # The HKU discovery failure is recorded during collection
        # through the source-discovery note in the manifest.
        pass

    return sources


def collect_registry_source(source, view_name, view_flag, entries, errors):
    source_record = {
        "source": source["label"],
        "registry_path": source["hive_name"] + "\\" + source["path"],
        "registry_view": view_name,
        "user_sid": source.get("user_sid"),
        "status": None,
        "subkeys_seen": 0,
        "entries_recorded": 0,
        "errors": [],
    }

    if source.get("status_override"):
        source_record["status"] = source["status_override"]
        if source.get("status_error"):
            source_record["errors"].append(source["status_error"])
        if source["status_override"] in {
            "HIVE_NOT_LOADED", "ACCESS_DENIED", "HIVE_ACCESS_ERROR",
            "INVALID_ORIGINAL_SID",
        }:
            errors.append({
                "stage": "open_original_user_hive",
                "source": source_record["registry_path"],
                "view": view_name,
                "error": source.get("status_error") or source["status_override"],
                "status": source["status_override"],
            })
        return source_record

    access = winreg.KEY_READ | view_flag

    try:
        root_key = winreg.OpenKey(
            source["hive"], source["path"], 0, access
        )
    except FileNotFoundError:
        source_record["status"] = "KEY_NOT_FOUND"
        return source_record
    except PermissionError as exc:
        source_record["status"] = "ACCESS_DENIED"
        source_record["errors"].append(str(exc))
        errors.append({
            "stage": "open_registry_key",
            "source": source_record["registry_path"],
            "view": view_name,
            "error": str(exc),
        })
        return source_record
    except OSError as exc:
        denied = (
            getattr(exc, "winerror", None) == 5
            or getattr(exc, "errno", None) == 13
        )
        source_record["status"] = (
            "ACCESS_DENIED" if denied else "ACCESS_OR_OPEN_ERROR"
        )
        source_record["errors"].append(str(exc))
        errors.append({
            "stage": "open_registry_key",
            "source": source_record["registry_path"],
            "view": view_name,
            "error": str(exc),
        })
        return source_record

    with root_key:
        subkeys, enum_errors = list_subkeys(root_key)
        source_record["subkeys_seen"] = len(subkeys)

        for error in enum_errors:
            source_record["errors"].append(error)

        for subkey_name in subkeys:
            full_key_path = source_record["registry_path"] + "\\" + subkey_name

            try:
                with winreg.OpenKey(root_key, subkey_name, 0, access) as app_key:
                    values = {}
                    value_errors = []

                    for field in SOFTWARE_FIELDS:
                        value, value_type, error = registry_value(app_key, field)
                        if value is not None:
                            values[field] = value
                            values[field + "_RegistryType"] = value_type
                        if error:
                            value_errors.append({
                                "field": field,
                                "error": error,
                            })

                    # Preserve all additional values as well, not just
                    # the common display and uninstall fields.
                    extra_values = {}
                    value_index = 0
                    while True:
                        try:
                            value_name, value_data, value_type = (
                                winreg.EnumValue(app_key, value_index)
                            )
                            extra_values[value_name] = {
                                "value": json_safe(value_data),
                                "registry_type": value_type,
                            }
                            value_index += 1
                        except OSError as exc:
                            if getattr(exc, "winerror", None) == 259:
                                break
                            value_errors.append({
                                "stage": "enumerate_values",
                                "error": str(exc),
                            })
                            break

                    record = {
                        "source_hive": source["hive_name"],
                        "source_registry_path": full_key_path,
                        "registry_view": view_name,
                        "user_sid": source.get("user_sid"),
                        "subkey_name": subkey_name,
                        "display_name": values.get("DisplayName"),
                        "display_version": values.get("DisplayVersion"),
                        "publisher": values.get("Publisher"),
                        "install_date": values.get("InstallDate"),
                        "install_location": values.get("InstallLocation"),
                        "uninstall_string": values.get("UninstallString"),
                        "selected_values": values,
                        "all_registry_values": extra_values,
                        "value_read_errors": value_errors,
                        "collected_utc": utc_now(),
                    }

                    entries.append(record)
                    source_record["entries_recorded"] += 1

                    for value_error in value_errors:
                        errors.append({
                            "stage": "read_registry_values",
                            "source": full_key_path,
                            "view": view_name,
                            **value_error,
                        })

            except FileNotFoundError:
                errors.append({
                    "stage": "open_subkey",
                    "source": full_key_path,
                    "view": view_name,
                    "error": "Subkey disappeared during collection.",
                })
            except OSError as exc:
                errors.append({
                    "stage": "open_subkey",
                    "source": full_key_path,
                    "view": view_name,
                    "error": str(exc),
                })

    source_record["status"] = (
        "COLLECTED_WITH_ERRORS"
        if source_record["errors"]
        else "COLLECTED"
    )
    return source_record


def write_json(path, data):
    with _report_open(path, "x", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def main():
    parser = argparse.ArgumentParser(
        description="Custos A22 installed-software acquisition collector"
    )
    parser.add_argument(
        "--case-root",
        default=str(DEFAULT_CASE_ROOT),
        help=r"Case root (default: C:\Custos\Case001)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "Installed Software_Output",
        help="Destination directory for all collected and generated files.",
    )
    args = parser.parse_args()

    if platform.system() != "Windows":
        print("ERROR: A22 must run on Windows.", file=sys.stderr)
        return 2

    if not is_admin():
        print(
            "ERROR: Administrator privileges are required. "
            "Re-run from an elevated terminal.",
            file=sys.stderr,
        )
        return 3

    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "_"
        + uuid.uuid4().hex[:8]
    )

    case_root = Path(args.case_root)
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    planned_outputs = [
        output_dir / "Installed Software_Inventory.json",
    ]
    collisions = [path for path in planned_outputs if path.exists()]
    if collisions:
        print(
            "ERROR: Output collision; no files were overwritten: "
            + ", ".join(str(path) for path in collisions),
            file=sys.stderr,
        )
        return 4

    started = utc_now()
    entries = []
    errors = []
    source_results = []

    # Discovery notes are explicit so an empty inventory is not
    # mistaken for proof that no software is installed.
    try:
        sources = registry_sources()
    except Exception as exc:
        sources = []
        errors.append({
            "stage": "discover_registry_sources",
            "error": str(exc),
            "traceback": traceback.format_exc(),
        })

    for source in sources:
        for view_name, view_flag in REGISTRY_VIEWS:
            result = collect_registry_source(
                source, view_name, view_flag, entries, errors
            )
            source_results.append(result)

    finished = utc_now()
    status = "COMPLETED_WITH_ERRORS" if errors else (
        "EMPTY_SOURCE" if not entries else "COMPLETED"
    )

    inventory_path = output_dir / "Installed Software_Inventory.json"
    write_json(inventory_path, {
        "artifact": ARTIFACT,
        "artifact_name": ARTIFACT_NAME,
        "collector_version": VERSION,
        "run_id": run_id,
        "started_utc": started,
        "completed_utc": finished,
        "collected_utc": utc_now(),
        "host_name": os.environ.get("COMPUTERNAME"),
        "operating_system": platform.platform(),
        "collection_status": status,
        "registry_source_count": len(source_results),
        "record_count": len(entries),
        "records": entries,
        "errors": errors,
        "limitations": [
            "This is a logical registry inventory, not a complete list of all software present or ever executed.",
            "Only currently accessible registry hives are examined; unloaded user hives are not mounted.",
            "When CUSTOS_ORIGINAL_SID differs from the process SID, HKCU is not substituted for the original hive; the original SID is queried under HKEY_USERS only if already loaded.",
            "Registry entries can be stale, incomplete, or intentionally absent.",
            "The 32-bit and 64-bit registry views may contain overlapping entries; records are preserved with their source view.",
            "Uninstall command strings are recorded as evidence and are never executed.",
            "The generated JSON is a derived inventory, not a raw registry hive acquisition.",
        ],
        "registry_sources": source_results,
    })

    print(f"Artifact: {ARTIFACT} - {ARTIFACT_NAME}")
    print(f"Case root: {case_root}")
    print(f"Output: {output_dir}")
    print(f"Registry source/view checks: {len(source_results)}")
    print(f"Software records collected: {len(entries)}")
    print(f"Errors recorded: {len(errors)}")
    print(f"Result: {status}")
    print(f"Inventory: {inventory_path}")

    return 0 if not errors else 1




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
    sys.exit(_run_with_integrity_manifest(main))
