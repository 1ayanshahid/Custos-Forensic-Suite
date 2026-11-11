import os, subprocess, json, hashlib
from datetime import datetime, timezone

ARTIFACT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(ARTIFACT_DIR)

EXCLUDED_PROFILE_NAMES = {
    "Default", "Default User", "All Users", "Public", "WDAGUtilityAccount"
}

def get_windows_profile_mappings():
    command = (
        "$ErrorActionPreference='Stop'; "
        "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); "
        "try { Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | "
        "Select-Object SID,LocalPath,Special | ConvertTo-Json -Compress -Depth 2 } "
        "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
    except OSError as exc:
        return [], f"Could not start PowerShell to map Windows profiles: {exc}"
    if result.returncode != 0:
        return [], result.stderr.strip() or (
            f"Win32_UserProfile query exited with code {result.returncode}"
        )
    try:
        profiles = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError as exc:
        return [], f"Could not parse Win32_UserProfile output: {exc}"
    if isinstance(profiles, dict):
        profiles = [profiles]
    return profiles, None

DST = os.environ.get(
    "CUSTOS_OUTPUT_DIR", os.path.join(ARTIFACT_DIR, "Registry Hive_Output")
)
FILES_DIR = os.path.join(DST, "Registry Hives_Files")

MACHINE_HIVES = {
    "SYSTEM":   r"HKLM\SYSTEM",
    "SOFTWARE": r"HKLM\SOFTWARE",
    "SAM":      r"HKLM\SAM",
    "SECURITY": r"HKLM\SECURITY",
}

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def save_key(name, key_path):
    dst = os.path.join(FILES_DIR, name)
    r = subprocess.run(["reg", "save", key_path, os.path.abspath(dst), "/y"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return {"hive": name, "source_key": key_path,
                "status": "error", "stderr": r.stderr.strip()}
                
    collected_at = datetime.now(timezone.utc).isoformat()
    try:
        size = os.path.getsize(dst)
        digest = sha256(dst)
    except OSError as exc:
        return {"hive": name, "source_key": key_path, "status": "error",
                "saved_as": dst,
                "stderr": f"reg save reported success but the export could not be read: {exc}"}

    return {"hive": name, "source_key": key_path, "status": "collected",
            "collected_at": collected_at,
            "saved_as": dst, "size": size,
            "sha256": digest}

def get_profiles():
    profiles, error = get_windows_profile_mappings()
    if error:
        return [], error
    return profiles, None

def collect():
    os.makedirs(DST, exist_ok=True)
    os.makedirs(FILES_DIR, exist_ok=True)
    rows = []
    for name, key in MACHINE_HIVES.items():
        rows.append(save_key(name, key))
    profiles, profile_error = get_profiles()
    if profile_error:
        rows.append({"hive": "NTUSER_<profile-root>",
                     "status": "error",
                     "stderr": f"Could not enumerate Windows profiles: {profile_error}"})
    else:
        eligible = []
        for profile in profiles:
            local_path = profile.get("LocalPath")
            sid = profile.get("SID")
            # Fix: Removed "is True" so truthy ints/strings are caught too
            if not local_path or not sid or profile.get("Special"):
                continue
            user = os.path.basename(os.path.normpath(local_path))
            if user in EXCLUDED_PROFILE_NAMES:
                continue
            eligible.append((user, local_path, sid))

        name_counts = {}
        for user, _, _ in eligible:
            name_counts[user.casefold()] = name_counts.get(user.casefold(), 0) + 1

        for user, profile_path, sid in eligible:
            hive_name = f"NTUSER_{user}"
            if name_counts[user.casefold()] > 1:
                detail = (
                    f"Multiple Windows profiles share the name '{user}'; "
                    "the existing A08 filename cannot distinguish them."
                )
                rows.append({"hive": hive_name, "status": "error", "stderr": detail})
                rows.append({
                    "hive": f"UsrClass_{user}",
                    "status": "error",
                    "stderr": detail
                })
                continue
            if not os.path.isdir(profile_path):
                detail = f"Profile path is missing or inaccessible: '{profile_path}'"
                rows.append({
                    "hive": hive_name, "status": "error",
                    "stderr": detail
                })
                rows.append({
                    "hive": f"UsrClass_{user}",
                    "status": "error",
                    "stderr": detail
                })
                continue
            rows.append(save_key(hive_name, f"HKU\\{sid}"))
            rows.append(save_key(f"UsrClass_{user}", f"HKU\\{sid}_Classes"))
            
    return {"status": "collected",
            "utc": datetime.now(timezone.utc).isoformat(),
            "count": len(rows), "records": rows}

def _reporting_main():
    d = collect()
    with open(os.path.join(DST, 'Registry Hive_Output.json'), 'w', encoding='utf-8') as _result_stream:
        json.dump(d, _result_stream, indent=2, ensure_ascii=False)
    print(d["status"], d["count"])

if __name__ == "__main__":
    from pathlib import Path as _ReportPath
    import sys as _report_sys
    _report_sys.path.insert(0, str(_ReportPath(__file__).resolve().parent.parent))
    _custos_embedded_reporting_namespace = {"__file__": __file__}
    exec('"""Embedded integrity-report writer with isolated globals."""\nimport hashlib\nimport json\nimport os\nfrom datetime import datetime, timezone\nfrom pathlib import Path\n\n\ndef _canonical_integrity_report(report):\n    # Isolated embedded implementation: collector globals cannot shadow its imports.\n    _inline_namespace = {}\n    exec(\'"""Canonical post-save integrity reports; never evidence of acquisition-time hashing."""\\nimport hashlib\\nfrom datetime import datetime, timezone\\nfrom pathlib import Path\\n\\n\\ndef _now():\\n    return datetime.now(timezone.utc).isoformat()\\n\\n\\ndef _metadata(info):\\n    return (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_dev, info.st_ino)\\n\\n\\ndef _read_hash(path):\\n    digest = hashlib.sha256()\\n    with path.open(\\\'rb\\\') as stream:\\n        for chunk in iter(lambda: stream.read(1024 * 1024), b\\\'\\\'):\\n            digest.update(chunk)\\n    return digest.hexdigest()\\n\\n\\ndef canonical_report(source):\\n    root = Path(source[\\\'output_directory\\\']).resolve()\\n    outputs = []\\n    for original in source.get(\\\'outputs\\\', []):\\n        entry = dict.fromkeys((\\\'path\\\', \\\'size_bytes\\\', \\\'sha256\\\', \\\'verification_sha256\\\',\\n                              \\\'last_modified_utc\\\', \\\'hash_timestamp_utc\\\',\\n                              \\\'verification_timestamp_utc\\\', \\\'verification_status\\\', \\\'error\\\'))\\n        entry[\\\'path\\\'] = original[\\\'path\\\']\\n        entry[\\\'verification_status\\\'] = \\\'failed\\\'\\n        try:\\n            path = (root / original[\\\'path\\\']).resolve()\\n            path.relative_to(root)\\n            before = path.stat()\\n            metadata = _metadata(before)\\n            entry[\\\'size_bytes\\\'] = before.st_size\\n            entry[\\\'last_modified_utc\\\'] = datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat()\\n            entry[\\\'sha256\\\'] = _read_hash(path)\\n            entry[\\\'hash_timestamp_utc\\\'] = _now()\\n            if _metadata(path.stat()) != metadata:\\n                raise RuntimeError(\\\'Saved file metadata changed during first read\\\')\\n            entry[\\\'verification_sha256\\\'] = _read_hash(path)\\n            entry[\\\'verification_timestamp_utc\\\'] = _now()\\n            if _metadata(path.stat()) != metadata:\\n                raise RuntimeError(\\\'Saved file metadata changed during independent verification read\\\')\\n            if entry[\\\'sha256\\\'] != entry[\\\'verification_sha256\\\']:\\n                raise RuntimeError(\\\'Saved-file SHA-256 mismatch between independent reads\\\')\\n            entry[\\\'verification_status\\\'] = \\\'verified\\\'\\n        except (OSError, ValueError, RuntimeError) as exc:\\n            entry[\\\'error\\\'] = str(exc)\\n        outputs.append(entry)\\n    failed = any(item[\\\'verification_status\\\'] == \\\'failed\\\' for item in outputs)\\n    return {\\n        \\\'schema_version\\\': 1,\\n        \\\'artifact_id\\\': source.get(\\\'artifact_id\\\'),\\n        \\\'artifact_name\\\': source.get(\\\'artifact_name\\\') or root.name.removesuffix(\\\'_Output\\\'),\\n        \\\'collector\\\': source.get(\\\'collector\\\', \\\'collector.py\\\'),\\n        \\\'hash_algorithm\\\': \\\'SHA-256\\\',\\n        \\\'verification_status\\\': \\\'failed\\\' if failed else \\\'verified\\\' if outputs else \\\'not_run\\\',\\n        \\\'verification_method\\\': \\\'Two independent reads of saved output files; SHA-256 comparison and size, mtime, ctime, device and file identity stability checks. Not acquisition-time hashing.\\\',\\n        \\\'collection_started_at_utc\\\': source.get(\\\'collection_started_at_utc\\\'),\\n        \\\'collection_ended_at_utc\\\': source.get(\\\'collection_ended_at_utc\\\'),\\n        \\\'collection_status\\\': \\\'partial\\\' if failed and source.get(\\\'collection_exit_code\\\') == 0 else source.get(\\\'collection_status\\\'),\\n        \\\'collection_exit_code\\\': 1 if failed and source.get(\\\'collection_exit_code\\\') == 0 else source.get(\\\'collection_exit_code\\\'),\\n        \\\'output_directory\\\': str(root),\\n        \\\'outputs\\\': sorted(outputs, key=lambda item: item[\\\'path\\\'].casefold()),        \\\'error\\\': source.get(\\\'error\\\'),\\n        \\\'errors\\\': source.get(\\\'errors\\\', []),\\n        \\\'generated_at_utc\\\': _now(),\\n        \\\'generated_at_local\\\': datetime.now().astimezone().isoformat(),\\n    }\\n\', _inline_namespace)\n    canonical = _inline_namespace[\'canonical_report\'](report)\n    manifest = report.get(\'consolidated_reports\', report.get(\'manifest\', {}))\n    if manifest == {}:\n        canonical.pop(\'manifest\', None)\n    else:\n        canonical[\'manifest\'] = manifest\n    return canonical\n\n\ndef _now():\n    return datetime.now(timezone.utc).isoformat()\n\n\ndef _snapshot(root):\n    if not root.is_dir():\n        return {}\n    result = {}\n    for path in root.rglob(\'*\'):\n        if path.is_file() and not path.name.endswith(\'_Hash & Timestamp Report.json\'):\n            info = path.stat()\n            result[path] = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)\n    return result\n\n\ndef run_reported(main, namespace):\n    import sys\n    if any(arg in (\'-h\', \'--help\') for arg in sys.argv[1:]):\n        return main()\n    directory = Path(namespace[\'__file__\']).resolve().parent\n    artifact_id, display_name = directory.name.split(\' - \', 1)\n    root = Path(namespace.get(\'DST\') or os.environ.get(\'CUSTOS_OUTPUT_DIR\') or directory / (display_name + \'_Output\')).resolve()\n    before = _snapshot(root)\n    resolver = namespace.get(\'resolve_output\')\n    if resolver:\n        def tracked_resolver(args):\n            nonlocal root, before\n            value = resolver(args)\n            root = Path(value).resolve()\n            before = _snapshot(root)\n            return value\n        namespace[\'resolve_output\'] = tracked_resolver\n    started = _now()\n    result = 0\n    failure = None\n    try:\n        result = main() or 0\n    except BaseException as exc:\n        failure = exc\n        result = (exc.code or 0) if isinstance(exc, SystemExit) else 1\n        if not isinstance(result, int):\n            result = 1\n    finally:\n        if resolver:\n            namespace[\'resolve_output\'] = resolver\n    ended = _now()\n    outputs = []\n    errors = []\n    for path, metadata in _snapshot(root).items():\n        if before.get(path) == metadata:\n            continue\n        entry = {\'path\': path.relative_to(root).as_posix(), \'size_bytes\': metadata[0]}\n        try:\n            info = path.stat()\n            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != metadata:\n                raise RuntimeError(\'Output changed before SHA-256 calculation\')\n            digest = hashlib.sha256()\n            with path.open(\'rb\') as stream:\n                for chunk in iter(lambda: stream.read(1024 * 1024), b\'\'):\n                    digest.update(chunk)\n            info = path.stat()\n            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != metadata:\n                raise RuntimeError(\'Output changed during SHA-256 calculation\')\n            entry.update(sha256=digest.hexdigest(), verification_status=\'verified\',\n                         last_modified_utc=datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(),\n                         hash_timestamp_utc=_now())\n        except (OSError, RuntimeError) as exc:\n            entry.update(sha256=None, verification_status=\'failed\', error=str(exc))\n            errors.append(str(exc))\n        outputs.append(entry)\n    if errors and result == 0:\n        result = 1\n    report = {\n        \'artifact_id\': artifact_id, \'collector\': directory.joinpath(\'collector.py\').name,\n        \'hash_algorithm\': \'SHA-256\',\n        \'verification_status\': \'failed\' if errors else \'verified\' if outputs else \'not_run\',\n        \'verification_method\': \'File size, modification time, and creation time remained unchanged during SHA-256 calculation.\',\n        \'collection_started_at_utc\': started, \'collection_ended_at_utc\': ended,\n        \'collection_status\': \'failed\' if failure and not isinstance(failure, SystemExit) else \'partial\' if result == 1 else \'completed\' if result == 0 else \'failed\',\n        \'collection_exit_code\': result, \'output_directory\': str(root),\n        \'outputs\': sorted(outputs, key=lambda item: item[\'path\'].casefold()),\n        \'artifact_name\': display_name, \'generated_at_utc\': _now(),\n        \'generated_at_local\': datetime.now().astimezone().isoformat(),\n    }\n    if failure and not isinstance(failure, SystemExit):\n        report[\'error\'] = {\'type\': type(failure).__name__, \'message\': str(failure)}\n    root.mkdir(parents=True, exist_ok=True)\n    destination = root / (display_name + \'_Hash & Timestamp Report.json\')\n    staging = destination.with_name(\'.\' + destination.name + \'.\' + str(os.getpid()) + \'.tmp\')\n    report = _canonical_integrity_report(report)\n    result = report[\'collection_exit_code\']\n    try:\n        with staging.open(\'x\', encoding=\'utf-8\', newline=\'\\n\') as stream:\n            json.dump(report, stream, indent=2, ensure_ascii=False)\n            stream.write(\'\\n\')\n            stream.flush()\n            os.fsync(stream.fileno())\n        os.replace(staging, destination)\n    finally:\n        staging.unlink(missing_ok=True)\n    if failure:\n        raise failure.with_traceback(failure.__traceback__)\n    return result\n', _custos_embedded_reporting_namespace)
    run_reported = _custos_embedded_reporting_namespace["run_reported"]
    raise SystemExit(run_reported(_reporting_main, globals()))
