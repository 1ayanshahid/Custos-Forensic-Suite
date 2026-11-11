import os, subprocess, json, hashlib
from datetime import datetime, timezone

ARTIFACT_DIR = os.path.dirname(os.path.abspath(__file__))
DST = os.path.abspath(os.environ.get(
    "CUSTOS_OUTPUT_DIR", os.path.join(ARTIFACT_DIR, "Windows Event Logs_Output")
))
FILES_DIR = os.path.join(DST, "Windows Event Logs_Files")
CHANNELS = ["System", "Application", "Security", "PowerShell/Operational"]

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _unused_output(path):
    import uuid
    if not os.path.lexists(path):
        return path
    stem, ext = os.path.splitext(path)
    while True:
        candidate = stem + "_" + uuid.uuid4().hex + ext
        if not os.path.lexists(candidate):
            return candidate


def export_channel(channel, source_file=None):
    safe = channel.replace("/", "_").replace("\\", "_")
    dst = _unused_output(os.path.join(FILES_DIR, safe + ".evtx"))
    command = ["wevtutil", "epl", source_file or channel, os.path.abspath(dst), "/ow:false"]
    if source_file:
        command.append("/lf:true")
    entry = {"channel": channel, "saved_as": dst, "scope": "full source channel",
             "method": "wevtutil epl", "status": "error"}
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                encoding="utf-8", errors="replace")
        if result.returncode != 0:
            entry["error"] = result.stderr.strip() or result.stdout.strip() or f"wevtutil exit {result.returncode}"
            return entry
        if os.path.getsize(dst) == 0:
            raise OSError("wevtutil produced an empty export")
        with open(dst, "rb") as stream:
            stream.read(1)
        import hashlib
        digest = hashlib.sha256()
        with open(dst, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        entry.update(status="collected", size=os.path.getsize(dst),
                     sha256=digest.hexdigest(), collected_at=datetime.now(timezone.utc).isoformat())
    except OSError as exc:
        entry["error"] = str(exc)
    return entry

def collect():
    os.makedirs(DST, exist_ok=True)
    os.makedirs(FILES_DIR, exist_ok=True)
    rows = [export_channel(c) for c in CHANNELS]
    return {"status": "partial" if any(r["status"] == "error" for r in rows) else "collected",
            "utc": datetime.now(timezone.utc).isoformat(),
            "count": len(rows), "records": rows}

def _reporting_main():
    d = collect()
    globals()["_evtx_export_errors"] = [
        f"{e['channel']}: {e['error']}"
        for e in d.get("evtx_exports", d.get("records", []))
        if e.get("status") == "error" and e.get("channel")
    ]
    with open(_unused_output(os.path.join(DST, 'Windows Event Logs_Output.json')), "x", encoding='utf-8') as _result_stream:
        json.dump(d, _result_stream, indent=2, ensure_ascii=False)
    print(d["status"], d["count"])
    if d.get("status") in ("partial", "error"):
        raise SystemExit(1)

if __name__ == "__main__":
    from pathlib import Path as _ReportPath
    import sys as _report_sys
    _report_sys.path.insert(0, str(_ReportPath(__file__).resolve().parent.parent))
    _custos_embedded_reporting_namespace = {"__file__": __file__}
    exec('"""Embedded integrity-report writer with isolated globals."""\nimport hashlib\nimport json\nimport os\nfrom datetime import datetime, timezone\nfrom pathlib import Path\n\n\ndef _canonical_integrity_report(report):\n    # Isolated embedded implementation: collector globals cannot shadow its imports.\n    _inline_namespace = {}\n    exec(\'"""Canonical post-save integrity reports; never evidence of acquisition-time hashing."""\\nimport hashlib\\nfrom datetime import datetime, timezone\\nfrom pathlib import Path\\n\\n\\ndef _now():\\n    return datetime.now(timezone.utc).isoformat()\\n\\n\\ndef _metadata(info):\\n    return (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_dev, info.st_ino)\\n\\n\\ndef _read_hash(path):\\n    digest = hashlib.sha256()\\n    with path.open(\\\'rb\\\') as stream:\\n        for chunk in iter(lambda: stream.read(1024 * 1024), b\\\'\\\'):\\n            digest.update(chunk)\\n    return digest.hexdigest()\\n\\n\\ndef canonical_report(source):\\n    root = Path(source[\\\'output_directory\\\']).resolve()\\n    outputs = []\\n    for original in source.get(\\\'outputs\\\', []):\\n        entry = dict.fromkeys((\\\'path\\\', \\\'size_bytes\\\', \\\'sha256\\\', \\\'verification_sha256\\\',\\n                              \\\'last_modified_utc\\\', \\\'hash_timestamp_utc\\\',\\n                              \\\'verification_timestamp_utc\\\', \\\'verification_status\\\', \\\'error\\\'))\\n        entry[\\\'path\\\'] = original[\\\'path\\\']\\n        entry[\\\'verification_status\\\'] = \\\'failed\\\'\\n        try:\\n            path = (root / original[\\\'path\\\']).resolve()\\n            path.relative_to(root)\\n            before = path.stat()\\n            metadata = _metadata(before)\\n            entry[\\\'size_bytes\\\'] = before.st_size\\n            entry[\\\'last_modified_utc\\\'] = datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat()\\n            entry[\\\'sha256\\\'] = _read_hash(path)\\n            entry[\\\'hash_timestamp_utc\\\'] = _now()\\n            if _metadata(path.stat()) != metadata:\\n                raise RuntimeError(\\\'Saved file metadata changed during first read\\\')\\n            entry[\\\'verification_sha256\\\'] = _read_hash(path)\\n            entry[\\\'verification_timestamp_utc\\\'] = _now()\\n            if _metadata(path.stat()) != metadata:\\n                raise RuntimeError(\\\'Saved file metadata changed during independent verification read\\\')\\n            if entry[\\\'sha256\\\'] != entry[\\\'verification_sha256\\\']:\\n                raise RuntimeError(\\\'Saved-file SHA-256 mismatch between independent reads\\\')\\n            entry[\\\'verification_status\\\'] = \\\'verified\\\'\\n        except (OSError, ValueError, RuntimeError) as exc:\\n            entry[\\\'error\\\'] = str(exc)\\n        outputs.append(entry)\\n    failed = any(item[\\\'verification_status\\\'] == \\\'failed\\\' for item in outputs)\\n    return {\\n        \\\'schema_version\\\': 1,\\n        \\\'artifact_id\\\': source.get(\\\'artifact_id\\\'),\\n        \\\'artifact_name\\\': source.get(\\\'artifact_name\\\') or root.name.removesuffix(\\\'_Output\\\'),\\n        \\\'collector\\\': source.get(\\\'collector\\\', \\\'collector.py\\\'),\\n        \\\'hash_algorithm\\\': \\\'SHA-256\\\',\\n        \\\'verification_status\\\': \\\'failed\\\' if failed else \\\'verified\\\' if outputs else \\\'not_run\\\',\\n        \\\'verification_method\\\': \\\'Two independent reads of saved output files; SHA-256 comparison and size, mtime, ctime, device and file identity stability checks. Not acquisition-time hashing.\\\',\\n        \\\'collection_started_at_utc\\\': source.get(\\\'collection_started_at_utc\\\'),\\n        \\\'collection_ended_at_utc\\\': source.get(\\\'collection_ended_at_utc\\\'),\\n        \\\'collection_status\\\': \\\'partial\\\' if failed and source.get(\\\'collection_exit_code\\\') == 0 else source.get(\\\'collection_status\\\'),\\n        \\\'collection_exit_code\\\': 1 if failed and source.get(\\\'collection_exit_code\\\') == 0 else source.get(\\\'collection_exit_code\\\'),\\n        \\\'output_directory\\\': str(root),\\n        \\\'outputs\\\': sorted(outputs, key=lambda item: item[\\\'path\\\'].casefold()),\\n        \\\'manifest\\\': source.get(\\\'consolidated_reports\\\', source.get(\\\'manifest\\\', {})),\\n        \\\'error\\\': source.get(\\\'error\\\'),\\n        \\\'errors\\\': source.get(\\\'errors\\\', []),\\n        \\\'generated_at_utc\\\': _now(),\\n        \\\'generated_at_local\\\': datetime.now().astimezone().isoformat(),\\n    }\\n\', _inline_namespace)\n    canonical = _inline_namespace[\'canonical_report\'](report)\n    manifest = report.get(\'consolidated_reports\', report.get(\'manifest\', {}))\n    if manifest == {}:\n        canonical.pop(\'manifest\', None)\n    else:\n        canonical[\'manifest\'] = manifest\n    return canonical\n\n\ndef _now():\n    return datetime.now(timezone.utc).isoformat()\n\n\ndef _snapshot(root):\n    if not root.is_dir():\n        return {}\n    result = {}\n    for path in root.rglob(\'*\'):\n        if path.is_file() and not path.name.endswith(\'_Hash & Timestamp Report.json\'):\n            info = path.stat()\n            result[path] = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)\n    return result\n\n\ndef run_reported(main, namespace):\n    import sys\n    if any(arg in (\'-h\', \'--help\') for arg in sys.argv[1:]):\n        return main()\n    directory = Path(namespace[\'__file__\']).resolve().parent\n    artifact_id, display_name = directory.name.split(\' - \', 1)\n    root = Path(namespace.get(\'DST\') or os.environ.get(\'CUSTOS_OUTPUT_DIR\') or directory / (display_name + \'_Output\')).resolve()\n    before = _snapshot(root)\n    resolver = namespace.get(\'resolve_output\')\n    if resolver:\n        def tracked_resolver(args):\n            nonlocal root, before\n            value = resolver(args)\n            root = Path(value).resolve()\n            before = _snapshot(root)\n            return value\n        namespace[\'resolve_output\'] = tracked_resolver\n    started = _now()\n    result = 0\n    failure = None\n    try:\n        result = main() or 0\n    except BaseException as exc:\n        failure = exc\n        result = (exc.code or 0) if isinstance(exc, SystemExit) else 1\n        if not isinstance(result, int):\n            result = 1\n    finally:\n        if resolver:\n            namespace[\'resolve_output\'] = resolver\n    ended = _now()\n    outputs = []\n    errors = []\n    for path, metadata in _snapshot(root).items():\n        if before.get(path) == metadata:\n            continue\n        entry = {\'path\': path.relative_to(root).as_posix(), \'size_bytes\': metadata[0]}\n        try:\n            info = path.stat()\n            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != metadata:\n                raise RuntimeError(\'Output changed before SHA-256 calculation\')\n            digest = hashlib.sha256()\n            with path.open(\'rb\') as stream:\n                for chunk in iter(lambda: stream.read(1024 * 1024), b\'\'):\n                    digest.update(chunk)\n            info = path.stat()\n            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != metadata:\n                raise RuntimeError(\'Output changed during SHA-256 calculation\')\n            entry.update(sha256=digest.hexdigest(), verification_status=\'verified\',\n                         last_modified_utc=datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(),\n                         hash_timestamp_utc=_now())\n        except (OSError, RuntimeError) as exc:\n            entry.update(sha256=None, verification_status=\'failed\', error=str(exc))\n            errors.append(str(exc))\n        outputs.append(entry)\n    errors.extend(namespace.get("_evtx_export_errors", []))\n    if errors and result == 0:\n        result = 1\n    report = {\n        \'errors\': errors,\n        \'artifact_id\': artifact_id, \'collector\': directory.joinpath(\'collector.py\').name,\n        \'hash_algorithm\': \'SHA-256\',\n        \'verification_status\': \'failed\' if errors else \'verified\' if outputs else \'not_run\',\n        \'verification_method\': \'File size, modification time, and creation time remained unchanged during SHA-256 calculation.\',\n        \'collection_started_at_utc\': started, \'collection_ended_at_utc\': ended,\n        \'collection_status\': \'failed\' if failure and not isinstance(failure, SystemExit) else \'partial\' if result == 1 else \'completed\' if result == 0 else \'failed\',\n        \'collection_exit_code\': result, \'output_directory\': str(root),\n        \'outputs\': sorted(outputs, key=lambda item: item[\'path\'].casefold()),\n        \'artifact_name\': display_name, \'generated_at_utc\': _now(),\n        \'generated_at_local\': datetime.now().astimezone().isoformat(),\n    }\n    if failure and not isinstance(failure, SystemExit):\n        report[\'error\'] = {\'type\': type(failure).__name__, \'message\': str(failure)}\n    root.mkdir(parents=True, exist_ok=True)\n    destination = root / (display_name + \'_Hash & Timestamp Report.json\')\n    destination = Path(namespace[\'_unused_output\'](str(destination)))\n    staging = destination.with_name(\'.\' + destination.name + \'.\' + str(os.getpid()) + \'.tmp\')\n    report = _canonical_integrity_report(report)\n    result = report[\'collection_exit_code\']\n    try:\n        with staging.open(\'x\', encoding=\'utf-8\', newline=\'\\n\') as stream:\n            json.dump(report, stream, indent=2, ensure_ascii=False)\n            stream.write(\'\\n\')\n            stream.flush()\n            os.fsync(stream.fileno())\n        os.replace(staging, destination)\n    finally:\n        staging.unlink(missing_ok=True)\n    if failure:\n        raise failure.with_traceback(failure.__traceback__)\n    return result\n', _custos_embedded_reporting_namespace)
    run_reported = _custos_embedded_reporting_namespace["run_reported"]
    raise SystemExit(run_reported(_reporting_main, globals()))
