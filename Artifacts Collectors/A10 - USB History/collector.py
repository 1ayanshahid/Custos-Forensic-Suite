import os, json, sys
from datetime import datetime, timezone
from Registry import Registry
import hashlib
import subprocess

ARTIFACT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(ARTIFACT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

_custos_embedded_prerequisite_namespace = {"__file__": __file__}
exec('import hashlib\nimport json\nimport os\nimport shutil\nimport subprocess\nimport sys\nfrom datetime import datetime\nfrom pathlib import Path\n\n\nA08_FOLDER = "A08 - Registry Hives"\nOUTPUT_MAP_FILENAME = ".custos-output-paths.json"\nEXCLUDED_PROFILE_NAMES = {\n    "Default", "Default User", "All Users", "Public", "WDAGUtilityAccount"\n}\n_PARENT_RUNS = set()\n\n\nclass PrerequisiteError(RuntimeError):\n    pass\n\n\ndef get_windows_profile_mappings():\n    command = (\n        "$ErrorActionPreference=\'Stop\'; "\n        "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); "\n        "try { Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | "\n        "Select-Object SID,LocalPath,Special | ConvertTo-Json -Compress -Depth 2 } "\n        "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"\n    )\n    try:\n        result = subprocess.run(\n            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],\n            capture_output=True, text=True, encoding="utf-8", errors="replace"\n        )\n    except OSError as exc:\n        return [], f"Could not start PowerShell to map Windows profiles: {exc}"\n    if result.returncode != 0:\n        return [], result.stderr.strip() or (\n            f"Win32_UserProfile query exited with code {result.returncode}"\n        )\n    try:\n        profiles = json.loads(result.stdout) if result.stdout.strip() else []\n    except json.JSONDecodeError as exc:\n        return [], f"Could not parse Win32_UserProfile output: {exc}"\n    if isinstance(profiles, dict):\n        profiles = [profiles]\n    return profiles, None\n\n\ndef artifact_output_dir(project_root, artifact_folder):\n    return os.path.join(os.path.abspath(os.fspath(project_root)),\n                        ".custos-backend", artifact_folder)\n\n\ndef _sha256_file(path):\n    digest = hashlib.sha256()\n    with open(path, "rb") as stream:\n        for block in iter(lambda: stream.read(1024 * 1024), b""):\n            digest.update(block)\n    return digest.digest()\n\n\ndef _read_manifest(project_root):\n    output_dir = artifact_output_dir(project_root, A08_FOLDER)\n    manifest_path = os.path.join(output_dir, "Registry Hive_Output.json")\n    try:\n        with open(manifest_path, "r", encoding="utf-8") as stream:\n            manifest = json.load(stream)\n    except (OSError, json.JSONDecodeError) as exc:\n        raise PrerequisiteError(\n            f"Cannot read A08 acquisition metadata at \'{manifest_path}\': {exc}"\n        ) from exc\n\n    if not isinstance(manifest, dict) or manifest.get("status") != "collected":\n        raise PrerequisiteError(\n            f"A08 metadata at \'{manifest_path}\' does not report a successful collection."\n        )\n    timestamp = manifest.get("utc")\n    try:\n        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))\n    except (AttributeError, TypeError, ValueError) as exc:\n        raise PrerequisiteError(\n            f"A08 metadata at \'{manifest_path}\' has no valid UTC timestamp."\n        ) from exc\n    records = manifest.get("records")\n    if not isinstance(records, list) or not all(\n        isinstance(record, dict) for record in records\n    ):\n        raise PrerequisiteError(\n            f"A08 metadata at \'{manifest_path}\' has an invalid records list."\n        )\n    return output_dir, timestamp, records\n\n\ndef _verify_record(output_dir, record, parser_factory=None):\n    name = record.get("hive")\n    if not isinstance(name, str) or not name or os.path.basename(name) != name:\n        raise PrerequisiteError("A08 metadata contains an invalid hive filename.")\n    if record.get("status") != "collected":\n        detail = record.get("stderr") or record.get("reason") or record.get("status")\n        raise PrerequisiteError(f"A08 did not collect \'{name}\': {detail}")\n\n    saved_as = record.get("saved_as")\n    if not isinstance(saved_as, str) or os.path.basename(saved_as) != name:\n        raise PrerequisiteError(\n            f"A08 metadata does not identify the expected saved file for \'{name}\'."\n        )\n    expected_path = os.path.abspath(os.path.join(output_dir, "Registry Hives_Files", name))\n    if not os.path.isfile(expected_path):\n        expected_path = os.path.abspath(os.path.join(output_dir, name))\n\n    digest = hashlib.sha256()\n    try:\n        with open(expected_path, "rb") as stream:\n            header = stream.read(8)\n            digest.update(header)\n            for block in iter(lambda: stream.read(1024 * 1024), b""):\n                digest.update(block)\n            size = os.fstat(stream.fileno()).st_size\n    except OSError as exc:\n        raise PrerequisiteError(\n            f"Required A08 export \'{expected_path}\' is missing or unreadable: {exc}"\n        ) from exc\n\n    if not header.startswith(b"regf"):\n        raise PrerequisiteError(f"A08 export \'{expected_path}\' has an invalid hive signature.")\n    if record.get("size") != size:\n        raise PrerequisiteError(f"A08 export \'{expected_path}\' has a size mismatch.")\n    recorded_hash = record.get("sha256")\n    if (\n        not isinstance(recorded_hash, str)\n        or digest.hexdigest().lower() != recorded_hash.lower()\n    ):\n        raise PrerequisiteError(f"A08 export \'{expected_path}\' has a SHA-256 mismatch.")\n    if parser_factory is not None:\n        try:\n            parser_factory(expected_path)\n        except Exception as exc:\n            raise PrerequisiteError(\n                f"A08 export \'{expected_path}\' cannot be opened as a registry hive: {exc}"\n            ) from exc\n    return expected_path\n\n\ndef _run_a08(project_root):\n    run_prerequisite_collector(project_root, A08_FOLDER)\n\n\ndef run_prerequisite_collector(project_root, artifact_folder):\n    project_root = os.path.abspath(os.fspath(project_root))\n    run_key = (os.path.normcase(project_root), artifact_folder)\n    if run_key in _PARENT_RUNS:\n        return\n\n    script = os.path.join(project_root, artifact_folder, "collector.py")\n    if not os.path.isfile(script):\n        raise PrerequisiteError(\n            f"Prerequisite collector \'{artifact_folder}\' was not found at \'{script}\'."\n        )\n\n    output_dir = artifact_output_dir(project_root, artifact_folder)\n    try:\n        os.makedirs(output_dir, exist_ok=True)\n        if os.name == "nt":\n            import ctypes\n            backend_dir = os.path.dirname(output_dir)\n            attrs = ctypes.windll.kernel32.GetFileAttributesW(backend_dir)\n            if attrs in (-1, 0xFFFFFFFF) or not ctypes.windll.kernel32.SetFileAttributesW(\n                backend_dir, attrs | 0x2\n            ):\n                raise OSError("Could not mark prerequisite backend directory hidden")\n    except OSError as exc:\n        raise PrerequisiteError(f"Cannot prepare prerequisite output directory: {exc}") from exc\n    env = os.environ.copy()\n    env["CUSTOS_OUTPUT_DIR"] = output_dir\n    try:\n        result = subprocess.run(\n            [sys.executable, script],\n            cwd=os.path.dirname(script),\n            env=env,\n            capture_output=True,\n            text=True,\n            encoding="utf-8",\n            errors="replace",\n        )\n    except OSError as exc:\n        raise PrerequisiteError(f"Could not start prerequisite \'{artifact_folder}\': {exc}") from exc\n    if result.returncode != 0:\n        detail = "\\n".join(\n            part.strip() for part in (result.stdout, result.stderr) if part.strip()\n        )\n        raise PrerequisiteError(\n            f"Prerequisite \'{artifact_folder}\' exited with code {result.returncode}."\n            + (f"\\n{detail}" if detail else "")\n        )\n    _PARENT_RUNS.add(run_key)\n\n\ndef _profile_names():\n    command = (\n        "$ErrorActionPreference=\'Stop\'; "\n        "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); "\n        "try { Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | "\n        "Select-Object SID,LocalPath,Special | ConvertTo-Json -Compress -Depth 2 } "\n        "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"\n    )\n    try:\n        result = subprocess.run(\n            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],\n            capture_output=True,\n            text=True,\n            encoding="utf-8",\n            errors="replace",\n        )\n    except OSError as exc:\n        raise PrerequisiteError(\n            f"Could not start PowerShell to map Windows profiles: {exc}"\n        ) from exc\n    if result.returncode != 0:\n        raise PrerequisiteError(\n            result.stderr.strip()\n            or f"Win32_UserProfile query exited with code {result.returncode}."\n        )\n    try:\n        profiles = json.loads(result.stdout) if result.stdout.strip() else []\n    except json.JSONDecodeError as exc:\n        raise PrerequisiteError(\n            f"Could not parse Win32_UserProfile output: {exc}"\n        ) from exc\n    if isinstance(profiles, dict):\n        profiles = [profiles]\n    if not isinstance(profiles, list) or not all(\n        isinstance(profile, dict) for profile in profiles\n    ):\n        raise PrerequisiteError("Windows returned invalid SID/profile mappings.")\n\n    names = {}\n    for profile in profiles:\n        local_path = profile.get("LocalPath")\n        if (\n            not local_path\n            or not profile.get("SID")\n            or profile.get("Special") in (True, "True", 1)\n        ):\n            continue\n        name = os.path.basename(os.path.normpath(local_path))\n        if name.casefold() in {item.casefold() for item in EXCLUDED_PROFILE_NAMES}:\n            continue\n        names.setdefault(name.casefold(), []).append(name)\n    return names\n\n\ndef ensure_a08_inputs(\n    project_root,\n    required_hives=(),\n    include_ntuser=False,\n    include_usrclass=False,\n    parser_factory=None,\n):\n    project_root = os.path.abspath(os.fspath(project_root))\n    required_hives = tuple(required_hives)\n    _run_a08(project_root)\n    output_dir, _, records = _read_manifest(project_root)\n    by_name = {}\n    for record in records:\n        name = record.get("hive")\n        if isinstance(name, str):\n            by_name.setdefault(name.casefold(), []).append(record)\n\n    exports = {}\n    for name in required_hives:\n        matches = by_name.get(name.casefold(), [])\n        if len(matches) != 1:\n            raise PrerequisiteError(\n                f"A08 metadata must contain exactly one \'{name}\' export; found {len(matches)}."\n            )\n        exports[name] = _verify_record(output_dir, matches[0], parser_factory)\n\n    user_records = []\n    for prefix, requested in (\n        ("NTUSER_", include_ntuser),\n        ("UsrClass_", include_usrclass),\n    ):\n        if requested:\n            user_records.extend(\n                record for record in records\n                if isinstance(record.get("hive"), str)\n                and record["hive"].startswith(prefix)\n            )\n\n    if user_records:\n        profile_names = _profile_names()\n        seen_hives = set()\n        for record in user_records:\n            hive_name = record["hive"]\n            if hive_name.casefold() in seen_hives:\n                raise PrerequisiteError(\n                    f"A08 metadata contains duplicate records for \'{hive_name}\'."\n                )\n            seen_hives.add(hive_name.casefold())\n            suffix = hive_name.split("_", 1)[1]\n            mapped = profile_names.get(suffix.casefold(), [])\n            if len(mapped) != 1:\n                print(\n                    f"WARNING: Skipping A08 export \'{hive_name}\'; it does not "\n                    "map to exactly one current Windows profile.",\n                    file=sys.stderr,\n                )\n                continue\n            try:\n                exports[hive_name] = _verify_record(\n                    output_dir, record, parser_factory\n                )\n            except PrerequisiteError as exc:\n                print(f"WARNING: Skipping A08 export \'{hive_name}\': {exc}", file=sys.stderr)\n\n    for prefix, requested in (\n        ("NTUSER_", include_ntuser),\n        ("UsrClass_", include_usrclass),\n    ):\n        if requested and not any(name.startswith(prefix) for name in exports):\n            if prefix == "UsrClass_" and include_ntuser and any(\n                name.startswith("NTUSER_") for name in exports\n            ):\n                print(\n                    "WARNING: No verified current-profile UsrClass export is "\n                    "available; A33 will only parse the verified NTUSER exports.",\n                    file=sys.stderr,\n                )\n            else:\n                raise PrerequisiteError(\n                    f"A08 has no verified, current-profile exports beginning with \'{prefix}\'."\n                )\n\n    return exports\n\n\ndef stage_a08_inputs(exports, destination):\n    destination = Path(destination)\n    for name, source in exports.items():\n        if name.startswith("NTUSER_"):\n            profile_name = name[len("NTUSER_"):]\n            filename = "NTUSER.DAT"\n        elif name.startswith("UsrClass_"):\n            profile_name = name[len("UsrClass_"):]\n            filename = "UsrClass.dat"\n        else:\n            raise PrerequisiteError(\n                f"Cannot determine the standard hive filename for \'{name}\'."\n            )\n        profile_directory = destination / profile_name\n        profile_directory.mkdir(parents=True, exist_ok=True)\n        staged = profile_directory / filename\n        shutil.copy2(source, staged)\n        if os.path.getsize(source) != os.path.getsize(staged):\n            raise PrerequisiteError(\n                f"Staged A08 export \'{name}\' does not match the source size."\n            )\n        source_hash = _sha256_file(source)\n        staged_hash = _sha256_file(staged)\n        if source_hash != staged_hash:\n            raise PrerequisiteError(\n                f"Staged A08 export \'{name}\' does not match the source SHA-256."\n            )\n', _custos_embedded_prerequisite_namespace)
run_prerequisite_collector = _custos_embedded_prerequisite_namespace['run_prerequisite_collector']

OUTPUT_MAP_FILENAME = ".custos-output-paths.json"

class PrerequisiteError(RuntimeError):
    pass

artifact_output_dir = _custos_embedded_prerequisite_namespace['artifact_output_dir']
SharedPrerequisiteError = _custos_embedded_prerequisite_namespace['PrerequisiteError']

def run_dependency(project_root, artifact_folder):
    try:
        run_prerequisite_collector(project_root, artifact_folder)
    except SharedPrerequisiteError as exc:
        raise PrerequisiteError(str(exc)) from exc

def _read_manifest(project_root, artifact_folder, prerequisite):
    run_dependency(project_root, artifact_folder)
    output_dir = artifact_output_dir(project_root, artifact_folder)
    artifact_name = os.path.basename(os.path.normpath(artifact_folder)).split(
        " - ", 1
    )[1]
    manifest_name = (
        "Registry Hive_Output.json"
        if artifact_folder == "A08 - Registry Hives"
        else f"{artifact_name}_Output.json"
    )
    manifest_path = os.path.join(output_dir, manifest_name)
    try:
        with open(manifest_path, "r", encoding="utf-8") as stream:
            manifest = json.load(stream)
    except FileNotFoundError:
        manifest_path = os.path.join(output_dir, "results.json")
        try:
            with open(manifest_path, "r", encoding="utf-8") as stream:
                manifest = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            raise PrerequisiteError(
                f"Cannot read {prerequisite} acquisition metadata at "
                f"'{manifest_path}': {exc}. Run {prerequisite} first."
            ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise PrerequisiteError(
            f"Cannot read {prerequisite} acquisition metadata at "
            f"'{manifest_path}': {exc}. Run {prerequisite} first."
        ) from exc

    if not isinstance(manifest, dict):
        raise PrerequisiteError(
            f"{prerequisite} metadata at '{manifest_path}' is not a JSON "
            f"object. Rerun {prerequisite} first."
        )
    timestamp = manifest.get("utc")
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise PrerequisiteError(
            f"{prerequisite} metadata at '{manifest_path}' has no valid UTC "
            "acquisition timestamp. Rerun the prerequisite collector."
        ) from exc
    records = manifest.get("records")
    if not isinstance(records, list) or not all(
        isinstance(record, dict) for record in records
    ):
        raise PrerequisiteError(
            f"{prerequisite} metadata at '{manifest_path}' has an invalid "
            "records list. Rerun {prerequisite} first."
        )
    return manifest_path, timestamp, records

def _verify_export_record(project_root, artifact_folder, prerequisite,
                          record, expected_name, signature,
                          parser_factory=None):
    out_dir = artifact_output_dir(project_root, artifact_folder)
    expected_path = os.path.abspath(os.path.join(out_dir, "Registry Hives_Files", expected_name))
    if not os.path.isfile(expected_path):
        expected_path = os.path.abspath(os.path.join(out_dir, expected_name))
    
    saved_as = record.get("saved_as")
    if not isinstance(saved_as, str) or not saved_as:
        raise PrerequisiteError(
            f"{prerequisite} metadata does not identify the saved file for "
            f"'{expected_name}'. Rerun {prerequisite}."
        )
        
    recorded_path = os.path.abspath(saved_as)
    
    if os.path.normcase(os.path.abspath(recorded_path)) != os.path.normcase(expected_path):
        raise PrerequisiteError(
            f"{prerequisite} metadata points '{expected_name}' to "
            f"'{recorded_path}', not the expected project export "
            f"'{expected_path}'. Rerun {prerequisite}."
        )
    if record.get("status") != "collected":
        detail = record.get("stderr") or record.get("reason") or record.get("status")
        raise PrerequisiteError(
            f"{prerequisite} did not successfully export '{expected_path}' "
            f"({detail}). Run {prerequisite} again."
        )
    try:
        with open(expected_path, "rb") as stream:
            header = stream.read(8)
            digest = hashlib.sha256()
            digest.update(header)
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            size = os.fstat(stream.fileno()).st_size
    except OSError as exc:
        raise PrerequisiteError(
            f"Required {prerequisite} export '{expected_path}' is missing or "
            f"unreadable: {exc}. Run {prerequisite} first."
        ) from exc
    if not header.startswith(signature):
        raise PrerequisiteError(
            f"Required {prerequisite} export '{expected_path}' has an invalid "
            f"file signature. Run {prerequisite} again."
        )
    if record.get("size") != size:
        raise PrerequisiteError(
            f"Required {prerequisite} export '{expected_path}' does not match "
            "the recorded acquisition size. Rerun the prerequisite collector."
        )
    recorded_hash = record.get("sha256")
    if (
        not isinstance(recorded_hash, str)
        or not recorded_hash
        or digest.hexdigest().lower() != recorded_hash.lower()
    ):
        raise PrerequisiteError(
            f"Required {prerequisite} export '{expected_path}' does not match "
            "the recorded acquisition digest. Rerun the prerequisite collector."
        )
    if parser_factory is not None:
        try:
            parser_factory(expected_path)
        except Exception as exc:
            raise PrerequisiteError(
                f"Required {prerequisite} export '{expected_path}' cannot be "
                f"opened as the expected artifact: {exc}. Rerun "
                f"{prerequisite}."
            ) from exc
    return expected_path

def _single_record(records, key, value, prerequisite, manifest_path):
    matches = [record for record in records if record.get(key) == value]
    if len(matches) != 1:
        raise PrerequisiteError(
            f"Expected exactly one '{value}' record in '{manifest_path}', "
            f"found {len(matches)}. Rerun {prerequisite}."
        )
    return matches[0]

def _confirm_source(prerequisite, timestamp, input_fn):
    print(
        f"{prerequisite} export timestamp: {timestamp}. Its existing metadata "
        "does not identify the source computer. Confirm that this is the "
        "intended export before proceeding."
    )
    try:
        answer = input_fn("Use this export? Type Y to continue: ").strip().lower()
    except (EOFError, OSError) as exc:
        raise PrerequisiteError(
            f"Confirmation is required to use this {prerequisite} export."
        ) from exc
    if answer not in ("y", "yes"):
        raise PrerequisiteError(
            f"{prerequisite} export was not selected. No collection was run."
        )

def require_a08_hives(project_root, hive_names, parser_factory=None, input_fn=input):
    prerequisite = "A08 - Registry Hives"
    artifact_folder = "A08 - Registry Hives"
    
    manifest_path, timestamp, records = _read_manifest(
        project_root, artifact_folder, prerequisite
    )

    result = {}
    for name in hive_names:
        record = _single_record(
            records, "hive", name, prerequisite, manifest_path
        )
        result[name] = _verify_export_record(
            project_root, artifact_folder, prerequisite, record, name,
            b"regf", parser_factory
        )
    return result

DST = os.environ.get(
    "CUSTOS_OUTPUT_DIR", os.path.join(ARTIFACT_DIR, "USB History_Output")
)

def get_current_control_set(reg):
    try:
        return "ControlSet%03d" % reg.root().subkey("Select").value("Current").value()
    except Exception:
        return "ControlSet001"

def enum_usb(reg, ccs):
    base = f"{ccs}\\Enum\\USBSTOR"
    rows = []
    try:
        usbstor = reg.root().find_key(base)
    except Exception:
        return rows
    for class_key in usbstor.subkeys():
        for instance in class_key.subkeys():
            try:
                vals = {v.name(): v.value() for v in instance.values()}
                rows.append({
                    "device_class": class_key.name(),
                    "instance_id": instance.name(),
                    "friendly_name": vals.get("FriendlyName"),
                    "device_desc": vals.get("DeviceDesc"),
                    "service": vals.get("Service"),
                    "container_id": vals.get("ContainerID")
                })
            except Exception as e:
                rows.append({"instance_id": instance.name(),
                             "status": "error", "reason": str(e)})
    return rows

def collect():
    source_hives = require_a08_hives(
        PROJECT_ROOT, ["SYSTEM"], Registry.Registry
    )
    system_hive = source_hives["SYSTEM"]
    try:
        os.makedirs(DST, exist_ok=True)
    except OSError as exc:
        raise PrerequisiteError(f"Could not create output directory '{DST}': {exc}")
        
    reg = Registry.Registry(system_hive)
    ccs = get_current_control_set(reg)
    rows = enum_usb(reg, ccs)
    return {"status": "collected",
            "source_hive": system_hive,
            "control_set": ccs,
            "utc": datetime.now(timezone.utc).isoformat(),
            "count": len(rows), "records": rows}

def _reporting_main():
    try:
        d = collect()
    except PrerequisiteError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
    with open(os.path.join(DST, 'USB History_Output.json'), 'w', encoding='utf-8') as _result_stream:
        json.dump(d, _result_stream, indent=2, ensure_ascii=False)
    print(d["status"], d["count"])

if __name__ == "__main__":
    from pathlib import Path as _ReportPath
    import sys as _report_sys
    _report_sys.path.insert(0, str(_ReportPath(__file__).resolve().parent.parent))
    _custos_embedded_reporting_namespace = {"__file__": __file__}
    exec('"""Embedded integrity-report writer with isolated globals."""\nimport hashlib\nimport json\nimport os\nfrom datetime import datetime, timezone\nfrom pathlib import Path\n\n\ndef _canonical_integrity_report(report):\n    # Isolated embedded implementation: collector globals cannot shadow its imports.\n    _inline_namespace = {}\n    exec(\'"""Canonical post-save integrity reports; never evidence of acquisition-time hashing."""\\nimport hashlib\\nfrom datetime import datetime, timezone\\nfrom pathlib import Path\\n\\n\\ndef _now():\\n    return datetime.now(timezone.utc).isoformat()\\n\\n\\ndef _metadata(info):\\n    return (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_dev, info.st_ino)\\n\\n\\ndef _read_hash(path):\\n    digest = hashlib.sha256()\\n    with path.open(\\\'rb\\\') as stream:\\n        for chunk in iter(lambda: stream.read(1024 * 1024), b\\\'\\\'):\\n            digest.update(chunk)\\n    return digest.hexdigest()\\n\\n\\ndef canonical_report(source):\\n    root = Path(source[\\\'output_directory\\\']).resolve()\\n    outputs = []\\n    for original in source.get(\\\'outputs\\\', []):\\n        entry = dict.fromkeys((\\\'path\\\', \\\'size_bytes\\\', \\\'sha256\\\', \\\'verification_sha256\\\',\\n                              \\\'last_modified_utc\\\', \\\'hash_timestamp_utc\\\',\\n                              \\\'verification_timestamp_utc\\\', \\\'verification_status\\\', \\\'error\\\'))\\n        entry[\\\'path\\\'] = original[\\\'path\\\']\\n        entry[\\\'verification_status\\\'] = \\\'failed\\\'\\n        try:\\n            path = (root / original[\\\'path\\\']).resolve()\\n            path.relative_to(root)\\n            before = path.stat()\\n            metadata = _metadata(before)\\n            entry[\\\'size_bytes\\\'] = before.st_size\\n            entry[\\\'last_modified_utc\\\'] = datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat()\\n            entry[\\\'sha256\\\'] = _read_hash(path)\\n            entry[\\\'hash_timestamp_utc\\\'] = _now()\\n            if _metadata(path.stat()) != metadata:\\n                raise RuntimeError(\\\'Saved file metadata changed during first read\\\')\\n            entry[\\\'verification_sha256\\\'] = _read_hash(path)\\n            entry[\\\'verification_timestamp_utc\\\'] = _now()\\n            if _metadata(path.stat()) != metadata:\\n                raise RuntimeError(\\\'Saved file metadata changed during independent verification read\\\')\\n            if entry[\\\'sha256\\\'] != entry[\\\'verification_sha256\\\']:\\n                raise RuntimeError(\\\'Saved-file SHA-256 mismatch between independent reads\\\')\\n            entry[\\\'verification_status\\\'] = \\\'verified\\\'\\n        except (OSError, ValueError, RuntimeError) as exc:\\n            entry[\\\'error\\\'] = str(exc)\\n        outputs.append(entry)\\n    failed = any(item[\\\'verification_status\\\'] == \\\'failed\\\' for item in outputs)\\n    return {\\n        \\\'schema_version\\\': 1,\\n        \\\'artifact_id\\\': source.get(\\\'artifact_id\\\'),\\n        \\\'artifact_name\\\': source.get(\\\'artifact_name\\\') or root.name.removesuffix(\\\'_Output\\\'),\\n        \\\'collector\\\': source.get(\\\'collector\\\', \\\'collector.py\\\'),\\n        \\\'hash_algorithm\\\': \\\'SHA-256\\\',\\n        \\\'verification_status\\\': \\\'failed\\\' if failed else \\\'verified\\\' if outputs else \\\'not_run\\\',\\n        \\\'verification_method\\\': \\\'Two independent reads of saved output files; SHA-256 comparison and size, mtime, ctime, device and file identity stability checks. Not acquisition-time hashing.\\\',\\n        \\\'collection_started_at_utc\\\': source.get(\\\'collection_started_at_utc\\\'),\\n        \\\'collection_ended_at_utc\\\': source.get(\\\'collection_ended_at_utc\\\'),\\n        \\\'collection_status\\\': \\\'partial\\\' if failed and source.get(\\\'collection_exit_code\\\') == 0 else source.get(\\\'collection_status\\\'),\\n        \\\'collection_exit_code\\\': 1 if failed and source.get(\\\'collection_exit_code\\\') == 0 else source.get(\\\'collection_exit_code\\\'),\\n        \\\'output_directory\\\': str(root),\\n        \\\'outputs\\\': sorted(outputs, key=lambda item: item[\\\'path\\\'].casefold()),\\n        \\\'manifest\\\': source.get(\\\'consolidated_reports\\\', source.get(\\\'manifest\\\', {})),\\n        \\\'error\\\': source.get(\\\'error\\\'),\\n        \\\'errors\\\': source.get(\\\'errors\\\', []),\\n        \\\'generated_at_utc\\\': _now(),\\n        \\\'generated_at_local\\\': datetime.now().astimezone().isoformat(),\\n    }\\n\', _inline_namespace)\n    canonical = _inline_namespace[\'canonical_report\'](report)\n    manifest = report.get(\'consolidated_reports\', report.get(\'manifest\', {}))\n    if manifest == {}:\n        canonical.pop(\'manifest\', None)\n    else:\n        canonical[\'manifest\'] = manifest\n    return canonical\n\n\ndef _now():\n    return datetime.now(timezone.utc).isoformat()\n\n\ndef _snapshot(root):\n    if not root.is_dir():\n        return {}\n    result = {}\n    for path in root.rglob(\'*\'):\n        if path.is_file() and not path.name.endswith(\'_Hash & Timestamp Report.json\'):\n            info = path.stat()\n            result[path] = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)\n    return result\n\n\ndef run_reported(main, namespace):\n    import sys\n    if any(arg in (\'-h\', \'--help\') for arg in sys.argv[1:]):\n        return main()\n    directory = Path(namespace[\'__file__\']).resolve().parent\n    artifact_id, display_name = directory.name.split(\' - \', 1)\n    root = Path(namespace.get(\'DST\') or os.environ.get(\'CUSTOS_OUTPUT_DIR\') or directory / (display_name + \'_Output\')).resolve()\n    before = _snapshot(root)\n    resolver = namespace.get(\'resolve_output\')\n    if resolver:\n        def tracked_resolver(args):\n            nonlocal root, before\n            value = resolver(args)\n            root = Path(value).resolve()\n            before = _snapshot(root)\n            return value\n        namespace[\'resolve_output\'] = tracked_resolver\n    started = _now()\n    result = 0\n    failure = None\n    try:\n        result = main() or 0\n    except BaseException as exc:\n        failure = exc\n        result = (exc.code or 0) if isinstance(exc, SystemExit) else 1\n        if not isinstance(result, int):\n            result = 1\n    finally:\n        if resolver:\n            namespace[\'resolve_output\'] = resolver\n    ended = _now()\n    outputs = []\n    errors = []\n    for path, metadata in _snapshot(root).items():\n        if before.get(path) == metadata:\n            continue\n        entry = {\'path\': path.relative_to(root).as_posix(), \'size_bytes\': metadata[0]}\n        try:\n            info = path.stat()\n            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != metadata:\n                raise RuntimeError(\'Output changed before SHA-256 calculation\')\n            digest = hashlib.sha256()\n            with path.open(\'rb\') as stream:\n                for chunk in iter(lambda: stream.read(1024 * 1024), b\'\'):\n                    digest.update(chunk)\n            info = path.stat()\n            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != metadata:\n                raise RuntimeError(\'Output changed during SHA-256 calculation\')\n            entry.update(sha256=digest.hexdigest(), verification_status=\'verified\',\n                         last_modified_utc=datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(),\n                         hash_timestamp_utc=_now())\n        except (OSError, RuntimeError) as exc:\n            entry.update(sha256=None, verification_status=\'failed\', error=str(exc))\n            errors.append(str(exc))\n        outputs.append(entry)\n    if errors and result == 0:\n        result = 1\n    report = {\n        \'artifact_id\': artifact_id, \'collector\': directory.joinpath(\'collector.py\').name,\n        \'hash_algorithm\': \'SHA-256\',\n        \'verification_status\': \'failed\' if errors else \'verified\' if outputs else \'not_run\',\n        \'verification_method\': \'File size, modification time, and creation time remained unchanged during SHA-256 calculation.\',\n        \'collection_started_at_utc\': started, \'collection_ended_at_utc\': ended,\n        \'collection_status\': \'failed\' if failure and not isinstance(failure, SystemExit) else \'partial\' if result == 1 else \'completed\' if result == 0 else \'failed\',\n        \'collection_exit_code\': result, \'output_directory\': str(root),\n        \'outputs\': sorted(outputs, key=lambda item: item[\'path\'].casefold()),\n        \'artifact_name\': display_name, \'generated_at_utc\': _now(),\n        \'generated_at_local\': datetime.now().astimezone().isoformat(),\n    }\n    if failure and not isinstance(failure, SystemExit):\n        report[\'error\'] = {\'type\': type(failure).__name__, \'message\': str(failure)}\n    root.mkdir(parents=True, exist_ok=True)\n    destination = root / (display_name + \'_Hash & Timestamp Report.json\')\n    staging = destination.with_name(\'.\' + destination.name + \'.\' + str(os.getpid()) + \'.tmp\')\n    report = _canonical_integrity_report(report)\n    result = report[\'collection_exit_code\']\n    try:\n        with staging.open(\'x\', encoding=\'utf-8\', newline=\'\\n\') as stream:\n            json.dump(report, stream, indent=2, ensure_ascii=False)\n            stream.write(\'\\n\')\n            stream.flush()\n            os.fsync(stream.fileno())\n        os.replace(staging, destination)\n    finally:\n        staging.unlink(missing_ok=True)\n    if failure:\n        raise failure.with_traceback(failure.__traceback__)\n    return result\n', _custos_embedded_reporting_namespace)
    run_reported = _custos_embedded_reporting_namespace["run_reported"]
    raise SystemExit(run_reported(_reporting_main, globals()))
