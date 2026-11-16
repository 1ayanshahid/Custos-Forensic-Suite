
"""
Custos Forensic Suite
Artifact: A14 - Browser Artifacts
Version: 1.0.0

Features:
- Requires an elevated administrator session.
- Discovers Chrome, Edge, Brave, Opera, Vivaldi and Firefox profiles.
- Preserves selected browser databases and supporting files.
- Records SHA-256 hashes and acquisition metadata.
- Parses acquired Chromium History and Firefox places.sqlite databases.
- Records errors and verification results.
- Does not decrypt passwords or cookies.
- Does not modify browser profiles or enable browser logging.

Python: 3.10+
Platform: Windows 10/11
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time
import uuid

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MODULE = "Browser Artifacts"
VERSION = "1.0.0"

DEFAULT_CASE_ROOT = Path(r"C:\Custos\Case001")

CHROMIUM_BROWSERS = {
    "Chrome": Path("AppData/Local/Google/Chrome/User Data"),
    "Edge": Path("AppData/Local/Microsoft/Edge/User Data"),
    "Brave": Path("AppData/Local/BraveSoftware/Brave-Browser/User Data"),
    "Chromium": Path("AppData/Local/Chromium/User Data"),
    "Vivaldi": Path("AppData/Local/Vivaldi/User Data"),
    "Opera": Path("AppData/Roaming/Opera Software/Opera Stable"),
    "Opera GX": Path("AppData/Roaming/Opera Software/Opera GX Stable"),
}

FIREFOX_ROOT = Path("AppData/Roaming/Mozilla/Firefox/Profiles")
FIREFOX_CACHE_ROOT = Path("AppData/Local/Mozilla/Firefox/Profiles")
FIREFOX_CACHE_DIR = Path("cache2")

CHROMIUM_CACHE_DIRS = (
    Path("Cache/Cache_Data"),
    Path("Code Cache"),
    Path("GPUCache"),
    Path("DawnCache"),
    Path("GrShaderCache"),
    Path("Service Worker/CacheStorage"),
)

CHROMIUM_FILES = {
    "History",
    "History-journal",
    "History-wal",
    "History-shm",
    "Bookmarks",
    "Preferences",
    "Secure Preferences",
    "Favicons",
    "Top Sites",
    "Shortcuts",
    "Web Data",
    "Web Data-journal",
    "Web Data-wal",
    "Web Data-shm",
    "Login Data",
    "Login Data-journal",
    "Login Data-wal",
    "Login Data-shm",
    "Cookies",
    "Cookies-journal",
    "Cookies-wal",
    "Cookies-shm",
    "Network/Cookies",
    "Network/Cookies-journal",
    "Network/Cookies-wal",
    "Network/Cookies-shm",
    "Network/Network Persistent State",
    "Current Session",
    "Current Tabs",
    "Last Session",
    "Last Tabs",
    "Visited Links",
    "Extension Cookies",
    "Extension Cookies-journal",
}
CHROMIUM_FILES_LOWER = {name.casefold() for name in CHROMIUM_FILES}

FIREFOX_FILES = {
    "places.sqlite",
    "places.sqlite-wal",
    "places.sqlite-shm",
    "cookies.sqlite",
    "cookies.sqlite-wal",
    "cookies.sqlite-shm",
    "formhistory.sqlite",
    "formhistory.sqlite-wal",
    "formhistory.sqlite-shm",
    "favicons.sqlite",
    "favicons.sqlite-wal",
    "favicons.sqlite-shm",
    "sessionstore.jsonlz4",
    "logins.json",
    "logins-backup.json",
    "key4.db",
    "key3.db",
    "cert9.db",
    "permissions.sqlite",
    "content-prefs.sqlite",
    "handlers.json",
    "containers.json",
    "prefs.js",
}
FIREFOX_FILES_LOWER = {name.casefold() for name in FIREFOX_FILES}

MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024


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
    digest = hashlib.sha256()

    with _report_open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def is_admin() -> bool:
    if os.name != "nt":
        return False

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _report_open(path, "x", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False, default=str)
        handle.write("\n")


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
    stat = _report_stat(path)

    return {
        "size_bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "mtime_utc": datetime.fromtimestamp(
            stat.st_mtime, timezone.utc
        ).isoformat(),
    }


def discover_profiles(all_profiles: bool) -> list[dict[str, Any]]:
    users_root = Path(os.environ.get("SystemDrive", "C:")) / "Users"

    if all_profiles:
        user_dirs = [
            path for path in users_root.iterdir()
            if path.is_dir()
            and path.name.lower() not in {
                "public", "default", "default user", "all users"
            }
        ] if users_root.is_dir() else []
    else:
        original_profile = os.environ.get("CUSTOS_ORIGINAL_PROFILE")
        current = (
            Path(original_profile).expanduser()
            if original_profile
            else Path.home()
        )
        user_dirs = [current] if current.is_dir() else []

    found = []

    for user_dir in user_dirs:
        for browser, relative_root in CHROMIUM_BROWSERS.items():
            root = user_dir / relative_root

            if not root.is_dir():
                continue

            try:
                children = list(root.iterdir())
            except OSError:
                children = []

            if browser.startswith("Opera"):
                candidates = [root]
            else:
                candidates = [
                    p for p in children
                    if p.is_dir()
                    and (
                        p.name.lower() == "default"
                        or p.name.lower().startswith("profile ")
                        or p.name.lower() == "guest profile"
                        or p.name.lower() == "system profile"
                    )
                ]

            for profile in candidates:
                found.append({
                    "user": user_dir.name,
                    "browser": browser,
                    "profile": profile.name,
                    "profile_path": str(profile),
                    "kind": "chromium",
                })

        for firefox_root, kind in (
            (user_dir / FIREFOX_ROOT, "firefox"),
            (user_dir / FIREFOX_CACHE_ROOT, "firefox_cache"),
        ):
            if not firefox_root.is_dir():
                continue

            try:
                firefox_profiles = [
                    p for p in firefox_root.iterdir() if p.is_dir()
                ]
            except OSError:
                firefox_profiles = []

            for profile in firefox_profiles:
                found.append({
                    "user": user_dir.name,
                    "browser": "Firefox",
                    "profile": profile.name,
                    "profile_path": str(profile),
                    "kind": kind,
                })

    # Deduplicate paths, case-insensitively for Windows.
    unique = {}
    for item in found:
        key = os.path.normcase(os.path.abspath(item["profile_path"]))
        unique[key] = item

    return list(unique.values())


def should_collect_chromium_file(path: Path) -> bool:
    rel = path.as_posix().replace("\\", "/").casefold()
    name = path.name.casefold()

    if name in CHROMIUM_FILES_LOWER:
        return True

    # Preserve selected cache/session-related database files when present.
    if rel.startswith("sessions/") and path.is_file():
        return True

    if rel.startswith("local storage/leveldb/") and path.is_file():
        return True

    if rel.startswith("indexeddb/") and path.is_file():
        return True

    if any(
        rel == cache_dir.as_posix().casefold()
        or rel.startswith(cache_dir.as_posix().casefold() + "/")
        for cache_dir in CHROMIUM_CACHE_DIRS
    ):
        return True

    return False


def collectable_files(
    profile: dict[str, Any],
    excluded_paths: set[str],
) -> list[Path]:
    root = Path(profile["profile_path"])
    selected: list[Path] = []
    try:
        for current, dirs, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            # Avoid following junctions/symlinks into other locations.
            dirs[:] = [
                d for d in dirs
                if (
                    not (current_path / d).is_symlink()
                    and os.path.normcase(
                        os.path.abspath(str(current_path / d))
                    ) not in excluded_paths
                )
            ]

            for name in files:
                source = current_path / name

                try:
                    if os.path.normcase(
                        os.path.abspath(str(source))
                    ) in excluded_paths:
                        continue
                    if source.is_symlink() or not source.is_file():
                        continue

                    relative = source.relative_to(root)

                    if profile["kind"] == "chromium":
                        if should_collect_chromium_file(relative):
                            selected.append(source)
                    elif profile["kind"] == "firefox_cache":
                        if (
                            relative.parts
                            and relative.parts[0].casefold()
                            == FIREFOX_CACHE_DIR.name.casefold()
                        ):
                            selected.append(source)
                    elif name.casefold() in FIREFOX_FILES_LOWER:
                        selected.append(source)

                except (OSError, ValueError):
                    continue

    except OSError:
        pass

    return sorted(selected, key=lambda p: str(p).lower())


def acquire_file(
    source: Path,
    profile: dict[str, Any],
    evidence_root: Path,
    run_id: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "source_path": str(source),
        "profile_path": profile["profile_path"],
        "browser": profile["browser"],
        "user": profile["user"],
        "profile": profile["profile"],
        "profile_kind": profile["kind"],
        "status": "ERROR",
        "acquired_path": None,
        "source_sha256_before": None,
        "acquired_sha256": None,
        "source_sha256_after": None,
        "errors": [],
    }

    try:
        before_meta = file_metadata(source)
        result["source_metadata_before"] = before_meta

        if before_meta["size_bytes"] > MAX_FILE_BYTES:
            result["status"] = "SKIPPED_SIZE_LIMIT"
            result["errors"].append("File exceeds configured size limit.")
            return result

        result["source_sha256_before"] = sha256_file(source)

        relative = source.relative_to(Path(profile["profile_path"]))
        safe_browser = "".join(
            c if c.isalnum() or c in "-_" else "_" for c in profile["browser"]
        )
        safe_user = "".join(
            c if c.isalnum() or c in "-_" else "_" for c in profile["user"]
        )
        safe_profile = "".join(
            c if c.isalnum() or c in "-_" else "_" for c in profile["profile"]
        )
        destination = (
            evidence_root / "Browser Artifacts_Files" / safe_user / safe_browser
            / safe_profile / relative
        )

        # Never overwrite an existing evidence file.
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise FileExistsError(
                f"Output collision; existing file was not overwritten: {destination}"
            )
        with source.open("rb") as source_stream, destination.open("xb") as target_stream:
            acquired_digest = hashlib.sha256()
            while True:
                chunk = source_stream.read(1024 * 1024)
                if not chunk:
                    break
                target_stream.write(chunk)
                acquired_digest.update(chunk)
        shutil.copystat(source, destination)

        result["acquired_path"] = str(destination)
        result["acquired_sha256"] = acquired_digest.hexdigest()

        try:
            result["source_sha256_after"] = sha256_file(source)
            after_meta = file_metadata(source)
            result["source_metadata_after"] = after_meta

            if result["source_sha256_after"] != result["source_sha256_before"]:
                result["errors"].append(
                    "Source content changed during acquisition."
                )

            if (
                before_meta["size_bytes"] != after_meta["size_bytes"]
                or before_meta["mtime_ns"] != after_meta["mtime_ns"]
            ):
                result["errors"].append(
                    "Source metadata changed during acquisition."
                )

        except OSError as exc:
            result["errors"].append(
                f"Could not re-check source after copying: {exc}"
            )

        if result["acquired_sha256"] != result["source_sha256_before"]:
            result["errors"].append(
                "Acquired file hash does not match source pre-copy hash."
            )

        result["status"] = (
            "VERIFICATION_FAILED" if result["errors"] else "ACQUIRED"
        )

    except PermissionError as exc:
        result["status"] = "ACCESS_DENIED"
        result["errors"].append(str(exc))

    except FileNotFoundError as exc:
        result["status"] = "SOURCE_DISAPPEARED"
        result["errors"].append(str(exc))

    except OSError as exc:
        result["status"] = "ACQUISITION_ERROR"
        result["errors"].append(str(exc))

    return result


def query_rows(db_path: Path, sql: str) -> list[dict[str, Any]]:
    rows = []

    # Read-only mode. Do not parse the live browser database.
    uri = db_path.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=10)
    connection.row_factory = sqlite3.Row

    try:
        cursor = connection.execute(sql)
        for row in cursor:
            rows.append(dict(row))
    finally:
        connection.close()

    return rows


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def sqlite_table_names(path: Path) -> set[str]:
    rows = query_rows(
        path,
        "SELECT name FROM sqlite_master WHERE type='table'",
    )
    return {str(row["name"]) for row in rows}


def sqlite_table_rows(path: Path, table: str) -> list[dict[str, Any]]:
    return query_rows(path, f"SELECT * FROM {_quote_identifier(table)}")


def sqlite_table_columns(path: Path, table: str) -> list[str]:
    rows = query_rows(path, f"PRAGMA table_info({_quote_identifier(table)})")
    return [str(row["name"]) for row in rows]


def browser_category_for_file(item: dict[str, Any]) -> str | None:
    source = Path(item["source_path"])
    profile_root = Path(item["profile_path"])
    try:
        relative = source.relative_to(profile_root)
    except ValueError:
        return None

    relative_text = relative.as_posix().casefold()
    filename = source.name.casefold()
    if item.get("profile_kind") == "firefox_cache" or relative_text.startswith(
        FIREFOX_CACHE_DIR.as_posix().casefold() + "/"
    ):
        return "cache"
    if item.get("profile_kind") == "chromium" and any(
        relative_text == cache_dir.as_posix().casefold()
        or relative_text.startswith(cache_dir.as_posix().casefold() + "/")
        for cache_dir in CHROMIUM_CACHE_DIRS
    ):
        return "cache"
    if filename in {"history", "places.sqlite"} or filename.startswith(
        ("history-", "places.sqlite-")
    ):
        return "history"
    if filename in {"cookies", "cookies.sqlite"} or filename.startswith(
        ("cookies-", "cookies.sqlite-")
    ):
        return "cookies"
    if filename in {
        "login data",
        "logins.json",
        "logins-backup.json",
    } or filename.startswith("login data-"):
        return "login"
    if filename in {"web data", "formhistory.sqlite"} or filename.startswith(
        ("web data-", "formhistory.sqlite-")
    ):
        return "web_data"
    return None


def _new_category_reports(run_id: str) -> dict[str, dict[str, Any]]:
    categories = {
        "history": "Browser History",
        "downloads": "Browser Downloads",
        "cookies": "Browser Cookies Metadata",
        "login": "Browser Login Metadata",
        "web_data": "Browser Web Data Metadata",
        "cache": "Browser Cache Inventory",
    }
    return {
        key: {
            "schema_version": 1,
            "artifact_id": "A14",
            "module": MODULE,
            "version": VERSION,
            "run_id": run_id,
            "category": name,
            "generated_utc": utc_now(),
            "collection_status": "NO_ACQUIRED_INPUT",
            "profile_count": 0,
            "record_count": 0,
            "profiles": [],
            "errors": [],
        }
        for key, name in categories.items()
    }


def _profile_bucket(
    report: dict[str, Any],
    item: dict[str, Any],
) -> dict[str, Any]:
    key = (
        item["user"].casefold(),
        item["browser"].casefold(),
        item["profile"].casefold(),
    )
    buckets = report.setdefault("_profile_index", {})
    if key not in buckets:
        bucket = {
            "user": item["user"],
            "browser": item["browser"],
            "profile": item["profile"],
            "sources": [],
            "tables": {},
            "errors": [],
            "_record_keys": {},
        }
        buckets[key] = bucket
        report["profiles"].append(bucket)
    return buckets[key]


def _add_table_records(
    bucket: dict[str, Any],
    table: str,
    rows: list[dict[str, Any]],
    record_type: str,
) -> None:
    destination = bucket["tables"].setdefault(table, [])
    seen = bucket["_record_keys"].setdefault(table, set())
    for row in rows:
        record = {**row, "record_type": record_type}
        key = json.dumps(record, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            destination.append(record)


def _login_metadata(path: Path, browser: str) -> list[dict[str, Any]]:
    if path.name.casefold() in {"logins.json", "logins-backup.json"}:
        with path.open("r", encoding="utf-8-sig") as stream:
            data = json.load(stream)
        logins = data.get("logins", [])
        if not isinstance(logins, list):
            raise ValueError("Firefox logins field is not a list.")
        return [
            {
                "hostname": login.get("hostname"),
                "form_submit_url": login.get("formSubmitURL"),
                "http_realm": login.get("httpRealm"),
                "guid": login.get("guid"),
                "time_created": login.get("timeCreated"),
                "time_last_used": login.get("timeLastUsed"),
                "time_password_changed": login.get("timePasswordChanged"),
                "times_used": login.get("timesUsed"),
                "encrypted_username_present": bool(login.get("encryptedUsername")),
                "encrypted_password_present": bool(login.get("encryptedPassword")),
            }
            for login in logins
            if isinstance(login, dict)
        ]

    columns = set(sqlite_table_columns(path, "logins"))
    allowed = (
        "origin_url",
        "action_url",
        "signon_realm",
        "date_created",
        "date_last_used",
        "date_password_modified",
        "times_used",
        "blacklisted_by_user",
        "scheme",
        "type",
        "federation_url",
    )
    selected = [column for column in allowed if column in columns]
    if not selected:
        raise sqlite3.OperationalError("No supported login metadata columns found.")
    rows = query_rows(
        path,
        "SELECT " + ", ".join(_quote_identifier(column) for column in selected)
        + " FROM logins",
    )
    return rows


def _cookie_metadata(path: Path) -> list[dict[str, Any]]:
    table = "moz_cookies" if path.name.casefold() == "cookies.sqlite" else "cookies"
    columns = set(sqlite_table_columns(path, table))
    allowed = (
        "name",
        "host_key",
        "host",
        "path",
        "creation_utc",
        "expires_utc",
        "expiry",
        "last_access_utc",
        "lastAccessed",
        "is_secure",
        "isSecure",
        "is_httponly",
        "isHttpOnly",
        "samesite",
        "sameSite",
        "source_scheme",
        "source_port",
        "is_persistent",
        "originAttributes",
    )
    selected = [column for column in allowed if column in columns]
    if not selected:
        raise sqlite3.OperationalError("No supported cookie metadata columns found.")
    return query_rows(
        path,
        "SELECT " + ", ".join(_quote_identifier(column) for column in selected)
        + f" FROM {_quote_identifier(table)}",
    )


def _web_data_metadata(path: Path) -> list[dict[str, Any]]:
    tables = sqlite_table_names(path)
    result = []
    for table in sorted(tables, key=str.casefold):
        if table.startswith("sqlite_"):
            continue
        try:
            columns = sqlite_table_columns(path, table)
            count = query_rows(
                path,
                f"SELECT COUNT(*) AS record_count FROM {_quote_identifier(table)}",
            )[0]["record_count"]
        except sqlite3.Error:
            raise
        result.append({
            "table": table,
            "record_count": count,
            "columns": columns,
        })
    return result


def _firefox_downloads(path: Path) -> list[dict[str, Any]]:
    tables = sqlite_table_names(path)
    if not {"moz_annos", "moz_anno_attributes", "moz_places"}.issubset(tables):
        return []
    return query_rows(
        path,
        """
        SELECT
            p.url,
            p.title,
            aa.name AS annotation_name,
            a.content AS annotation_content,
            a.dateAdded
        FROM moz_annos AS a
        LEFT JOIN moz_anno_attributes AS aa
            ON aa.id = a.anno_attribute_id
        LEFT JOIN moz_places AS p
            ON p.id = a.place_id
        WHERE aa.name LIKE '%download%'
        ORDER BY a.dateAdded
        """,
    )


def parse_acquired_databases(
    acquired_files: list[dict[str, Any]],
    run_id: str,
) -> dict[str, dict[str, Any]]:
    reports = _new_category_reports(run_id)
    cache_sources: set[str] = set()

    for item in acquired_files:
        category = browser_category_for_file(item)
        if category is None:
            continue
        report = reports[category]
        if item.get("status") != "ACQUIRED" or not item.get("acquired_path"):
            report["errors"].append({
                "source_path": item["source_path"],
                "status": item.get("status"),
                "errors": item.get("errors", []),
            })
            continue

        source = Path(item["source_path"])
        acquired = Path(item["acquired_path"])
        bucket = _profile_bucket(report, item)
        if source.as_posix().casefold() not in {
            path.casefold() for path in bucket["sources"]
        }:
            bucket["sources"].append(str(source))
        download_bucket = None
        if category == "history":
            download_bucket = _profile_bucket(reports["downloads"], item)
            if source.as_posix().casefold() not in {
                path.casefold() for path in download_bucket["sources"]
            }:
                download_bucket["sources"].append(str(source))

        try:
            if category == "history":
                if source.name.casefold() == "history":
                    tables = sqlite_table_names(acquired)
                    for table in ("urls", "visits"):
                        if table in tables:
                            _add_table_records(
                                bucket, table, sqlite_table_rows(acquired, table),
                                "history",
                            )
                    if not {"urls", "visits"}.intersection(tables):
                        bucket["errors"].append(
                            "No supported Chromium history tables found."
                        )
                elif source.name.casefold() == "places.sqlite":
                    tables = sqlite_table_names(acquired)
                    for table in ("moz_places", "moz_historyvisits"):
                        if table in tables:
                            _add_table_records(
                                bucket, table, sqlite_table_rows(acquired, table),
                                "history",
                            )
                    if not {"moz_places", "moz_historyvisits"}.intersection(tables):
                        bucket["errors"].append(
                            "No supported Firefox history tables found."
                        )
            elif category == "cookies":
                if source.name.casefold() in {"cookies", "cookies.sqlite"}:
                    rows = _cookie_metadata(acquired)
                    _add_table_records(bucket, "cookie_metadata", rows, "cookie")
            elif category == "login":
                if source.name.casefold() in {
                    "login data",
                    "logins.json",
                    "logins-backup.json",
                }:
                    rows = _login_metadata(acquired, item["browser"])
                    _add_table_records(bucket, "login_metadata", rows, "login")
            elif category == "web_data":
                if source.name.casefold() == "formhistory.sqlite":
                    tables = sqlite_table_names(acquired)
                    if "moz_formhistory" in tables:
                        count = query_rows(
                            acquired,
                            "SELECT COUNT(*) AS record_count FROM moz_formhistory",
                        )[0]["record_count"]
                        bucket["tables"]["form_history"] = [{
                            "record_count": count,
                            "columns": sqlite_table_columns(acquired, "moz_formhistory"),
                        }]
                elif source.name.casefold() == "web data":
                    bucket["tables"]["web_data_metadata"] = _web_data_metadata(acquired)
        except (OSError, ValueError, sqlite3.Error, json.JSONDecodeError) as exc:
            bucket["errors"].append(f"{source.name}: {exc}")

        if category == "history":
            try:
                if source.name.casefold() == "history":
                    tables = sqlite_table_names(acquired)
                    if "downloads" in tables:
                        _add_table_records(
                            _profile_bucket(reports["downloads"], item),
                            "downloads",
                            sqlite_table_rows(acquired, "downloads"),
                            "download",
                        )
                    if "downloads_url_chains" in tables:
                        _add_table_records(
                            _profile_bucket(reports["downloads"], item),
                            "downloads_url_chains",
                            sqlite_table_rows(acquired, "downloads_url_chains"),
                            "download_url",
                        )
                elif source.name.casefold() == "places.sqlite":
                    rows = _firefox_downloads(acquired)
                    if rows:
                        _add_table_records(
                            download_bucket,
                            "downloads",
                            rows,
                            "download",
                        )
            except (OSError, sqlite3.Error) as exc:
                download_bucket["errors"].append(
                    f"{source.name}: {exc}"
                )

    for item in acquired_files:
        if browser_category_for_file(item) != "cache":
            continue
        report = reports["cache"]
        if item.get("status") != "ACQUIRED" or not item.get("acquired_path"):
            report["errors"].append({
                "source_path": item["source_path"],
                "status": item.get("status"),
                "errors": item.get("errors", []),
            })
            continue

        source_key = os.path.normcase(os.path.abspath(item["source_path"]))
        if source_key in cache_sources:
            continue
        cache_sources.add(source_key)
        bucket = _profile_bucket(report, item)
        acquired_path = Path(item["acquired_path"])
        evidence_folder_index = next(
            (
                index for index, part in enumerate(acquired_path.parts)
                if part.casefold() == "browser artifacts_files"
            ),
            None,
        )
        relative_acquired = (
            Path(*acquired_path.parts[evidence_folder_index:]).as_posix()
            if evidence_folder_index is not None
            else acquired_path.name
        )
        record = {
            "source_path": item["source_path"],
            "acquired_path": relative_acquired,
            "size_bytes": item.get("source_metadata_before", {}).get("size_bytes"),
            "last_modified_utc": item.get("source_metadata_before", {}).get("mtime_utc"),
            "sha256": item.get("acquired_sha256"),
        }
        _add_table_records(bucket, "cache_files", [record], "cache_file")

    output_names = {
        "history": "Browser History.json",
        "downloads": "Browser Downloads.json",
        "cookies": "Browser Cookies Metadata.json",
        "login": "Browser Login Metadata.json",
        "web_data": "Browser Web Data Metadata.json",
        "cache": "Browser Cache Inventory.json",
    }
    primary_names = {
        "history": {"history", "places.sqlite"},
        "downloads": {"history", "places.sqlite"},
        "cookies": {"cookies", "cookies.sqlite"},
        "login": {"login data", "logins.json", "logins-backup.json"},
        "web_data": {"web data", "formhistory.sqlite"},
    }
    for key, report in reports.items():
        report.pop("_profile_index", None)
        total_records = 0
        for profile in report["profiles"]:
            profile.pop("_record_keys", None)
            profile["sources"].sort(key=str.casefold)
            if key in primary_names and profile["sources"] and not any(
                Path(source).name.casefold() in primary_names[key]
                for source in profile["sources"]
            ):
                profile["errors"].append(
                    "SQLite sidecars were acquired without the primary database."
                )
            total_records += sum(len(rows) for rows in profile["tables"].values())
            profile["record_count"] = sum(
                len(rows) for rows in profile["tables"].values()
            )
        report["profiles"].sort(
            key=lambda profile: (
                profile["user"].casefold(),
                profile["browser"].casefold(),
                profile["profile"].casefold(),
            )
        )
        report["profile_count"] = len(report["profiles"])
        report["record_count"] = total_records
        if key in {"cookies", "cache"}:
            report["errors"] = deduplicate_source_errors(report["errors"])
        report["collection_status"] = (
            "PARTIAL" if report["errors"] or any(
                profile["errors"] for profile in report["profiles"]
            )
            else "SUCCESS" if total_records or report["profiles"]
            else "NO_ACQUIRED_INPUT"
        )
        report["errors"].sort(key=lambda error: str(error.get("source_path", "")).casefold())
        report["_output_name"] = output_names[key]

    return reports


def deduplicate_source_errors(
    errors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    deduplicated: dict[str, dict[str, Any]] = {}
    unkeyed: list[dict[str, Any]] = []

    for error in errors:
        source_path = error.get("source_path")
        if not source_path:
            unkeyed.append(error)
            continue

        key = os.path.normcase(os.path.abspath(source_path))
        existing = deduplicated.get(key)
        if existing is None:
            deduplicated[key] = dict(error)
            existing_errors = error.get("errors", [])
            deduplicated[key]["errors"] = (
                list(existing_errors)
                if isinstance(existing_errors, list)
                else [existing_errors]
            )
            deduplicated[key]["_statuses"] = [error.get("status")]
            continue

        if error.get("status") not in existing["_statuses"]:
            existing["_statuses"].append(error.get("status"))
        messages = error.get("errors", [])
        if not isinstance(messages, list):
            messages = [messages]
        for message in messages:
            if message not in existing["errors"]:
                existing["errors"].append(message)

    for error in deduplicated.values():
        statuses = error.pop("_statuses")
        if len(statuses) > 1:
            error["statuses"] = statuses

    return [
        *unkeyed,
        *sorted(
            deduplicated.values(),
            key=lambda item: (
                str(item.get("source_path", "")).casefold(),
                str(item.get("status", "")).casefold(),
            ),
        ),
    ]


def parse_result_summary(reports: dict[str, dict[str, Any]]) -> dict[str, int]:
    return {
        "parse_errors": sum(
            len(report["errors"])
            + sum(len(profile["errors"]) for profile in report["profiles"])
            for report in reports.values()
        ),
        "records": sum(report["record_count"] for report in reports.values()),
    }


def run_collection(args: argparse.Namespace) -> int:
    if os.name != "nt":
        print("[ERROR] This module is designed for Windows.")
        return 2

    if not is_admin():
        print("[ERROR] Administrator privileges are required.")
        print("[INFO] Close this window and launch the module using")
        print("       your BAT file configured to request UAC elevation.")
        return 2

    case_root = args.case_root.resolve()
    evidence_root = args.output_dir.expanduser().resolve()
    derived_root = evidence_root
    files_root = evidence_root / "Browser Artifacts_Files"

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id += "_" + uuid.uuid4().hex[:8]
    profiles = discover_profiles(args.all_profiles)
    overlapping_profiles = [
        profile["profile_path"]
        for profile in profiles
        if output_overlaps_source(
            evidence_root, Path(profile["profile_path"])
        )
    ]
    if overlapping_profiles:
        print(
            "[FATAL] --output-dir is inside a recursively scanned browser "
            "profile. Select another destination; collection scope will not "
            "be narrowed. Overlapping profile(s): "
            + ", ".join(overlapping_profiles)
        )
        return 2
    collisions = [
        path for path in (
            evidence_root / "Browser Artifacts_Files",
        )
        if path.exists()
    ]
    if collisions:
        print(
            "[FATAL] Output collision; no files were overwritten: "
            + ", ".join(str(path) for path in collisions)
        )
        return 2
    evidence_root.mkdir(parents=True, exist_ok=True)
    files_root.mkdir(parents=True, exist_ok=True)
    excluded_paths = walk_exclusions()

    print(f"[INFO] Module: {MODULE} v{VERSION}")
    print(f"[INFO] Run ID: {run_id}")
    print(f"[INFO] Case root: {case_root}")

    acquisition = {
        "module": MODULE,
        "version": VERSION,
        "run_id": run_id,
        "started_utc": utc_now(),
        "case_root": str(case_root),
        "administrator": True,
        "all_profiles_requested": args.all_profiles,
        "profiles_discovered": profiles,
        "files": [],
        "errors": [],
    }

    if not profiles:
        acquisition["errors"].append(
            "No supported browser profiles were discovered."
        )

    total_files = 0

    for profile in profiles:
        print(
            f"[INFO] {profile['user']} | {profile['browser']} | "
            f"{profile['profile']}"
        )

        try:
            files = collectable_files(profile, excluded_paths)
        except Exception as exc:
            acquisition["errors"].append({
                "profile": profile,
                "error": str(exc),
            })
            continue

        for source in files:
            result = acquire_file(
                source, profile, evidence_root, run_id
            )
            acquisition["files"].append(result)
            total_files += 1

            print(
                f"       {result['status']}: {source.name}"
            )

    acquisition["finished_utc"] = utc_now()
    acquisition["files_considered"] = total_files

    print("[INFO] Parsing acquired databases...")
    parsed_reports = parse_acquired_databases(acquisition["files"], run_id)
    parse_result = parse_result_summary(parsed_reports)

    statuses = [item["status"] for item in acquisition["files"]]
    failures = [
        status for status in statuses
        if status not in {"ACQUIRED"}
    ]
    acquired_count = sum(
        1 for status in statuses if status == "ACQUIRED"
    )

    if any(status == "VERIFICATION_FAILED" for status in statuses):
        overall_status = "VERIFICATION_FAILED"
    elif not profiles:
        overall_status = "SOURCE_UNAVAILABLE"
    elif failures or acquisition["errors"] or parse_result["parse_errors"]:
        overall_status = "PARTIAL"
    elif acquired_count == 0:
        overall_status = "SOURCE_AVAILABLE_EMPTY"
    else:
        overall_status = "SUCCESS"

    acquisition["status"] = overall_status
    output_paths = []
    for report in parsed_reports.values():
        output_name = report.pop("_output_name")
        report["run_status"] = overall_status
        result_path = derived_root / output_name
        write_json(result_path, report)
        output_paths.append(result_path)

    print()
    print(f"[RESULT] Status: {overall_status}")
    print(f"[RESULT] Profiles: {len(profiles)}")
    print(f"[RESULT] Files acquired: {acquired_count}")
    print(f"[RESULT] Parsed records: {parse_result['records']}")
    for result_path in output_paths:
        print(f"[RESULT] Artifact output: {result_path}")

    return 0 if overall_status in {
        "SUCCESS", "SOURCE_AVAILABLE_EMPTY"
    } else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Custos A14 Browser Artifacts Collector"
    )
    parser.add_argument(
        "--case-root",
        type=Path,
        default=DEFAULT_CASE_ROOT,
        help="Custos case root (default: C:\\Custos\\Case001)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "Browser Artifacts_Output",
        help="Destination directory for all collected and generated files.",
    )
    parser.add_argument(
        "--all-profiles",
        action="store_true",
        help="Search eligible profile directories under C:\\Users",
    )

    args = parser.parse_args()

    try:
        return run_collection(args)
    except KeyboardInterrupt:
        print("\n[ERROR] Interrupted by user.")
        return 130
    except Exception as exc:
        print(f"[FATAL] {type(exc).__name__}: {exc}")
        return 1




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
