# A14 — Browser Artifacts

## Run and scope

Windows-only; elevated privileges are required. The collector uses Python
standard-library modules, including `sqlite3`. `--case-root` is metadata,
`--output-dir` selects the output directory, and `--all-profiles` searches
eligible profiles under `C:\Users`. Otherwise, current-profile discovery
honors `CUSTOS_ORIGINAL_PROFILE`, then `Path.home()`.

The collector covers the supported Chromium profiles (Chrome, Edge, Brave,
Chromium, and Vivaldi), Firefox profile databases, and browser cache paths
listed in `collector.py`. Acquired files are byte copies under
`Browser Artifacts_Files/<user>/<browser>/<profile>/`; source basenames and
relative paths are preserved. Existing output collisions are not overwritten.
Output directories inside a recursively scanned profile are rejected.

## Output files

The output directory contains six category JSON files and one
`Browser Artifacts_Hash & Timestamp Report.json`. It does not create an
acquisition manifest, standalone verification report, or collection summary.

* `Browser History.json` — Chromium `urls` and `visits` rows; Firefox
  `moz_places` and `moz_historyvisits` rows. SQLite columns and native values
  are preserved with a `record_type` field.
* `Browser Downloads.json` — Chromium `downloads` and
  `downloads_url_chains` rows; Firefox download annotations when supported by
  the acquired Places schema.
* `Browser Cookies Metadata.json` — cookie names, host/path and available
  timestamps/security metadata. Cookie values are not included in this report.
* `Browser Login Metadata.json` — login origin and available usage/time
  metadata. Usernames, passwords, and encrypted credential values are not
  included; Firefox encrypted-field presence is represented as booleans.
* `Browser Web Data Metadata.json` — database table names, column names, and
  row counts. Autofill, payment, and other Web Data row contents are not
  disclosed in this report.
* `Browser Cache Inventory.json` — one inventory record per acquired cache
  file with its relative output path, size, last-modified time, and SHA-256.
* `Browser Artifacts_Hash & Timestamp Report.json` — the standard report for
  the saved category JSONs and acquired evidence files.

Each category file includes run metadata, its collection status, profile
identifiers, source paths, record counts, and category-specific errors. A
missing database is not represented as a successful empty parse. Repeated
records within a table are deduplicated by their complete serialized row;
records from different browser profiles remain separate.

## Interpretation and validation

Browser database timestamps are retained in their native units; they are not
converted to local time. SQLite schemas vary by browser version, and parsing
errors are recorded rather than treated as empty results. Live profiles can
change during collection. The acquired files, including relevant WAL/SHM
sidecars, are primary evidence; parsed category JSONs are derived output.

The hash/timestamp report lists saved files and their SHA-256 values. Compare
category records with the corresponding acquired database using a read-only
SQLite/browser-forensics parser. Do not infer that a record identifies a
specific person or action without corroborating evidence.

Copied browser databases may contain sensitive data even when the derived
metadata reports omit credential and cookie values. Protect the output
directory accordingly. The collector does not decrypt credentials.
