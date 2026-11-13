# A18 — Windows Recycle Bin collector

A18 reads the on-disk Recycle Bin locations selected by the operator. It
preserves modern `$I` metadata files, parses supported `$I` metadata, and
records corresponding `$R` items. It copies `$R` content only when the
operator explicitly selects content collection. It never restores, deletes,
renames, moves, or executes a source item.

Collection is scoped to all accessible, lettered local fixed and removable
drives discovered when the launcher runs. Network drives and unavailable
volumes are not included. A18 automatically checks all SID folders found
below each discovered volume's Recycle Bin roots. Access denial is reported
as incomplete scope, not as an empty Recycle Bin.

## What Windows stores

Modern Windows stores each user's Recycle Bin entries below a volume-specific
directory such as `D:\$Recycle.Bin\S-1-5-21-...`. The volume is part of an
entry's identity: identical generated filenames on different volumes are
separate entries. A SID directory is the Recycle Bin ownership context. It
does not establish which human performed a deletion.

For modern formats:

- `$I...` is the per-item index/metadata file. Its binary data contains a
  format version, the original size, a Windows FILETIME deletion time, and
  the original path.
- `$R...` is the corresponding recycled file or directory content. Pairing
  uses the exact generated name with its leading `$I` changed to `$R`, and is
  limited to the same volume and SID folder. Original filenames are not used
  to make pairs.
- A matching `$R` can be missing, inaccessible, or a reparse point. A `$I`
  can be orphaned; an `$R` without `$I` is recorded as an orphan.

Windows 95 through Server 2003 used legacy `INFO`/`INFO2` formats in
locations such as `RECYCLER` or `RECYCLED`. A18 detects and preserves those
index files separately as unsupported legacy items. It does not parse an
`INFO`/`INFO2` file as a modern `$I` record.

## Verified modern `$I` formats and references

The parser supports only the two layouts implemented by maintained Rifiuti2
source:

| Version | Verified layout used by A18 |
|---|---|
| 1 (Vista layout) | 8-byte little-endian version at offset 0; 8-byte original size at offset 8; 8-byte FILETIME at offset 16; a fixed 520-byte UTF-16LE path area at offset 24 (544 bytes total). Rifiuti2 documents a rare 543-byte variant; A18 preserves it, withholds the unreliable size, and reports a warning. |
| 2 (Windows 10 layout) | Same 8-byte version, size and FILETIME fields; a 4-byte little-endian UTF-16 character count at offset 24; path bytes begin at offset 28 and are limited by that count. The path is not inferred from unused trailing bytes. |

Short files, malformed UTF-16, unreasonable/truncated path boundaries, and
unknown versions stay preserved as original bytes and are reported as
malformed, partial, or unsupported. A18 does not guess a layout from a
filename. Version 1 is the supported fixed-size layout even when a warning
identifies a nonstandard length. FILETIME is retained as its original integer
and converted from 100-nanosecond ticks since 1601-01-01 UTC. ISO output has
microsecond precision; the remaining 0–9 ticks are separately retained.
Invalid/out-of-range times have a null UTC conversion, not an invented date.

Implementation references (upstream parser source and documentation):

- [Rifiuti2 project documentation](https://abelcheung.github.io/rifiuti2/)
- [Rifiuti2 `$I` layout offsets](https://github.com/abelcheung/rifiuti2/blob/master/src/rifiuti-vista.h)
- [Rifiuti2 modern metadata parser](https://github.com/abelcheung/rifiuti2/blob/master/src/rifiuti-vista.c) — version checks, path boundaries, FILETIME and `$I` to `$R` pairing.
- [Rifiuti2 format-version declarations](https://github.com/abelcheung/rifiuti2/blob/master/src/utils.h) — versions 1 and 2 for modern `$Recycle.bin`; legacy INFO formats are separate.
- [Microsoft: File Times](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times) — FILETIME epoch, UTC representation and precision context.

A18 contains a small parser for these verified fields and has no third-party
Python package dependency. Rifiuti2 is an optional independent validation
reference; it is not automatically downloaded or run by A18. It can report
the modern index fields, but should be used only with a compatible version and
its output timezone options understood. Compare parsed values to the original
index filename and bytes; do not treat the parser as an acquisition tool.

## Requirements and administrator access

- Windows with Python 3.12 in the existing project environment:
  `E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe`
- No packages are installed by this collector. It uses the Python standard
  library and Windows APIs for drive type and local-only SID account lookup.
- `launch.bat` checks elevation and requests the standard Windows UAC approval
  before starting the collector. If approval is cancelled, collection does
  not start. Run as administrator to improve access, but elevation does not
  guarantee access to every volume or SID folder.
- Sources must be accessible local fixed/removable drive letters. Network
  shares are not included.

Local account resolution uses Windows `LookupAccountSidW` against the local
computer (`.`) only. It does not intentionally query a domain controller or
remote computer. Unresolved SIDs remain in the output as valid identifiers.

## Launching and selecting scope

Double-click `launch.bat`. It requests administrator permission, then prompts
only for an output folder; press Enter to use the default
`Recycle Bin_Output` folder beside the launcher. A18 discovers all accessible
local fixed and removable drive letters and enumerates every SID folder on
them. Unavailable volumes are reported and skipped. No source-drive, SID, or
collection-mode prompt is shown.

Metadata-only is always the launcher's default. `$R` items are never copied
unless `--collect-content` is explicitly supplied on the command line.
Network drives are not included. A18 creates the timestamped run folder under
the chosen output destination.

Command-line examples:

```bat
"E:\FYP Custos Forensic Suite\artifacts\A18 - Recycle Bin\launch.bat"

"E:\FYP Custos Forensic Suite\artifacts\A18 - Recycle Bin\launch.bat" --volume D: --volume E:

"E:\FYP Custos Forensic Suite\artifacts\A18 - Recycle Bin\launch.bat" --volume D: --collect-content
```

Run the collector directly (does not elevate):

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" "E:\FYP Custos Forensic Suite\artifacts\A18 - Recycle Bin\collector.py" --volume D:
```

For an explicitly scoped run, repeat `--volume`; if no `--volume` arguments
are supplied, A18 automatically discovers accessible local fixed and
removable drives. A18 always enumerates all accessible SID folders on the
selected/discovered volumes. Use `--collect-content` only when `$R` content
is in scope. Provide `--output-dir` to select another folder; otherwise the
A18 artifact folder is used. `--overwrite` explicitly
permits replacement if an individual output file collides within a run;
without it, existing files are protected. A18 always creates a new
timestamped acquisition subfolder and never reuses or clears an existing run
folder. If a timestamped folder already exists, choose a new destination or
retry later; `--overwrite` does not delete/rebuild a run folder.

Exit codes:

- `0` — successful scoped enumeration and collection (including a successfully
  enumerated empty scope).
- `1` — partial collection, incomplete enumeration, unsupported/malformed
  metadata, access/copy errors, or skipped content.
- `2` — invalid arguments/scope, output setup failure, or collection could not
  start.

## Output layout

The chosen destination must already exist and must not be inside any selected
volume's `$Recycle.Bin` tree. A18 creates a unique UTC-stamped acquisition
folder there:

```text
<chosen destination>\
  A18-RecycleBin-<UTC timestamp>\
    Recycle Bin-collection.json
    volume-D\
      S-1-5-21-...\
        metadata\
          $I<generated-name>
        content\
          $R<generated-name>
      legacy_metadata\
        RECYCLER\
          S-1-5-21-...\
            INFO2
```

`metadata` holds byte-for-byte copies of modern `$I` files, including malformed
and unsupported files. `content` is created only as needed in content mode and
contains copied matching and orphan `$R` files/directories. Legacy indexes
are kept in `legacy_metadata` and separately identified as unsupported.
Volume and SID directories keep same-named generated items distinct. No source
item is restored or moved.

File copies are binary-safe. A18 reports observed source changes and individual
child copy errors. Reparse points are recorded but skipped. Directory
filesystem entry size is not treated as the sum of its children. Ordinary
copies preserve selected file bytes, not source filesystem metadata or
timestamps; destination creation/write times reflect the copy. They do not
preserve every NTFS property, including ACLs, alternate data streams,
sparse/compressed allocation, hard-link relationships, or exact filesystem
structure.

## JSON field guide

The UTF-8 `Recycle Bin-collection.json` contains:

### Top-level fields

- `artifact_id` — `A18`.
- `collection_started_at_utc`, `collection_ended_at_utc` — observation interval
  in UTC ISO 8601.
- `collection_started_at_local`, `collection_ended_at_local` — the same
  boundary instants in local ISO 8601 with explicit offsets.
- `collection_time_zone_id`, `collection_time_zone_id_source`,
  `collection_time_zone_id_error`, `collection_clock_adjusted` — detected
  Windows zone ID and source, lookup error if any, and backward-clock clamp
  indicator. The source `$I` deletion timestamp is historical; its UTC value
  remains unchanged, with a separate `deletion_time_local` display value.
  See
  [`COLLECTION_TIMESTAMPS.md`](../COLLECTION_TIMESTAMPS.md).
- `status` — overall `success`, `partial`, or `failed`.
- `cancelled` — true when Ctrl+C stopped collection after it began; A18 writes
  the entries already recorded and marks the scope incomplete when it can.
- `acquisition_status` — `success`, `partial`, or `failed` assessment of
  scoped enumeration and preserving selected metadata.
- `metadata_parsing_status` — `complete` or `partial`; malformed, unknown,
  truncated, inaccessible, or legacy formats make this partial. A successfully
  enumerated empty scope has no records to parse and remains complete.
- `content_copy_status` — `not_requested`, `complete`, `partial`, or `failed`;
  content outcomes are per-entry in all cases.
- `collection_mode` — `metadata_only` or `metadata_plus_content`.
- `scope.selected_volumes` — normalized selected drive roots.
- `scope.sid_scope` — always `all_accessible_sid_folders`; A18 has no SID filter.
- `scope.selected_sids` — always null because all accessible SID folders are included.
- `scope.output_destination` — selected existing destination, or the A18
  artifact folder when no destination was provided.
- `scope.collection_output_root` — timestamped folder created for this run.
- `enumeration.complete` — whether all enumerated selected locations were
  accessible and completely listed. Missing roots are recorded as absent;
  access denial makes this false.
- `enumeration.locations` — each attempted root/SID directory with
  `path`, `status` (`enumerated`, `not_present`, or `inaccessible`) and
  `complete`.
- `entries` — one record for each discovered `$I` or `$R`, including orphans.
- `unsupported_items` — detected legacy INFO/INFO2 indexes; preserved without
  modern parsing.
- `unclassified_items` — non-`$I`/`$R` items directly in SID folders and
  non-SID items at roots enumerated during all-SID collection. They are inventoried,
  not interpreted as records.
- `counts.entries` — length of `entries`.
- `counts.pairs` — records with `pairing_status` `paired`.
- `counts.unpaired_entries` — `$I`-only plus `$R`-only records.
- `counts.ambiguous_pairs` — same-suffix ambiguous names retained without
  guessing a pair.
- `counts.parse_failures` — unreadable, malformed, unsupported, or partial
  modern `$I` parses.
- `counts.copy_failures` — failed metadata/content or legacy-index copies.
- `counts.unsupported_legacy_indexes` — number of preserved legacy indexes.
- `counts.unclassified_items` — number of unrelated/unclassified items recorded
  inside SID folders or at selected Recycle Bin roots.
- `output_paths.collection_json` — result JSON path.
- `errors` — scope-wide errors with `stage`, `source_path`,
  `exception_type`, `winerror`, and `message`.
- `limitations` — known limits recorded for this run.

### Entry fields

- `source_volume`, `recycle_bin_root`, `sid_folder_name` — source identity
  context. Entries from different values are not merged.
- `resolved_account_name` — local account name if the local-only lookup
  succeeds; otherwise null.
- `account_resolution` — lookup result, such as `local_computer_lookup`,
  `unresolved_local_only`, or `not_available_off_windows`.
- `i_filename`, `i_source_path`, `i_output_path` — original `$I` identity and
  preserved-copy path. These are null for an orphan `$R`.
- `metadata_preservation_status` — `copied`, `partial`, `failed`, or
  `not_applicable`.
- `r_filename`, `r_source_path` — paired or orphan `$R` identity. Null when
  absent.
- `pairing_status` — `paired`, `i_only`, `r_only`, or `ambiguous`.
- `i_format_version` — verified numeric version 1/2, unknown numeric version,
  or null if no version could be read.
- `metadata_parse_status` — `parsed`, `partial`, `malformed`, `unsupported`,
  `unreadable`, or `not_applicable`.
- `original_path` — decoded path only when the supported path field is
  complete and valid; otherwise null.
- `original_size_bytes` — size reported by `$I`, or null if invalid/unavailable.
  This is distinct from current `$R` observed size.
- `deletion_time_filetime_100ns` — raw unsigned FILETIME ticks.
- `deletion_time_utc` — converted ISO 8601 UTC time, or null if invalid.
- `deletion_time_local` — the same instant converted to the collector
  computer's local timezone, or null if invalid. This is a display conversion;
  the original FILETIME and UTC value remain authoritative.
- `deletion_time_100ns_remainder` — sub-microsecond tick remainder (0–9);
  preserves precision not representable in Python's datetime.
- `i_file_size_bytes` — currently observed size of the `$I` filesystem entry.
- `i_filesystem_metadata`, `r_filesystem_metadata` — observed kind,
  reparse status, entry size, available creation/write/access UTC timestamps,
  device and file identifier. Filesystem timestamps describe the live source,
  not the deletion event.
- `r_item_type` — `file`, `directory`, `reparse_point`, `missing`,
  `inaccessible`, or `other`.
- `observed_content_size_bytes` — current `$R` file size observed on the
  source. Null for directories: their entry size is not recursive content
  size.
- `content_copy_status` — `not_requested`, `not_started`, `copied`,
  `partial`, `failed`, `missing`, `inaccessible`, `skipped_reparse_point`, or
  `unsupported_item_type`.
- `content_output_path` — destination path when content copying was attempted.
- `content_copy_summary` — copied file/directory counts, accessible byte sum,
  and status for copied items. `bytes` reports bytes copied during this run,
  not a source directory's total size.
- `parse_warnings` — boundaries, encoding, timestamp, or format concerns.
- `collection_observed_at_utc` — entry observation time.
- `errors` — entry-level errors with stage, source path, exception type,
  Windows error when available, and message.

For `unsupported_items`, `source_volume`, `legacy_root`, `sid_folder_name`,
`source_path`, `filename`, `format`, `parse_status`, `reason`,
`filesystem_metadata`, `output_path`, `preservation_status`, and `errors`
describe the detected legacy INFO/INFO2 index and its preserved original copy.
For `unclassified_items`, `source_volume`, `scope_location`, `source_path`,
`filesystem_metadata`, `reason`, optional `sid_folder_name`, and optional
`error` describe an item not interpreted as a modern recycle-bin record.

Every `filesystem_metadata` object contains `kind`, `reparse_point`,
`size_bytes`, `creation_time_utc`, `last_write_time_utc`,
`last_access_time_utc`, `device_id`, and `file_id`. Timestamps can be null
when unavailable or outside the representable range. The `errors` objects
contain `stage`, `source_path`, `exception_type`, `winerror`, and `message`.

### Pairing and size examples (illustrative only)

If one SID directory contains `$Iabc` and `$Rabc`, they are paired by that
generated name. `$Iabc` without `$Rabc` is `i_only`; `$Rabc` without `$Iabc`
is `r_only`. The same generated name in another volume or SID directory is a
different entry. A zero-byte `$R` file is valid and has an observed size of
zero. A directory's `$I` original size remains what the metadata reported;
its current directory-entry size is not the recursive size of `$R` contents.

A FILETIME example such as `2026-10-10T17:14:30.123456+00:00` is an illustrative
UTC conversion only. The timestamp is metadata about the Recycle Bin record;
it does not identify the person who caused the deletion or the time a file was
permanently erased.

## Validation guide

For controlled manual validation on an authorized lab system:

1. Make a disposable test file containing known bytes on a selected test
   volume, delete it into the Recycle Bin through normal Windows behavior, and
   record its SID folder, `$I` bytes and paired `$R` data. Do not empty the bin.
2. Run metadata-only collection for that volume/SID. Confirm `$I` bytes are
   unchanged in `metadata`, correct parsed version/path/size/time fields,
   matching `$R` metadata, and no `content` copy.
3. Repeat with `--collect-content`; compare source and output file bytes
   directly on a stable fixture. No hashes are calculated.
4. For parser cross-checking, run a compatible Rifiuti2 `rifiuti-vista`
   executable against a copied fixture SID folder and compare path, size,
   version and deletion time with UTC/timezone output options accounted for.
   Rifiuti2 is an independent parser, not a substitute for byte preservation.
5. Build synthetic fixture bytes for both supported versions, long v2 paths,
   Unicode paths, zero size, truncated fields, invalid UTF-16, unknown
   versions, zero/out-of-range FILETIME and the documented 543-byte v1 variant.
6. Test same generated names in different volume/SID scopes, `$I`-only,
   `$R`-only, ambiguous suffixes, inaccessible paths, a disappearing source,
   reparse points, partially readable directory children, output inside source
   rejection, spaces in output paths, and existing destination collisions.
7. Confirm access denial leaves `enumeration.complete` false and never becomes
   an empty-bin success. Verify output JSON decodes as UTF-8 and all counts
   agree with `entries`/`unsupported_items`.
8. From another working directory, test quoted command-line arguments and
   exit codes. Manually test UAC approval, cancellation, and already-elevated
   execution on a controlled machine.
9. Compare source filesystem listings and metadata before/after. A18 has no
   code path for restore, delete, move, rename, permission changes, or
   Recycle Bin emptying.

Record manual live acquisition, independent-parser comparison, and UAC tests
separately. No such manual validation is claimed by this README.

## Common issues and limits

- **UAC cancelled:** run again and approve, or stop; no collection starts.
- **Python not found:** restore the existing `.venv` or update the launcher
  only after confirming the approved Python executable path.
- **SID inaccessible:** run elevated if authorized; A18 will retain the
  location error and mark enumeration incomplete. It will not change ACLs.
- **No `$Recycle.Bin` folder:** the selected path is recorded as not present.
  The collector does not search unselected volumes or unallocated space.
- **Malformed or unsupported `$I`:** the original bytes are still preserved
  when readable; parsed values remain null where not verified.
- **Missing `$R`:** `$I` is retained as `i_only`; it is not automatically
  searched by original filename.
- **Destination conflict:** choose a new output folder or explicitly use
  `--overwrite` only when replacing an existing output file is intended.
- **Partial directory copy:** inspect each entry's errors and summary. A
  directory is not called complete if a child is inaccessible, changes, or is
  skipped.

## Coverage reference

| Information | Source/parser | Meaning | Availability or limitation |
|---|---|---|---|
| Selected volume and Recycle Bin root | Explicit drive selection; filesystem enumeration | Identifies the source volume and its `$Recycle.Bin` or legacy root | No automatic scan of unselected volumes; only local fixed/removable letters |
| SID folder | On-disk SID directory name | Recycle Bin ownership context | Not proof of a human actor; inaccessible SID folders are errors |
| Resolved account | Local-only `LookupAccountSidW` against `.` | Local account name when the selected host can resolve it | No intentional domain/remote lookup; unresolved SID remains recorded |
| `$I` format/version | Rifiuti2-verified v1/v2 field offsets; A18 parser | Identifies supported modern metadata layout | Unknown versions and malformed data are preserved, not guessed |
| Original path and original size | Parsed `$I` bytes | Values reported by Windows Recycle Bin metadata | Null if field is incomplete/invalid; not derived from `$R` |
| Deletion time | Raw FILETIME from `$I`, converted to UTC | Metadata timestamp associated with the recycle record | Invalid time retains raw ticks and has null UTC; does not attribute a person |
| `$I` source bytes | Binary-safe file copy | Preserves readable original metadata file | Copy can fail or source can change; ordinary copy does not preserve all NTFS attributes |
| `$R` pairing and kind | Same-folder generated-name pairing plus `lstat` metadata | Finds corresponding recycled file/directory and its present state | Missing, ambiguous, inaccessible and orphan entries are reported |
| `$R` observed size | Current filesystem metadata | Current file length; directory entry size only for directories | Not the original `$I` size; directory entry size is not recursive size |
| Optional `$R` content | Binary-safe copy to selected output | Copies selected file bytes or traverses selected directory | Opt-in only; reparse points skipped; inaccessible/changed children make it partial |
| Legacy INFO/INFO2 | On-disk legacy roots and filenames | Identifies older Recycle Bin index formats | Preserved separately; A18 does not parse these formats |
| Collection observations/errors | A18 enumeration and filesystem calls | Records scope, collection times, statuses, warnings and failures | Live data can change; access denial prevents a completeness claim |

Live Recycle Bin data may change while the collector runs. A standard copy is
not a forensic image, write blocker, volume snapshot, or complete preservation
of NTFS metadata. Complete coverage means only the selected, accessible
Recycle Bin contents observed during this run. It excludes already emptied or
permanently deleted items and files deleted outside the Recycle Bin. Running
collection software can affect the live OS, including access-time behavior.
