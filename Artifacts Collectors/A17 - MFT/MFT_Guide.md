# A17 — NTFS Master File Table acquisition

## Scope and safety

`$MFT` is the NTFS metadata file whose records describe files and directories
on an NTFS volume. This collector obtains the logical `$MFT` data stream for one local volume per
collector invocation. The launcher automatically runs it for every ready,
lettered local NTFS fixed or removable volume. It preserves each binary as the
primary artifact and writes separate operational collection-result JSON. It does not
parse the binary or acquire ordinary file contents.

The collector is read-only toward the source: it queries volume metadata and
invokes RawCopy to read the MFT. It does not repair, defragment, unlock, mount,
or change the source volume. A live system can still change `$MFT` while it is
being read, so the result is not an atomic snapshot or equivalent to
hardware-write-blocked offline acquisition. Never treat deleted-record flags
as proof that the content is recoverable.

## Requirements and RawCopy setup

- Windows with an accessible, unlocked local NTFS volume.
- The project's 64-bit interpreter:
  `E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe`
- Python 3.10 or newer; the collector uses only the Python standard library.
- Administrator rights are requested by the launcher because RawCopy needs
  low-level volume reads. Elevation does not guarantee every volume can be
  accessed.
- The verified `RawCopy64.exe` placed beside this README. The collector never
  downloads or installs the tool.

The upstream project is [jschicht/RawCopy](https://github.com/jschicht/RawCopy).
The `RawCopy64.exe` currently present in A17 was checked against the exact
x64 executable tracked by the pinned source revision
[0d8d690c0f0fe9d2c68c5fce02d26d0efa53459c](https://github.com/jschicht/RawCopy/commit/0d8d690c0f0fe9d2c68c5fce02d26d0efa53459c);
its `readme.txt` documents version 1.0.0.22 and the syntax used here. For a
replacement, obtain the x64 executable from the official repository.
The collector checks the PE version, x64 architecture, and pinned upstream Git
blob identifier before executing the file. This confirms that the executable
matches that repository object; it does not independently establish the
publisher's trustworthiness.

```text
E:\FYP Custos Forensic Suite\artifacts\A17 - MFT\RawCopy64.exe
```

The executable's PE version resource and x64 PE architecture are recorded. If
either does not match, or the file differs from the pinned upstream executable,
the collector refuses to execute it. The check uses the upstream Git blob
identifier solely to verify the tool binary; no MFT-content hash is generated
or added to the result JSON.
RawCopy is an older third-party tool; the upstream project does not provide a
modern Windows-version compatibility matrix. Its README says it is incompatible
with Windows 2000/NTFS 3.0. Validate the specific binary and target OS in a
controlled lab before relying on it.

### Verified invocation

RawCopy documents:

```text
RawCopy64.exe /FileNamePath:C:0 /OutputPath:<existing-folder> /OutputName:MFT-C.bin
```

`C:0` means file reference 0 on volume C:, the `$MFT` record. RawCopy reads the
NTFS file through its low-level reader and writes the file's default unnamed
data stream using the documented `/OutputName` override. `/AllAttr` is not
enabled: the target is the `$MFT` data stream, not every attribute of an
arbitrary record. The collector launches this as a Windows argument list with
`shell=False`; it does not use Git Bash or a shell command string.

References:

- [RawCopy source and documented `readme.txt`](https://github.com/jschicht/RawCopy)
- [RawCopy upstream change log](https://github.com/jschicht/RawCopy/blob/master/changelog.txt)
- [Microsoft `GetVolumeInformationW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw)
- [Microsoft `GetDiskFreeSpaceExW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexw)
- [Microsoft `NTFS_VOLUME_DATA_BUFFER`](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-ntfs_volume_data_buffer)
- [Microsoft `FSCTL_GET_NTFS_VOLUME_DATA`](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_ntfs_volume_data)

## Run the collector

Double-click `launch.bat`. It checks administrator access first and, if needed,
asks Windows to elevate the batch launcher itself using the standard `RunAs`
verb. This makes the launcher—not `python.exe`—the UAC target. It then checks
for the Python interpreter and RawCopy. With no command-line arguments it asks
only for an output folder after elevation; pressing Enter selects the default
`MFT_Output` folder beside the launcher. It discovers ready, lettered local
NTFS fixed and removable volumes and runs the same single-volume collector once
per discovered volume. Network drives, optical drives, non-NTFS volumes, and
volumes without a drive letter are not included. Output is separated into
`<output folder>\<drive letter>\` subfolders to prevent filename collisions.
Each volume receives its own binary and collection-result JSON. If one volume
fails or is partial, the launcher continues with the remaining volumes and
returns a nonzero result; review every per-volume JSON for coverage.
Canceling UAC ends without acquisition.

From Command Prompt, the no-argument launcher also collects all discovered
volumes and prompts only for the output directory:

```bat
"E:\FYP Custos Forensic Suite\artifacts\A17 - MFT\launch.bat"
```

To collect one explicitly selected volume, pass `--source` and `--output-dir`:

```bat
"E:\FYP Custos Forensic Suite\artifacts\A17 - MFT\launch.bat" --source C: --output-dir "D:\Forensic Output"
```

Direct invocation (does not elevate):

```bat
"E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" "E:\FYP Custos Forensic Suite\artifacts\A17 - MFT\collector.py" --source C: --output-dir "D:\Forensic Output"
```

The collector's output directory must already exist. The launcher creates the
root and per-volume directories automatically. Within each per-volume folder,
the final binary filename is `MFT-MFT-<drive letter>.bin`. If it already exists,
acquisition is refused; pass
`--overwrite` only when replacement is intended. RawCopy writes to a unique
temporary output first. The collector replaces the final file only after
successful checks; interrupted or invalid output is kept under a `.partial`
filename. The result JSON has a timestamped filename. Prefer a destination on
a different volume to reduce source-volume changes during a live acquisition.

## Generated files

1. **`MFT-C.bin`** — successfully acquired binary `$MFT` data stream. If
   validation fails after a file was produced, the collector retains it as
   `A17-MFT-C.partial-<UTC timestamp>.bin`. Neither is JSON or ordinary text.
   Keep the binary unchanged; use a compatible parser on a copy when needed.
2. **`MFT-collection-<UTC timestamp>.json`** — acquisition operation
   details, diagnostics, validation observations, errors, and limitations.
3. **Parser output** — not generated by this collector. Parsing is optional
   and independent of acquisition; a parser failure does not invalidate or
   replace the binary.

This implementation does not bundle or run MFTECmd or another parser. For
independent review, the official
[MFTECmd repository](https://github.com/EricZimmerman/MFTECmd) documents:

```bat
MFTECmd.exe -f "D:\Forensic Output\copy-of-MFT-C.bin" --json "D:\Forensic Output\Parsed MFT" --sn --at
```

`-f` selects the MFT binary, `--json` selects a separate parser-output folder,
`--sn` includes DOS filename types, and `--at` requests all timestamps from
the `$FILE_NAME` attribute. Check the README shipped with the parser version
you obtain. Parser output format and supported attributes depend on that
version; A17 does not fabricate parsed records or merge parser output into its
collection-result JSON.

## Collection-result JSON: every field

- `artifact_id` — constant `A17`.
- `artifact_name` — `MFT`.
- `collection_started_at_utc`, `collection_ended_at_utc` — operation start and
  end in UTC ISO 8601 with an explicit `+00:00` offset. These are collection
  times, not file timestamps.
- `collection_started_at_local`, `collection_ended_at_local` — those same
  instants converted to local ISO 8601 values with the applicable offset.
- `collection_time_zone_id`, `collection_time_zone_id_source`,
  `collection_time_zone_id_error`, `collection_clock_adjusted` — detected
  Windows zone identifier and source, any lookup error, and whether a backward
  clock adjustment required the end to be clamped. See
  [`COLLECTION_TIMESTAMPS.md`](../COLLECTION_TIMESTAMPS.md).
- `acquisition_status` — `success` means RawCopy exited 0 and output passed
  the defined checks; `partial` means an artifact was produced but a tool or
  validation problem occurred; `failed` means acquisition did not produce an
  output file. A separately reported JSON-write failure may also result in no
  saved result document.
- `parsing_status` — `not_requested`; no parser was run.
- `collection_host.operating_system` — host platform string.
- `collection_host.python_version` — Python version.
- `collection_host.python_architecture` — Python architecture used.
- `source.volume_specification` — user-supplied local drive, such as `C:`.
- `source.volume` — available source details: normalized root, label, volume
  serial number, filesystem name, filesystem flags, maximum component length,
  total/free bytes, and NTFS values.
- `source.volume.volume_root` — normalized drive root used for the volume
  queries; `volume_label` is the user-facing label and
  `volume_serial_number` is the serial reported by Windows.
- `source.volume.filesystem` — filesystem name; must be `NTFS`.
- `source.volume.filesystem_flags` — capability flags returned by Windows;
  the collector preserves the numeric value without inventing flag labels.
- `source.volume.maximum_component_length` — maximum filename-component
  length reported for that volume.
- `source.volume.total_bytes` and `free_bytes_available_to_caller` — total
  volume space and current free bytes visible to this caller; available space
  can be affected by quotas and can change after the check.
- `source.volume.ntfs.bytes_per_sector`, `bytes_per_cluster` — NTFS geometry
  returned by `FSCTL_GET_NTFS_VOLUME_DATA`.
- `source.volume.ntfs.bytes_per_file_record_segment` — reported MFT record
  segment size used for bounded structure checks.
- `source.volume.ntfs.mft_valid_data_length_bytes` — Windows-reported MFT
  length used as an expected-length comparison, not a promise of an atomic
  capture.
- `source.volume.ntfs.mft_start_lcn` — MFT starting logical cluster number;
  it is volume metadata, not a file path.
- The `source.volume.ntfs` values are geometry and MFT location/length context;
  none are timestamps.
- `acquisition_tool.name`, `path` — tool name and executable path.
- `acquisition_tool.file_version_resource` — version embedded in the local
  executable. The collector requires `1.0.0.22`.
- `acquisition_tool.pe_machine` — PE architecture code; this collector
  requires x64 (`0x8664`).
- `acquisition_tool.pinned_upstream_binary_match` — true after the local
  executable matches the pinned upstream Git blob identifier.
- `acquisition_tool.upstream_version_documented` — upstream README version
  associated with the pinned source revision.
- `acquisition_tool.upstream_source`, `upstream_revision` — source location
  and pinned source revision used to document the invocation.
- `acquisition_tool.acquisition_semantics` — states that MFT file reference 0
  and the default unnamed data stream are targeted.
- `invocation_arguments` — actual argument vector passed to RawCopy. It
  includes the selected source volume and output locations.
- `tool_exit_code` — RawCopy process exit status; null if it was not launched.
- `output.mft_binary_path` — final binary path on success, retained `.partial`
  path when the tool produced an incomplete or invalid file, or null if no
  binary was created.
- `output.mft_size_bytes` — observed size if the file exists, otherwise null.
- `output.result_json_path` — collection-result JSON destination.
- `diagnostics.stdout`, `diagnostics.stderr` — tool output captured as UTF-8
  text with replacement for undecodable bytes. `interrupted` indicates
  interruption handled by the wrapper.
- `validation_checks.exists` — whether the expected binary exists.
- `validation_checks.size_bytes` — observed binary length.
- `validation_checks.record_size_bytes` — record size reported by Windows.
- `validation_checks.expected_mft_length_bytes` — Windows MFT length used for
  size comparison.
- `validation_checks.record_size_aligned` — whether output length is an exact
  multiple of the reported MFT record size.
- `validation_checks.expected_length_matches` — whether output length equals
  the reported MFT valid-data length; null if unavailable.
- `validation_checks.sampled_record_offsets` — bounded sample record indexes
  and their four-byte signature (`FILE`, `BAAD`, or other decoded bytes), plus
  whether each signature is recognized. The first record must be `FILE` for
  this check to pass; other sampled positions may be uninitialized.
- `validation_checks.sampled_file_signatures`, `sampled_records` — sample
  totals. Empty/uninitialized records need not have a FILE signature.
- `validation_checks.record_zero_signature` — first MFT record signature.
- `validation_checks.valid` — conservative structural plausibility result,
  not a proof of complete acquisition or MFT integrity.
- `validation_checks.limitations` — scope of the structural checks.
- `errors` — failures with `category`, exception type, Win32 error when
  present, and message.
- `limitations` — known scope and interpretation boundaries for this run.

### Status and exit codes

Collector process exit codes: `0` success, `1` partial, `2` failure, including
UAC cancellation. RawCopy's exit code is separately recorded in
`tool_exit_code`; a zero tool code alone does not establish a valid artifact.
The JSON `acquisition_status` is the acquisition outcome; `parsing_status`
remains `not_requested`.

## Reading MFT data and limits

A binary MFT contains fixed-size records and NTFS attributes, not ready-to-read
paths. Use a parser that understands the target NTFS record format and
attributes. The collector does not parse, discard, or summarize parser fields.
If parsing is done separately:

- A record number/reference identifies an MFT slot; it is not necessarily a
  complete path. Parent references may be unresolved or reused.
- Sequence numbers help distinguish record reuse; they do not make historical
  reconstruction complete.
- Multiple `$FILE_NAME` attributes can represent hard links or DOS/Win32 names.
  Do not silently choose one if a parser exposes several.
- In-use/deleted flags describe record state observed by the parser, not
  recoverability of file content.
- `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps are different metadata
  attributes. They do not independently prove user activity.
- Resident/nonresident and named data-stream fields describe storage metadata;
  this task does not extract file or alternate-stream contents.
- A security ID in a record is not automatically a resolved security
  descriptor or permissions list.
- Unsupported attributes, parse errors, and unresolved paths are parser
  limitations and should be preserved in any separately created parser output.
- Acquisition success and parser success are independent; a parser can fail or
  not understand data in an otherwise acquired MFT.

## Validation

1. Confirm the requested drive is a local NTFS volume in Explorer or with
   `Get-Volume -DriveLetter C` (substitute the selected letter). The collector
   independently calls `GetVolumeInformationW`; it rejects non-NTFS volumes.
2. Check that the binary and result JSON exist, that the JSON says
   `acquisition_status: success`, and that the `tool_exit_code` is zero.
3. Review JSON `validation_checks`: record-size alignment, expected length,
   and bounded `FILE`/`BAAD` signatures. Not every record/region must begin
   with `FILE`; uninitialized slots and other record states exist.
4. Independently open a copy of the binary with a compatible MFT parser. Check
   that it recognizes the expected record size and record 0, and retain parser
   warnings and extra supported fields. This parser validation is not performed
   by this collector.
5. Compare a small set of known files with parser output and current filesystem
   metadata. Run comparisons close in time and account for live changes,
   multiple names, unresolved parent references, and timestamp semantics.
6. Use fixtures/mocks for invalid volume, missing tool, tool failure, bad
   signature, overwrite refusal, and parsing-not-requested behavior. Do not
   alter real service/volume state or corrupt/fill a disk to create failures.
7. Test UAC approval, cancellation, argument forwarding, and already-elevated
   launch manually on Windows. These launcher checks have not been performed
   automatically.

## Common issues

- **RawCopy not found** — obtain and verify `RawCopy64.exe` manually and place
  it in the A17 folder. Nothing is downloaded automatically.
- **UAC cancelled** — no acquisition is started; approve the prompt to
  continue.
- **Drive unavailable or BitLocker locked** — unlock it manually through the
  approved Windows workflow, then rerun. The collector does not unlock volumes
  or request recovery keys.
- **Volume is not NTFS** — select a local NTFS drive; other filesystems are not
  supported by this collector.
- **Access denied / cannot query NTFS data** — run `launch.bat` and approve
  UAC. Some protected or unavailable volumes may still fail.
- **Insufficient destination space** — select an existing folder with at least
  the reported MFT length available; additional working space is prudent.
- **Existing MFT output** — choose another output folder or pass `--overwrite`
  only if replacing that file is intended.
- **Partial result** — preserve the binary and JSON; inspect tool diagnostics,
  exit code, size checks, and signature samples. Do not rename a partial
  artifact as successful.

## Coverage

| Information | Acquisition/parser source | Available conditions | Limitation |
|---|---|---|---|
| Raw `$MFT` unnamed data stream | RawCopy64; NTFS file reference 0 | RawCopy binary verified, Windows, accessible unlocked NTFS volume, administrator access | Live changes possible; no atomic snapshot; no guarantee all historical/deleted content survives |
| Volume label, serial, filesystem and flags | `GetVolumeInformationW` | Volume accessible to caller | Metadata can be unavailable for locked or inaccessible volumes |
| Source-volume free space | `GetDiskFreeSpaceExW` | Source volume accessible to caller | Quotas can affect available bytes; value is an observation |
| Destination free-space estimate | `shutil.disk_usage` | Destination exists and is accessible | Space can change after check; not a reservation |
| MFT length and record size | `FSCTL_GET_NTFS_VOLUME_DATA` / `NTFS_VOLUME_DATA_BUFFER` | Read access to NTFS volume metadata | Used as comparison context; not a snapshot guarantee |
| Sampled record signatures | Bounded reads at record 0 and four spread points | Output file exists and record size is known | Plausibility only; does not inspect every record or prove complete/integral MFT |
| Parsed MFT fields | Not implemented | Use a separate compatible parser on a copy | No parser records, paths, timestamps, flags, or attributes are emitted by A17 |
