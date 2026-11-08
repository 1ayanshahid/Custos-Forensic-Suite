# A01 — RAM / Physical Memory Acquisition

A01 acquires a raw Windows physical-memory image using the downloaded
`go-winpmem_amd64_1.0-rc2_signed.exe` stored in this artifact folder. It does
not download tools, install Python packages, or change Windows security
settings. The previous Belkasoft vendor package has been removed.

## Files and preserved data

- `launch.bat` requests standard Windows UAC permission and starts A01.
- `collector.py` validates the destination and free-space estimate, runs
  WinPmem, retains bounded tool diagnostics, and writes a separate collection
  result JSON.
- `go-winpmem_amd64_1.0-rc2_signed.exe` is the existing external tool. Keep it
  in this folder.
- Existing `.mem`, `.cfg`, screenshots, and other validation materials are
  preserved; removing the Belkasoft vendor package does not remove prior
  captures.

## Tool and verified command

The actual executable was inspected in place. Its help identifies it as a
Windows memory-acquisition tool and advertises this command shape:

```text
winpmem acquire [<flags>] [<filename>]
```

The exact binary's `help acquire` output advertises `--progress`,
`--driver_path`, `--service_name`, `--nosparse`, and
`--compression=snappy|gzip`. It has no `--version` command and no PE
product/file version metadata. The filename supplies the available version
label `1.0-rc2`; a more precise embedded version could not be verified.
Although the filename contains `signed`, Windows Authenticode inspection
reported `NotSigned`. Windows may block its driver; A01 reports such failures
and does not bypass them or change test-signing, driver-blocking, or other
security policy.

The upstream `acquire.go` source sets compression to `none` by default and
shows sparse output enabled unless `--nosparse` is passed. A01 therefore
omits compression flags to request uncompressed raw output and retains the
default sparse-file behavior. It passes only the inspected flags:

```text
go-winpmem_amd64_1.0-rc2_signed.exe --verbose acquire --progress <unique-output.raw>
```

`--verbose` is a global flag, so it precedes the `acquire` command.
`--progress` is an acquire flag. No output image is produced during
implementation or during tool-help checks.

Official references:

- [WinPmem repository README](https://github.com/Velocidex/WinPmem)
- [Upstream acquire command source](https://github.com/Velocidex/WinPmem/blob/f59d776a3defc6aa869fdcb0bbe3aafe39ee1a55/go-winpmem/cmd/acquire.go)

## Requirements and launch

- Windows, Python 3.12 in the existing project environment, and the existing
  WinPmem executable.
- Administrator approval through ordinary UAC. The acquisition driver
  requires privileged access. If Windows blocks it, stop and follow your
  organization's policy; do not disable protections.
- Double-click `launch.bat`. It asks once:

  > Enter a custom save folder, or press Enter to save in this artifact folder:

  Press Enter to use the A01 artifact folder. A custom destination must
  already exist. Paths with spaces are accepted.
- The launcher resolves Python as `.venv\Scripts\python.exe` relative to the
  project root derived from its own location, so the current working directory
  does not matter.
- The launcher asks for the destination before requesting UAC so the prompt
  remains interactive. Acquisition begins only after UAC approval. It waits
  for the elevated collector and returns its exit code.
- If already elevated, the collector runs directly after the destination
  prompt.

Command-line examples from Command Prompt:

```bat
"E:\FYP Custos Forensic Suite\artifacts\A01 - Ram\launch.bat"
"E:\FYP Custos Forensic Suite\artifacts\A01 - Ram\launch.bat" --output-dir "E:\Lab Results\RAM_Output"
```

Direct collector invocation from an elevated PowerShell or Command Prompt:

```powershell
& "E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" `
  "E:\FYP Custos Forensic Suite\artifacts\A01 - Ram\collector.py" `
  --output-dir "E:\Lab Results\RAM_Output"
```

When `--output-dir` is omitted, direct collector use asks the same one-time
destination question. An empty answer selects the A01 folder. Invalid folders
and write failures are reported; A01 does not silently switch destinations.

## Storage preflight

Before starting WinPmem, A01 confirms the destination exists and is writable,
checks free space and installed physical memory, and requires at least **twice
the installed RAM plus 1 GiB** free. This is a conservative preflight
threshold, not an exact image-size prediction or guaranteed upper bound.
Physical-address-space gaps and device-memory layout can make the logical
memory image larger than installed RAM. WinPmem's default sparse output may
use less physical disk space, but the logical raw image can still be large.
Leave additional space for filesystem use and other activity.

If Windows cannot report installed memory or destination free space, A01
refuses to begin acquisition. Insufficient space also fails before WinPmem
starts; the failure result JSON is written to the selected destination when
possible.

## Outputs

For each run A01 chooses a unique UTC-timestamped pair, adding a numeric suffix
if needed:

- `A01_memory_<UTC timestamp>.raw` — the uncompressed raw memory output. The
  image may be sparse; this does not change its raw format.
- `RAM_collection_<UTC timestamp>.json` — wrapper/tool result and diagnostics.

Existing files are never intentionally overwritten. A capture created before
WinPmem fails or the operator cancels is retained and reported as partial
when an output exists. Do not analyze or present a partial capture as complete.
The separate result JSON is published with exclusive-create behavior, adding
a suffix if another result file appears.

Direct collector use prints WinPmem's output while it runs. The double-click
launcher temporarily captures that output and displays it after the elevated
collector exits, then reports the final status, image path, observed size if
available, and collection-result path. The result JSON includes:

| Field | Meaning |
|---|---|
| `artifact_id` | Constant identifier `A01`. |
| `status` | `success`, `partial`, or `failed`. |
| `status_basis` | Why the status was selected and what it does not prove. |
| `tool` | Actual executable path/name, filename version label, unavailable embedded-version fields, size, help output, verified options, raw/sparse behavior, and signature warning. Null if inspection could not complete. |
| `tool.path`, `tool.filename` | Resolved executable path and actual filename. |
| `tool.version_label_from_filename` | Version-like label in the filename (`1.0-rc2`); not an embedded version claim. |
| `tool.version_reported_by_binary` | Null because this executable has no version command. |
| `tool.binary_version_metadata` | Null because PE product/file version values are absent. |
| `tool.version_note` | Describes version evidence and its limits. |
| `tool.size_bytes` | Executable size observed during the run. |
| `tool.authenticode_status` | Observed signature state (`not_signed` for the inspected executable). |
| `tool.help_exit_code`, `tool.acquire_help` | Result and text from a non-acquisition help invocation. |
| `tool.supported_acquire_options` | Acquisition arguments found in this executable's help. |
| `tool.raw_output_basis` | Reason for selecting no compression and the default sparse raw-file behavior. |
| `tool.authenticity_warning` | Authenticode/driver-blocking warning. |
| `invocation_arguments` | Exact executable and argument list used, or empty if acquisition did not start. |
| `output.image_path` | Planned unique image path, or null if destination setup failed. |
| `output.format`, `compression`, `sparse_output` | Selected output format and known behavior. |
| `output.observed_size_bytes` | File size observed after the tool stopped; null if no image was created or inaccessible. |
| `output.result_json_path` | Result-file destination. |
| `timestamps.wrapper_start_utc`, `wrapper_end_utc` | Wrapper operation boundaries in UTC. |
| `timestamps.wrapper_start_local`, `wrapper_end_local` | Same boundaries in local time with UTC offset. |
| `timestamps.local_timezone_identifier` | System time-zone identifier when available. |
| `timestamps.tool_reported_acquisition_duration` | WinPmem's `Completed imaging in ...` duration when present; otherwise null. This is distinct from wrapper timing. |
| `timestamps.meaning` | Clarifies the timing fields. |
| `tool_exit_code` | WinPmem process exit code, or null if it did not start. |
| `diagnostics.line_count_retained`, `total_line_count`, `line_limit`, `truncated`, `lines` | Bounded captured WinPmem output. The launcher displays the complete temporary log after collection; the JSON retains only the last 80 lines. |
| `diagnostics.start_error` | Failure to create/run the process, if applicable. |
| `validation.checks[]` | Named prerequisite checks with `passed` booleans. |
| `validation.storage` | Free space, installed RAM, conservative estimate/reserve, outcome, and explanation; null if not measured. |
| `errors` | Wrapper and acquisition errors. |
| `limitations[]` | Interpretation and completeness cautions. |

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | WinPmem returned zero and produced a nonempty output. This is not proof of a complete/correct image. |
| `1` | Incomplete/partial capture or cancellation with an output file retained. |
| `2` | Prerequisite/acquisition failure without a usable capture, or failure to save the required result JSON. If result writing fails after acquisition, the image may still remain; the launcher reports its path and the JSON write error. |

## Manual validation with Volatility

Use a separate analysis workstation or a working copy of the image. Install
Volatility 3 and locally provision matching Windows symbols according to
Volatility's documentation. Run the compatibility and process-list checks:

```powershell
$python = "E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe"
$image = "E:\FYP Custos Forensic Suite\artifacts\A01 - Ram\Output & Validation\your_capture.raw"
& $python -c "import sys; sys.argv[0] = 'vol'; from volatility3.cli import main; main()" --offline -f $image windows.info
& $python -c "import sys; sys.argv[0] = 'vol'; from volatility3.cli import main; main()" --offline -f $image windows.pslist
```

Use local symbols where needed, for example by adding
`--symbol-dirs "E:\Volatility Symbols"` before `-f`. No symbols are downloaded
by A01. `windows.info` and `windows.pslist` results provide useful checks but
do not by themselves prove a complete or correct memory acquisition.

## Limitations and validation status

- WinPmem is a kernel-driver-based acquisition tool and affects the live
  system. “Agentless” does not mean no privilege or system impact.
- A successful exit code and nonempty file support a completion assessment but
  do not establish forensic completeness or correctness.
- Physical memory layout can make output larger than installed RAM; the
  preflight estimate is not a strict maximum.
- An unsigned driver may be blocked by Windows security controls. A01 does not
  change those controls, enable test signing, or use a bypass.
- No live RAM capture was started while implementing this wrapper. Mocked
  tests validate wrapper behavior only. A controlled acquisition on a
  designated test machine and independent Volatility validation remain
  necessary.
