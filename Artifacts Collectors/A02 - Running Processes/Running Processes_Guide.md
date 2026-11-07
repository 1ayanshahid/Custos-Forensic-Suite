# Artifact A02 — Running Processes

## Purpose

Artifact A02 captures a **live, read-only snapshot** of the Windows processes and system threads running on the computer. It creates two UTF-8 JSON files:

1. A process inventory containing process IDs, parent IDs, names, executable paths, command lines, users, start times, statuses, and thread counts.
2. A system-wide thread inventory containing thread IDs, owner process IDs and names, priorities, creation times, and cumulative CPU time.

The collector uses `psutil` for process enumeration and the documented Windows Toolhelp API for the thread snapshot. It does not stop, modify, suspend, or terminate processes.

## Why this artifact is useful

This artifact helps with:

- Identifying unfamiliar or unexpected processes
- Reviewing process parent-child relationships
- Checking which executable and command line created a process
- Connecting a thread to a process through the PID
- Comparing the process snapshot with a known system baseline
- Investigating suspicious activity at collection time

Process and thread information changes continuously. The collection records therefore represent a point-in-time snapshot, not a permanent history.

## Files

- `collector.py` — Collects and writes the JSON snapshots.
- `launch.bat` — Requests administrator permission and runs the collector with the project Python environment.
- `README.md` — This usage and validation guide.

## Requirements

- Windows
- Administrator access is recommended; Windows may deny fields for protected or restricted processes even with elevation.
- Python configured for the project
- The `psutil` package installed in the project virtual environment

Before using A02, run the project setup script from the project root:

```powershell
.\setup_environment.bat
```

This creates `.venv` and installs the packages listed in `requirements-dev-lock.txt`, including `psutil`.

## Run the collector

### Recommended method

From Windows File Explorer, open this A02 folder and double-click:

```text
launch.bat
```

If administrator elevation is requested, approve the UAC prompt.

Without a command-line argument, the launcher asks for an output folder or JSON filename. Pressing Enter uses a timestamped file in the A02 folder, for example:

```text
processes_20261101_010000.json
```

The thread file is automatically placed beside it with a `_threads` suffix:

```text
processes_20261101_010000_threads.json
```

### Manual method with an output folder

Run from PowerShell:

```powershell
& "E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" "collector.py" --output "C:\path\to\Output & Validation\Running Processes_Output"
```

### Manual method with explicit output filenames

```powershell
& "E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" "collector.py" `
  --output "C:\path\to\processes.json" `
  --threads-output "C:\path\to\threads.json"
```

Existing output files are not replaced by default. Use `--overwrite` only when replacing an existing file is intentional:

```powershell
& "E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" "collector.py" --output "C:\path\to\processes.json" --overwrite
```

## Output files

### Process output

The process JSON contains top-level collection metadata followed by a `processes` array. Important fields include:

| Field | Meaning |
|---|---|
| `schema_version` | JSON schema version for this artifact |
| `artifact` | Artifact identifier |
| `outcome` | `completed`, `partial`, or `failed` |
| `process_count` | Number of process records returned |
| `collection_started_at_utc` | Collection start time in UTC |
| `collection_ended_at_utc` | Collection end time in UTC |
| `collection_errors` | Process enumeration and field-access errors |
| `pid` | Process ID |
| `parent_pid` | Parent process ID |
| `name` | Process name |
| `executable_path` | Full executable path when available |
| `command_line` | Command-line arguments |
| `username` | Account associated with the process |
| `creation_time_utc` | Process creation time in UTC |
| `status` | Current process status reported by `psutil` |
| `thread_count` | Number of threads reported for the process |

### Thread output

The thread JSON contains a top-level collection summary followed by a `threads` array. Important fields include:

| Field | Meaning |
|---|---|
| `outcome` | `completed`, `partial`, or `failed` |
| `thread_count` | Number of thread records returned |
| `collection_errors` | Summarized thread-enumeration and field-access errors |
| `thread_id` | System thread ID |
| `owner_process_id` | PID that owns the thread |
| `owning_process_name` | Process name joined from the process snapshot |
| `base_priority` | Base priority from `THREADENTRY32` |
| `current_priority` | Best-effort relative thread priority |
| `creation_time_utc` | Thread creation time in UTC |
| `user_cpu_time_seconds` | Cumulative user-mode CPU time for the thread |
| `kernel_cpu_time_seconds` | Cumulative kernel-mode CPU time for the thread |

## How to read the output

A JSON viewer or a modern text editor with JSON formatting is recommended.

1. Open the process JSON first.
2. Check `outcome`; `completed` means both snapshots finished without detected errors, while `partial` means some fields or records were unavailable.
3. Review `collection_started_at_utc` and `collection_ended_at_utc` to establish the collection window.
4. Review `collection_errors`. A `null` process field is often explained by a matching access, exit, zombie, or process-reuse error.
5. Search the `processes` array for a suspicious PID, executable path, command line, user, or process name.
6. Compare `pid` and `creation_time_utc` with later snapshots. PIDs can be reused, so the creation time helps confirm process identity.
7. Use `parent_pid` to find the parent process record and trace the process relationship.
8. Open the thread JSON and connect records using `owner_process_id` or verify a thread's `owning_process_name`.
9. Treat CPU values as cumulative totals, not active CPU usage percentages.

## Example review questions

- Does every running process have a known executable path?
- Does the executable exist in an expected Windows directory?
- Is the process name consistent with its executable and command line?
- Which account owns the process?
- Does the parent PID correspond to a normal parent process or an unexpected launcher?
- Did a PID that appears in another collection start at the same creation time?
- Does a process have a thread count that differs substantially from normal baseline behavior?
- Are unexpected collection errors concentrated under protected or system processes?

## Validation

### 1. Check the files were created

Confirm that both expected files exist and are non-empty.

In PowerShell:

```powershell
Get-ChildItem "C:\path\to\output" -Filter "*.json" |
  Select-Object Name, Length, LastWriteTime
```

### 2. Check JSON syntax

Using PowerShell, parse each file:

```powershell
$processes = Get-Content "C:\path\to\processes.json" -Raw | ConvertFrom-Json
$threads = Get-Content "C:\path\to\processes_threads.json" -Raw | ConvertFrom-Json

$processes | Format-List artifact, outcome, process_count, collection_started_at_utc
$threads | Format-List artifact, outcome, thread_count, collection_started_at_utc
```

If parsing succeeds, the output is valid JSON. The loader will display an error if the file is truncated or malformed.

### 3. Verify the process snapshot

```powershell
Write-Output "Processes reported by collector: $($processes.process_count)"
Write-Output "Process records in array: $($processes.processes.Count)"

$processes.processes |
  Where-Object { $_.pid -and $_.name } |
  Sort-Object pid |
  Select-Object -First 20 pid, parent_pid, name, executable_path, status, thread_count
```

The reported process count should generally match the number of records in the `processes` array.

### 4. Cross-check the current process list

Compare an output record against live Windows process data:

```powershell
Get-Process | Select-Object Id, ProcessName, Path | Sort-Object Id | Select-Object -First 20
```

Minor differences are expected because live processes can start or exit while the snapshot is collected.

### 5. Verify the thread snapshot

```powershell
Write-Output "Threads reported by collector: $($threads.thread_count)"
Write-Output "Thread records in array: $($threads.threads.Count)"

$threads.threads |
  Where-Object { $_.thread_id } |
  Sort-Object owner_process_id |
  Select-Object -First 20 thread_id, owner_process_id, owning_process_name, base_priority, current_priority
```

Confirm that at least some process owners in the thread output appear in the process output:

```powershell
$processIDs = @($processes.processes.pid)
$threadOwners = $threads.threads |
  Where-Object { $_.owner_process_id -in $processIDs } |
  Select-Object -ExpandProperty owner_process_id -Unique

Write-Output "Matching thread-owner PIDs: $($threadOwners.Count)"
```

### 6. Validate collection time and errors

```powershell
Write-Output "Process errors: $($processes.collection_errors.Count)"
Write-Output "Thread errors: $($threads.collection_errors.Count)"
Write-Output "Process limitation count: $($processes.limitations.Count)"
Write-Output "Thread limitation count: $($threads.limitations.Count)"
```

A few errors may be normal for protected, terminating, or access-restricted processes. A large number of failures, an empty array, or a `failed` outcome should be investigated.

## Interpret collection outcomes

- `completed`: the relevant inventory completed and no reported collection errors were detected.
- `partial`: collection continued, but at least one record or field was unavailable.
- `failed`: enumeration produced no usable records or failed before data collection could complete.

## Limitations

- This is a live snapshot; processes and threads may start, exit, or change during collection.
- A PID alone is not enough for permanent process identity. Use it with `creation_time_utc`.
- Access depends on Windows security policy and token privileges.
- Administrator elevation improves visibility but does not bypass protected-process restrictions.
- Unavailable values are `null` and are explained by collection-error data.
- Thread CPU values are cumulative totals, not instantaneous utilization.
- The thread snapshot does not classify threads as user-mode or kernel-mode.
- The Toolhelp snapshot does not provide thread state, wait reason, start address, or context-switch count.
- This artifact is not a dump of memory, handles, modules, network connections, or kernel objects.

## Troubleshooting

### Administrator permission cancelled

Approve the UAC prompt and rerun `launch.bat`. The output can contain more complete process information with elevation, although protected processes may remain inaccessible.

### Python environment not found

The launcher expects the project environment at:

```text
E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe
```

Run the project setup script, then verify:

```powershell
Test-Path "E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe"
```

If your project environment is located elsewhere, update the `PYTHON` variable in `launch.bat`.

### `psutil` is missing

Install it in the project environment:

```powershell
& "E:\FYP Custos Forensic Suite\.venv\Scripts\python.exe" -m pip install psutil
```

The same package can be installed as part of normal project setup from `requirements-dev-lock.txt`.

### Output refused or overwritten unexpectedly

The collector refuses to replace existing files unless `--overwrite` is supplied. Choose a new timestamped filename or folder, or explicitly use `--overwrite` only when replacement is intended.

### Output directory does not exist

Create the directory before collection:

```powershell
New-Item -ItemType Directory -Force "C:\path\to\Output & Validation\A02"
```

Then pass that directory to `--output`.
