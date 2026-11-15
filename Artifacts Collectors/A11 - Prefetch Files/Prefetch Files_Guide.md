# A11 Prefetch Files

Source: C:\Windows\Prefetch\*.pf (raw copies)
        + prefetch_parsed.csv (decoded via PECmd)

Method: copy .pf files + SHA-256, then PECmd 2026.10.3 (Zimmerman)
        parses copies into CSV; Python wrapper loads into JSON.

Privilege: Administrator

Output: Prefetch Files_Output.json + Prefetch Files_Hash & Timestamp Report.json
        + Prefetch Files_Files/*.pf + prefetch_parsed.csv + PECmd console log
Hash and timestamp report (launcher): Prefetch Files_Hash & Timestamp Report.json


Validation: See the artifact-specific interpretation and validation steps below. Prior-run counts and screenshots are illustrative only; compare with the current host and collection time.

Limits: Prefetch may be disabled on some SSD/Windows configs. Not
        every execution is captured — retention ~128 files. Run count
        can wrap. `-q` used to suppress per-file progress. .pf files
        are also preserved raw + hashed for independent verification.
        Tool version pinned in _tools/PECmd/.

## Understanding and validating A11 results

### Detailed field reading and validation workflow

The JSON `records` are parsed Prefetch metadata, not copies of the original file content. `executable` is the parsed program name; `hash_suffix` helps distinguish same-named executable paths; `version` describes the parser's format interpretation; `run_count` is the count encoded in the Prefetch file; `last_run` and previous-run fields are timestamps decoded from that file. Volume fields and `source_file` provide context. `parsing_error` means the file did not yield a complete normalized record. The raw `.pf` copies and their `raw_files` hash/size records preserve the underlying evidence.

Validate by comparing one record with the matching raw `.pf` in PECmd and confirming its output in `prefetch_parsed.csv`. Ensure parser CSV rows and JSON records are consistent, while accounting for explicitly failed files. Check each raw copy's SHA-256 and size. Do not convert a missing Prefetch file into a claim that a program was never run: Prefetch may be disabled, aged out, or unavailable, and a Prefetch run count is not a user-action audit trail.


From the suite root, check JSON syntax with the shared environment: `".venv\Scripts\python.exe" -m json.tool "<selected-output-folder>\Prefetch Files_Output.json"` (replace the placeholder with the actual default or custom output directory).

In `Prefetch Files_Output.json`, `status`, `count`, `tool`, `source_dir`, `csv_file`, `raw_files`, and `records` describe acquisition and parsing. Parsed records can include `executable`, `hash_suffix`, `version`, `run_count`, `last_run`, prior-run times, volume information, `source_file`, and `parsing_error`. The CSV contains parser rows; copied `.pf` files are raw evidence. Missing times or parsing errors mean unavailable data, not a zero time.

Validate that JSON counts agree with records/CSV rows, inspect each raw file's name/size/SHA-256, and re-parse a representative copied `.pf` with the documented PECmd version. Preserve copies unchanged. Prefetch retention and enablement vary; it is not a complete execution log or proof of a user's intent.
