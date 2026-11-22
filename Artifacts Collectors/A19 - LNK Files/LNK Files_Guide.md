# A19 LNK Files

Source: %USERPROFILE%\Recent\*.lnk + %USERPROFILE%\Desktop\*.lnk

Method: copy raw .lnk + SHA-256, then LECmd (Zimmerman) parses copies
        into CSV; Python wrapper loads into JSON.

Privilege: User (current user only)

Output: LNK Files_Output.json + LNK Files_Hash & Timestamp Report.json
        + LNK Files_Files/*.lnk + LNK Files_Files/lnk_parsed.csv
Hash and timestamp report (launcher): LNK Files_Hash & Timestamp Report.json


Validation: See the artifact-specific interpretation and validation steps below. Prior-run counts and screenshots are illustrative only; compare with the current host and collection time.

Limits: Raw preservation + parsing done on copies. LNK embedded
       times are copied properties, not shortcut-open times. MAC
       from originating machine (may be spoofed). No remote target
       resolution. Tool version pinned in _tools/LECmd/.

## Understanding and validating A19 results

### Detailed field reading and validation workflow

Each `records` item represents a parsed shortcut. `source_file` identifies which copied `.lnk` produced it. Target fields such as `local_path`, `network_path`, `common_path`, `relative_path`, and `working_dir` are alternate representations and may be empty depending on the shortcut. `arguments` are stored shortcut arguments, not proof they were executed. Embedded target times and target MFT/volume fields describe metadata carried by the link; they are not a reliable click time. `raw_files` records copied link sizes and hashes.

Validate by selecting a JSON row, opening its matching acquired `.lnk` in LECmd, and comparing target and volume details with `lnk_parsed.csv`. Verify the link copy's hash before parsing. A link can refer to an unavailable network path or deleted file, and a stale link can remain long after use. Limit conclusions to the current-user folders actually searched; this is not all-user or complete shortcut history.


From the suite root, check JSON syntax with the shared environment: `".venv\Scripts\python.exe" -m json.tool "<selected-output-folder>\LNK Files_Output.json"` (replace the placeholder with the actual default or custom output directory).

Start with `LNK Files_Output.json` and `lnk_parsed.csv`. `status`, `count`, `raw_files`, and `records` summarize copied shortcuts and parsing. Records can include `source_file`, target path fields, `arguments`, embedded target-file times, file size, drive/volume metadata, machine identifiers, and target MFT reference; not all fields are always present.

Validate that each parsed row maps to a copied `.lnk`, JSON/CSV counts agree, hashes/sizes match, and a representative copy parses with the documented LECmd version. Embedded target-file times are not when a shortcut was created, viewed, or clicked. Discovery is limited to the documented current-user Recent/Desktop locations; remote paths may not resolve locally.
