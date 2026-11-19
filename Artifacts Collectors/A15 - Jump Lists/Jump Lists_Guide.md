# A15 Jump Lists

Source: %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\
        AutomaticDestinations\*.automaticDestinations-ms
        CustomDestinations\*.customDestinations-ms

Method: copy raw containers + SHA-256, then JLECmd (Zimmerman) parses
        copies into 2 CSVs (Automatic + Custom); Python wrapper merges
        into Jump Lists_Output.json.

Privilege: User (current user only)

Output: Jump Lists_Output.json + Jump Lists_Hash & Timestamp Report.json
        + Jump Lists_Files/*.automaticDestinations-ms, *.customDestinations-ms
        + Jump Lists_Files/jumplist_parsed_AutomaticDestinations.csv
        + Jump Lists_Files/jumplist_parsed_CustomDestinations.csv
Hash and timestamp report (launcher): Jump Lists_Hash & Timestamp Report.json

Validation: See the artifact-specific interpretation and validation steps below. Prior-run counts and screenshots are illustrative only; compare with the current host and collection time.

Limits: Raw preservation + parsing on copies. DestList times vs
       embedded LNK times are different event types. AppId hash
       needs lookup table (JLECmd resolves known ones). No remote
       target resolution. Tool version pinned in _tools/JLECmd/.

## Understanding and validating A15 results

### Detailed field reading and validation workflow

First separate Automatic and Custom Jump List entries using `kind` and the two counts. `app_id` identifies the container's application identifier; `app_description` is a friendly lookup and may be unknown. `source_file` traces a row to the copied container. `target_created`, `target_modified`, and `target_accessed` are embedded target-file metadata, not the time the list was examined. `mru`, `interaction_count`, and `pin_status` describe list-specific ordering/activity signals and should be interpreted using the parser's schema. CSVs retain tabular parser output; `raw_files` preserve container bytes.

Validate one entry by opening its copied `.automaticDestinations-ms` or `.customDestinations-ms` file with JLECmd and comparing its target and AppID with the JSON/CSV. Verify source-copy hash and size before analysis. Do not merge the different timestamp types into a single “opened at” claim. A Jump List can persist after a target has moved or been deleted, and parser support may vary by container version.


From the suite root, check JSON syntax with the shared environment: `".venv\Scripts\python.exe" -m json.tool "<selected-output-folder>\Jump Lists_Output.json"` (replace the placeholder with the actual default or custom output directory).

Use `Jump Lists_Output.json` to separate `automatic_count` from `custom_count`; `raw_files` lists copied containers and integrity metadata. Each `records` entry has `kind`, `source_file`, `app_id`/`app_description`, and entry-specific target, arguments, MRU/interaction, pin, volume, and embedded timestamp fields. The `jumplist_parsed_*.csv` files contain parser rows.

Validate that each parsed row traces to a copied container, CSV totals agree with JSON counts, and raw sizes/hashes match. Re-parse a representative container copy with the documented JLECmd version. Distinguish DestList/MRU data from embedded LNK target times: neither automatically gives a precise time a person opened a file. AppID descriptions may be unresolved.
