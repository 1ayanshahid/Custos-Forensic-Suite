# A12 Shimcache and AppCompatCache

Source: <A08 SYSTEM hive>\ControlSet001\Control\Session Manager\AppCompatCache

Method: AppCompatCacheParser 2026.10.1 (Eric Zimmerman) on saved hive.
        Python wrapper loads CSV into normalized JSON.

Prerequisite: A08 SYSTEM hive. The collector runs A08 quietly first, then uses its verified saved export.

Privilege: Administrator (for A08 acquisition)

Output: Shimcache and AppCompatCache_Output/*.csv + Shimcache and AppCompatCache_Output.json
Hash and timestamp report (launcher): Shimcache and AppCompatCache_Hash & Timestamp Report.json


Validation: See the artifact-specific interpretation and validation steps below. Prior-run counts and screenshots are illustrative only; compare with the current host and collection time.

Limits: Executed column is "No" for all entries on Windows 10/11 —
        the execution flag is not reliably set on modern builds. Treat
        shimcache as "path was referenced" evidence, not proof of
        execution. UWP app entries appear as raw package-family hashes,
        not plain paths (normal for AppX packages). Not every execution
        is represented. Build/retention differences. Tool version pinned
        in _tools/.

## Understanding and validating A12 results

### Detailed field reading and validation workflow

`records` and the emitted CSVs describe data parsed from a saved SYSTEM hive. Use `source_hive` and `control_set` to verify the input, `tool` to identify the parser, and `count`/`csv_files` to understand how many rows and tables were produced. Rows can include cache path/name, entry type, parser timestamps, and an `Executed` indicator. Interpret the parser's timestamp according to its field name; it is not automatically a process launch time. On Windows 10/11, Shimcache's execution indicator is commonly not reliable and may always be false.

Validate the A08 SYSTEM hive used by the run, compare the JSON records with the named CSV output, and parse a working copy with the documented AppCompatCacheParser version. Report missing CSVs, nonzero tool return codes, or parser errors as coverage limitations. A path in the cache can indicate a reference by the compatibility subsystem, but on its own does not prove execution, installation, or user interaction.


From the suite root, check JSON syntax with the shared environment: `".venv\Scripts\python.exe" -m json.tool "<selected-output-folder>\Shimcache and AppCompatCache_Output.json"` (replace the placeholder with the actual default or custom output directory).

`Shimcache and AppCompatCache_Output.json` summarizes parsing of the saved A08 SYSTEM hive. Review `status`, `source_hive`, `control_set`, `count`, `csv_files`, `records`, and `reason`; CSVs hold detailed Shimcache/AppCompatCache rows while JSON contains wrapper records. Read executable/path and parser-provided time fields (including `LastModifiedTimeUTC` when present) as cache metadata, not confirmed launch times. Execution flags can be unreliable on modern Windows.

Validate the A08 hive/control set, compare JSON count/records with parser CSVs, and inspect representative entries by parsing a working copy of the same hive with the documented AppCompatCacheParser version. Review parser errors and unparsed CSVs rather than interpreting them as empty. Cache path presence alone does not prove execution.
