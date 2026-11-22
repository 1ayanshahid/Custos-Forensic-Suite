# A16 SRUM Database

Source: C:\Windows\System32\sru\SRUDB.dat + SRUDB.jfm + SRU\*.log
        + A08 SOFTWARE hive (for app ID resolution)

Method: robocopy /B (locked file copy) + SrumECmd 2026.10.1 (Zimmerman)
        parses ESE database into CSV tables; Python wrapper loads
        row counts + sample rows into JSON.

Prerequisite: A08 SOFTWARE hive. The collector runs A08 quietly first, then uses its verified saved export.

Privilege: Administrator (robocopy /B needs backup privilege)

Output: SRUM Database_Output/SRUDB.dat + sidecars + CSVs + SRUM Database_Output.json
Hash and timestamp report (launcher): SRUM Database_Hash & Timestamp Report.json


Validation: See the artifact-specific interpretation and validation steps below. Prior-run counts and screenshots are illustrative only; compare with the current host and collection time.

Limits: Raw preservation + ESE parsing on copy. ID-map joins resolve
        app/SID names via SOFTWARE hive. Resource byte counters are
        not proof of exfiltration. Missing recent in-memory cache may
        limit completeness. Period times are interval context, not
        per-event timestamps. Tool version pinned in _tools/SrumECmd/.

## Understanding and validating A16 results

### Detailed field reading and validation workflow

`raw_files` describe database, log, and sidecar acquisitions; `tables` describe the parser's derived output. For each table, `file` names its CSV, `count` reports parsed rows, and `sample` is a preview only. Read table fields according to the SRUM schema and keep interval start/end fields, application identifiers, user/SID associations, and resource counters distinct. `software_hive` records whether a SOFTWARE hive was available for name resolution; unresolved IDs do not mean the underlying SRUM row is invalid.

Validate raw acquired files by their recorded size/hash and compare each table count with its corresponding CSV. Re-run SrumECmd against a working copy of the acquired database and reconcile table names/counts. Review `status`, `reason`, and missing tables before interpreting absence. SRUM counters are resource-accounting observations over intervals; they do not establish the content or destination of network traffic or prove exfiltration. Missing sidecars or volatile cache state can make the database incomplete.


From the suite root, check JSON syntax with the shared environment: `".venv\Scripts\python.exe" -m json.tool "<selected-output-folder>\SRUM Database_Output.json"` (replace the placeholder with the actual default or custom output directory).

Read `SRUM Database_Output.json` as a table-level parse summary. `status`, `table_count`, `raw_files`, and `tables` describe copied SRUM database/sidecars and decoded tables; each table's `count`, `file`, and `sample` are metadata and examples, not the full table. Use its SrumECmd CSV for complete rows and raw `SRUDB.dat`, `SRUDB.jfm`, and logs as evidence. App/SID resolution may depend on the SOFTWARE hive.

Validate raw sizes/hashes, compare each table count with its CSV rows, and re-parse a working copy using the documented SrumECmd version. Review missing tables and parser errors. SRUM resource/byte counters are not proof of exfiltration; missing in-memory state or unresolved ID mappings can limit interpretation.
