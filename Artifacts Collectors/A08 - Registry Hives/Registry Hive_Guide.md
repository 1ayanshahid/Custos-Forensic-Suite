# A08 Registry Hives

Source: HKLM\SYSTEM, HKLM\SOFTWARE, HKLM\SAM, HKLM\SECURITY
        HKU\<SID> and HKU\<SID>_Classes (per loaded user profile)

Method: reg save (logical hive export) + SHA-256

Privilege: Administrator

Output: Registry Hive_Output/Registry Hives_Files/{SYSTEM,SOFTWARE,SAM,
        SECURITY,NTUSER_<user>,UsrClass_<user>} + Registry Hive_Output.json

Hash and timestamp report (launcher): Registry Hive_Hash & Timestamp Report.json

Validation: See the artifact-specific interpretation and validation steps below. Prior-run counts and screenshots are illustrative only; compare with the current host and collection time.

Limits: reg save produces a logical export, not a byte-identical copy
       of the on-disk hive file. Volatile keys are omitted. SAM and
       SECURITY contain credential material — handle with care.
       Only currently loaded user hives are exported; service accounts
       not logged in (e.g. ddagentuser) cannot be saved via HKU.
       .LOG1/.LOG2 sidecars not captured by reg save — a separate
       raw copy step would be required for byte-level fidelity.

Profile discovery uses Windows `Win32_UserProfile` SID/LocalPath mappings,
not a fixed `C:\Users` directory. A08 saves NTUSER and UsrClass logical
exports for eligible profiles when their registry keys are available.
Duplicate profile directory names are reported as export errors rather than
overwritten. The manifest records each exported file's hash, size, and
per-file acquisition time, but not the source computer or SID/profile path.
Consumers run A08 quietly first, then verify the manifest, file signature,
size, hash, parser readability, and current profile-name mapping. A08 always
writes its output to its own configured folder, not the dependent collector's
custom output folder. A32, A33, A34, and A35 use all successfully verified
current-profile exports; A33 can use both NTUSER and UsrClass exports. Review
A08 per-hive errors to identify unavailable profiles or hive types.

## Understanding and validating A08 results

### Detailed field reading and validation workflow

Read the JSON record array as an inventory of export attempts. A hive record with `VERIFIED`-style status means the export operation and recorded copy checks succeeded; it does not mean every key was read or that the file is a physical, byte-for-byte hive image. The size is in bytes and the digest is hexadecimal SHA-256. `source_key` identifies the Windows registry hive, while `saved_as` names the corresponding output. Treat the acquisition timestamp as the export time, not the time represented by registry values.

For validation, first match each result record to its saved hive by filename and root hive identity. Check that the file is readable by a registry parser, then inspect one known key from that hive. For `NTUSER_<user>` and `UsrClass_<user>` exports, compare the suffix to the current Windows profile mapping and review the A08 acquisition time and per-hive status. If a copy or export status is failed, report it as incomplete rather than treating it as absent evidence.


From the suite root, check JSON syntax with the shared environment: `".venv\Scripts\python.exe" -m json.tool "<selected-output-folder>\Registry Hive_Output.json"` (replace the placeholder with the actual default or custom output directory).

Open `Registry Hive_Output.json` first. Its `status`, `utc`, `count`, `records`, and optional `stderr` summarize the hive export; `count` is the number of hive-result records, not registry keys. Each record identifies `hive`, `source_key`, per-hive `status`, `collected_at`, `saved_as`, `size`, and `sha256`. Separate machine hives from `NTUSER_<user>` and `UsrClass_<user>` exports and review each record's status before opening its saved file.

Validate that every successfully collected `saved_as` file exists and its size and SHA-256 match the record. Open a copy with a registry viewer/parser and confirm the expected root hive and representative keys. Match user-hive suffixes to current profile names and review any failed per-profile records. `reg save` creates a logical export, not a byte-identical physical hive; matching hashes prove output integrity, not completeness. SAM and SECURITY are sensitive evidence.
