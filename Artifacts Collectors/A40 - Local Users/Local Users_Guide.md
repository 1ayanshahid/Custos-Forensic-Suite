# A40 — Local Users

A40 makes a read-only inventory of local Windows user accounts. Its primary source is pywin32's `NetUserEnum`; it enriches each listed account with `NetUserGetInfo` and local SID lookup. A fixed, non-interactive PowerShell call to `Get-LocalUser` is used as an independently identified comparison and supplemental source. It is not a silent substitute for NetAPI: differences remain visible, supplemental-only records are retained, and provider disagreement makes the inventory partial.

The inventory does not include domain users, group membership, active logon sessions, profile-folder contents, passwords, password hashes, or authentication material. It does not create or change accounts or settings.

**Reference-material note:** The supplied Custos Master Handbook and Tools & Artifact Details PDF were not accessible in this environment, so this implementation does not claim to have consulted them. API behavior and field coverage below are grounded in the cited official Microsoft documentation and the implemented provider behavior.

## Scope and identity

- A **local user** is an account in the local computer's account database (normally the local SAM). A **domain user** is managed by a domain controller and is not enumerated by this artifact.
- A **logon session** is a current Windows session, not an account. Enumerating sessions belongs to A42.
- The collector checks the documented Windows `ProductType` registry value. A domain controller (`LanmanNT`) is rejected before user enumeration because its security database is Active Directory. The collector does not relabel domain accounts as local users.
- `NetUserEnum` is called with a null server name, which means the local computer, and `FILTER_NORMAL_ACCOUNT` (`2`). Microsoft documents that this selects normal user-account data rather than the trust/machine-account classes. The chosen filter and all page/resume details are included in JSON.
- A **SID** is the stable account identity when available; a username can be renamed. A full name is a display field and is not an identity key. Accounts are not merged on display name. If the primary entry has no SID, exact username matching may be used for provider reconciliation and the provider disagreement remains reported.
- Built-in classification is based only on documented domain-relative SID RIDs: 500 (administrator account) and 501 (guest account). The display name is never used. Renaming a built-in account does not change this SID-based result. Other RIDs, including identities not covered by this implementation's verified references, are not called built-in.
- `enabled` describes the current `UF_ACCOUNTDISABLE` bit where the provider supplies it. `locked_out` describes the current `UF_LOCKOUT` bit. These values are snapshots, not histories; a null state is not treated as false.

## APIs and references

The implementation uses the installed pywin32 bindings:

| Operation | Implementation |
|---|---|
| Enumerate local normal accounts | `win32net.NetUserEnum(None, level, 2, -1, resume_handle)` |
| Query each account | `win32net.NetUserGetInfo(None, username, level)` |
| Read local password-policy maximum age | `win32net.NetUserModalsGet(None, 0)` |
| Resolve account SID | Prefer `NetUserGetInfo` level-4 `user_sid`; use `win32security.LookupAccountName(local_computer, username)` if that field is unavailable; convert with `ConvertSidToStringSid` |
| Check workstation/server/domain-controller scope | Read-only `HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType` |
| Independent comparison/supplement | Fixed `Get-LocalUser` script using PowerShell `-NoProfile -NonInteractive`, structured JSON, explicit timeout and UTF-8 |

The installed pywin32 version in the development environment exposed `NetUserEnum` information levels 0, 1, 2, 3, 10, 11, and 20; `NetUserGetInfo` exposed 0, 1, 2, 3, 4, 10, 11, and 20. A live level-4 query returned the `user_sid` field. The implementation uses level 3 for primary enumeration and levels 4, 3, then 2 for each account, proceeding to a lower level when a higher level fails. Level 0 is the enumeration fallback. SID level 23 is documented by Microsoft but was rejected by the installed pywin32 binding during development; A40 does not depend on it.

The collector reports the levels actually attempted and used. Other Windows/pywin32 combinations may expose different behavior. It does not assume that a documented native level is necessarily supported by every installed binding.

Official references:

- [NetUserEnum](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserenum) — local target semantics, enumeration levels, account filters, and resume handles.
- [NetUserGetInfo](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusergetinfo) — per-account query levels.
- [USER_INFO_2](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_2), [USER_INFO_3](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_3), and [USER_INFO_4](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_4) — fields, timestamps, password age, flags, account metadata, and the level-4 SID member.
- [USER_INFO_23](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_23) — documented SID-bearing structure; not used because the installed pywin32 binding rejected level 23.
- [Well-known SIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids) — domain-relative administrator and guest account RIDs used for built-in identification.
- [USER_MODALS_INFO_0](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_0) — maximum local password age.
- [NetUserModalsGet](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsget) — read-only modal/policy query.
- [UF account flags](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_2) — documented flags are named in that structure's remarks and members.
- [Get-LocalUser](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localuser) — Windows PowerShell local-account comparison properties.
- [Win32_OperatingSystem](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem) — documented Windows operating-system role property used as scope context; this implementation reads the local ProductType registry value directly.

### Coverage table

| Information | API/information level | Meaning | Availability or limitation |
|---|---|---|---|
| Username, flags, provider user/RID, common details | `NetUserEnum` level 3; fallback level 0 | Account enumeration record | Level 0 supplies only names. The enumeration filter excludes trust/machine account classes. |
| Full name, comment, user comment | `NetUserGetInfo` levels 4/3; fallback level 2 | Human-readable account metadata | Null/unavailable values are preserved as null with field status. Empty strings are preserved. |
| SID | `NetUserGetInfo` level 4 `user_sid`; `LookupAccountName` fallback; optional `Get-LocalUser` SID | Account security identifier | Resolution can fail or race with rename/deletion. The failed resolution is reported. |
| Built-in identity | SID authority/subauthority/RID | Recognized local administrator/guest identities at RID 500/501 | Not determined from English names. Non-matching shapes or RIDs are not classified as built-in. |
| Enabled/disabled, lockout, password-policy flags | `USER_INFO_4`/`USER_INFO_3`/`USER_INFO_2` `flags` | Current documented bit interpretations | Raw flags and unknown bits are retained. Provider absence or malformed values are not converted to false. |
| Password-required, cannot-change, never-expires | `flags`; selected `Get-LocalUser` properties where available | Account configuration metadata | Says nothing about knowing, recovering, or possessing a password. Does not collect credentials. |
| Password age | `USER_INFO_4`/`USER_INFO_3`/`USER_INFO_2` `password_age` | Seconds elapsed since password last changed | Kept as seconds. A password-last-set time is explicitly marked as an estimate derived at query time. |
| Password expiration | `password_expired`/flag; `NetUserModalsGet` level 0 | Expired state or estimated expiration under the returned maximum-age policy | Estimated UTC expiry is not a direct stored timestamp. `TIMEQ_FOREVER` is kept as a policy sentinel. |
| Account expiration | `acct_expires` | Account expiration, separate from password expiration | Absolute UTC seconds are converted; zero, forever, invalid, and unavailable remain distinct statuses. |
| Last logon/logoff | `USER_INFO_4`/`USER_INFO_3`/`USER_INFO_2` | Provider-reported last logon/logoff | Zero is reported as `zero_not_recorded`, not converted to 1970. Values can be stale, unavailable, or provider-limited. |
| Privilege level | `priv` in levels 2/3/4 | NetAPI `USER_PRIV_GUEST`, `USER_PRIV_USER`, or `USER_PRIV_ADMIN` class | Not a complete local-group membership or effective-rights analysis. |
| Primary group identifier | Level 3 | Primary-group RID | Identifier only; no group inventory or membership enumeration is performed. |
| Home directory, drive, profile, logon script | Levels 3/4; some fields also level 2 | Configured account path fields | Paths are metadata only. The collector does not inspect the referenced contents. |
| Permitted workstations | Levels 2/3/4 | Provider workstations string | Preserved as provider text; not parsed into policy claims. |
| Logon-hours data | Levels 2/3/4 | Raw provider bitmap and units-per-week | Bitmap is encoded as hex. No schedule is decoded because the collector does not claim verified bit ordering/time semantics. |
| Logon count, bad-password count, authentication flags | Levels 2/3/4 | Provider counters and authorization flags | Current provider values only; legitimate zero values are retained and documented unknown sentinels are labeled. |
| Country code, code page, maximum storage | Levels 2/3/4 | Additional provider values | `TIMEQ_FOREVER` storage is represented as null with an `unlimited_sentinel` field status. |
| Principal source | `Get-LocalUser` `PrincipalSource` | Provider's account-source classification | Null when absent. Never guessed from username or profile path. |

## Requirements and launcher

- Supported host: Windows workstation or member/standalone server with a conventional local account database. Domain controllers are out of scope and explicitly rejected.
- Python: 64-bit Windows Python 3.10 or newer. Run the project-root `setup_environment.bat` once to create `.venv` and install the pinned dependencies from `requirements-dev-lock.txt`.
- Dependency: `pywin32`, installed by the project setup script. The artifact launcher checks required imports and does not install packages itself.
- Administrator access is requested by `launch.bat` using the standard UAC `runas` verb. It relaunches the batch file and waits; the selected output path and overwrite option are carried in the inherited process environment, not interpolated into a PowerShell command. Collection starts only after the relaunched instance verifies administrator access. Collector output stays visible in the elevated window, and its `0`, `1`, or `2` exit code is propagated unchanged. UAC cancellation or failure exits without collecting. Elevation does not guarantee that every provider field will be available.
- PowerShell `Get-LocalUser` is optional. If the module/command is unavailable or fails, the provider error is recorded. It never silently replaces NetAPI. The primary NetAPI result remains available when possible.

The project setup script must be run before the first artifact launcher. It only prepares Python dependencies; it does not install optional external tools or grant administrator permissions.

## Run the collector

Double-click `launch.bat`. If no output is specified, the collector prompts for a JSON destination. Press Enter to use a new timestamped JSON file in the `Local Users_Output` folder. You may enter either a JSON filename or an existing folder; when you enter a folder, the collector creates a new timestamped `Local Users-<UTC timestamp>.json` file inside it.

From this artifact folder, Command Prompt examples (quotes protect paths containing spaces):

```bat
launch.bat
launch.bat --output "D:\Cases\Local Users.json"
launch.bat --output "D:\Cases\Local Users_Output"
launch.bat --output "D:\Cases\Local Users.json" --overwrite
```

The standalone Python entry point can also be run from this artifact folder:

```bat
..\..\.venv\Scripts\python.exe collector.py --output "D:\Cases\Local Users.json"
```

An existing output file is never replaced unless `--overwrite` is explicitly supplied. Selecting an existing folder creates a new timestamped file within that folder, without overwriting existing files. The reusable entry point is `collect_local_users(output_path, ...)`; it returns the structured inventory and writes UTF-8 JSON.

Exit codes: `0` = success; `1` = partial inventory; `2` = failure or launcher/dependency error. `launch.bat` waits for the elevated collector and propagates its exit code. When elevation is used, press a key in the elevated window after the collector result is displayed.

## Generated files and JSON format

Files in this artifact:

- `collector.py` — reusable collector, CLI, providers, normalization, error handling, and output writer.
- `launch.bat` — one launcher; performs dependency/admin checks and the inline UAC request.
- `README.md` — this guide.
- `Local Users-<UTC timestamp>.json` — default collected output in this folder, unless a destination is selected.

The JSON has these top-level fields:

| Field | Meaning |
|---|---|
| `artifact_id` | Always `A40`. |
| `collection_started_at_utc`, `collection_ended_at_utc` | ISO 8601 UTC observation bounds, ending in `Z`. |
| `collection_started_at_local`, `collection_ended_at_local` | Same observations with the host's local offset. |
| `collection_time_zone_id` | Windows time-zone registry key name, when readable. |
| `collection_time_zone_id_error` | Null or a direct error explaining why the ID was unavailable. |
| `collection_clock_adjusted` | True only if the observed end was earlier than the start; end is clamped to start rather than reporting negative duration. |
| `scope` | Local machine, computer name, local account database, and observed computer role. It does not assert domain-user/session coverage. |
| `status` | `success`, `partial`, or `failed`. `success` requires completed non-empty primary enumeration and no detected provider or record errors; mismatches and recoverable omissions are `partial`; a complete primary failure with no accounts and an unsupported scope are `failed`. |
| `providers` | Provider names/roles, attempted information levels, enumeration page details, supplemental provider status, and errors. |
| `enumeration_complete` | True only when primary enumeration completed with at least one account and no successful supplemental-provider disagreement. |
| `primary_enumeration_complete` | Whether the NetAPI page sequence ended with resume handle zero without enumeration errors. |
| `provider_consistency` | `match`, `mismatch`, or `not_compared`, NetAPI-only/Get-LocalUser-only counts, and username-only fallback match count. SID comparison is preferred; exact username is used only when the primary record lacks a SID. |
| `account_count` | Number of account records emitted, including supplemental-only accounts. |
| `accounts` | Explicitly allowlisted account records. |
| `password_policy` | Maximum password age metadata from `NetUserModalsGet(level=0)` or an unavailable status. No minimum length/history or password content is collected. |
| `errors` | Enumeration, provider mismatch, scope, or per-account process errors. |
| `warnings` | Recoverable conditions such as use of a documented fallback information level. |
| `limitations` | Scope and interpretation cautions applicable to this run. |
| `output_path` | Resolved output path. |

### Account record fields

Every account record has the following documented keys. A value can be null when unavailable; field-specific status objects and per-account errors explain important distinctions.

| Field | Meaning |
|---|---|
| `username` | Provider account name; not a stable identity by itself. |
| `sid`, `sid_source`, `sid_resolution` | SID text, source, resolution status, optional resolved domain/type, and lookup errors. If the SID found before enrichment conflicts with level 4, the initial identity SID is retained and both SID values are included with `mismatch` status. |
| `builtin_account` | SID-based classification status, recognized label, and RID. |
| `principal_source` | `Get-LocalUser` classification when supplied; otherwise null. |
| `account_flags` | Original numeric `UF_*` flags value. |
| `account_flag_names` | Names for verified bits that are set; null if flags are unavailable. |
| `unknown_account_flag_bits` | Any bits not covered by this implementation's documented mask. |
| `enabled`, `disabled`, `locked_out` | Normalized interpretations of account-disabled/lockout flags. |
| `password_required`, `password_cannot_be_changed`, `password_never_expires`, `password_expired` | Account configuration/status flags, not credentials. |
| `supplemental_account_settings` | Direct allowlisted `Get-LocalUser` enabled, user-may-change-password, password-required, and password-never-expires values; allows independent comparison with NetAPI interpretations. |
| `password_age_seconds` | Raw provider age in seconds since last password change. |
| `password_last_set_utc_derived` | Estimate computed as query observation time minus password age; not a directly stored timestamp. |
| `password_last_set_derivation_status` | `derived_from_password_age`, direct supplemental provider value, or unavailable. |
| `password_last_set_observed_at_utc` | Observation time used for age derivation; null when not derived. |
| `password_last_set_uncertainty` | Explanation that the derived time is query-time-based and not a precise stored time. |
| `password_expires_utc_derived` | Estimate based on derived last-set time plus finite local maximum-age policy; null when never/unavailable. |
| `password_expiration_status` | `never`, `policy_never`, `derived_from_local_password_policy`, or `unavailable`. |
| `supplemental_timestamps` | Selected direct `Get-LocalUser` password-set, password-expiry, last-logon, and account-expiry timestamp values, if returned; no secret properties. |
| `password_never_expires_supplemental` | Optional Boolean exposed by the supplemental provider. |
| `account_expiration` | Object with raw provider value, UTC value, and status. Separate from password expiry. |
| `privilege_level`, `privilege_classification` | NetAPI privilege number and mapped guest/user/administrator class, if recognized. Not group membership. |
| `primary_group_id`, `provider_user_id` | Provider group RID and user RID. These are identifiers, not a group inventory. |
| `full_name`, `description`, `user_comment` | Distinct provider text fields; empty string remains empty. |
| `home_directory`, `home_drive`, `profile_path`, `logon_script_path` | Configured path metadata only; referenced files are not read. |
| `permitted_workstations`, `logon_server` | Provider text fields, without further parsing. |
| `last_logon`, `last_logoff` | Objects containing original integer, UTC time where valid, and a status such as `available`, `zero_not_recorded`, `invalid_timestamp`, or `unavailable`. |
| `logon_hours` | Raw bitmap as lowercase hexadecimal, byte length, units/week, and an explicit statement that it is not decoded. |
| `logon_hours_units_per_week` | Provider-reported units/week integer. |
| `auth_flags`, `bad_password_count`, `logon_count`, `country_code`, `code_page` | Raw NetAPI values; legitimate zero values remain zero. |
| `bad_password_count_status`, `logon_count_status` | `unknown_sentinel` for the provider's all-bits-set unknown counter sentinel; otherwise the corresponding availability state. |
| `max_storage_bytes` | Storage limit; null with `unlimited_sentinel` when provider reports `TIMEQ_FOREVER`. |
| `information_levels_used` | NetAPI provider to information-level mapping used for this record. |
| `sources` | Explicit provider names that contributed information. |
| `observed_at_utc` | UTC time used for field observation and password-age derivation. |
| `errors` | Per-record enrichment/SID/provider errors. The account record is retained when details fail. |

### Values, flags, and timestamps

- `null` means the property was unavailable, not returned, not applicable, or not resolved; consult the surrounding status object, provider information, and `errors`.
- `0`, `false`, and `""` are preserved when the provider actually returned them. They are not treated as missing.
- Status values remain only where they are part of a specific result, such as account expiration, last logon/logoff, password derivation, counters, SID resolution, or provider errors. A per-field status map is not emitted.
- Account flag values are preserved numerically, including unknown bits. The names emitted are limited to documented flag meanings. In particular, password-related flags express policy/configuration only; A40 neither infers that a password is known nor retrieves one.
- Numeric NetAPI time values are preserved in `raw`. Valid Unix-seconds timestamps are converted to UTC. Zero last-logon/logoff values are marked `zero_not_recorded`; account-expiration `TIMEQ_FOREVER` is marked `never`. A zero account-expiration value is retained as the Unix epoch because Microsoft documents `TIMEQ_FOREVER`, not zero, as its never-expire sentinel. Invalid values are not turned into plausible dates.
- Bad-password and logon counters retain the provider number and report `unknown_sentinel` when the provider's all-bits-set value means unknown.
- Password age is not itself a last-set timestamp. Any derived last-set and expiry values say they are derived and retain the observation time/policy basis. Account expiration and password expiration are different fields.
- Logon-hours data is retained as a hex bitmap with its units/week. No local-time schedule is inferred.
- Major error categories are `access_denied` (Windows refused the operation), `account_disappeared` (an enumerated name was no longer queryable), `unsupported_information_level` (the binding/provider rejected a requested level), `provider_failure` (other native/provider failure), `unexpected_provider_type`/`unexpected_provider_record` (malformed result), `pagination_no_progress` (resume handle repeated), `provider_account_set_mismatch` (primary and supplemental sets differ), and `domain_controller_scope_unsupported`/`local_scope_unverified` (scope could not safely be treated as local SAM). `unsupported_information_level_fallback` is a warning when a lower level succeeded. Raw provider messages can vary by Windows locale/version; production parsing does not use localized display tables.

Illustrative excerpt (not a real account; contains no credentials):

```json
{
  "artifact_id": "A40",
  "status": "partial",
  "enumeration_complete": false,
  "account_count": 1,
  "accounts": [
    {
      "username": "ExampleRenamedAdmin",
      "sid": "S-1-5-21-100-200-300-500",
      "builtin_account": {
        "status": "classified",
        "classification": "built_in_administrator_identity",
        "rid": 500
      },
      "enabled": true,
      "locked_out": false,
      "account_expiration": {
        "raw": 4294967295,
        "utc": null,
        "status": "never"
      },
      "password_age_seconds": 86400,
      "password_last_set_derivation_status": "derived_from_password_age",
      "logon_hours": {
        "bitmap_hex": "ff00",
        "byte_length": 2,
        "units_per_week": 168,
        "decoding": "not_performed; bit ordering/time semantics are not inferred"
      },
      "errors": []
    }
  ]
}
```

## Validation

For a read-only comparison, run A40 and independently inspect:

```powershell
Get-LocalUser | Select-Object Name, SID, Enabled, FullName, Description, PrincipalSource, PasswordRequired, PasswordExpires, PasswordLastSet, LastLogon, AccountExpires
```

Or from Command Prompt:

```bat
net user
net user "SomeLocalUsername"
```

These are secondary visual references only; their localized/formatted output is not parsed by A40. Compare names and SIDs first, then enabled state and suitable metadata. `Get-LocalUser` availability/coverage depends on the Windows edition and PowerShell module. Differences must be investigated; they are not silently accepted as proof of complete coverage.

Manual live checks still required on authorized Windows lab systems:

- Compare the live result with `Get-LocalUser` and `net user`; inspect any provider mismatch.
- Test UAC approval, cancellation, and already-elevated launch; confirm final exit code and path handling from a different current directory and with spaces in output paths.
- Confirm permissions/Windows edition differences and no account, password, policy, or membership changes. Do not create, disable, lock, rename, or otherwise modify real accounts to manufacture test cases.
- Live/manual checks do not cover every Windows release, local policy, API return condition, or pywin32 build.

## Limitations and common issues

- The system can change while collection runs: accounts can be added, removed, renamed, or changed between enumeration and enrichment. A missing account is retained with an enrichment error when its enumerated record is available.
- A permission/API/provider failure can prevent fields or pages from being read. The inventory reports incomplete/partial/failure and retains available records; it cannot promise that no account is ever missed.
- In the development environment, a read-only live run returned zero primary `NetUserEnum` entries while `Get-LocalUser` returned seven accounts. The collector retained all seven supplemental records, reported a provider mismatch, and returned `partial` rather than claiming a verified empty inventory. This live check wrote no output file. The implementation does not hide this observed provider difference.
- Windows PowerShell's `Get-LocalUser` module is not present on every SKU/installation. Its missing or failed result is reported and is not a substitute for successful NetAPI enumeration.
- `NetUserGetInfo` level 2/3/4 native structures include a password member, but Microsoft's API documentation says NetUserEnum/NetUserGetInfo return a null pointer for it. The implementation excludes that member from the allowlist and serialization regardless of the value seen in a test fixture. Passwords, hashes, credential material, tokens, and authentication secrets are never written or logged.
- The opaque `parms` member is intentionally not emitted; Microsoft reserves it for application-specific configuration and its contents are not a predictable, safely interpretable account field.
- `last_logon`/`last_logoff` fields may be zero or provider-limited; they are not proof of all Windows logon activity.
- This collector does not resolve profile directories to infer accounts, and does not inspect paths or produce an account-creation timestamp.
- If the JSON destination already exists, rerun with `--overwrite` only when replacement is intended. If pywin32 imports fail, rerun the project-root `setup_environment.bat`. If access is denied, use the launcher and approve UAC; do not assume elevation makes every requested field available.
- Output path/write errors are surfaced and do not produce a successful collection status.
