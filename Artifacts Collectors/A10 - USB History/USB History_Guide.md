# A10 USB History

Source: <A08 SYSTEM hive>\ControlSet00N\Enum\USBSTOR

Method: python-registry reads saved hive; recursive subkey walk

Privilege: Administrator (for A08 acquisition)

Output: USB History_Output/USB History_Output.json
Hash and timestamp report (launcher): USB History_Hash & Timestamp Report.json


Prerequisite: This collector runs A08 - Registry Hives quietly first, then
verifies the required saved hive using its manifest, size, SHA-256, registry
signature, and parser readability. It uses A08's configured output folder;
missing or invalid exports stop collection with an error.

Validation: See the artifact-specific interpretation and validation steps below. Prior-run counts and screenshots are illustrative only; compare with the current host and collection time.

Limits: Reads only USBSTOR branch (USB mass storage). Other USB device
        types (keyboards, mice, phones in MTP) are covered by other
        Enum subkeys. Device instance may lack a trustworthy serial;
        FriendlyName/DeviceDesc properties retrieved where present.
        Registry traces alone are not a complete connection timeline —
        no first-insertion or last-removal timestamp here.

## Understanding and validating A10 results

### Detailed field reading and validation workflow

Use `source_hive` and `control_set` to understand which saved SYSTEM view was parsed. `device_class` groups a USBSTOR class, while `instance_id` distinguishes a device instance; `friendly_name` and `device_desc` are descriptive registry values and can be missing or generic. `service` indicates the configured driver/service name, and `container_id` may assist correlation but is not guaranteed. `count` is the number of records emitted by this collector, not every USB device Windows has ever seen.

Validate against the same A08 SYSTEM export, not an unrelated current live hive: inspect `Enum\USBSTOR` with a read-only registry parser and compare representative class/instance values. Reconcile JSON `count` with array length and note the control set. A result can be empty because there are no mass-storage entries in the selected hive; phones using MTP and other USB classes are outside this query. Do not equate an instance record with proof of a particular connection time or user.


From the suite root, check JSON syntax with the shared environment: `".venv\Scripts\python.exe" -m json.tool "<selected-output-folder>\USB History_Output.json"` (replace the placeholder with the actual default or custom output directory).

Read `USB History_Output.json` fields `status`, `source_hive`, `control_set`, `utc`, `count`, `records`, and `reason`. Each record describes an instance under the SYSTEM hive's `Enum\\USBSTOR` branch; use `device_class`, `instance_id`, `friendly_name`, `device_desc`, `service`, and `container_id` when present. Optional names/IDs can be absent.

Validate against the A08 SYSTEM hive this collector used: confirm the source hive/control set and inspect matching USBSTOR keys in a read-only registry viewer. Reconcile `count` with `records` and inspect status/reason before interpreting an empty list. This covers USB mass-storage entries only; it does not enumerate every USB class, prove a device was connected at a specific time, or identify who used it.
