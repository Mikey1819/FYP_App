# First read-only evidence from the VirtualBox lab

> **Archived 26 October 2026.** Describes the legacy **Evidence upload** page (manual file exchange and the earlier agent team), which was removed on 27 October 2026; its code is in commit `81b9d52` and earlier. Current design: [ARCHITECTURE.md](../../design/ARCHITECTURE.md); current status: [PROGRESS.md](../../../PROGRESS.md).

Historical VM validation covers the original five controls; see [FIRST_VM_IMPORT_VALIDATION.md](../../evaluation/FIRST_VM_IMPORT_VALIDATION.md). Collector v4 now assesses 16 controls in [BENCHMARK_MAPPING.md](../../design/BENCHMARK_MAPPING.md), retaining effective firewall/NLA context. Its eleven added checks still need independent VM comparison. Legacy v1/v2 files retain five checks; v3 retains twelve. Follow [VM_BRIDGE.md](VM_BRIDGE.md) for the approved password-length request/receipt flow.

To use the expansion, copy the updated `Collect-Server2022Evidence.ps1` from the exchange folder into `C:\FYP` inside the VM. Run the following there as Administrator, then copy the new JSON back to the exchange folder and upload it in the dashboard:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\FYP\Collect-Server2022Evidence.ps1" -ExpectedComputerName $env:COMPUTERNAME -OutputPath "C:\FYP\server-evidence-v4.json"
```

Choose a new filename if that file already exists. This collects evidence only. The updated collector is also used by the approved runner when both scripts are in the same VM directory.

## Set up file transfer

Use VirtualBox Guest Additions and one dedicated shared folder. This does not require Windows network sharing, RDP, WinRM or firewall changes. Guest Additions installs integration drivers inside the VM; this is separate from the read-only collector. Your existing clean snapshot is the recovery point.

1. Start `FYP-Server2022-Manual` and log into Windows Server.
2. In the VM window choose **Devices -> Insert Guest Additions CD Image**.
3. Inside the VM, open **File Explorer -> This PC**, open the VirtualBox Guest Additions CD, and run **VBoxWindowsAdditions.exe**. Complete setup and restart the VM. If Windows blocks the installer or a required restart is pending, report the actual message rather than disabling security features.
4. In VirtualBox, open the VM's **Settings -> Shared Folders** (or **Devices -> Shared Folders -> Shared Folder Settings**). Add the dedicated host folder below:

   ```text
   C:\Users\User\Documents\Degree\FYP 1\FYP_App\window_cis_compliance_dashboard_prototype\cis_compliance_dashboard_prototype\data\vm_exchange
   ```

5. Set **Folder Name** to `FYP-Exchange`. Enable **Auto-mount**; make it permanent if that option appears. Leave **Read-only** unchecked so the VM can return the JSON file to this folder. Share this dedicated folder only; it contains the collector copy and future evidence.
6. Inside the VM, type this address into File Explorer:

   ```text
   \\VBOXSVR\FYP-Exchange
   ```

You should see `Collect-Server2022Evidence.ps1`. If the folder is unavailable, first confirm Guest Additions installation/restart and the exact share name. Do not enable Windows SMB sharing or change firewall rules to repair a VirtualBox shared folder.

Oracle documents [Guest Additions and shared folders](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/guestadditions.html), including the `\\VBOXSVR\share` Windows path. No Extension Pack is needed for these instructions.

## Transfer confirmed and snapshot choice

On 19 October, the user confirmed that the collector file is visible in VM Explorer. The setup steps above are retained for reference; proceed to collection below. Visibility alone does not prove the collector ran or the VM can write the returned JSON.

Keep `Clean_Server2022_Before_Hardening`. A file seen through `\\VBOXSVR\FYP-Exchange` resides on the host: its contents are not part of the VM virtual disk snapshot and are not restored with it. If you copied the file onto the VM's own C: drive, that copy is part of the VM disk state and will be absent when restoring a snapshot taken before the copy.

An optional additional snapshot named `Ready_For_Assessment_After_Guest_Additions` can preserve the prepared VM, including installed Guest Additions and files copied into its virtual disk. Do not delete or replace the original clean snapshot. Restoring the older snapshot can also undo later VM integration/configuration setup; shared-folder files should be backed up separately. See Oracle's [snapshot contents](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/working-with-vms.html) and [shared-folder documentation](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/guestadditions.html). No snapshot was created or restored by the assistant.

## If the assumed share name is unavailable

In the confirmed setup, Explorer exposes the share as Z: and the assumed `\\VBOXSVR\FYP-Exchange` path did not resolve. The user successfully copied the collector from Z: into C:\FYP inside the VM, ran it there with output C:\FYP\server-evidence.json, then copied the JSON back to Z: in Explorer. Use the actual share mapping; do not change firewall or networking settings. Preserve the first export and choose a new output filename for later collections.

## Run inside the VM only

Open **Windows PowerShell as Administrator inside Windows Server**. Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "\\VBOXSVR\FYP-Exchange\Collect-Server2022Evidence.ps1" -ExpectedComputerName $env:COMPUTERNAME -OutputPath "\\VBOXSVR\FYP-Exchange\server-evidence.json"
```

The execution-policy option applies to this child PowerShell process; it does not set a permanent machine policy. The script checks Server 2022 x64/build 20348, standalone role and the selected computer name before collecting security configuration. It refuses client Windows and domain-joined machines. It does not change passwords, account settings, firewall, registry policy, RDP, services or domain membership.

For an independent identity check, also run these read-only commands in the VM console and retain their output separately from the JSON:

```powershell
hostname
(Get-CimInstance Win32_ComputerSystemProduct).UUID
```

On success it prints the output path, computer name and machine UUID. Send that output (or a screenshot) and tell the assistant the file is ready. The file will already be accessible on the laptop at:

```text
C:\Users\User\Documents\Degree\FYP 1\FYP_App\window_cis_compliance_dashboard_prototype\cis_compliance_dashboard_prototype\data\vm_exchange\server-evidence.json
```

If it says the file already exists, preserve that evidence and choose a new filename such as `server-evidence-02.json`. If it fails, send the exact error; do not weaken VM settings to make a control pass. Unknown/error observations are valid evidence of an unfinished check.

## Inspect on the laptop

You can now use the dashboard's **Imported VM Assessments** page. Upload the returned JSON, enter the computer name and UUID shown independently in the VM console, and review the results. Uploading only previews; **Save imported assessment** persists the original file and immutable evaluated snapshot. The same exact file is saved once even on repeated clicks. Saved history survives restart and offers the original JSON for download.

Imported records live in `data/preview_imports.sqlite3`, alongside `preview.sqlite3`. When `CIS_DASHBOARD_DB` is overridden, the import path uses the same directory and stem with `_imports.sqlite3` appended. VM proposals/decisions/receipts/AI traces use the import stem plus `_bridge.sqlite3`; back up all three databases with the app stopped. The six synthetic pages remain separate. Imported numeric risk scores remain unavailable. History lists the latest 50 snapshots by collection time; missing/error checks remain visible alongside coverage.

The CLI remains available for a read-only inspection without saving:

The assistant will compare the displayed hostname/UUID with the file and run this command from the Windows project folder (`window_cis_compliance_dashboard_prototype`), replacing the two placeholders with the actual confirmed values:

```powershell
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B scripts\tools\inspect_server_evidence.py cis_compliance_dashboard_prototype\data\vm_exchange\server-evidence.json --expected-hostname "VM_COMPUTER_NAME" --expected-machine-uuid "VM_UUID"
```

The CLI returns checked/selected coverage, Compliant/Non-Compliant/Error/Unknown and source references. It never changes Windows or writes a database. Original export bytes must be preserved. A schema-valid export is not proof that every collector matches the benchmark: complete the independent manual checks in BENCHMARK_MAPPING.md, resolve discrepancies and record timings before A11 is complete. Do not present results from five selected controls as full CIS compliance.

## Developer checks

From the application folder:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

From the Windows project folder (`window_cis_compliance_dashboard_prototype`):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\vm\test_collector_helpers.ps1
```

The PowerShell helper tests load the collector with `-FunctionsOnly` and use fixture data; they do not query the host's security configuration or run secedit. No local host collection should be used as a substitute for the VM test. PDF review packages installed in the project venv are authoring tools only; the dashboard and importer do not depend on them.
