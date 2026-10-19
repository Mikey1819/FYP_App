# First read-only evidence from the VirtualBox lab

The collector is prepared and fixture-tested, but has not yet run on your VM. It assesses only the five selected controls in [BENCHMARK_MAPPING.md](BENCHMARK_MAPPING.md). The Streamlit demonstration still displays its original synthetic data; the first real file will be inspected separately before dashboard integration.

## Set up file transfer

Use VirtualBox Guest Additions and one dedicated shared folder. This does not require Windows network sharing, RDP, WinRM or firewall changes. Guest Additions installs integration drivers inside the VM; this is separate from the read-only collector. Your existing clean snapshot is the recovery point.

1. Start `FYP-Server2022-Manual` and log into Windows Server.
2. In the VM window choose **Devices -> Insert Guest Additions CD Image**.
3. Inside the VM, open **File Explorer -> This PC**, open the VirtualBox Guest Additions CD, and run **VBoxWindowsAdditions.exe**. Complete setup and restart the VM. If Windows blocks the installer or a required restart is pending, report the actual message rather than disabling security features.
4. In VirtualBox, open the VM's **Settings -> Shared Folders** (or **Devices -> Shared Folders -> Shared Folder Settings**). Add the dedicated host folder below:

   ```text
   C:\Users\User\Documents\Degree\FYP 1\FYP_App\cis_compliance_dashboard_prototype\data\vm_exchange
   ```

5. Set **Folder Name** to `FYP-Exchange`. Enable **Auto-mount**; make it permanent if that option appears. Leave **Read-only** unchecked so the VM can return the JSON file to this folder. Share this dedicated folder only; it contains the collector copy and future evidence.
6. Inside the VM, type this address into File Explorer:

   ```text
   \\VBOXSVR\FYP-Exchange
   ```

You should see `Collect-Server2022Evidence.ps1`. If the folder is unavailable, first confirm Guest Additions installation/restart and the exact share name. Do not enable Windows SMB sharing or change firewall rules to repair a VirtualBox shared folder.

Oracle documents [Guest Additions and shared folders](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/guestadditions.html), including the `\\VBOXSVR\share` Windows path. No Extension Pack is needed for these instructions.

## Run inside the VM only

Open **Windows PowerShell as Administrator inside Windows Server**. Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "\\VBOXSVR\FYP-Exchange\Collect-Server2022Evidence.ps1" -ExpectedComputerName $env:COMPUTERNAME -OutputPath "\\VBOXSVR\FYP-Exchange\server-evidence.json"
```

The execution-policy option applies to this child PowerShell process; it does not set a permanent machine policy. The script checks Server 2022 x64/build 20348, standalone role and the selected computer name before collecting security configuration. It refuses client Windows and domain-joined machines. It does not change passwords, account settings, firewall, registry policy, RDP, services or domain membership.

On success it prints the output path, computer name and machine UUID. Send that output (or a screenshot) and tell the assistant the file is ready. The file will already be accessible on the laptop at:

```text
C:\Users\User\Documents\Degree\FYP 1\FYP_App\cis_compliance_dashboard_prototype\data\vm_exchange\server-evidence.json
```

If it says the file already exists, preserve that evidence and choose a new filename such as `server-evidence-02.json`. If it fails, send the exact error; do not weaken VM settings to make a control pass. Unknown/error observations are valid evidence of an unfinished check.

## Inspect on the laptop

The assistant will compare the displayed hostname/UUID with the file and run this command from the repository root, replacing the two placeholders with the actual confirmed values:

```powershell
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B scripts\inspect_server_evidence.py cis_compliance_dashboard_prototype\data\vm_exchange\server-evidence.json --expected-hostname "VM_COMPUTER_NAME" --expected-machine-uuid "VM_UUID"
```

The CLI returns checked/selected coverage, Compliant/Non-Compliant/Error/Unknown and source references. It never changes Windows or writes the dashboard database. Original export bytes must be preserved. A schema-valid export is not proof that every collector matches the benchmark: complete the independent manual checks in BENCHMARK_MAPPING.md, resolve discrepancies and record timings before A11 is complete. Do not present results from five selected controls as full CIS compliance.

## Developer checks

From the application folder:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

From the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\test_collector_helpers.ps1
```

The PowerShell helper tests load the collector with `-FunctionsOnly` and use fixture data; they do not query the host's security configuration or run secedit. No local host collection should be used as a substitute for the VM test. PDF review packages installed in the project venv are authoring tools only; the dashboard and importer do not depend on them.
