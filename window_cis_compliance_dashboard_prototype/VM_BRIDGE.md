# VM assessment and approved action exchange

Streamlit and local Qwen3 run on the laptop; the collector and guarded executor run inside the lab VM. Files cross the existing VirtualBox shared folder. This is a manual file-mediated connection, not a background remote service or a one-click remote scan.

The first executable action sets **minimum password length to 14**, for a confirmed non-compliant `1.1.4` observation below 14. Firewall/NLA and lockout changes are not implemented in this runner. Unknown is not permission to remediate.

## Current evidence and limits

Collector v2 retains the five policy observations and adds effective Public firewall enabled, RDP listener NLA required, and NLA policy source. Import v1 remains supported. New context does not rewrite old snapshots or turn missing policy entries into an invented pass/failure/risk score. Your screenshots showed firewall enabled and NLA required despite unconfigured Group Policy entries. Run v2 to include these readings in the export; do not disable protection for the demonstration.

The normal app shows real imported evidence only, with local AI tool investigation and a labelled deterministic proposal alternative. The model cannot approve or execute. Numeric risk scoring for imports remains unavailable. The old synthetic app is preserved as a separate legacy entry point and is absent from normal navigation.

Historical test (not current state): the first live VM receipt was verified: request `a7f9ce7846df45dd936bd474d3703cb1` changed minimum password length from 0 to 14. Collector v2 also confirms effective firewall enabled and NLA required. The user later reset the minimum back to 0 for repeated testing. A new baseline, proposal, approval and receipt are required for each test. See VM_VALIDATION.md. Do not replay a consumed request. Tests additionally cover passing and failed verification using mocked execution; they do not execute host security commands.

## 1. Copy the updated scripts

Prepared laptop exchange folder:

`C:\Users\User\Documents\Degree\FYP 1\FYP_App\window_cis_compliance_dashboard_prototype\cis_compliance_dashboard_prototype\data\vm_exchange`

Choose a working directory inside each VM. **C:\FYP is only the example used by the existing VM**, not a built-in requirement. In VM Explorer, open **Z:** and copy both files into your chosen directory:

- `Collect-Server2022Evidence.ps1` (updated v2)
- `Invoke-ApprovedVmAction.ps1`

Replace the scripts with the updated copies; retain existing JSON exports. Both scripts must be together. Use Explorer if elevated PowerShell cannot see Z:. The earlier UNC path did not resolve, so this guide does not assume it works.

Keep your clean VM snapshot. Restoring a snapshot also restores the runner's replay ledger: discard old requests after rollback and collect new evidence before a new approval. Do not delete the ledger to retry a failed request.

## 2. Collect and import a fresh baseline

Open **Windows PowerShell as Administrator inside the Server 2022 VM**. This example uses C:\FYP; substitute your chosen directory if different:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\FYP\Collect-Server2022Evidence.ps1" -ExpectedComputerName "WIN-VFT30DUDRHQ" -OutputPath "C:\FYP\server-evidence-v2.json"
```

Choose a new output filename if it already exists. Copy the JSON from C:\FYP back to Z: using Explorer.

On the laptop, start Streamlit from the application folder:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open **Imported VM Assessments**, upload the new JSON and enter:

- Computer name: `WIN-VFT30DUDRHQ`
- Machine UUID: `e5d10741-f200-4292-a099-e6be76032f4e`

Choose **Analyze uploaded evidence**. No previous assessment is loaded. Review the uploaded results and effective firewall/NLA readings. Under **3. Review a solution and run it in the VM**, save the device working directory. This setting is persisted by machine UUID; it does not broaden the supported OS or actions. Commands appear only after a valid directory is saved.

## 3. Investigate and decide

Under **3. Review a solution and run it in the VM**, select **Investigate this VM finding with local Ollama**. The model can inspect the finding, rule, related context and supported action, then save a proposal. It may instead request operational review or stop at a bounded failure. The current test's trace shows what actually happened; previous runs and proposals are not listed.

If the model is unavailable, **Prepare deterministic password-length proposal** remains available. Do not present that fallback as an AI decision.

Open the proposal. Review the target, original evidence digest, observation, action, parameters and impact. The minimum applies when local passwords are next set or changed; it does not rotate existing passwords. Check provisioning compatibility. Enter your administrator name (an audit label, not authenticated login), tick the review box and choose **Approve and create VM request**, or **Reject proposal**.

Rejection exports no request. Approval alone changes nothing. Download the approved `<request-id>-request.json` to the shared folder and copy it into the saved working directory inside the VM. Approval expires after 24 hours.

## 4. Apply inside the VM

Streamlit displays the **exact command**, including the request ID, SHA-256, target identity and saved VM directory. Copy it into elevated PowerShell **inside the VM**. Paths with spaces, apostrophes and PowerShell special characters are passed as literal arguments.

For manual use, the runner resolves a relative `-RequestPath` against `$PSScriptRoot`, not the current terminal directory. Omitted `-OutputDirectory` defaults to `$PSScriptRoot`; a relative output path is resolved there too. The directory must already exist. Helper lookup also uses `$PSScriptRoot`. The replay ledger remains machine-local under ProgramData so changing workspace does not permit replay.

Copy the expected request hash directly from Streamlit; do not derive it from the received file. The runner checks Server 2022 standalone x64, hostname/UUID, hash, action/parameters and expiry. It asks you to type `APPLY <request-id>`. A different confirmation cancels.

The runner labels the pre-action check, approved execution and post-action check separately. Helper collection is quiet during execution; it no longer prints the confusing no-hardening message. The runner displays the observed post-action password length and distinguishes command failure, unavailable read-back and failed comparison. It refuses changed or unknown preconditions. After a durable one-time claim, it executes only fixed `net.exe accounts /minpwlen:14`. A machine-local exclusive file lock prevents concurrent execution; the attempt ledger prevents replay from another workspace. Neither JSON nor model output can supply commands.

There is no automatic rollback or retry. A crash/failed write can leave an uncertain outcome: collect evidence and review before any newly approved attempt. Do not reuse the old request. The runner prints the receipt path. `applied` means the command returned successfully; it is not the final compliance verdict.

## 5. Return and verify

Keep the current Streamlit session open while executing inside the VM. Copy `<request-id>-receipt.json` back to Z:. Upload under **4. Return the receipt from this test**, then choose **Verify and save VM receipt**. A receipt from another test request is rejected, even if it targets the same VM.

The importer checks the approved request ID/hash, target, precondition and timestamps. It evaluates fresh post-action evidence with the reviewed minimum-length rule. **Verified compliant** requires successful execution and compliant fresh evidence; command success alone cannot pass.

The page shows only the current test's returned result, with its original input in an expander. Choose **Start new test** to clear results, proposal and receipt from the page. Collect fresh evidence after any intentional lab change, upload it, and obtain a new approval. Reopening the app starts at upload; it does not restore old results. SQLite is retained internally for request binding/audit, not as a visible history browser. The VM replay ledger is unchanged.

This lab bridge assumes trusted administrators and script copies. Files are user-supplied observations, not authenticated remote attestation. The independently copied hash detects changed request bytes; it is not a signing system. Do not expose this as a production multi-user service.

## Teacher demonstration

Show real VM export → findings and effective context → actual local AI tools → exact proposal → rejection with no request → separate approval → guarded VM action → returned receipt → fresh compliant password length with original history retained.

If live rehearsal is unfinished, identify that limit. Keep synthetic risk and simulated NLA demonstrations labelled separately.

## References

- [Reviewed CIS mapping](BENCHMARK_MAPPING.md), `1.1.4`, printed pages 38–39.
- [Microsoft Net Accounts reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/net-commands-on-operating-systems).
- [Microsoft firewall ActiveStore](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile?view=windowsserver2022-ps).
- [Microsoft NLA properties](https://learn.microsoft.com/en-us/windows/win32/termserv/win32-tsgeneralsetting).
