# Agent connection to the lab VM (PowerShell Remoting)

The Scanner Agent reaches the VM itself over WinRM. Nobody copies scripts in or JSON out. It sends only the repository's fixed collector ([scripts/vm/Collect-Server2022Evidence.ps1](../../scripts/vm/Collect-Server2022Evidence.ps1)) with typed parameters. Model text is never sent to the VM. The Remediation Agent uses the same channel for its read-only precheck and for approved actions.

```text
Laptop: Streamlit + agents (Python, pypsrp)  --NTLM-encrypted WinRM-->  127.0.0.1:55985
        VirtualBox NAT port forward "fyp-winrm"  ------------------->  VM 10.0.2.15:5985 (WinRM HTTP listener)
```

## Already done on the laptop (26 October 2026)

- `pypsrp==0.8.1` installed in the project venv (in `requirements.txt`). No laptop WinRM service, TrustedHosts or firewall change is needed. The laptop is only the client.
- VirtualBox NAT rule on `FYP-Server2022-Manual` (UUID `e5d10741-…`): `fyp-winrm,tcp,127.0.0.1,55985,,5985`. It is bound to loopback, so only this laptop can reach it.
  - Inspect: `VBoxManage showvminfo e5d10741-f200-4292-a099-e6be76032f4e --machinereadable | findstr Forwarding`
  - Remove: `VBoxManage controlvm e5d10741-f200-4292-a099-e6be76032f4e natpf1 delete fyp-winrm`

## One-time setup inside the VM

Open **Windows PowerShell as Administrator inside the Server 2022 VM**:

```powershell
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Test-WSMan -ComputerName localhost
```

`Test-WSMan` should print a `wsmid` / `ProtocolVersion` block. This step creates the HTTP listener on port 5985 and its inbound firewall rule. Leave `AllowUnencrypted` and Basic auth at their defaults (off); the agent uses NTLM with message encryption.

Use the **built-in Administrator** account. Windows strips the admin token from other local administrators over the network (UAC remote restrictions). The collector needs a full admin token for `secedit /export`, and the dashboard reports `not_admin` if the token is filtered.

Restoring `Clean_Server2022_Before_Hardening` undoes this setup. Run it again after a restore.

**After a snapshot restore, check the laptop-side port forward too.** Restoring brings back the VM's VirtualBox settings from when the snapshot was taken. That can remove the `fyp-winrm` rule, and the dashboard then reports `unreachable` (this happened on 30 October). Re-add it from the laptop (allowed while the VM is running):

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm e5d10741-f200-4292-a099-e6be76032f4e natpf1 "fyp-winrm,tcp,127.0.0.1,55985,,5985"
```

Check: `Invoke-WebRequest http://127.0.0.1:55985/wsman -Method Post` should fail with **401**. A 401 means the WinRM listener answered and wants a login; no answer at all means the forward or `Enable-PSRemoting` is missing.

## Reaching a server by its network address: the access helper

> **Optional.** It is not needed for the lab VM through the port forward (`127.0.0.1:55985`); the one-time setup above already covers that. Use it only to scan by network address: another server, or the VM through a host-only adapter instead of the port forward.

The connection form takes any **WinRM host** and port. The collector and runner still accept only a stand-alone Windows Server 2022 that matches the registered hostname and UUID.

The helper lives in its own folder, [scripts/server_access/](../../scripts/server_access/): `FYP-ServerAccess.ps1`, `Start-ServerAccess.cmd`, the README and the fixture test `test_server_access.ps1`. The connection form offers the first three as **Download helper (.zip)**, under the expander *Scanning by network address? Optional server access helper*. On the server, as administrator:

1. Check `Get-FileHash .\FYP-ServerAccess.ps1` against the SHA-256 shown under the download button.
2. Double-click `Start-ServerAccess.cmd`.
3. The window shows the computer name, UUID and IPv4 addresses for the form.
4. Click **Allow scanning** with the laptop's address. For the VirtualBox host-only network this is usually `192.168.56.1`.
5. Scan.
6. Click **Revert changes**.

**Allow** saves the current state to `C:\ProgramData\FYP-ServerAccess\state.json` first. It then adds one rule, `FYP-ServerAccess-WinRM`, that admits only that address on TCP 5985. If Remoting was off, it also runs `Enable-PSRemoting` and puts the built-in WinRM firewall rules and `LocalAccountTokenFilterPolicy` back as they were.

**Revert** undoes only what Allow changed. Anything that was already on stays on.

The helper refuses to run on a workstation, never changes a CIS setting, never enables Basic login or unencrypted traffic, and never handles a password. Its tests (`scripts/server_access/test_server_access.ps1`) use fixtures only. **Allow** and **Revert** have not yet been run on the VM.

## Use it

1. Start the dashboard (`.\.venv\Scripts\python.exe -m streamlit run app.py` from the application folder).
2. Open **Agentic hardening**. In **Connect to the VM**, enter computer name `WIN-VFT30DUDRHQ` and UUID `e5d10741-f200-4292-a099-e6be76032f4e`, keep host `127.0.0.1` and port `55985`, and enter the Administrator password.
3. Choose **Connect and check identity**. The dashboard checks the hostname, machine UUID and administrator token before anything else. Once connected, the form folds into a status line with **Disconnect**, and the sidebar shows the connection on every page.
4. **Start agentic round**: the Orchestrator delegates the Scanner Agent, which collects over this channel. After you approve fixes, **Execute approved fixes… → Confirm and execute** uses the same channel for the Remediation Agent's precheck, the approved actions and the verification rescan.

The password stays in the Streamlit session's memory only. It is never written to SQLite, logs, prompts or traces.

## Failure states

| State | Meaning |
| --- | --- |
| `unreachable` | Nothing answered: the VM is off, `Enable-PSRemoting` hasn't been run, or the port forward is missing |
| `auth_failed` | Wrong username or password |
| `not_admin` | Connected, but without an administrator token (use built-in Administrator) |
| `wrong_target` | The machine answering is not the registered hostname and UUID. Nothing is collected |
| `collection_failed` | The collector threw inside the VM (e.g. unsupported OS). No assessment is created |

## Limits and design notes

- Evidence collected over this channel is stored as `Live`, including the remediation runner's before/after evidence (since 3 November 2026; the 12 earlier runner records were relabelled). The file-era scans (19–26 October) were removed from the database on 3 November; a local backup is in `data/backup_before_cleanup_2026-11-03/`. `Imported` remains only for the command-line client's `--evidence file.json`. The **History and drift** table shows the source of every assessment.
- Hardening can cut this channel. Future firewall controls (for example disabling local firewall rule merging), WinRM service policies and network logon rights can break remoting. The Remediation Agent must refuse, or flag, any action that would disconnect its own channel before verification.
- The Remediation Agent runs [Invoke-RemediationAction.ps1](../../scripts/vm/Invoke-RemediationAction.ps1) over this channel for approved library actions, as described in [ARCHITECTURE.md](../design/ARCHITECTURE.md). Its precheck runs the same read-only collector without storing a new assessment. The manual file exchange of the retired upload page is documented in [archived VM_BRIDGE.md](../archive/legacy/VM_BRIDGE.md).
- Nothing needs to be copied into the VM for the agentic page: the collector and runner are sent over the channel on every call.
- Nothing is run by hand inside the VM. The shared-folder worker ([archived SCANNER_CONNECTION.md](../archive/legacy/SCANNER_CONNECTION.md)) was removed on 29 October, and the collector's and cross-check's save-to-file modes on 3 November: they needed a person inside the VM, so they did not satisfy D6.
