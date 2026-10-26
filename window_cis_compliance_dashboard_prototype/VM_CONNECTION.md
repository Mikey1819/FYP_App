# Agent connection to the lab VM (PowerShell Remoting)

The Scanner Agent reaches the VM itself over WinRM. Nobody copies scripts in or JSON out. It sends only the repository's fixed collector ([scripts/Collect-Server2022Evidence.ps1](scripts/Collect-Server2022Evidence.ps1)) with typed parameters. Model text is never sent to the VM. The Remediation Agent will reuse this channel for approved actions.

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

## Use it

1. Start the dashboard (`.\.venv\Scripts\python.exe -m streamlit run app.py` from the application folder).
2. Enter computer name `WIN-VFT30DUDRHQ` and UUID `e5d10741-f200-4292-a099-e6be76032f4e`.
3. In **Scanner live connection — PowerShell Remoting (WinRM)**, keep host `127.0.0.1` and port `55985`, then enter the Administrator password. Choose **Connect and check identity**. The agent checks the hostname, machine UUID and admin token before doing anything else.
4. Choose **Scan VM now**. A new assessment opens with no upload.
5. When **Run multi-agent hardening review** runs while connected, the Scanner Agent's `request_recollection` tool collects again over WinRM and opens the result as a new assessment.

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

- Evidence is still labelled `Imported` in storage, because the importer and storage enforce that mode. Relabelling it `Live` for channel-collected runs is a follow-up.
- Hardening can cut this channel. Future firewall controls (for example disabling local firewall rule merging), WinRM service policies and network logon rights can break remoting. The Remediation Agent must refuse, or flag, any action that would disconnect its own channel before verification.
- On the **Agentic hardening** page, the Remediation Agent also uses this channel. It runs [Invoke-RemediationAction.ps1](scripts/Invoke-RemediationAction.ps1) for approved library actions, as described in [ARCHITECTURE.md](ARCHITECTURE.md). The legacy upload page still uses the manual file exchange ([VM_BRIDGE.md](VM_BRIDGE.md)).
- Nothing needs to be copied into the VM for the agentic page: the collector and runner are sent over the channel on every call.
- The shared-folder worker ([SCANNER_CONNECTION.md](SCANNER_CONNECTION.md)) remains a fallback.
