# First imported VM assessment validation

## Result and limits

Latest clarification, 21 October: the user deliberately reset minimum password length to 0 after the successful test. The newer export collected `2026-10-21T03:15:03.213240Z` reports 0 (Non-Compliant), SHA-256 `82fd94c7fb4302936167e1214f79529d9843b1adfc4206d9599b94c9cf438d35`. Earlier 14-character evidence is historical, not proof of current posture. The app now starts blank and shows only the test explicitly uploaded by the user; each repeat needs new approval and its own receipt.

The first user-run Windows Server VM export passed strict offline validation and was saved on 19 October 2026. Five observations agree with manual checks. Later collector v2 data confirms effective firewall/NLA settings, and a real VM password-length change has returned a verified receipt (below). Missing explicit policy interpretation remains separate from effective protection; full preview completion/rehearsal is not claimed.

## Live action and v2 verification, inspected 21 October 2026

Read-only inspection of `data/preview_imports_bridge.sqlite3` found the actual receipt for request `a7f9ce7846df45dd936bd474d3703cb1`. Its SHA-256 binding matches the saved approved request; runner status is `applied` and persisted verdict is **Verified compliant**. Decoded before/after exports pass the strict importer with the independently confirmed VM identity.

- Before: minimum password length **0**, Non-Compliant; completed `2026-10-20T13:11:17.937012Z`.
- After: minimum password length **14**, Compliant; completed `2026-10-20T13:11:18.343104Z`.
- Before file SHA-256: `462929ee45591b425bf7058b8ec00a34d1885bb7941f172180eb29307e1c2815`.
- After file SHA-256: `da8f69c1e0d2e0d559dd986c5153d1ed05f95d2dedd6bedbc1816904f0ea3f43`.

The user executed this inside the VM, then imported the receipt. No assistant-run host hardening occurred. Files are supplied evidence, not signed attestation. Screenshot wording “No hardening applied” came from the read-only collector before/after the command; it did not mean the approved command was skipped. Updated runner/helper output removes that ambiguity. The original baseline remains unchanged; the normal app now points to fresh receipt evidence after saving and warns when viewing an older snapshot.

The available `server-evidence-v2.json`, completed `2026-10-20T13:00:35.709745Z`, validates Public firewall enabled=True, NLA required=1, source=0. It is a pre-action baseline (password length 0), not evidence that the later change failed. Its explicit firewall/NLA policy observations remain missing/Unknown.

## Identity and provenance

- Hostname: WIN-VFT30DUDRHQ.
- UUID: e5d10741-f200-4292-a099-e6be76032f4e. Both identifiers match the user's separate VM console screenshot.
- Export reports Windows Server 2022 Standard Evaluation, version 10.0.20348, x64, ProductType 3, PartOfDomain false, DomainRole 2.
- Catalogue: cis-server2022-standalone-2.0.0-preview1; exact source profile: Level 1 - Member Server.
- Original export: `cis_compliance_dashboard_prototype/data/vm_exchange/server-evidence.json` (3,222 bytes).
- SHA-256: `4a1cb6597536b8041ac1633de1bb79364cb54b1a5f583fb7f63e20f91e8a1087`.
- Collected: 19 October 2026, 22:19:33.807916 to 22:19:34.150750 Malaysia time (UTC+08:00). Collector-reported duration: 0.342834 seconds. This is one five-control collection interval from supplied timestamps, not independently timed end-to-end validation or a performance guarantee.
- User ran the collector from C:\FYP inside the VM and copied the JSON back through mapped drive Z:. The assumed VBOXSVR/FYP-Exchange path did not resolve; no configuration was changed to work around it.
- Data is imported user-supplied evidence, not authenticated remote attestation or a current live scan.

## Findings

| ID | Check | Exported observation | Reviewed rule | Result | Independent manual comparison |
| --- | --- | --- | --- | --- | --- |
| 1.1.4 | Minimum password length | 0 | At least 14 | Non-Compliant | Matches user-reported value 0 |
| 1.2.2 | Account lockout threshold | 0 | 1 through 5 | Non-Compliant | Matches user-reported value 0 |
| 2.3.1.1 | Guest account enabled | false (disabled) | false | Compliant | Matches user-reported Disabled |
| 9.3.1 | Public firewall policy | Policy value missing | DWORD 1 | Unknown | Matches user screenshot: Not configured |
| 18.10.57.3.9.4 | NLA policy | Policy value missing | DWORD 1 | Unknown | Matches user screenshot: Not configured |

Coverage is 3/5 evaluated, with 1 compliant, 2 non-compliant, 2 unknown and 0 collection errors. The displayed 33% is 1/3 among evaluated checks, not whole-server CIS compliance. Missing policy values do not establish that effective firewall protection or NLA is disabled. Password policy length 0 describes the configured minimum, not the actual length of existing passwords.

## Checks completed

From the Windows project folder:

```powershell
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B scripts\inspect_server_evidence.py cis_compliance_dashboard_prototype\data\vm_exchange\server-evidence.json --expected-hostname WIN-VFT30DUDRHQ --expected-machine-uuid E5D10741-F200-4292-A099-E6BE76032F4E
```

The CLI exited 0. ImportedEvidenceStore revalidated and inserted the export into `cis_compliance_dashboard_prototype/data/preview_imports.sqlite3`, preserving original bytes and evaluated rules. A fresh Python process reopened the record and verified byte equality. Streamlit AppTest rendered the actual imported view without exceptions and confirmed target selection, 3/5 coverage, 2 Unknown and incomplete-coverage warning. Evidence summary is in ignored `data/vm_exchange/validation-summary.json`. No application source changed; the previous 79-test suite remains the latest general suite result. These checks do not constitute browser visual QA.

## Manual comparison procedure

Inspect without editing; record the actual displayed values, including Not Configured. Do not change settings merely to match expectations.

1. Open `secpol.msc`. Under Account Policies / Password Policy, capture Minimum password length.
2. Under Account Policies / Account Lockout Policy, capture Account lockout threshold.
3. Under Local Policies / Security Options, capture Accounts: Guest account status.
4. Open `gpedit.msc`. Under Computer Configuration / Windows Settings / Security Settings / Windows Defender Firewall with Advanced Security, open firewall properties and capture the Public Profile / Firewall state. Do not substitute an effective-state display for the policy view; record any difference separately.
5. Under Computer Configuration / Administrative Templates / Windows Components / Remote Desktop Services / Remote Desktop Session Host / Security, capture Require user authentication for remote connections by using Network Level Authentication.

See [BENCHMARK_MAPPING.md](BENCHMARK_MAPPING.md) for source pages and audit distinctions. If a path is missing or observations differ, preserve the result and investigate. Manual comparisons are complete for the exported observations. Compliance treatment of known absent policy values remains under review; visual QA and spoken rehearsal are not complete. PREVIEW_COMPLETE is not set.

## Manual comparison and interpretation checkpoint 20 October 2026, 09:40 Malaysia time (UTC+08:00)

The user reported minimum password length 0, lockout threshold 0 and Guest disabled after the requested secpol.msc inspection. These three confirmations are text reports, not screenshot evidence. A separate NLA policy screenshot shows Not Configured; the firewall properties screenshot shows the Public Profile tab with Firewall state Not configured. Those two screenshots were reviewed in the chat; no screenshot files were saved to the repository. Observation capture times were not independently recorded. All five observations agree with the original export; no new collector run is claimed.

Not configured is not the same as effective protection disabled. Microsoft documents ActiveStore as the combined active firewall policy, including local stores and GPOs; NLA's unconfigured policy leaves the target's local setting in effect. Sources: https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile?view=windowsserver2022-ps and https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-terminalserver . Neither source establishes this VM's effective state without additional observations.

The current preview1 evaluator retains Unknown for a missing policy value. This is a conservative implementation choice, not a CIS severity and not a safe/pass result. Now that absence is manually confirmed, the next rule review should distinguish a known policy requirement gap from a collection error or genuinely unavailable evidence. Verify the exact source audit semantics before adding a control-specific absent-value rule in a new catalogue version. Preserve original bytes and historical results; any reassessment must be a separate record. Do not globally convert missing evidence to failure or high risk.

Recommended next evidence: read-only Get-NetFirewallProfile -PolicyStore ActiveStore output inside the confirmed VM, then separately obtain effective NLA/RDP state and operational context. No discovery scan or host configuration change. Risk still requires reviewed impact/exposure/privilege/likelihood/history inputs; the synthetic scores must not be reused for this VM. Imported AI investigation and remediation remain unavailable in the current application.

## Effective firewall configuration recorded 20 October 2026, 09:47 Malaysia time (UTC+08:00)

User supplied a VM console screenshot of `Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction`. Domain, Private and Public each show Enabled=True, DefaultInboundAction=Block, DefaultOutboundAction=Allow. This is supplementary screenshot evidence, not part of the original JSON. The screenshot does not display hostname or collection time; attribution to the confirmed VM follows the ongoing user-directed VM procedure. No live query was performed by the assistant.

This establishes the reported active configuration of all three profiles, including Public. It does not identify which network profile is in use, verify filtering by traffic tests, or enumerate rule exceptions. Default inbound Block does not mean every inbound connection is blocked. It refutes the inference that the earlier Not configured policy view necessarily means the firewall is disabled. Explicit benchmark policy conformance remains a distinct review; the old snapshot/risk scores are unchanged.

Next: inspect effective NLA using the read-only Win32_TSGeneralSetting properties UserAuthenticationRequired and PolicySourceUserAuthenticationRequired inside the VM. Microsoft reference: https://learn.microsoft.com/en-us/windows/win32/termserv/win32-tsgeneralsetting . No setting method is authorized or needed for this check.

## Effective NLA configuration recorded 20 October 2026, 09:49 Malaysia time (UTC+08:00)

User supplied a console screenshot of the requested read-only Win32_TSGeneralSetting query. TerminalName=RDP-Tcp, UserAuthenticationRequired=1, PolicySourceUserAuthenticationRequired=0. Microsoft defines these as connection-time authentication required and configuration source Server, respectively. This corroborates local NLA configuration despite the Group Policy Not Configured observation. It does not establish that RDP is enabled, listening or reachable; no connectivity or login test was performed. Attribution to the same VM follows the ongoing user procedure; this screenshot itself shows no hostname or capture timestamp. Screenshot reviewed in chat, not saved as an image file.

Both supplementary observations now exist: firewall profiles Enabled=True and RDP-Tcp NLA required from server configuration. Do not label either protection disabled based on absent Group Policy values. Benchmark enforcement requirements remain separate from effective configuration; review the source audit before changing compliance semantics. Original JSON and saved preview1 results remain immutable and still show two Unknown policy observations. The supplemental facts are documented here, not yet added to the imported database/schema/UI. No numeric VM risk score is assigned.

All manual checks requested so far have been provided. Next software work: source-audit decision for absent policies, versioned evidence/rule support if needed, and presentation of policy versus effective configuration without replacing historical results. Remaining readiness work includes visual/spoken rehearsal; no real remediation is authorized by these observations.
