# Benchmark mapping: CIS Server 2022 Stand-alone v2.0.0 (32 controls)

This is the authoritative record of which controls are assessed, against which benchmark text, and with which rule. The code holds them as one catalogue of 32 controls (`hardening/server2022_catalogue.py`). The sections below are dated: they record the source review of each group of controls as it was added, from 5 (19 October) to 32 controls (26 October). It records source review, not a successful VM assessment or CIS certification. The original synthetic demo-v1 catalogue and historical scores remain unchanged.

## Edition decision (26 October 2026)

This Stand-alone v2.0.0 edition is the project baseline (decision D3 in [AGENTS.md](../../AGENTS.md)). The report's CIS Microsoft Windows Server 2022 Benchmark v5.1.0 is not used: its Intended Audience (printed page 26) covers domain-joined/AD-managed systems and explicitly excludes standalone/workgroup systems, which is what the lab VM is. Report Table 3.2 IDs are candidates only; each must be re-checked against this edition's numbering, values and pages before implementation.

## Source and applicability

- Source: `C:\Users\User\Documents\Degree\FYP 1\myown\OWN\CIS_Microsoft_Windows_Server_2022_Stand-alone_Benchmark_v2.0.0.pdf`.
- Title/version/date: CIS Microsoft Windows Server 2022 Stand-alone Benchmark v2.0.0, 25 March 2026.
- File: 5,098,178 bytes, 918 PDF pages; SHA-256 `474f467dd90b5cd50598589e427c2360502b8d25e633f729efd89f44662c5d1d`.
- Printed page 23 (PDF page 24) explicitly scopes this edition to standalone systems. It states that CIS tested the guide on Datacenter edition; our Standard Evaluation VM still needs selected-control validation.
- Exact profile label: **Level 1 - Member Server**, printed page 28 (PDF page 29). Preserve this source label even though the edition's audience is standalone. Do not interpret the label as authorization to join a domain.
- Catalogue ID: `cis-server2022-standalone-2.0.0-full1`; evidence format `schema_version` 5, collector `server2022-readonly-v5`. These identifiers are stored in every saved scan, so they stay fixed. (The groups below first shipped under their own IDs and schema numbers 1-4; those were merged into this one catalogue on 4 November 2026.)
- Reviewed content: cover, scope/profile and complete selected recommendation/audit sections. Eleven relevant pages rendered and visually inspected; relevant section text extracted with PyMuPDF. No full 918-page review is claimed. Images stay in ignored `data/benchmark_review/` and the source PDF is not copied into the repository.

## Five selected controls

All five are Automated, Level 1 - Member Server in this edition. Page numbers below are printed numbers; add one for the PDF viewer page.

| Source ID | Selected check | Deterministic comparison | Pages | Collector observation |
| --- | --- | --- | --- | --- |
| 1.1.4 | Minimum password length | integer >= 14 | 38-39 | `secedit /export`, System Access / MinimumPasswordLength |
| 1.2.2 | Account lockout threshold | integer 1 through 5 inclusive; 0 fails | 51-52 | `secedit /export`, System Access / LockoutBadCount |
| 2.3.1.1 | Guest account status | enabled boolean = false | 132-133 | Local Win32_UserAccount with SID RID 501; invert its typed Disabled property |
| 9.3.1 | Public firewall policy state | REG_DWORD = 1 | 275-276 | HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile : EnableFirewall |
| 18.10.57.3.9.4 | Require NLA for remote connections | REG_DWORD = 1 | 733-734 | HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services : UserAuthentication |

Important distinctions:

- Demo lockout range is 1-10; the reviewed standalone range is **1-5**. Keep these catalogues separate rather than rewriting old evidence/scores.
- Public firewall is one explicitly selected profile/control, not a claim about all profiles, the active network profile, service health or internet exposure. The original demo uses Domain profile.
- Firewall/NLA observations follow the policy registry locations documented in the benchmark. An absent value ("Not configured") is **Non-Compliant** under decision D5 (see the 26 October section below; this line originally said Unknown), never an inferred pass from an OS default. A wrong registry type or failed read is Error. A DWORD other than 1 is non-compliant for the selected policy comparison. Actual effective protection may differ and is recorded separately as effective context.
- Account policy export describes local-account policy on this standalone target. It is not proof of every existing password's length or the treatment of built-in Administrator lockout (a separate control).
- Guest identity uses SID RID 501, not the display name. Missing/ambiguous identity is an error.
- Synthetic exposure/risk factors are never reused for a real server. Live risk scores are derived by rule from benchmark attributes ([RISK_DERIVATION.md](RISK_DERIVATION.md)); remediation uses the pre-approved library in [ARCHITECTURE.md](ARCHITECTURE.md). (When this section was first written, on 19 October, neither existed.)

## Account-policy expansion, 24 October 2026

These seven Automated, Level 1 checks come from the same PDF/hash. Recommendation and audit text were extracted; the rendered lockout-duration recommendation was also visually checked. New mappings are implemented and fixture-tested, not yet independently compared against the VM UI.

| Source ID | Added check | Comparison | Printed pages | System Access export key |
| --- | --- | --- | --- | --- |
| 1.1.1 | Password history | integer >= 24 | 31-33 | PasswordHistorySize |
| 1.1.2 | Maximum password age, days | integer 1 through 365 inclusive | 34-35 | MaximumPasswordAge |
| 1.1.3 | Minimum password age, days | integer >= 1 | 36-37 | MinimumPasswordAge |
| 1.1.5 | Password complexity | integer = 1 | 41-43 | PasswordComplexity |
| 1.1.7 | Reversible encryption | integer = 0 | 46-47 | ClearTextPassword |
| 1.2.1 | Lockout duration, minutes | integer >= 15 | 49-50 | LockoutDuration |
| 1.2.4 | Reset lockout counter, minutes | integer >= 15 | 55-56 | ResetLockoutCount |

The exporter preserves INF `-1` for MaximumPasswordAge (never expires) and LockoutDuration (administrator unlock required). Neither passes these selected finite-duration rules; no coercion to an unsigned integer or inferred compliance. Microsoft documents the keys/sentinels in [Password Policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0b40db09-d95d-40a6-8467-32aedec8140c) and [Account Lockout Policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/2cd39c97-97cd-4859-a7b4-1229dad5f53d). Other negative readings are collector errors under this bounded contract. Each comparison is independent; lockout timings are only effective with an enabled threshold. Cross-setting relationship validation is not implemented.

Manual validation: compare the first five added readings in `secpol.msc` -> Account Policies -> Password Policy, and the final two in Account Lockout Policy. Record UI/export differences, including UI 0 versus INF -1 for never/indefinite settings. Missing values remain Unknown; export failure yields Error for all nine account-policy observations. No new executable action was added.

## Local security expansion, 24 October 2026

These four Automated, Level 1 settings were added to the previous twelve. Recommendation/audit text was reviewed in the same source PDF; printed page 179 was rendered and visually checked. Implementation is fixture-tested; independent VM comparison is pending.

| Source ID | Added check | Comparison | Printed pages | Observation |
| --- | --- | --- | --- | --- |
| 2.3.1.2 | Limit blank local passwords to console logon | DWORD = 1 | 134-135 | HKLM\SYSTEM\CurrentControlSet\Control\Lsa:LimitBlankPasswordUse |
| 2.3.10.1 | Allow anonymous SID/name translation | integer = 0 | 179-180 | secedit export, System Access / LSAAnonymousNameLookup |
| 2.3.10.2 | Block anonymous SAM account enumeration | DWORD = 1 | 181-182 | HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymousSAM |
| 2.3.10.3 | Block anonymous SAM account/share enumeration | DWORD = 1 | 183-184 | HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymous |

The anonymous lookup mapping uses Microsoft's [Local Account Policies specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/d6eaa54a-f609-48e9-8461-b32738d77a47): zero disables the setting, nonzero enables it. This check uses the existing read-only export; the other three use read-only REG_DWORD access. Missing values remain Unknown; bad types/read failures remain Error. Export failure does not discard independent registry readings. Compare all four with `secpol.msc` -> Local Policies -> Security Options inside the VM.

Account renaming recommendations 2.3.1.3/2.3.1.4 (printed 136-139) were reviewed but deferred. The source also asks for names that conceal account purpose; checking only inequality with English default names would not fully implement that recommendation. No account-name compliance or automatic rename is claimed.

## Firewall, audit and RDP expansion to 32 controls, 26 October 2026

Schema 5 uses `cis-server2022-standalone-2.0.0-full1` and collector `server2022-readonly-v5`. It adds 16 Automated, Level 1 - Member Server controls to the previous 16, for **32 assessed controls**.

**Review method.** I extracted the title, profile and audit procedure text programmatically from the same PDF with PyMuPDF. The PDF's SHA-256 was rechecked as `474f467d…` and the extract is reproducible with [scripts/tools/extract_benchmark_audit.py](../../scripts/tools/extract_benchmark_audit.py). I did not render or visually inspect these pages. Independent VM comparison is pending.

| Source ID | Check | Rule | Printed pages | Observation |
| --- | --- | --- | --- | --- |
| 9.2.1 | Private firewall state | DWORD = 1 | 260-261 | `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile:EnableFirewall` |
| 9.2.2 | Private inbound connections: Block | DWORD = 1 | 262-263 | `…\PrivateProfile:DefaultInboundAction` |
| 9.2.6 | Private log dropped packets | DWORD = 1 | 270-271 | `…\PrivateProfile\Logging:LogDroppedPackets` |
| 9.2.7 | Private log successful connections | DWORD = 1 | 272-274 | `…\PrivateProfile\Logging:LogSuccessfulConnections` |
| 9.3.2 | Public inbound connections: Block | DWORD = 1 | 277-278 | `…\PublicProfile:DefaultInboundAction` |
| 9.3.6 | Public log dropped packets | DWORD = 1 | 285-286 | `…\PublicProfile\Logging:LogDroppedPackets` |
| 9.3.7 | Public log successful connections | DWORD = 1 | 287-288 | `…\PublicProfile\Logging:LogSuccessfulConnections` |
| 17.1.1 | Audit Credential Validation: Success and Failure | flags include 3 | 291-293 | `auditpol` subcategory `{0cce923f-…}` |
| 17.2.2 | Audit Security Group Management: include Success | flags include 1 | 296-297 | `{0cce9237-…}` |
| 17.2.3 | Audit User Account Management: Success and Failure | flags include 3 | 298-299 | `{0cce9235-…}` |
| 17.5.1 | Audit Account Lockout: include Failure | flags include 2 | 306-307 | `{0cce9217-…}` |
| 17.5.4 | Audit Logon: Success and Failure | flags include 3 | 312-313 | `{0cce9215-…}` |
| 18.10.57.2.2 | Do not allow passwords to be saved | DWORD = 1 | 705-706 | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:DisablePasswordSaving` |
| 18.10.57.3.9.1 | Always prompt for password upon connection | DWORD = 1 | 727-728 | `…\Terminal Services:fPromptForPassword` |
| 18.10.57.3.9.3 | RDP security layer: SSL | DWORD = 2 | 731-732 | `…\Terminal Services:SecurityLayer` |
| 18.10.57.3.9.5 | Client connection encryption level: High | DWORD = 3 | 735-736 | `…\Terminal Services:MinEncryptionLevel` |

**Audit values.** The collector runs `auditpol /backup` (read-only) and reads the numeric `Setting Value` column: 0 = none, 1 = Success, 2 = Failure, 3 = both. Unlike the "Inclusion Setting" text, this value doesn't depend on the OS language. It is assessed with a new `has_flags` rule, so CIS "include Success" passes both Success and Success-and-Failure. *Unverified assumption:* that the VM's backup CSV has the `Setting Value` column (the standard GPO `audit.csv` format). If it doesn't, the five audit controls report Unknown, never a false Compliant. The first live scan will confirm.

**Not configured (decision D5, 26 Oct).** Each firewall and RDP recommendation's audit step names a value under `HKLM\SOFTWARE\Policies` that must be set. A missing value ("Not configured") therefore fails the recommendation and is assessed as **Non-Compliant**. This also applies to the original 9.3.1 and NLA checks; earlier documents described them as Unknown. The collected *effective* firewall/NLA state never turns a failing policy into a pass. It only lowers the risk Exposure factor (see RISK_DERIVATION.md). Missing non-policy values remain Unknown.

### Where the report's Table 3.2 IDs differ from this edition

| Report ID / control | Stand-alone v2.0.0 | Decision |
| --- | --- | --- |
| 9.1.1, 9.1.2, 9.1.6 Domain profile | **No Domain profile section**: a standalone server has no domain network | Not applicable. Replaced by 9.2.7 and 9.3.7 (log successful connections) so the firewall area keeps 8 controls |
| 9.3.8 Public log dropped packets | **9.3.6** | Implemented as 9.3.6 |
| 17.2.5 Security Group Management | **17.2.2** | Implemented as 17.2.2 |
| 17.2.6 User Account Management | **17.2.3** | Implemented as 17.2.3 |
| 1.2.3 Administrator account lockout | 1.2.3 exists but is **Manual** (UI-only audit) | Not implemented; no automated audit procedure |
| 2.3.1.3 / 2.3.1.4 account renames | Present (Automated) | Deferred: checking against default names alone does not meet the "conceal account purpose" intent |

Final count: 32 implemented (Account Policies 9, Local Security Options 5, Firewall 8, Advanced Audit 5, RDP 5). The report's minimum of 30 is met; its proposed 36 cannot all apply to a standalone server.

## Independent manual comparison

**Tool-based cross-check (29 October):** `scripts/tools/cross_check_controls.py` reads all 32 values in the VM with different tools from the collector (see [Get-CrossCheckValues.ps1](../../scripts/vm/Get-CrossCheckValues.ps1)) and compares them with a stored scan; see VM_TRIAL_RUNBOOK.md Part C. It does not replace the GUI views below for the three values that only the security policy database holds (1.1.5, 1.1.7, 2.3.10.1), or for report screenshots.

Inside the VM, inspect these views without changing values. Record observed values and screenshots with collection time; do not press Apply after editing settings.

| Check | Manual view |
| --- | --- |
| Password length | `secpol.msc` -> Account Policies -> Password Policy -> Minimum password length |
| Lockout threshold | `secpol.msc` -> Account Policies -> Account Lockout Policy -> Account lockout threshold |
| Guest status | `secpol.msc` -> Local Policies -> Security Options -> Accounts: Guest account status |
| Public firewall policy | `gpedit.msc` -> Computer Configuration -> Windows Settings -> Security Settings -> Windows Defender Firewall with Advanced Security -> Windows Defender Firewall Properties -> Public Profile -> Firewall state |
| NLA policy | `gpedit.msc` -> Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security -> Require user authentication for remote connections by using Network Level Authentication |

The PDF's Group Policy paths include a Policies segment used in its editor examples; local editor layout can omit it. Record Not Configured explicitly. A missing local template/UI path is a validation gap, not authorization to install templates or force a registry write. Compare actual observations to the source and collector before claiming A11.

## Collector validation boundaries

The single-file PowerShell collector performs local CIM reads, a bounded `secedit /export`, and read-only 64-bit registry access. It writes temporary export/log files and a new JSON file, removes only its known temporary files and refuses output overwrite. It does not configure security policy, enable RDP/WinRM, or execute model-generated commands.

The offline importer requires explicitly selected hostname/UUID; checks supported OS/build/role, schema, catalogue/hash/profile, all 32 required unique records, sources, timestamps and exact scalar types. Imported files are user-supplied observations, not cryptographically authenticated attestation. Hashes identify bytes and do not prove collection authenticity. The CLI evaluates without writing the dashboard database.

Fixture tests cover parser/comparison/error/target boundaries. Separate imported-evidence dashboard/storage integration is fixture-tested. The first user-run VM export is received and validated, with collector-reported duration 0.342834s; see FIRST_VM_IMPORT_VALIDATION.md. Independent manual agreement remains pending.

Technical references: [Microsoft secedit export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export), [Win32_UserAccount](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-useraccount), [Win32_OperatingSystem](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem).

## Extraction script extended, 11 November 2026

`scripts/tools/extract_benchmark_audit.py` was first written on 26 October for the firewall, audit and Remote Desktop candidates. On 11 November it was extended to all five areas: it now extracts every candidate in sections 1.1, 1.2, 2.3.1, 2.3.10, 9.1-9.3, 17.1.1, 17.2, 17.5, 18.10.57.2.2 and 18.10.57.3.9 (57 candidates), adds the Rationale and Impact text, marks the 32 catalogue controls as [SELECTED] and ends with a check that all 32 were found in the PDF. Its output reproduces the earlier reviews of the first 16 controls (19-24 October), which were made by text extraction and visual checks without a saved script; it does not replace or redate those reviews.
