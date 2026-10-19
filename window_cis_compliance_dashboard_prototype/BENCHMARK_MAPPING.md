# Reviewed Server 2022 standalone preview subset

Reviewed 19 October 2026, Asia/Kuala_Lumpur. This records source review, not a successful VM assessment or CIS certification. The original synthetic demo-v1 catalogue and historical scores remain unchanged.

## Source and applicability

- Source: `C:\Users\User\Documents\Degree\FYP 1\myown\OWN\CIS_Microsoft_Windows_Server_2022_Stand-alone_Benchmark_v2.0.0.pdf`.
- Title/version/date: CIS Microsoft Windows Server 2022 Stand-alone Benchmark v2.0.0, 25 March 2026.
- File: 5,098,178 bytes, 918 PDF pages; SHA-256 `474f467dd90b5cd50598589e427c2360502b8d25e633f729efd89f44662c5d1d`.
- Printed page 23 (PDF page 24) explicitly scopes this edition to standalone systems. It states that CIS tested the guide on Datacenter edition; our Standard Evaluation VM still needs selected-control validation.
- Exact profile label: **Level 1 - Member Server**, printed page 28 (PDF page 29). Preserve this source label even though the edition's audience is standalone. Do not interpret the label as authorization to join a domain.
- Catalogue ID: `cis-server2022-standalone-2.0.0-preview1`.
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
- Firewall/NLA observations follow the policy registry locations documented in the benchmark. An absent value is **Unknown / manual review needed**, not an inferred pass from an OS default. A wrong registry type or failed read is Error. A DWORD other than 1 is non-compliant for the selected policy comparison. Actual effective protection may differ and must be discussed separately.
- Account policy export describes local-account policy on this standalone target. It is not proof of every existing password's length or the treatment of built-in Administrator lockout (a separate control).
- Guest identity uses SID RID 501, not the display name. Missing/ambiguous identity is an error.
- No live risk arithmetic is added yet: synthetic exposure/risk factors cannot be silently reused for a real server. No real remediation implementation is included.

## Independent manual comparison

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

The offline importer requires explicitly selected hostname/UUID; checks supported OS/build/role, schema, catalogue/hash/profile, all five unique records, sources, timestamps and exact scalar types. Imported files are user-supplied observations, not cryptographically authenticated attestation. Hashes identify bytes and do not prove collection authenticity. The CLI evaluates without writing the dashboard database.

Fixture tests cover parser/comparison/error/target boundaries. Real VM execution, independent manual agreement, collector timing and dashboard integration are still pending.

Technical references: [Microsoft secedit export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export), [Win32_UserAccount](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-useraccount), [Win32_OperatingSystem](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem).
