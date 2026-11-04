# Risk factor derivation

Generated from `hardening/risk.py` by `scripts/tools/generate_risk_derivation.py`; rule version `rules-2026-10-26 (Table 4.15 derivation; category assignments under researcher review)`. Do not edit by hand: change the attributes or rules in code and regenerate.

The report formula is `R = 6I + 5E + 4P + 3L + 2D` (Section 4.6.2.4). No factor value is assigned directly. Each control records three attributes read from its CIS Stand-alone v2.0.0 entry, and fixed rules map them to I, P and L. The rules follow report Table 4.15, and the wording comes from the Table 4.14a/4.14c rubrics. E and D are determined at assessment time.

## Rules

**Security Impact (I).** Taken from the consequence stated in the benchmark Rationale/Impact text.

| Consequence category | I | Rubric basis |
| --- | --- | --- |
| `critical_protection_lost` | 5 | credentials recoverable or the network boundary disabled: severe compromise of critical security functions (4.14a score 5) |
| `protection_weakened` | 4 | authentication or network protection weakened: may significantly affect system security (4.14a score 4) |
| `misuse_easier` | 3 | unauthorised activity or information disclosure made easier: affects an important security function (4.14a score 3) |
| `minor_reduction` | 2 | password ageing only: minor reduction in security posture (4.14a score 2) |
| `detection_only` | 2 | logging or audit visibility only: minor reduction in security posture (4.14a score 2) |

**Privilege Impact (P).** Taken from the accounts, groups or rights the setting governs.

| Privilege scope | P | Rubric basis |
| --- | --- | --- |
| `admin_identity_or_stored_credentials` | 5 | exposes the administrator identity or stored credentials: directly affects highly privileged access (4.14c score 5) |
| `all_local_accounts` | 4 | applies to every local account including the built-in Administrator: may contribute to administrative access (4.14c score 4) |
| `remote_admin_logon` | 4 | protects remote administrative access to the server: may contribute to administrative access (4.14c score 4) |
| `guest_or_anonymous` | 2 | affects only Guest or anonymous access: limited user-level functions (4.14c score 2) |
| `logging_only` | 1 | governs logging only: minimal implications for privileges (4.14c score 1) |

**Likelihood (L).** Taken from the benchmark Profile Level and Assessment Status (Table 4.15).

| Profile level | Assessment status | L |
| --- | --- | --- |
| Level 1 | Automated | 4 |
| Level 1 | Manual | 3 |
| Level 2 | Automated | 3 |
| Level 2 | Manual | 2 |

**Exposure (E).** Base value from the exposure surface (Table 4.14b), plus 1 when the *collected* effective Public firewall state is disabled, for network-reachable surfaces. Surfaces: `network_logon` = 3, `network_anonymous` = 4, `network_boundary` = 4, `remote_desktop` = 4, `local_account` = 3, `local_secret` = 2, `detection` = 2. Exception: for 9.2.1, 9.2.2, 9.3.1, 9.3.2, 18.10.57.3.9.4, when the policy is Not configured but the collected effective local state shows the protection is on, E = 1 ("minimal exposure"). The finding stays Non-Compliant (decision D5) because CIS requires the policy itself.

**Configuration State or Drift (D).** From the previous comparable assessment (Table 4.14e): 1 when there is none, 3 when the control was already non-compliant, 5 when it was compliant before (a regression). A scan that the Scanner Agent's own rescan replaced within the same round is not a previous assessment.

## Per-control derivation

| Control | Title | Consequence (I) | Privilege scope (P) | L | Surface (base E) | Base R with D=1 |
| --- | --- | --- | --- | --- | --- | --- |
| 1.1.4 | Minimum password length | `protection_weakened` = 4 | `all_local_accounts` = 4 | 4 | `network_logon` = 3 | 69 |
| 1.2.2 | Account lockout threshold | `protection_weakened` = 4 | `all_local_accounts` = 4 | 4 | `network_logon` = 3 | 69 |
| 2.3.1.1 | Guest account enabled | `misuse_easier` = 3 | `guest_or_anonymous` = 2 | 4 | `local_account` = 3 | 55 |
| 9.3.1 | Public firewall policy EnableFirewall | `critical_protection_lost` = 5 | `remote_admin_logon` = 4 | 4 | `network_boundary` = 4 | 80 |
| 18.10.57.3.9.4 | NLA policy UserAuthentication | `protection_weakened` = 4 | `remote_admin_logon` = 4 | 4 | `remote_desktop` = 4 | 74 |
| 1.1.1 | Enforce password history | `misuse_easier` = 3 | `all_local_accounts` = 4 | 4 | `network_logon` = 3 | 63 |
| 1.1.2 | Maximum password age (days) | `minor_reduction` = 2 | `all_local_accounts` = 4 | 4 | `network_logon` = 3 | 57 |
| 1.1.3 | Minimum password age (days) | `minor_reduction` = 2 | `all_local_accounts` = 4 | 4 | `network_logon` = 3 | 57 |
| 1.1.5 | Password complexity enabled | `protection_weakened` = 4 | `all_local_accounts` = 4 | 4 | `network_logon` = 3 | 69 |
| 1.1.7 | Reversible password encryption enabled | `critical_protection_lost` = 5 | `admin_identity_or_stored_credentials` = 5 | 4 | `local_secret` = 2 | 74 |
| 1.2.1 | Account lockout duration (minutes) | `misuse_easier` = 3 | `all_local_accounts` = 4 | 4 | `network_logon` = 3 | 63 |
| 1.2.4 | Reset lockout counter after (minutes) | `misuse_easier` = 3 | `all_local_accounts` = 4 | 4 | `network_logon` = 3 | 63 |
| 2.3.1.2 | Restrict blank local passwords to console logon | `protection_weakened` = 4 | `all_local_accounts` = 4 | 4 | `network_logon` = 3 | 69 |
| 2.3.10.1 | Anonymous SID/name translation enabled | `misuse_easier` = 3 | `admin_identity_or_stored_credentials` = 5 | 4 | `network_anonymous` = 4 | 72 |
| 2.3.10.2 | Block anonymous enumeration of SAM accounts | `misuse_easier` = 3 | `guest_or_anonymous` = 2 | 4 | `network_anonymous` = 4 | 60 |
| 2.3.10.3 | Block anonymous enumeration of SAM accounts and shares | `misuse_easier` = 3 | `guest_or_anonymous` = 2 | 4 | `network_anonymous` = 4 | 60 |
| 9.2.1 | Private firewall policy EnableFirewall | `critical_protection_lost` = 5 | `remote_admin_logon` = 4 | 4 | `network_boundary` = 4 | 80 |
| 9.2.2 | Private firewall policy inbound connections: Block | `protection_weakened` = 4 | `remote_admin_logon` = 4 | 4 | `network_boundary` = 4 | 74 |
| 9.2.6 | Private firewall policy log dropped packets | `detection_only` = 2 | `logging_only` = 1 | 4 | `detection` = 2 | 40 |
| 9.2.7 | Private firewall policy log successful connections | `detection_only` = 2 | `logging_only` = 1 | 4 | `detection` = 2 | 40 |
| 9.3.2 | Public firewall policy inbound connections: Block | `protection_weakened` = 4 | `remote_admin_logon` = 4 | 4 | `network_boundary` = 4 | 74 |
| 9.3.6 | Public firewall policy log dropped packets | `detection_only` = 2 | `logging_only` = 1 | 4 | `detection` = 2 | 40 |
| 9.3.7 | Public firewall policy log successful connections | `detection_only` = 2 | `logging_only` = 1 | 4 | `detection` = 2 | 40 |
| 17.1.1 | Audit Credential Validation: Success and Failure | `detection_only` = 2 | `logging_only` = 1 | 4 | `detection` = 2 | 40 |
| 17.2.2 | Audit Security Group Management: include Success | `detection_only` = 2 | `logging_only` = 1 | 4 | `detection` = 2 | 40 |
| 17.2.3 | Audit User Account Management: Success and Failure | `detection_only` = 2 | `logging_only` = 1 | 4 | `detection` = 2 | 40 |
| 17.5.1 | Audit Account Lockout: include Failure | `detection_only` = 2 | `logging_only` = 1 | 4 | `detection` = 2 | 40 |
| 17.5.4 | Audit Logon: Success and Failure | `detection_only` = 2 | `logging_only` = 1 | 4 | `detection` = 2 | 40 |
| 18.10.57.2.2 | Do not allow RDP passwords to be saved | `misuse_easier` = 3 | `admin_identity_or_stored_credentials` = 5 | 4 | `local_secret` = 2 | 62 |
| 18.10.57.3.9.1 | Always prompt for password upon RDP connection | `misuse_easier` = 3 | `remote_admin_logon` = 4 | 4 | `remote_desktop` = 4 | 68 |
| 18.10.57.3.9.3 | RDP security layer: SSL | `protection_weakened` = 4 | `remote_admin_logon` = 4 | 4 | `remote_desktop` = 4 | 74 |
| 18.10.57.3.9.5 | RDP client connection encryption level: High | `misuse_easier` = 3 | `remote_admin_logon` = 4 | 4 | `remote_desktop` = 4 | 68 |

## Limitations to state in the report

- **L does not separate the selected controls.** All 32 are Level 1 and Automated, so L = 4 for every one; it adds a constant 12 to every score and has no effect on the ranking. This follows from applying Table 4.15 as written.
- **Category assignment is a researcher judgement.** It is made once per control from the benchmark rationale and is recorded in code with a paraphrased rationale. It is not inferred at runtime, and the model never sets it.
- **Exposure is configuration-based.** The NAT lab never establishes internet reachability, so E = 5 arises only from a collected disabled firewall.
- **The score ranks findings; it does not predict anything.** It is not CVSS, not EPSS and not a probability of exploitation.
