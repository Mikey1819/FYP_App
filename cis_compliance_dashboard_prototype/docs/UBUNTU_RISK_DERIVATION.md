# Ubuntu risk derivation (generated)

Policy: **ubuntu-risk-2026-11-06-draft1 (reviewed by Teoh Kai Hong (blanket chat approval 2026-11-06; not an itemized review), 2026-11-06T06:55:55+00:00)**. Generated from `catalogues/ubuntu2204-risk.json` by `tools/ubuntu_risk_report.py`; do not edit by hand.

Method: the Windows rubric `R = 6I + 5E + 4P + 3L + 2D`, reusing its category tables, likelihood mapping, surface baselines and bands (Low 20–39, Moderate 40–59, High 60–79, Critical 80–100). Only confirmed Non-Compliant findings are scored. L is a compatibility heuristic, not a measured exploit probability. E is the base surface exposure only; no Linux effective-context adjustment has been reviewed. D is 1 with no comparable prior, 3 for a persistent failure, 5 for a regression.

Scores are withheld in the dashboard until a named reviewer approves this policy.

## Linux extensions requiring review

| Kind | Name | Score | Reason |
| --- | --- | --- | --- |
| consequence | `session_hygiene` | 2 | Session management weakness unrelated to passwords: minor reduction in security posture (4.14a score 2 tier). |
| privilege | `privilege_escalation_path` | 4 | Weakens a barrier between unprivileged code and root: may contribute to administrative access (same tier as the Windows 4.14c score 4 wording). |
| privilege | `host_network_path` | 2 | Governs host packet handling rather than accounts or rights: limited privilege implications (4.14c score 2 tier). |
| surface | `remote_shell` | 4 | Remote interactive administrative service (OpenSSH): significant network/remote exposure on the shared scale, the same semantic tier as the Windows remote-desktop surface baseline, derived from SSH facts only. |
| surface | `local_exploit_mitigation` | 2 | Kernel/userspace exploit mitigation or confinement that matters after an attacker already runs code locally: limited local exposure. |
| surface | `system_software` | 3 | Installed package versions across all services; reachability depends on which services listen, so controlled network/remote exposure without asserting Internet reachability. |

## Per-control factors

| Control | Consequence (I) | Privilege (P) | Surface (E) | L | Score D=1 / 3 / 5 | Rationale (paraphrase) |
| --- | --- | --- | --- | --- | --- | --- |
| 1.2.2.1 | protection_weakened (4) | privilege_escalation_path (4) | system_software (3) | 3 | 66 / 70 / 74 | Outstanding security updates leave known, published vulnerabilities in place. |
| 1.3.1.1 | protection_weakened (4) | privilege_escalation_path (4) | local_exploit_mitigation (2) | 4 | 64 / 68 / 72 | Without the AppArmor packages, mandatory access control cannot confine compromised programs. |
| 1.5.1 | misuse_easier (3) | privilege_escalation_path (4) | local_exploit_mitigation (2) | 4 | 58 / 62 / 66 | Predictable memory layout makes memory-corruption exploits easier to write. |
| 1.5.3 | misuse_easier (3) | privilege_escalation_path (4) | local_exploit_mitigation (2) | 4 | 58 / 62 / 66 | Core dumps of privileged programs can disclose sensitive memory contents. |
| 1.5.4 | misuse_easier (3) | privilege_escalation_path (4) | local_exploit_mitigation (2) | 4 | 58 / 62 / 66 | Prelinking modifies binaries, interfering with integrity checking and easing shared-library tampering. |
| 2.1.2 | misuse_easier (3) | guest_or_anonymous (2) | network_anonymous (4) | 4 | 60 / 64 / 68 | An unneeded unauthenticated discovery service adds network attack surface and discloses host information. |
| 3.3.1 | protection_weakened (4) | host_network_path (2) | network_boundary (4) | 4 | 66 / 70 / 74 | A host that forwards packets can act as a router and bypass network segmentation. |
| 3.3.2 | misuse_easier (3) | host_network_path (2) | network_boundary (4) | 4 | 60 / 64 / 68 | Sending ICMP redirects can be abused to alter other hosts' routing. |
| 3.3.8 | misuse_easier (3) | host_network_path (2) | network_boundary (4) | 4 | 60 / 64 / 68 | Accepting source-routed packets lets senders dictate paths around network controls. |
| 4.1.3 | critical_protection_lost (5) | remote_admin_logon (4) | network_boundary (4) | 4 | 80 / 84 / 88 | An inactive host firewall exposes every listening service. |
| 4.1.4 | protection_weakened (4) | remote_admin_logon (4) | network_boundary (4) | 4 | 74 / 78 / 82 | Missing loopback rules allow spoofed loopback traffic from the network or break local services. |
| 4.1.7 | protection_weakened (4) | remote_admin_logon (4) | network_boundary (4) | 4 | 74 / 78 / 82 | Permissive default policies admit traffic that no rule explicitly allows. |
| 5.1.7 | session_hygiene (2) | remote_admin_logon (4) | remote_shell (4) | 4 | 62 / 66 / 70 | Unresponsive sessions are not detected and remain open. |
| 5.1.10 | protection_weakened (4) | remote_admin_logon (4) | remote_shell (4) | 4 | 74 / 78 / 82 | Host-based trust lets one compromised host authenticate users to another. |
| 5.1.16 | misuse_easier (3) | remote_admin_logon (4) | remote_shell (4) | 4 | 68 / 72 / 76 | More authentication attempts per connection make online guessing easier. |
| 5.1.19 | critical_protection_lost (5) | remote_admin_logon (4) | remote_shell (4) | 4 | 80 / 84 / 88 | Accounts with empty passwords could log in remotely without any secret. |
| 5.1.20 | protection_weakened (4) | admin_identity_or_stored_credentials (5) | remote_shell (4) | 4 | 78 / 82 / 86 | Direct root login over SSH exposes the root identity and removes individual accountability. |
| 5.1.21 | misuse_easier (3) | remote_admin_logon (4) | remote_shell (4) | 4 | 68 / 72 / 76 | User-supplied environment variables can subvert access restrictions or programs at login. |
| 5.2.2 | misuse_easier (3) | privilege_escalation_path (4) | local_account (3) | 4 | 63 / 67 / 71 | Without a pseudo-terminal, a program run through sudo can keep access to the user's terminal after it exits. |
| 5.2.3 | detection_only (2) | logging_only (1) | detection (2) | 4 | 40 / 44 / 48 | Privileged command use is harder to review without a dedicated sudo log. |
| 5.3.3.2.2 | protection_weakened (4) | all_local_accounts (4) | network_logon (3) | 4 | 69 / 73 / 77 | Short passwords are practical to guess or crack. |
| 5.4.1.1 | minor_reduction (2) | all_local_accounts (4) | network_logon (3) | 4 | 57 / 61 / 65 | Passwords without a maximum age extend the useful life of a stolen credential. |
| 5.4.1.3 | minor_reduction (2) | all_local_accounts (4) | network_logon (3) | 4 | 57 / 61 / 65 | Too little expiry warning leads to rushed, weaker password choices or lockouts. |
| 5.4.1.5 | minor_reduction (2) | all_local_accounts (4) | network_logon (3) | 4 | 57 / 61 / 65 | Accounts with expired passwords stay usable indefinitely instead of being disabled. |
| 6.3.1.1 | detection_only (2) | logging_only (1) | detection (2) | 3 | 37 / 41 / 45 | Without the audit packages, security-relevant events cannot be recorded. |
| 6.3.1.2 | detection_only (2) | logging_only (1) | detection (2) | 3 | 37 / 41 / 45 | A stopped audit service records no events. |
| 6.3.1.3 | detection_only (2) | logging_only (1) | detection (2) | 3 | 37 / 41 / 45 | Processes started before the audit daemon are not audited unless auditing is enabled at boot. |
| 6.3.3.4 | detection_only (2) | logging_only (1) | detection (2) | 3 | 37 / 41 / 45 | Unaudited time changes can hide activity by confusing log timelines. |
| 6.3.3.6 | detection_only (2) | logging_only (1) | detection (2) | 3 | 37 / 41 / 45 | Use of privileged programs by ordinary users goes unrecorded. |
| 6.3.3.8 | detection_only (2) | logging_only (1) | detection (2) | 3 | 37 / 41 / 45 | Changes to user and group identity files go unrecorded. |
