# Ubuntu sources and assessment boundary

The authoritative local benchmark is CIS Ubuntu Linux 22.04 LTS v2.0.0, SHA256 `37b8d91eadb5621656ff38d24c39ac34b9589087a3f3a9fbba2c8a2dd665b6da`. Printed page references for the exact 30 recommendations are in `catalogues/ubuntu2204.json`. The complete relevant recommendation extracts, including applicability and remediation cautions, were reviewed as project material. No PDF command was executed on the VM.

The content pin is [ComplianceAsCode v0.1.80](https://github.com/ComplianceAsCode/content/releases/tag/v0.1.80), commit `a1b32362394c7739a7a94426c61c7cb24449d9a0`. The downloaded release ZIP matched its official SHA512. The extracted Ubuntu datastream SHA256 is `c8be1aa2bf93284507b8810ea829f8904ab4552865f07d106561d5fd5d06ca67`. Its license is preserved beside it. The [upstream CIS mapping](https://github.com/ComplianceAsCode/content/blob/a1b32362394c7739a7a94426c61c7cb24449d9a0/controls/cis_ubuntu2204.yml) identifies benchmark version 2.0.0. Each mapped rule and variable selector was resolved against actual XML IDs. No IDs were inferred from CIS numbers.

The pin is a reproducible content choice, not a claim to be the newest release. OpenSCAP engine version remains unset until compatibility inspection and validation. Catalogue activation remains false. A human has not approved source interpretations, site policies or Linux risk attributes.

Run from the existing application directory:

```powershell
..\.venv-integration\Scripts\python.exe -B -m tools.check_sources
```

This verifies hashes, classification/counts, rule presence and variable selectors. It does not attest that a collector, remediation runner or live target is accepted. `tools/build_source_manifest.py` reproduces the draft inventory from the isolated downloaded cache; it intentionally resets review/implementation status rather than inventing approval.

## Interpretations and gaps requiring review

- Manual updates: package-index refresh is mutating even though the PDF includes it under audit. Assessment will only read existing metadata. Refresh, exact upgrade plan and human patch review are separate operations.
- Avahi: package retention needs the PDF's dependency/site-policy exception. Disabled units alone cannot establish an approved retention exception.
- Sudo PTY: use the PDF's no-negation audit requirement. A later positive line does not excuse a `!use_pty` occurrence for this benchmark predicate.
- Password maximum: the audit and examples specify 365; the isolated 356 in remediation prose is recorded as a source inconsistency. Defaults and existing applicable accounts both matter.
- Sudo logfile: `/var/log/sudo.log` is the proposed project destination; the benchmark's dedicated-log requirement is broader than that exact example.
- SSH keepalive: benchmark compliance requires both values positive. PDF example 15/3 and upstream selector 300/3 must not be confused with a mandatory benchmark threshold. Neither is keyboard-inactivity detection.
- UFW: all three directions matter. Deny/reject/disabled are audit alternatives; project deny/deny/deny is an unapproved action policy. An outgoing allow policy is not silently accepted.
- Audit: check loaded and persistent semantic coverage, applicable architectures, UID_MIN and unset-auid handling. Immutable audit configuration can require a separately approved reboot. Initial GRUB support cannot silently claim zipl support.
- Effective-state gaps include systemd-coredump restrictions, existing warning-age accounts, sysctl load precedence/UFW override, SSH Match contexts, firewall rule ordering, and privileged-file discovery completeness.

The per-control `direct_probe_reason` records these distinctions. Reserved action IDs are an inventory, not executable remediation coverage.

## Parser references

The password parser applies sorted drop-ins, then the main configuration, then supported PAM arguments, following the Ubuntu 22.04 [pwquality configuration manual](https://manpages.ubuntu.com/manpages/jammy/man5/pwquality.conf.5.html) and [PAM module manual](https://manpages.ubuntu.com/manpages/jammy/man8/pam_pwquality.8.html). Unsupported PAM control flow remains unresolved.

Audit normalization uses exact path/permission/syscall/filter tokens following the Ubuntu 22.04 [auditctl manual](https://manpages.ubuntu.com/manpages/jammy/man8/auditctl.8.html). Suppression rules and unsupported filters are refused; substring matches and command exit zero do not establish coverage.

Current tests use synthetic normalized evidence. The fixed target I/O class and pure parsers are implemented, but a complete deployed collector, pinned engine invocation and authenticated end-to-end assessment are not yet implemented or validated.

## SCAP and direct-probe reconciliation rule (proposed 6 November 2026; pending human review)

Selected ComplianceAsCode rule results are extra subchecks on the control. They do not replace the direct effective-state probes, which stay authoritative:

| SCAP result | Direct probes have a failure | Direct probes have no failure |
| --- | --- | --- |
| `pass` | subcheck pass; the control stays Non-Compliant (a SCAP pass never cancels a direct failure) | subcheck pass |
| `fail` | subcheck fail (agrees) | `conflict` → control **Unknown**, never a confirmed finding or risk input |
| `error` | Error unless the direct failure already makes it Non-Compliant | Error |
| `notapplicable` | neutral (`inapplicable`); cannot make a control pass on its own | neutral |
| `unknown`/`notchecked`/`notselected`/`informational`/`fixed` | unresolved (`missing`) | unresolved → Unknown |

- **Reviewed Avahi retention exception:** with an explicitly reviewed retention exception (2.1.2), a failing `package_avahi_removed` rule is recorded as superseded, not as a conflict.
- **Why conflict is not a failure:** upstream rule variables and checks can differ from the PDF. Examples: SSH keepalive 300/3 versus the PDF's "positive" requirement, and the `zipl` rule on GRUB. A SCAP-only failure therefore needs investigation before it counts as a confirmed failure.
- **Where the rule set comes from:** the target helper builds the rule set only from `vm/ubuntu/spec.py`, which a test keeps equal to the pinned catalogue mapping, profile and datastream hash.
- **Live envelopes:** a Live (SSH) envelope must carry a `scap_rules` observation for every mapped control. That observation may be `error`, but it cannot be omitted. Synthetic fixtures may omit it, which gives direct-only results.
