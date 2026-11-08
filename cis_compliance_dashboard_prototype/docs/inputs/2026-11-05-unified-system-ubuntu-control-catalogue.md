# Unified system: Ubuntu 30-control assessment and remediation catalogue

Version 3 — active review catalogue, 5 November 2026. Read with the [one-system design](2026-11-05-unified-vm-hardening-system-design.md) and [implementation plan](../plans/2026-11-05-unified-vm-hardening-system-plan.md). These are internal Ubuntu capabilities added to the teammate's existing application and launched through its existing `cis_compliance_dashboard_prototype/app.py`. This revision updates integration placement; the 30 control IDs and their assessment/remediation scope are unchanged.

The IDs, Server profile levels and page references below were checked against the local CIS Ubuntu Linux 22.04 LTS v2.0.0 PDF. Pages refer to **printed page numbers**, not the PDF viewer's page index. The proposed predicates, implementation choices and safety conditions are our engineering design; they are not claims that every implementation detail is prescribed by CIS.

Scope: **30 distinct CIS recommendations; 24 L1 and 6 L2; 29 Automated and 1 Manual classifications.** Keep five areas with six recommendations each. Multiple subchecks or multiple execution steps do not inflate the control count. All 30 receive an executable registered remediation family; an action may be withheld on a particular VM when prerequisites or recovery guarantees are missing.

The initial supported VM is a standalone Ubuntu 22.04 server, not a router, using UFW as its managed firewall, with recoverable VM console access and a non-root SSH administrator. IPv6 is assessed whenever enabled. Do not silently disable IPv6 or replace nftables/iptables management to make the catalogue pass. If the VM uses a different firewall manager, register that as an applicability mismatch and review the deployment choice.

## 1. Control definitions

Every row becomes one manifest entry. `U-<CIS-ID>` below denotes the proposed action family; the stored action identifier is `ubuntu.<CIS-ID>.v1`. A family can contain several fixed steps under one exact approval. No family is enabled merely because its ID appears here.

### A. System and software security

| # | CIS ID / page / class | Assessment contract | Registered remediation and verification |
|---|---|---|---|
| 1 | **2.4.1.2**, p.324, L1 Automated | If cron is installed, /etc/crontab (stat -L) is owned by uid 0 and gid 0 and grants no group or other permissions (CIS example 600). Cron absent is outside applicability, never a pass. | **U-2.4.1.2:** `chown root:root` and `chmod og-rwx` on /etc/crontab only; no recursive change; a symlinked or non-regular file is refused. Preview the exact before/after mode and ownership. Recover the exact prior mode and ownership. |
| 2 | **1.3.1.1**, p.136, L1 Automated | Both `apparmor` and `apparmor-utils` installed successfully. This recommendation is package presence, not evidence that all applications are confined. | **U-1.3.1.1:** install the two approved packages and exact required dependencies through the package primitive. Preview versions and service effects. Verify package states. Do not silently change boot flags or force all profiles into enforce mode. |
| 3 | **1.5.1**, p.151, L1 Automated | `kernel.randomize_va_space=2` in effective runtime and the configuration that wins at boot. Resolve file precedence, not a single matching line. | **U-1.5.1:** edit only the approved sysctl entries, preserve ownership/mode, set runtime value using a fixed argument list. Verify both effective and persisted configuration; recovery restores the recorded file content and previous runtime value. |
| 4 | **1.5.3**, p.159, L1 Automated | Hard core limit zero; `fs.suid_dumpable=0` at runtime and persistently; include applicable systemd-coredump restrictions. Document conditional subchecks. | **U-1.5.3:** guarded limits/sysctl edits and applicable coredump configuration; validate every step and reload only affected components. Check all required subchecks, not only sysctl. Preview effects on debugging and future sessions. Recover exact prior settings. |
| 5 | **1.5.4**, p.162, L1 Automated | `prelink` absent. Package database failure is Error, not proof of absence. | **U-1.5.4:** if installed, perform the benchmark's approved reversal of prelinking before removing the package. Preview affected binaries, package transaction and disk needs. Snapshot required; record reversal/removal failures. Verify absence and basic executable health. No generic promise of an automatic reinstall rollback. |
| 6 | **2.1.2**, p.221, L1 Automated | Avahi service/socket not running or enabled under the supported package-present configuration; package absence is an accepted path. Check all relevant units. | **U-2.1.2:** retain package where feasible and stop/disable/mask its service and socket, following the audited allowed state. Declare service dependency impacts. Verify units and listening sockets. Recovery restores prior mask/enabled/running states. |

### B. Authentication and access control

| # | CIS ID / page / class | Assessment contract | Registered remediation and verification |
|---|---|---|---|
| 7 | **5.3.3.2.2**, p.605, L1 Automated | Effective password-quality minimum length at least 14. Resolve PAM arguments and pwquality configuration precedence; a compliant drop-in overridden elsewhere is insufficient. | **U-5.3.3.2.2:** plan a narrowly scoped `minlen=14` configuration and removal/replacement of conflicting lower overrides in explicitly approved locations. If PAM support is missing, include an explicit prerequisite installation/configuration plan. Validate authentication configuration and test in a disposable account/session; never reset user passwords. |
| 8 | **5.4.1.1**, p.653, L1 Automated | Default maximum age and every applicable password-bearing account have a maximum in 1..365 days. Check consistency with minimum age. Do not export password hashes. | **U-5.4.1.1:** set default maximum to 365 and change only enumerated non-compliant eligible accounts to 365. Bind username, UID, prior aging values and account-set digest. Preview immediate expiration risks, especially the connection user; block unsafe execution until recovery/maintenance requirements are met. Verify defaults and each account. |
| 9 | **5.4.1.3**, p.660, L1 Automated | Default warning period and applicable existing accounts are at least seven days. | **U-5.4.1.3:** update default and enumerated non-compliant accounts to seven days. Preserve stricter compliant values. Verify both sources. Restore only captured aging fields during approved recovery, not the entire shadow file. |
| 10 | **5.4.1.5**, p.665, L1 Automated | Default post-password-expiry inactivity and applicable account values are 0..45 days. This concerns time after password expiry, not time since last login. | **U-5.4.1.5:** set default and listed non-compliant accounts to 45 days, preserving stricter compliant values. Preview accounts that could become disabled immediately. Recheck account identity and aging before execution. Verify fields and management-user access. |
| 11 | **5.2.2**, p.559, L1 Automated | Effective sudo policy enables `use_pty` without a later applicable negation. Parse included files and scope. | **U-5.2.2:** construct a staged sudoers change, validate the complete proposed configuration with `visudo`, then atomically install with root ownership and correct permissions. Verify effective policy and a second authenticated sudo-capable session. Preserve current session and exact recovery backup. |
| 12 | **5.2.3**, p.562, L1 Automated | Sudo policy defines the required dedicated log destination; verify policy and path safety, and report destination health separately. | **U-5.2.3:** set the proposed site path `/var/log/sudo.log`, with secure parent/file ownership and mode, after whole-policy validation. Test one harmless approved sudo invocation and expected log event. Do not loosen permissions or alter unrelated logging settings. |

### C. Network and firewall security

| # | CIS ID / page / class | Assessment contract | Registered remediation and verification |
|---|---|---|---|
| 13 | **3.3.1**, p.379, L1 Automated | IPv4 forwarding zero and applicable IPv6 forwarding zero, both runtime and persisted. | **U-3.3.1:** fixed changes to the two forwarding keys, only on a registered non-router VM. Detect container/router/VPN dependencies before allowing execution. Verify effective and boot settings plus management connectivity. |
| 14 | **3.3.2**, p.383, L1 Automated | IPv4 `all` and `default` send-redirects settings zero, runtime and persisted. | **U-3.3.2:** update only the required sysctl keys using the common transaction primitive. Detect conflicting load sources including UFW sysctl configuration. Verify both keys and persistence. |
| 15 | **3.3.8**, p.407, L1 Automated | `all` and `default` source-route acceptance zero for IPv4 and applicable IPv6, runtime and persisted. | **U-3.3.8:** update the exact four applicable keys; explicitly prove disabled IPv6 before excluding its checks. Verify all applicable observations. An unsupported sysctl is not silently a pass. |
| 16 | **4.1.3**, p.430, L1 Automated | UFW runtime active and service enabled, with supporting package/service evidence. | **U-4.1.3:** include installation as an explicit prerequisite if absent; then enable the approved UFW configuration only after management allow-rules, effective guest port/source address, outbound dependencies and recovery watchdog are checked. Verify runtime/service state and a new SSH connection. |
| 17 | **4.1.4**, p.433, L1 Automated | Required loopback acceptance and anti-spoofing rules exist with effective ordering, for applicable address families. | **U-4.1.4:** add only the missing reviewed loopback rules in the correct order. Capture existing IPv4/IPv6 rule sets. Preserve other rules; never run `ufw reset`. Verify semantic rule behaviour and management connectivity. |
| 18 | **4.1.7**, p.440, L1 Automated | Incoming, outgoing and routed default policies meet the recommendation. The PDF allows deny/reject/disabled states as applicable; an incoming-only check is inadequate. | **U-4.1.7:** proposed lab target is incoming deny, outgoing deny and routed deny. Preview exact allow-rules needed for SSH return traffic, DNS, approved package repositories, time and other declared services before defaults change. Allow entries are explicitly approved, not inferred from open ports alone. Arm recovery watchdog, test new SSH plus declared egress, then verify all defaults. |

### D. Audit and logging — selected Level 2 controls

| # | CIS ID / page / class | Assessment contract | Registered remediation and verification |
|---|---|---|---|
| 19 | **6.3.1.1**, p.752, L2 Automated | Required audit packages, including applicable audit dispatcher support, installed. | **U-6.3.1.1:** install `auditd` and `audispd-plugins` with exact approved dependencies/versions. Verify package state. Record service activation caused by package scripts as a declared side effect. |
| 20 | **6.3.1.2**, p.754, L2 Automated | Audit service enabled and active. | **U-6.3.1.2:** enable/start using the Ubuntu-supported service method after package/configuration checks. Avoid an unnecessary restart of an active audit daemon. Verify active/enabled state and an independent harmless audit event where supported. |
| 21 | **6.3.1.3**, p.756, L2 Automated | Boot configuration includes the required `audit=1` argument for applicable kernel entries. Show current-kernel command line separately. | **U-6.3.1.3:** edit the approved bootloader source, generate/validate output without removing other arguments, record backup and pending reboot. A separately approved reboot continuation verifies new boot ID, the same VM identity and current command line. Do not claim runtime activation before reboot. Support the registered GRUB layout only; unexpected bootloaders require a reviewed implementation. |
| 22 | **6.3.3.4**, p.783, L2 Automated | Required time-change syscall/path audit coverage in persistent and loaded rules, for supported architectures. | **U-6.3.3.4:** generate a fixed, architecture-aware rules file, validate and load using the approved audit mechanism. Preserve other rules and exclude unsupported syscalls correctly. If audit is immutable, stage the approved change and use the explicit reboot continuation. Verify persistent and runtime coverage. |
| 23 | **6.3.3.8**, p.799, L2 Automated | Required watches/rules cover user and group identity files in persistent and loaded configuration. | **U-6.3.3.8:** install reviewed identity-file watch rules with exact paths/permissions/keys. Handle optional files according to benchmark applicability; never create password databases just to satisfy a watch. Verify semantic rule coverage and a disposable-account test event. |
| 24 | **6.3.3.6**, p.791, L2 Automated | Audit rules cover the discovered privileged executable set on eligible filesystems, using the benchmark's UID threshold and unset-UID handling. | **U-6.3.3.6:** bounded read-only discovery produces an exact executable list/digest; approval binds that list, architecture and UID_MIN. Generate fixed per-path rules, validate and load. A changed discovery set invalidates the plan. Do not execute discovered binaries during scanning. Verify runtime/persistent rules; test using a known harmless approved executable in the lab. |

### E. OpenSSH security

All six use the shared SSH configuration transaction: parse the complete Include/Match structure, preserve existing access policy, stage exact edits, run `sshd -t`, check effective `sshd -T` values for registered connection contexts, keep the current channel, arm approved recovery, reload the service and prove a new authenticated connection. An arbitrary appended drop-in is not sufficient because first-value and Match semantics matter. The initial implementation supports explicitly tested Include/Match forms and refuses unanalysable configurations with a reason.

| # | CIS ID / page / class | Assessment contract | Registered remediation and verification |
|---|---|---|---|
| 25 | **5.1.20**, p.550, L1 Automated | Effective `PermitRootLogin=no` for audited contexts. | **U-5.1.20:** set `no`; prove a working non-root sudo-capable account before execution. Do not disable the sole available administration path. Verify effective policy and successful non-root reconnect. |
| 26 | **5.1.19**, p.548, L1 Automated | Effective `PermitEmptyPasswords=no`. | **U-5.1.19:** set `no` through the SSH transaction. Verify effective values and continued approved authentication; no password values are read or changed. |
| 27 | **5.1.16**, p.542, L1 Automated | Effective maximum authentication attempts is a valid positive value no greater than four. | **U-5.1.16:** set four where non-compliant; preserve a stricter valid value. Verify configuration and a fresh connection with the explicitly selected key; uncontrolled SSH-agent key offers must not exhaust attempts. |
| 28 | **5.1.7**, p.520, L1 Automated | Both client-alive interval and count are greater than zero; apply a separately recorded site policy if stricter. These detect unresponsive connections, not keyboard inactivity. | **U-5.1.7:** proposed lab values are interval 15 seconds and count three, following the PDF example. Verify effective positive values and reconnect. ComplianceAsCode may choose other values, so review/tailor its rule variables instead of silently treating a stricter content default as the PDF requirement. |
| 29 | **5.1.10**, p.528, L1 Automated | Effective host-based authentication disabled. | **U-5.1.10:** set `HostbasedAuthentication=no` only after proving the management account uses supported password/key authentication. Verify effective values and the replacement connection. |
| 30 | **5.1.21**, p.552, L1 Automated | Effective user-provided environment support disabled. | **U-5.1.21:** set `PermitUserEnvironment=no`; show potential workflow impact and verify effective configuration plus the management connection. Do not delete user environment files unnecessarily. |

## 2. Required metadata for every control

The implementation manifest must contain all these fields before its control is enabled:

```text
control_id, platform, benchmark_id, benchmark_version, benchmark_sha256,
title, area, server_level, cis_assessment_type, source_pages,
catalogue_version, predicate_id, predicate_version, applicability_predicate,
required_observations, allowed_types, missing_value_policy,
scap_rule_ids[], scap_variable_values{}, content_release, content_commit,
datastream_sha256, direct_probe_ids[], authoritative_source_policy,
pass_fixture, fail_fixture, missing_fixture, error_fixture,
risk_attributes, risk_policy_version, action_ids[], prerequisite_ids[]
```

Do not invent XCCDF rule IDs from CIS numbering: one CIS recommendation can map to several SCAP rules. Resolve IDs against the pinned Ubuntu datastream and verify every expected rule exists. Where no suitable mapping exists, the direct inspection must have an explicit reason and its own reviewed predicate. Catalogue tests reject duplicate IDs, missing mappings without reasons and incomplete source provenance.

A required observation records its tool/probe version, target identity, start/end timestamps, command exit state, typed normalized value, sanitized supporting evidence and digest. Never include `/etc/shadow` hashes, full private keys, arbitrary environment dumps or secrets in raw exported evidence. Derive account aging fields on the VM and transmit only those fields and account identifiers necessary for approval.

## 3. Required metadata for every action family

```text
action_id, version, supported_control_ids[], platform,
implementation_sha256, fixed_entrypoint, parameter_schema,
preconditions[], changes[], dependency_edges[], conflicts[],
service_impacts[], connection_impact, reboot_policy,
timeout_seconds, approval_ttl_seconds, evidence_freshness_seconds,
before_state_schema, backup_manifest_schema, verification_predicate_id,
recovery_kind, recovery_parameters_schema, manual_recovery_instructions
```

Default before-state freshness is five minutes and a new precheck runs immediately before each write. This freshness limit is a project safety policy, not a CIS requirement. A package operation that takes longer must collect fresh before-state after waiting for any package lock. Maximum evidence/index age for the updates assessment is proposed as 24 hours; it is also a project policy. The UI must show both limits.

Action parameters are proposed by deterministic planners. The LLM selects eligible action IDs and order; it cannot supply arbitrary file content, package names, accounts, ports, paths, numeric policy values or shell snippets. A human-adjustable site policy is validated and versioned before proposal generation, never inserted into an already approved request.

## 4. Cross-control dependencies and execution order

Use a directed acyclic dependency graph plus conflict detection. The scheduler validates the graph independently of the agent's proposed order.

1. Finish approved package installations and required upgrades before enabling restrictive outbound UFW defaults. Package effects may change SSH/systemd configuration and invalidate later previews.
2. Audit packages precede audit service and rule loading. Rule files can be staged before a reboot, but runtime verification waits until they are loaded.
3. Establish and test non-root management access before disabling root SSH login. This provisioning prerequisite is separately visible; it is not permission to create accounts silently.
4. Validate and preserve sudo capability before changing sudo policy or authentication-related settings. Do not change the active management user's aging without an explicit impact review.
5. SSH and UFW actions run sequentially, each with its own connectivity check. Never overlap two watchdog-protected network transactions.
6. Collect all approved boot-dependent changes, then propose a single explicit reboot continuation bound to those completed requests. A reboot is not an extra CIS control or a hidden automatic action.
7. Full assessment follows the batch. Before each action, revalidate its read-set: if an earlier action changed a relevant file/account/package, the old approval is stale and a fresh proposal is required. Do not automatically reuse blanket approval.

For multiple controls editing the same file, support a deterministic composite plan only when the preview explicitly lists all member controls, exact shared diff and recovery. Its single execution receipt links to every member; each control still has its own verification result. Initially, sequential individually approved transactions are acceptable even if they require another review after a shared-file change. One-click remediation of all 30 is not a first-release requirement.

## 5. Recovery classes

| Class | Controls | Required recovery proof |
|---|---|---|
| Scoped file/runtime change | ASLR, core dumps, sysctl, Avahi | Exact prior file metadata/content and runtime/service states restored in a disposable VM test |
| Authentication policy | Password, sudo | Valid staged configuration, preserved management session, exact affected field restoration, independent login/sudo test |
| Connectivity | UFW and OpenSSH | Armed pre-authorised watchdog, backup integrity, second-connection acknowledgement, tested timeout restoration, console fallback |
| Package/binary transaction | Updates, AppArmor, prelink, audit packages | Approved solver plan, package-manager health, snapshot recovery; no claim that reinstall/downgrade reverses all maintainer-script effects |
| Boot/audit activation | Boot audit flag, immutable audit-rule changes | Preserved boot configuration, explicit reboot approval, boot-ID evidence, console/snapshot recovery and post-boot verification |

## 6. Coverage and acceptance record

For each of the 30 rows, record: implementation file/action version; benchmark and content provenance; passing fixture; failing fixture; absent/error case; deterministic preview; rejected/expired/stale request refusal; successful approved VM change; independent post-change audit; recovery test; final limitations. The dashboard and evaluation must report **assessment coverage and executable remediation coverage separately**.

Release target is 30 assessment definitions and 30 implemented remediation families. A live VM can be compliant, inapplicable or blocked for a particular action without requiring an unnecessary write. Demonstrate each action's failing-to-compliant transition on disposable/revertible test states, not by damaging the final demonstration VM to exercise every button. Synthetic tests alone do not prove live coverage.

**Review decision:** this catalogue intentionally includes a Manual patching control and six L2 audit controls to match the report's subject areas. If a strict all-L1 or all-Automated scope is desired, replace controls through a catalogue revision before implementation; do not relabel these seven recommendations.

## 7. Risk-attribute manifest, following the Windows method

The earlier draft's handwritten I/E/P/L table is deliberately not carried into this active catalogue. Numeric factors must be generated from reviewed categorical attributes and effective evidence using the teammate's method. Do not recover or hardcode that old table during implementation.

For every one of the 30 IDs above, the risk manifest must record: consequence category, privilege category, exposure surface, CIS Server level, Automated/Manual classification, benchmark rationale/pages, any Linux-specific context mapping, reviewer and policy version. The manifest cannot be activated with an unreviewed or unrecognised category. The generated report must show each attribute, its mapped factor and the evidence-based exposure/history adjustments.

Reuse the existing Windows category mappings where their meanings fit, the same formula and bands, the same four likelihood mappings and the same drift comparability rules. The six L2 Automated audit recommendations use L=3; the L1 Manual update recommendation uses L=3; the other 23 L1 Automated recommendations use L=4 under that compatibility heuristic. These classifications do not imply empirical exploit probabilities. I/P values are not invented merely to complete a table: assign categories from the benchmark and review named Linux extensions before enabling their scores.

A shared rule yields the same factor on both backends. Different platforms need not receive the same score for unrelated controls. Keep deterministic risk order distinct from an agent's permitted execution order. The source of authority and exact mapping tables are specified in the active implementation plan's risk section.

## 8. Delivery in the shared UI

All rows use the same Controls, Risk ranking, Fixes, Results and Agent log tabs already present in the teammate's Agentic hardening page. Extend the current `app.py` and existing `hardening` views on the development branch. The same connection form authenticates and verifies the target before the router selects this catalogue and `UbuntuBackend` for Ubuntu, or the unchanged Windows engine through `WindowsBackend` for Windows. Connecting alone does not execute a control. Windows retains its own catalogue and existing action library. One selected CIS recommendation may have multiple required subchecks and execution steps but remains one control.

Place host-side Ubuntu implementation under `backends/ubuntu/`, target helper source under `vm/ubuntu/`, and manifests under `catalogues/`, all within the existing `cis_compliance_dashboard_prototype` application directory. The directories are internal modules, not separately launched applications. Shared connection/router services live under `system/`, and the Windows adapter imports the existing `hardening/` package in place. Protected Windows engine files remain unchanged; record and regression-test the authorised entry-point/view integration edits against the pre-change baseline. No runtime Windows source copy or alternative application root is required.

The shared UI must obtain selected-control count and supported-action count from the backend: Ubuntu expects 30 selected controls/30 implemented control-remediation families; Windows retains its recorded baseline counts. Do not globally replace the Windows count with 30 or show a result from one platform under the other platform's control ID.

Source: [CIS Ubuntu 22.04 v2.0.0 PDF](C:/Users/teohk/Downloads/CIS_Ubuntu_Linux_22.04_LTS_Benchmark_v2.0.0.pdf). Full benchmark procedures and applicability notes must be reviewed when implementing each row; descriptions above are engineering summaries, not reproduced benchmark text.

> Amendment 2026-11-08 (administrator decision): row 1 replaced 1.2.2.1 (Manual; an unbounded update job does not meet U-1.2.2.1) with 2.4.1.2 in the same area. Stored scans keep the earlier selection as catalogue v1.
