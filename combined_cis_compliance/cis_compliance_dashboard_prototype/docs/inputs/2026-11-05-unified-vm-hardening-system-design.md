# One VM hardening system: Windows and Ubuntu design

Version 3 — 5 November 2026. **Active design updated for the user's existing-application workflow.** This replaces version 2's separate application/source-copy arrangement and the earlier Ubuntu-rebuild design. The filenames remain stable. It is planning documentation, not implemented functionality or authorisation to change a VM.

## 1. The agreed product

The team will deliver **one hardening system by extending Khoo Teng Yi's existing Windows application in its current project**. Users continue launching its existing `cis_compliance_dashboard_prototype/app.py`. Teoh Kai Hong adds Ubuntu assessment/remediation modules within that application. Users enter either VM's information in the same connection form on **Agentic hardening**, connect, and use the existing workflow. The system discovers the supported connection protocol, authenticates, verifies the actual OS and machine identity, and selects the correct backend.

There is no separate Ubuntu application, separate Ubuntu dashboard, mandatory OS-selection page, iframe containing a second app, or requirement to run two Streamlit servers. Separate Python modules and internal database files are implementation details of one system.

Confirmed requirements:

- Preserve Windows functionality, engine logic, scripts and test coverage. Make scoped integration edits to the existing `app.py` and presentation files on a development branch; retain a recoverable pre-change baseline. Do not delete/replace the Windows implementation or alter existing environments/live databases.
- Retain his UI appearance, navigation, interaction sequence and terminology.
- Follow his deterministic risk calculation, factor-derivation style, rubrics, risk bands and drift rules.
- Reuse the existing Ubuntu VM if compatible. Do not reinstall/reset it by default; inspect it and take a recovery snapshot before approved setup/testing changes.
- Ubuntu target: Server 22.04 LTS; CIS Ubuntu Linux 22.04 LTS v2.0.0; proposed 30 selected controls with remediation support for all 30.
- Use the existing local Ollama installation and `qwen3:8b`.
- Keep reports unchanged during implementation; maintain a change log for later alignment.

## 2. Architecture and alternatives

**Chosen direction: extend the existing entry point and views, with two internal platform backends.** Develop on `integrate/unified-vm-hardening` in the teammate's existing project. Modify `app.py` and the current presentation files to call shared connection, identity, router and backend interfaces. Add `system/`, `backends/windows/adapter.py`, `backends/ubuntu/`, Ubuntu helpers/catalogues and integration tests inside the existing application directory. The Windows adapter imports the existing sibling `hardening/` services; their predicates, scoring, scripts and approval bytes remain unchanged. There is no runtime Windows source copy and no replacement application directory.

Record the pre-change Git reference and file hashes; preserve any uncommitted source in a verified recovery archive before edits. If no Git repository exists at the chosen location, preserve a verified source-only archive and establish version control without discarding files. An optional worktree retains the same project layout and entry point. The current Ubuntu workspace holds these documents/reference work, not a second integration application.

An immediate rewrite of the Windows engine into generic classes would create unnecessary regression risk. Two separately developed applications combined later would repeat the integration problem. Neither is the delivery model.

```text
Administrator
    |
    v
Existing cis_compliance_dashboard_prototype/app.py
    teammate's existing UI, extended in place
    Agentic hardening: SAME connection form
    hostname + machine identity + address + port + username + password
    |
    v
Connection service
    bounded protocol discovery at that exact endpoint
    -> trust/authentication -> read-only OS and identity checks
    |
    v
Verified backend router
    |                                         |
    +-- Server 2022 + WinRM                    +-- Ubuntu 22.04 + SSH
        WindowsBackend                            UbuntuBackend
        existing Windows functions                Teoh's Ubuntu functions
        Windows collector/actions                 Linux collector/actions
    |                                         |
    +----------- common presentation records --+
                        |
                        v
Same Overview / Agentic hardening / History and drift pages
Same Fixes / Risk ranking / Controls / Results / Agent log tabs
Same Scan -> Analyse -> Plan -> Approve -> Execute -> Verify workflow
```

Each backend uses the same four role concepts and safety principles. Platform-specific agents/tools remain internal implementations; they are not different products. Both use one local model service. A single active VM is supported initially; writes are serialized. History can show previously assessed targets from either platform through one read-only repository facade.

## 3. Exactly how the form works

Keep the form in its existing location. Adjust only Windows-specific labels:

| Current Windows label | Shared label | Interpretation |
|---|---|---|
| VM computer name | VM hostname | Expected hostname, verified after connection |
| VM machine UUID | VM machine identity | Windows machine UUID or Ubuntu `/etc/machine-id`; hint explains both |
| WinRM host | VM IP address / host | Enter the real host or configured forwarding endpoint |
| Port | Port | The exact service/forwarded port; no assumption that it reveals the OS |
| Administrator account | Username | Windows account or Ubuntu SSH account |
| Password | Password | Session-only authentication secret |
| Connect and check identity | Connect and check identity | Detect, authenticate and verify; does not start hardening |

Advanced options remain inside this form: Auto/SSH/WinRM connection method, SSH key authentication, separate sudo password if needed, and public trust information. Auto is default. Existing Windows saved profiles retain their account/endpoint settings. A blank/new profile must not force the username `Administrator` or force a Windows forwarding port on an Ubuntu user.

Discovery is bounded and unauthenticated. Examine an SSH protocol exchange or a WinRM `/wsman` protocol response only at the submitted endpoint, with no redirects, subnet scan or search of other ports. A response is merely a transport candidate. A generic HTTP response or port number does not prove WinRM or Windows. If ambiguous, show a clear result and allow the advanced manual transport setting. Never silently try credentials through a second protocol after authentication failure. Preserve the teammate's actual WinRM authentication and message-encryption behaviour; do not introduce Basic authentication, TLS bypass or a downgrade fallback. Unsupported TLS/security modes receive a diagnostic, not an invented compatibility claim.

Before SSH login, verify the server host key against an enrolled key or independently obtained fingerprint. First-time fingerprint confirmation is a conditional step inside the same form. Changing an enrolled key requires deliberate re-enrolment. Password mode explicitly disables implicit agent/key-file attempts; key mode uses the selected key only. These policies are supported by [Paramiko's SSH client API](https://docs.paramiko.org/en/stable/api/client.html).

After authentication, a fixed read-only probe reads Windows OS/CIM identity or Ubuntu OS-release/machine identity. Route only after checking a supported OS/release, expected hostname/identity and required capabilities. Windows Server 2022 is reached through WinRM; Ubuntu 22.04 through SSH. An SSH connection to another OS is not automatically Ubuntu. Display **Detected OS**, transport and capabilities, then attach the backend. Unsupported, wrong-identity or unverified targets cannot scan/harden. Protocol discovery and identity checking use no LLM.

Connecting does not run an assessment or remediation automatically. The user starts the existing round workflow after connection. The page changes its catalogue/data to the detected platform while retaining the same interface.

Connection sessions are ephemeral and own credentials; workflow sessions are durable and own rounds/approvals. Reconnecting to the same verified target/registration epoch can resume an existing workflow, but never automatically executes or creates a round. The Windows adapter passes the persisted backend workflow session ID to original methods, not the newly created connection ID.

## 4. UI and code preservation

Capture the existing Windows pages, tabs, fields, action buttons, status messages, examples and state transitions as the baseline. Scoped edits are authorised in `app.py` and `hardening/connection_view.py`, `agentic_view.py`, `overview_view.py`, `history_view.py`, and `ui.py`. Extend the same connection form and adapt the same views to a common `WorkspaceSnapshot` and typed `WorkspaceBackend` commands. Move Windows-specific service construction into the new adapter; add shared `system/ui/` helpers where needed. Keep styles/navigation and Windows behavior. Do not duplicate whole pages, choose shell commands in the UI or recalculate risk there.

Existing Windows engine modules, scripts and catalogue/risk/storage rules stay protected and unchanged. Any required engine change needs separate justification and review; routine integration edits within the stated presentation boundary are already authorised. Preserve all existing tests and never weaken their expected outcomes. Existing code may be extended in the listed files, but no Windows function or feature may be removed.

Preserve optional administrator goals, per-proposal approve/reject, bulk decisions where eligible, comments, execution confirmation, deterministic fallback, previous-round read-only viewing and resumed history. Linux-specific package plans, reboot continuation and recovery requirements appear inside the existing Fixes/Results areas. Shared labels remain `Compliant`, `Non-Compliant`, `Unknown`, `Error`, and `Low`, `Moderate`, `High`, `Critical`. Execution verdicts remain separate from assessment status.

A baseline manifest distinguishes protected engine/script hashes from authorised entry-point/view edits. Protected files must still match; authorised edits require a recorded diff and regression evidence. A recoverable pre-change Git reference/archive preserves the earlier source. Windows backend and shared-UI regression tests protect behavior; passing engine tests alone does not prove the extended UI preserved confirmation or approval semantics. Use a new project-root `.venv-integration` and explicit isolated data paths before constructing services; neither the existing environment nor live databases are development targets.

## 5. Responsibilities and internal boundaries

| Owner / component | Responsibility |
|---|---|
| Teammate's Windows implementation | Existing Windows assessment, risk inputs, registered actions and WinRM behaviour |
| Teoh's Ubuntu implementation | Ubuntu identity, SSH, 30-control assessment, Linux factor inputs, all 30 remediation families and VM validation |
| Shared integration work | Existing-UI extension, form, detector/router, common presentation contracts, history facade and regression tests |
| Administrator | Target trust/enrolment, goals, manual reviews, exact approvals, maintenance/recovery decisions |
| LLM roles | Bounded tool decisions/explanations only; no OS detection, compliance arithmetic, score changes, commands or approvals |

UI, transport, domain predicates, risk derivation, storage and privileged execution stay separate. The frontend does not know whether a control uses registry policy, UFW or PAM. Backend capability records determine what can be displayed/executed. An unsupported operation is explicit, never a successful no-op.

## 6. Data, scoring and execution contracts

Retain three SQLite files and 11 application table purposes per platform, initially under one application data directory partitioned into `windows/` and `ubuntu/`. Add one integration coordination database for durable workflow bindings, atomic unique operation claims, append-only transition events and target ownership. These seven runtime files belong to one system; the Windows three-file contract remains unchanged. The common history facade normalizes read models; it never sends Ubuntu evidence to the strict Windows importer. Original live databases remain untouched. Any later historical-data import uses a verified copied backup and an explicit migration procedure.

Shared UI commands cover assessment mode, decisions, execution, auxiliary operation proposal/dispatch, manual review, cancellation and reconciliation. No UI panel bypasses that interface to call Ubuntu-private services. Auxiliary maintenance/recovery proposals use the same review/approval path, with distinct types and no inflation of CIS-control counts. Atomic host dispatch claims precede backend calls; crashes leave unresolved ownership until reconciled, rather than permitting a second dispatch based on a stale timeout.

Ubuntu exports use namespace `ubuntu-cis`, version 1, with registered target/epoch, collector/catalogue/content hashes, UTC timestamps, typed observations and sanitized source artifacts. Preserve exact sanitized export bytes and hash. Compound predicates aggregate required subchecks. Do not import secrets, shadow password hashes or private keys in JSON or SCAP/OVAL artifacts. Manual reviews are append-only records bound to exact evidence/state; they cannot overwrite raw observations or waive a known failure.

Risk follows Windows's deterministic method: `R=6I+5E+4P+3L+2D`; score confirmed Non-Compliant findings only. Bands are Low 20–39, Moderate 40–59, High 60–79, Critical 80–100. I and P derive from reviewed consequence/privilege categories; E from reviewed surface/effective context; L from the existing profile/classification mapping; D from compatible history: no prior=1, persistent failure=3, regression=5. Persistent failure remains D=3 even if raw values changed. Linux evidence mappings may differ; the rubric and arithmetic do not. Review documented Linux extensions rather than force a control into an unrelated Windows category. Never hardcode the earlier draft's numeric per-control table.

Every Ubuntu remediation uses a fixed registered implementation. Approvals bind target/epoch, evidence, action version/hash, exact parameters/change set, before-state, expiry and recovery. The root-owned target runner acquires a lock, verifies identity and the exact read-set, atomically claims the request and executes at most once. Unknown execution stops further writes. Verification uses fresh evidence and the same compliance predicate. Systemd-supervised long jobs/recovery survive SSH or dashboard closure. An armed recovery marker blocks another action until resolved. Snapshot restores require explicit host-authoritative epoch renewal; unchanged VM identity does not reliably reveal an undisclosed restore.

When Ollama is unavailable, an explicit deterministic assessment mode calls the original Windows scanner/risk/history services or the Ubuntu equivalents and records a non-agentic assessment. It does not invent proposals or LLM decisions. Previously approved work may execute without AI only through the existing guarded fallback while its original round/approval remains eligible. The same page displays this mode and its unavailable/skipped stages.

Full 30-family support includes package updates, sudo/password policies, SSH, UFW, audit rules and boot activation. Each needs a preview, guard, execution, verification and recovery implementation. Some requests are blocked until prerequisites/maintenance are satisfied; this is different from permanently leaving a control without implemented remediation. Auxiliary metadata refresh, reboot and recovery operations use their own registry namespace and are not counted as extra CIS controls.

## 7. Scope and release gates

The existing Ubuntu VM is reused after a read-only inventory. A separately registered test clone is optional. Full action evaluation requires snapshots/console recovery and disposable test states, not unrestricted modification of a personal/production machine.

The proposed catalogue has 24 Level 1 controls, six Level 2 audit controls and one Manual patching recommendation among the 30. Keep those labels. Neither a 30-control subset nor a successful demonstration establishes full CIS certification.

Develop the common UI/detection route early in the existing application: first prove Windows still works through the same interface, then prove a read-only Ubuntu result flows into the same tabs. Implement the remaining Ubuntu backend and all 30 remediation families behind the frozen contract. Release requires a recoverable pre-change source baseline, unchanged protected Windows logic, reviewed integration diffs, Windows UI/backend regression gates, correct OS routing, 30 validated assessments/actions, crash/recovery tests, live evidence and runbooks.

From the teammate's existing `cis_compliance_dashboard_prototype` directory, launch `..\.venv-integration\Scripts\python.exe -m streamlit run app.py`. This is the same existing entry point, extended to support both platforms; Ubuntu is an internal backend. The old Ubuntu prototype remains reference material. No application code or VM changes are made while updating these planning documents.

## 8. Active documents and evidence

- [Implementation plan](../plans/2026-11-05-unified-vm-hardening-system-plan.md) — complete development tasks and interfaces.
- [Ubuntu control/action catalogue](2026-11-05-unified-system-ubuntu-control-catalogue.md) — all 30 recommendations and action obligations.
- Implementation project and inspected baseline: `C:\Users\teohk\OneDrive\Desktop\FYP_App-main\window_cis_compliance_dashboard_prototype`; retain and extend its nested `cis_compliance_dashboard_prototype/app.py`.
- Planning documents and Ubuntu reference workspace: `C:\Users\teohk\OneDrive\Documents\GitHub\FYP_App\ubuntu_cis_compliance_dashboard_prototype`; not the new application root.
- [Database schema supplied by the user](C:/Users/teohk/Downloads/DATABASE_SCHEMA.md).
- [CIS Ubuntu 22.04 v2.0.0 PDF](C:/Users/teohk/Downloads/CIS_Ubuntu_Linux_22.04_LTS_Benchmark_v2.0.0.pdf); SHA-256 `37b8d91eadb5621656ff38d24c39ac34b9589087a3f3a9fbba2c8a2dd665b6da`.

Code inspection supports the architecture diagnosis. The teammate's documented test results are historical; this planning turn did not rerun his suite or connect to either VM. Actual VM identity, network, dependency and recovery details are execution inputs, not assumed facts.
