# Moving from the demonstration to real Windows evidence

Decision updated 19 October 2026, Malaysia time. The user has installed the standalone Server 2022 VM and confirmed creating its clean snapshot. The supplied screenshot shows Standard Evaluation, version 10.0.20348/build 20348, 64-bit, PartOfDomain=False and DomainRole=2. These are user-supplied observations; no agent-run live assessment or snapshot restore test occurred. No real remediation is authorized by this setup discussion.

## Baseline decision

Keep the current application and installed **standalone Windows Server 2022 VM**. This fits the report's single-server scope and explicit exclusion of Active Directory/domain-specific policies. There is no need to reset the VM, dashboard, database design or AI integration.

The report does name **CIS Microsoft Windows Server 2022 Benchmark v5.1.0**. CIS currently lists that edition and a separate **Microsoft Windows Server 2022 Stand-alone v2.0.0** in its [official Server benchmark catalogue](https://www.cisecurity.org/benchmark/microsoft_windows_server). The [CIS Windows benchmark knowledge base](https://cisecurity.atlassian.net/wiki/spaces/CSKB/pages/2939486448) explains the domain-joined scope of its general Windows benchmarks. Match the actual role to the edition before claiming compliance.

| Target situation | Baseline direction |
| --- | --- |
| Installed standalone Server 2022 lab | Stand-alone v2.0.0 reviewed for five selected controls; exact profile label is Level 1 - Member Server despite the standalone edition's scope |
| Existing domain-joined Server 2022 member or domain controller | Review the report's Server 2022 v5.1.0 and its applicable role/profile; this is not the proposed new lab |
| Windows desktop/laptop running a client OS | A separate matching Windows client benchmark and validated catalogue are required; outside this first preview |

The matching Stand-alone v2.0.0 PDF is now supplied and reviewed for five selected controls. See BENCHMARK_MAPPING.md for its hash, pages, exact profile label, values and collector/manual audit mapping. This is source verification, not a successful real-server assessment. Keep the new catalogue separate from demo-v1 and the report's domain-oriented v5.1.0 edition; explain the baseline choice to the teacher. Report revisions remain deferred.

### Supplied document scope check, 19 October

- File: `C:\Users\User\Documents\Degree\FYP 1\myown\OWN\CIS_Microsoft_Windows_Server_2022_Benchmark_v5.1.0.pdf` (6,059,578 bytes).
- SHA-256: `81b666672e34fd9b0c2e161d1c7cfe01e02efd67eeecf7639d289a5f1a0cf759`.
- Cover: CIS Microsoft Windows Server 2022 Benchmark, v5.1.0, dated 07-28-2026.
- Printed page 26, Intended Audience: domain-joined/AD-managed scope; explicitly excludes standalone/workgroup systems. Printed page 31 lists Level 1 Domain Controller and Member Server profiles.
- Decision: retain this document as the report's reference, but do not activate its rules as a verified standalone baseline. Request the separate Stand-alone edition; do not change domain membership just to match this file.
- Review limits: targeted cover/scope/profile text inspection only, using standard-library PDF stream decoding because PDF extraction/rendering dependencies were unavailable. This is not a complete document review or visual page verification; no control mappings were validated. The source file was not changed or copied into the repository.

## How different devices fit the design

Physical versus virtual hardware is not sufficient to choose a benchmark. OS product/version, machine role, applicable profile and supported collection method determine which reviewed controls can run. VM and physical targets may share a catalogue when those requirements match, but each target still needs validation.

The intended workflow is:

1. Explicitly select a target; collect read-only OS/build and role evidence. Never scan the network to discover a target.
2. Validate the identity and platform metadata. Missing or conflicting metadata prevents a verified assessment; a machine name alone is insufficient.
3. Match a reviewed catalogue to OS, role and profile. Unsupported combinations return an explicit unsupported result rather than silently using Server 2022 rules.
4. Collect the full selected scope through registered collectors; retain collection failures as Error/Unknown and display coverage.
5. Apply deterministic comparisons and risk rules; then let the local AI investigate permitted evidence and propose a supported action.
6. Bind administrator approval to the exact target, finding, action and parameters. Execute only through a registered implementation, then collect separate verification evidence.

This is the **next-stage design**, not implemented multi-platform support. The current app is synthetic and its only executor is a simulator. Supporting additional Windows versions requires separately reviewed rules, collectors, action implementations and tests. The development laptop is excluded from real hardening throughout this project preparation.

## Smallest next implementation milestone

Start with read-only evidence imported from the installed lab VM, avoiding a remote access service for the first integration. Source review and the guarded collector/strict offline importer are implemented and fixture-tested. On 19 October the user confirmed the collector is visible in VM Explorer after shared-folder setup. The first JSON export has now been returned, validated and saved; see VM_VALIDATION.md for actual results and remaining manual comparisons. The separate Imported VM Assessments page and immutable storage are integrated and fixture-tested. Capture exact machine identity in the first export and compare all selected results with independent manual observations before claiming A11. Follow VM_EVIDENCE.md for collection and import.

Before collector implementation, record:

- Target identifier, OS product/edition/build, standalone/member/DC role and collection timestamp/timezone.
- Exact benchmark title/version/profile, source file identity and reviewed page/section references.
- For each selected control: applicability, typed expected value, operator, collection method, independent manual check and error handling.
- Evidence provenance: imported real VM output, distinct from synthetic fixtures and direct live collection.

These five topics now have reviewed mappings in BENCHMARK_MAPPING.md; real collection still needs validation:

| Topic | Review needed before real evidence is accepted |
| --- | --- |
| Password length | Exact minimum, policy scope and effective policy source |
| Account lockout | Exact permitted range, zero semantics and policy scope |
| Guest account | Correct account identity and applicable role; do not rely only on a localized/display name |
| Windows firewall | Exact profile(s) required by the chosen control; the current Domain-profile fixture does not establish standalone coverage |
| RDP NLA | Exact source reference and effective setting; retain client compatibility context for any later remediation |

Do not simply rename DEMO controls as CIS controls. Retain the demonstration catalogue and historical records; introduce a separate reviewed version once mappings are verified. A parser must reject target/catalogue/type mismatches and distinguish missing evidence from compliance. Model text must never create active rules or commands.

## Evidence required to finish A11

1. Review the actual matching PDF and save mappings for approximately five applicable controls.
2. Implement bounded read-only collection/export and import validation for the confirmed lab target. Test invalid/missing values and mismatched targets/catalogues using fixtures first.
3. Collect real VM evidence, preserve source/time/target metadata, and independently inspect each setting using the benchmark's audit guidance.
4. Compare the application's status to those independent results and record discrepancies, coverage and collection/evaluation timing separately from model latency.
5. Save a reproducible validation record. A11 requires real assessment evidence; it does not require live remediation if that remains unauthorized and explicitly simulated.

Only after these dependencies arrive can this milestone be completed. Browser visual QA and spoken practice remain separate presentation tasks. The current technical rehearsal and saved backup remain usable meanwhile.
