# Database schema

The dashboard stores everything in **4 SQLite files** with **11 tables**, under `cis_compliance_dashboard_prototype/data/` (the environment variable `CIS_DASHBOARD_DB` changes the base path; the client package uses `%LOCALAPPDATA%\FYP-Hardening\data`). Most of the detail is stored as JSON inside a few columns, so each table lists both its columns and the JSON fields inside them.

Checked against the real databases on 4 November 2026; the servers file (file 4) was added on 5 November 2026.

## At a glance

```
preview_imports.sqlite3                 preview_imports_framework.sqlite3
┌───────────────────────────┐           ┌──────────────────────────┐
│ imported_assessments      │◄─digest───│ framework_runs           │
│ (one row = one scan)      │           │ (one row = one run)      │
└───────────────────────────┘           └────────────┬─────────────┘
                                                     │ run_id
preview_imports_agentic.sqlite3                      ▼
┌──────────────────────────────────────────────────────────────────┐
│ agentic_rounds ──children──► investigation_runs ──► investigation_events │
│      │ framework_run_id                (team_id = round id)       │
│      ▼                                                            │
│ rem_proposals ──id──► rem_decisions, rem_comments, rem_receipts   │
│ drift_records (current_run_id = framework run)                    │
└──────────────────────────────────────────────────────────────────┘
```

How the IDs connect:

- `framework_runs.digest` = `imported_assessments.digest`: the SHA-256 of the scan's original evidence bytes.
- `framework_run_id` (in rounds, proposals and drift) = `framework_runs.run_id`.
- `rem_decisions.id`, `rem_comments.id` and `rem_receipts.id` = `rem_proposals.id`: one proposal, at most one of each.
- `investigation_runs.payload.team_id` = `agentic_rounds.id`. `investigation_events.run_id` = `investigation_runs.run_id`.
- `target_id` is always `windows:<machine UUID>` of the server; `servers.machine_uuid` is that same UUID.

All times are UTC, in ISO 8601 format. The dashboard shows them in Malaysia time.

---

## File 1: `preview_imports.sqlite3`, the scan evidence

### `imported_assessments`: one row per scan

| Column | Type | Meaning |
| --- | --- | --- |
| `digest` | TEXT, primary key | SHA-256 of the original evidence bytes (`raw`). Identifies the scan. |
| `hostname` | TEXT | Computer name of the scanned server, e.g. `WIN-VFT30DUDRHQ` |
| `target_id` | TEXT | `windows:<machine UUID>` |
| `collected_at` | TEXT | When the collector finished on the server |
| `imported_at` | TEXT | When the dashboard saved it |
| `snapshot` | TEXT (JSON list) | The assessed result of every control (32 entries) |
| `raw` | BLOB (JSON) | The exact bytes the collector script returned. Kept unchanged as evidence. |

**Each entry in `snapshot`:**

| Field | Meaning |
| --- | --- |
| `assessment_id` | `import-<digest>` |
| `status` | `Compliant`, `Non-Compliant`, `Unknown` or `Error` |
| `detail` | Short explanation, e.g. "Observed value does not satisfy the rule" |
| `control` | The CIS rule: `control_id`, `title`, `area`, `rule` (`operator` + `expected`, e.g. `at_least` 14), `profile`, `catalogue_version`, `source_reference` (benchmark section and pages), `source_verified`, `not_configured_fails` |
| `evidence` | What was read: `control_id`, `value` (`null` = not configured), `source` (where it was read on the server), `mode` (`Live`), `collected_at`, `target_id`, `error` |

**Fields in `raw`:**

| Field | Meaning |
| --- | --- |
| `schema_version`, `collector_id`, `catalogue_id` | Which collector and control catalogue produced it (currently 5, `server2022-readonly-v5`, `cis-server2022-standalone-2.0.0-full1`) |
| `benchmark_sha256`, `profile` | Fingerprint of the CIS PDF and the profile (`Level 1 - Member Server`) |
| `evidence_mode`, `started_at`, `completed_at` | Collection details |
| `target` | `hostname`, `machine_uuid`, `os_caption`, `os_version`, `build_number`, `os_architecture`, `product_type`, `part_of_domain`, `domain_role` |
| `observations` | One per control: `control_id`, `source`, `state` (`ok`, `missing`, `error`), `value`, `error`, `collected_at` |
| `effective_context` | Extra readings in the same shape, used for risk exposure, e.g. `firewall_public_enabled` |

---

## File 2: `preview_imports_framework.sqlite3`, the run register

### `framework_runs`: one row per assessment run

| Column | Type | Meaning |
| --- | --- | --- |
| `run_id` | TEXT, primary key | The run ID used everywhere else as `framework_run_id` |
| `digest` | TEXT | The scan's `imported_assessments.digest` |
| `target_id` | TEXT | `windows:<machine UUID>` |
| `created_at` | TEXT | When the run was registered |

A run is complete when it is created and never changes: triggers refuse updates, deletes and replacement. The file's `PRAGMA user_version` is 2; the dashboard refuses a file in any other layout rather than resetting it.

---

## File 3: `preview_imports_agentic.sqlite3`, agents, fixes and drift

### `agentic_rounds`: one row per round

| Column | Type | Meaning |
| --- | --- | --- |
| `id` | TEXT, primary key | Round ID |
| `session_id` | TEXT | Groups the rounds of one dashboard session |
| `created_at` | TEXT | When the round was saved |
| `payload` | TEXT (JSON) | Everything about the round (below) |

**Fields in `payload`.** `kind` decides which ones appear:

| Field | In | Meaning |
| --- | --- | --- |
| `kind` | both | `assessment` (scan, analyse, plan) or `verification_scan` (execute and re-check) |
| `framework_run_id` | both | The scan this round analysed. For a verification round, the re-check scan (`null` if none ran). |
| `orchestrator_run_id` | both | The Orchestrator's `investigation_runs.run_id` |
| `children` | both | Agent role → its `investigation_runs.run_id` |
| `outcome` | both | Assessment: `outcome` (`awaiting_approval`, `no_fix_proposed`, `no_findings`, `incomplete`, …), `reason`, `proposals` (proposal IDs), `skipped` (deferred findings with `reason_code` and `reason`). Verification: `outcome` (`finish`, `next_round`, `remediation_review`, `fallback`, `incomplete`), `reason_code`, `reason`. |
| `analysis` | assessment | The risk ranking calculated by code: findings with score, level and factors; Unknown/Error gaps |
| `analysis_outcome` | assessment | The Analysis Agent's decisions: `attention` flags, `gap_triage`, `rescan_requested` |
| `goal` | assessment | The administrator's goal: `text`, `constraints`, `read_as`. `null` if none was given. |
| `scanned_runs` | assessment | Every scan taken in the round, including replaced ones |
| `remediated_run_id` | verification | The assessment scan whose approved fixes were executed |
| `verdicts` | verification | One per fix: `proposal_id`, `control_id`, `action_id`, `verdict` |

### `investigation_runs`: one row per agent run

| Column | Type | Meaning |
| --- | --- | --- |
| `run_id` | TEXT, primary key | Agent run ID |
| `assessment_id` | TEXT | `agentic-<session_id>` |
| `created_at` | TEXT | When the agent started |
| `payload` | TEXT (JSON) | `agent_role` (Orchestrator, Scanner, Analysis, Remediation), `team_id` (= round ID), `scenario`, `model` (`qwen3:8b`), `provenance` (`Local Ollama`), `limits` (`steps`, `calls`, `seconds`, `request_seconds`, `invalid`), `target_id`, `evidence_mode`, `framework_run_id`, `handoff` |

### `investigation_events`: every step an agent took

| Column | Type | Meaning |
| --- | --- | --- |
| `sequence` | INTEGER, primary key, auto-increment | Global order of events |
| `run_id` | TEXT | The agent run (`investigation_runs.run_id`) |
| `kind` | TEXT | `request`, `tool`, `tool_rejected`, `nudge` or `finished` |
| `created_at` | TEXT | When it happened |
| `payload` | TEXT (JSON) | Depends on `kind` (below) |

| `kind` | `payload` fields | Meaning |
| --- | --- | --- |
| `request` | `step` | The model was asked for its next move |
| `tool` | `name`, `arguments`, `result` | A tool call that code accepted and ran |
| `tool_rejected` | `name`, `error`, `arguments` | A tool call that code refused. Nothing happened. |
| `nudge` | `available` | The model answered without a tool call and was reminded once |
| `finished` | `status`, `summary`, `duration_seconds`, `tool_calls`, `proposal_id`, `outcome` | How the agent stopped |

### `rem_proposals`: one row per proposed fix

| Column | Type | Meaning |
| --- | --- | --- |
| `id` | TEXT, primary key | Proposal (request) ID |
| `run_id` | TEXT | The scan's `framework_run_id` |
| `payload` | BLOB (JSON) | `request_id`, `session_id`, `framework_run_id`, `evidence_sha256`, `hostname`, `machine_uuid`, `control_id`, `action_id` (e.g. `REM-1.1.4`), `value` (target value, e.g. 14), `expected_before` (value seen at scan time), `rank` (order in the plan), `risk_score`, `reason`, `proposed_by`, `created_at` |

### `rem_decisions`: the administrator's approve or reject

| Column | Type | Meaning |
| --- | --- | --- |
| `id` | TEXT, primary key | The proposal ID |
| `decision` | TEXT | `approved` or `rejected` |
| `payload` | BLOB (JSON) | **Approved:** the exact request the VM will run: `request_id`, `evidence_sha256`, `hostname`, `machine_uuid`, `control_id`, `action_id`, `value`, `expected_before`, `schema_version`, `approved_by`, `approved_at`, `expires_at` (1 hour later). The VM checks the SHA-256 of these bytes before it changes anything. **Rejected:** `operator`, `comment`, `at`. |

### `rem_comments`: optional comment on a decision

| Column | Type | Meaning |
| --- | --- | --- |
| `id` | TEXT, primary key | The proposal ID |
| `payload` | TEXT (JSON) | `comment`, `operator`, `at` |

The comment is kept separate so the approved request bytes stay exactly what the VM checks.

### `rem_receipts`: the result of an execution attempt

| Column | Type | Meaning |
| --- | --- | --- |
| `id` | TEXT, primary key | The proposal ID. At most one attempt per proposal. |
| `payload` | BLOB (JSON) | **From the VM:** `schema_version`, `request_id`, `request_sha256`, `status` (`applied`, `execution_failed`, `verification_unavailable`), `before_evidence` and `after_evidence` (base64 collector output), and `error` when the write failed. **Refused or uncertain:** `schema_version`, `request_id`, `status` (e.g. `skipped`, `refused`, `channel_lost`, `invalid_receipt`), `error`. |
| `verdict` | TEXT | `Verified compliant`, `Verification failed`, `Refused before execution: …` or `Unresolved: …` (outcome uncertain; never retried) |

### `drift_records`: settings that changed between two scans

| Column | Type | Meaning |
| --- | --- | --- |
| `id` | TEXT, primary key | SHA-256 of previous run, current run and control, so each change is stored once |
| `target_id` | TEXT | `windows:<machine UUID>` |
| `current_run_id` | TEXT | The newer scan's `framework_run_id` |
| `control_id` | TEXT | The control that changed |
| `payload` | TEXT (JSON) | `previous_run_id`, `current_run_id`, `detected_at`, `control_id`, `title`, `before`, `after`, `status_before`, `status_after`, `change` (e.g. `Improvement`, `Regression`, `Unknown -> Compliant`) |

---

## File 4: `preview_imports_servers.sqlite3`, saved servers

### `servers`: one row per saved server ("My servers")

| Column | Type | Meaning |
| --- | --- | --- |
| `machine_uuid` | TEXT, key | The server's machine UUID, read from the server itself (lower case) |
| `hostname` | TEXT | Its computer name, read from the server |
| `os_caption` | TEXT | Its Windows edition, read from the server |
| `host`, `port` | TEXT, INTEGER | Where it was last reached (WinRM) |
| `username` | TEXT | The administrator account used (never the password) |
| `note` | TEXT | The administrator's own note, at most 120 characters |
| `added_at`, `last_connected_at` | TEXT | When it was saved and last connected |
| `pairing_id` | TEXT or NULL | The helper's record of this laptop's pairing (32 hex). NULL only for a server saved by address before that was removed (5 November 2026); Re-pair fills it |
| `laptop_address`, `paired_at` | TEXT or NULL | This laptop's address as the server saw it, and when it paired |

The server keeps its own side of each pairing in `C:\ProgramData\FYP-ServerAccess\pairings.json` (Administrators and SYSTEM only), not in these files.

---

## Rules and how to look inside

- **Append-only.** The 10 audit tables (files 1 to 3) have database triggers that refuse `UPDATE`, `DELETE` and inserting over an existing ID; the database aborts with a message such as "Immutable agentic audit". A record can be added but never changed, which keeps the audit trail trustworthy.
- **Editable.** `servers` (file 4) is the laptop's own list of servers, so it can be changed: a note, a new address, a removed server. Removing a server never touches its audit records.
- **No secrets.** Server passwords are never stored. They stay in the dashboard's session memory only.
- **Viewing.** The read-only viewer decodes the JSON and can't change anything. From the project folder:

```powershell
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe scripts\tools\show_database.py                    # files, tables, row counts, latest scans and rounds
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe scripts\tools\show_database.py table rem_proposals  # raw rows of any table
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe scripts\tools\show_database.py servers                # saved servers
```

A generic SQLite browser also works, but open the files read-only, and expect the JSON columns to show as long text.

Code that creates these tables: `hardening/import_storage.py` (file 1), `hardening/framework.py` (file 2), `hardening/remediation.py` (file 3), `hardening/servers.py` (file 4).
