# Real VM trial runbook

> **Status, 1 November 2026.** Parts A, B, D and E were run on 30 October (PROGRESS.md: 3 fixes verified; the audit controls read real values). **Still to run: Part C (cross-check, before and after a fix) and Part F (next round and the drift test).** The steps below follow the current page layout (tabs); a shorter checklist for the remaining parts is at the end.

The first end-to-end agentic run on the real lab VM. It takes about 60–90 minutes. Each part says what to do and what to record; the records become evidence for report Chapter 5 (functional, compliance accuracy, safety, NFR06 timing, drift).

**Target:** VirtualBox VM `FYP-Server2022-Manual`, computer name `WIN-VFT30DUDRHQ`, UUID `e5d10741-f200-4292-a099-e6be76032f4e`. **Never** run anything here against the laptop itself.

**Stop rule:** if anything unexpected happens — a `wrong_target` or channel error, a verdict you don't understand, a change you didn't approve — stop, don't retry, take a screenshot, and restore the snapshot from Part A. Every agent step is also recorded in the databases, so nothing is lost by stopping.

## Part A — Prepare (10 min)

1. Start the VM and log in at the VirtualBox console as Administrator.
2. Inside the VM, in **Windows PowerShell as Administrator**, check that remoting still works:
   ```powershell
   Test-WSMan -ComputerName localhost
   ```
   It should print a `wsmid` block. If it errors, run `Enable-PSRemoting -Force -SkipNetworkProfileCheck` first ([VM_CONNECTION_SETUP.md](VM_CONNECTION_SETUP.md)).
3. In VirtualBox take a snapshot named **`Before_Agentic_Trial`**. (The older `Clean_Server2022_Before_Hardening` snapshot predates WinRM, so restoring that one would also remove remoting.)
4. On the laptop, check the model is available: `ollama list` should show `qwen3:8b`. Close other GPU-heavy programs; a round is about 6–8 minutes.
5. Start the dashboard from `cis_compliance_dashboard_prototype`:
   ```powershell
   .\.venv\Scripts\python.exe -m streamlit run app.py
   ```

## Part B — Assessment round (10 min)

1. Open **Agentic hardening**. Enter the computer name and UUID above, keep host `127.0.0.1` and port `55985`, enter the Administrator password, and choose **Connect and check identity**.
2. Choose **Start agentic round** and note the clock time. Wait for it to finish (up to 10 minutes).
3. **Record:**

| Item | Where to find it | Value |
| --- | --- | --- |
| Round duration (NFR06 ≤ 10 min) | **Agent log** tab: Orchestrator "Seconds" | |
| Outcome sentence | **Fixes** tab: "Orchestrator summary" | |
| Compliant / Non-Compliant / Unknown / Error | **Controls** tab counters | |
| Did each agent complete? Rejected calls? | **Agent log** tab (one expander per agent) | |
| Analysis Agent flags and gap triage | **Risk ranking** tab | |
| Number of proposed fixes | **Fixes** tab | |

4. **Check the open question from collector v5 (confirmed on 30 October):** in the **Controls** tab, the five audit controls (17.1.1, 17.2.2, 17.2.3, 17.5.1, 17.5.4) must show numbers, not Unknown. If they are Unknown, the `auditpol /backup` column assumption was wrong — stop here and tell me; nothing has been changed yet.
5. Take screenshots of the Fixes, Risk ranking, Controls and Agent log tabs (report Figures 4.12–4.14).

## Part C — Independent cross-check (5 min; compliance accuracy evidence)

On the laptop, open a **second** PowerShell window in the repository folder (leave the dashboard running) and run:

```powershell
cis_compliance_dashboard_prototype\.venv\Scripts\python.exe scripts\tools\cross_check_controls.py --out cis_compliance_dashboard_prototype\data\crosscheck_round1.md
```

Type the Administrator password when it asks; it isn't stored. The script checks it reached the right VM with an administrator token, then runs the read-only [Get-CrossCheckValues.ps1](../../scripts/vm/Get-CrossCheckValues.ps1) there. That script reads all 32 values with different tools from the collector: `net accounts`, `Get-LocalUser`, `reg query` and `auditpol /get`. It then prints a table comparing them with the dashboard's latest scan, ending in **"N of 32 controls agree"**. The table is also saved to `crosscheck_round1.md`.

- **Disagree** on any row: screenshot it and tell me; don't change anything.
- Three values exist only in the security policy database (1.1.5, 1.1.7, 2.3.10.1), so the script reads them from a secedit export like the collector. Check those three in `secpol.msc` by eye, and take one screenshot there for the report.
- If WinRM fails, fix the connection first (see the failure states in [VM_CONNECTION_SETUP.md](VM_CONNECTION_SETUP.md)); the cross-check runs only from the laptop.

## Part D — Decide (5 min)

1. In the **Fixes** tab, enter your name as administrator (and a comment if you like).
2. **Approve** the proposals, but **reject one** (suggestion: `18.10.57.2.2`, saved RDP passwords) so the rejection path is exercised too.
3. Be aware of what approving does:
   - Password policy fixes apply at the *next* password change; your current Administrator password keeps working.
   - The lockout threshold fix (`1.2.2` → 5) means 5 wrong passwords lock an account. Type the Administrator password carefully when reconnecting. If you get locked out, wait 30 minutes or restore the snapshot.
   - RDP policy fixes do not affect the VirtualBox console or WinRM.

## Part E — Remediation phase (5 min)

1. Choose **Execute approved fixes…**, check the confirmation list, then **Confirm and execute**, and note the clock time.
2. **Record:**

| Item | Where | Value |
| --- | --- | --- |
| Phase duration | **Agent log** tab, Remediation phase: Orchestrator "Seconds" | |
| Orchestrator's next step and sentence | **Results** tab banner | |
| Remediation Agent tool sequence | **Agent log** tab (expect precheck → execute_fixes → report_results) | |
| Verdicts (all "Verified compliant"?) | **Results** tab | |
| Did the rejected fix stay untouched? | **Results** tab / VM check below | |

3. Rerun the Part C command with `--out cis_compliance_dashboard_prototype\data\crosscheck_after_fix.md`. It now compares against the verification scan; the fixed controls should agree at their new values.

## Part F — Next round and drift (15 min)

1. Choose **Run next round**. Expect: the fixed controls are Compliant; 1.2.1 and 1.2.4 likely change from Unknown to Compliant (Windows usually sets default lockout timers once a threshold exists; this trial is the first real confirmation, so record what actually happens); the rejected fix is proposed again. Record the outcome and duration.
2. Open **History and drift**: the fixed controls should appear as *Improvement* records. Screenshot it.
3. **Drift test.** In the VM, undo one fix on purpose:
   ```powershell
   net accounts /lockoutthreshold:0
   ```
   Back in the dashboard, **Run next round** again. Expect 1.2.2 to be ranked with **D = 5** (score 77 instead of 69), a *Regression* record on the History page, and possibly the Analysis Agent flagging it as `regression`. Record what you see.

## Part G — Finish

1. Optionally restore the `Before_Agentic_Trial` snapshot to get the VM back to its pre-trial state.
2. Tell me the trial is done and paste the tables above (or send screenshots). The full agent traces are already in `cis_compliance_dashboard_prototype/data/preview_imports_agentic.sqlite3`, so I can extract the exact tool sequences and timings for the report myself.

## Remaining real-VM checklist (after 30 October)

About 40 minutes. Take a snapshot first (Part A, step 3).

1. **Connect** (Part B, step 1) and **Run next round** or **Start agentic round**. Record the round time from the Agent log.
2. **Part C before:** run `cross_check_controls.py --out cis_compliance_dashboard_prototype\data\crosscheck_round1.md`. Check 1.1.5, 1.1.7 and 2.3.10.1 in `secpol.msc` and take one screenshot.
3. Approve one or two low-impact fixes (for example 1.1.4 or 2.3.10.3), reject one, then **Confirm and execute**.
4. **Part C after:** rerun the cross-check with `--out …\crosscheck_after_fix.md`.
5. **Part F drift test:** inside the VM run `net accounts /lockoutthreshold:0`, then **Run next round**. Expect 1.2.2 with D = 5 (score 77) and a *Regression* record on **History and drift**.
6. Screenshots for report Figures 4.11–4.16 (REPORT_REVISIONS A6): Overview, Controls (filter Non-Compliant), Risk ranking with a finding open, Fixes, the execution confirmation, Results, History and drift.
7. Download the **Round report** for each round.
