# Real VM trial runbook

The first end-to-end agentic run on the real lab VM. It takes about 60–90 minutes. Each part says what to do and what to record; the records become evidence for report Chapter 5 (functional, compliance accuracy, safety, NFR06 timing, drift).

**Target:** VirtualBox VM `FYP-Server2022-Manual`, computer name `WIN-VFT30DUDRHQ`, UUID `e5d10741-f200-4292-a099-e6be76032f4e`. **Never** run anything here against the laptop itself.

**Stop rule:** if anything unexpected happens — a `wrong_target` or channel error, a verdict you don't understand, a change you didn't approve — stop, don't retry, take a screenshot, and restore the snapshot from Part A. Every agent step is also recorded in the databases, so nothing is lost by stopping.

## Part A — Prepare (10 min)

1. Start the VM and log in at the VirtualBox console as Administrator.
2. Inside the VM, in **Windows PowerShell as Administrator**, check that remoting still works:
   ```powershell
   Test-WSMan -ComputerName localhost
   ```
   It should print a `wsmid` block. If it errors, run `Enable-PSRemoting -Force -SkipNetworkProfileCheck` first ([VM_CONNECTION.md](VM_CONNECTION.md)).
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
| Round duration (NFR06 ≤ 10 min) | Section 2 table: Orchestrator "Seconds" | |
| Outcome sentence | Section 2 banner | |
| Compliant / Non-Compliant / Unknown / Error | Section 3 counters | |
| Did each agent complete? Rejected calls? | Section 2 table and "Agent decisions" expander | |
| Analysis Agent flags and gap triage | Section 4 | |
| Number of proposed fixes | Section 5 | |

4. **Check the open question from collector v5:** in Section 3's control list, the five audit controls (17.1.1, 17.2.2, 17.2.3, 17.5.1, 17.5.4) must show numbers, not Unknown. If they are Unknown, the `auditpol /backup` column assumption was wrong — stop here and tell me; nothing has been changed yet.
5. Take screenshots of Sections 2–5.

## Part C — Manual cross-check (10 min; compliance accuracy evidence)

Inside the VM, in PowerShell as Administrator, run these read-only commands and compare with the dashboard's observed values:

```powershell
net accounts
auditpol /get /subcategory:"Credential Validation","Logon","Account Lockout","User Account Management","Security Group Management"
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' | Select-Object RestrictAnonymous,RestrictAnonymousSAM,LimitBlankPasswordUse
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
```

| Control | Dashboard observed | Manual observed | Agree? |
| --- | --- | --- | --- |
| 1.1.1 password history | | `net accounts`: Length of password history | |
| 1.1.4 minimum length | | `net accounts`: Minimum password length | |
| 1.2.2 lockout threshold | | `net accounts`: Lockout threshold | |
| 17.5.4 Logon audit | | `auditpol`: Logon | |
| 2.3.10.3 RestrictAnonymous | | registry | |
| 18.10.57.3.9.4 NLA policy | | registry (absent = Not configured) | |

## Part D — Decide (5 min)

1. Enter your name as administrator in Section 5.
2. **Approve** the proposals, but **reject one** (suggestion: `18.10.57.2.2`, saved RDP passwords) so the rejection path is exercised too.
3. Be aware of what approving does:
   - Password policy fixes apply at the *next* password change; your current Administrator password keeps working.
   - The lockout threshold fix (`1.2.2` → 5) means 5 wrong passwords lock an account. Type the Administrator password carefully when reconnecting. If you get locked out, wait 30 minutes or restore the snapshot.
   - RDP policy fixes do not affect the VirtualBox console or WinRM.

## Part E — Remediation phase (5 min)

1. Choose **Execute N approved fix(es) with the Remediation Agent** and note the clock time.
2. **Record:**

| Item | Where | Value |
| --- | --- | --- |
| Phase duration | Section 6 timeline: Orchestrator "Seconds" | |
| Orchestrator's next step and sentence | Section 6 banner | |
| Remediation Agent tool sequence | "Agent decisions" expander (expect precheck → execute_fixes → report_results) | |
| Verdicts (all "Verified compliant"?) | Section 6 table | |
| Did the rejected fix stay untouched? | Section 6 table / VM check below | |

3. In the VM, rerun `net accounts` and the `auditpol` line from Part C and confirm the new values match the verdicts.

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
