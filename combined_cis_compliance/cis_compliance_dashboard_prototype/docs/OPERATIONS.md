# Operations and recovery guide: Ubuntu hardening (FYP-Ubuntu2204)

This is the practical runbook for the one existing application. Development history is in `docs/INTEGRATION_PROGRESS.md`; the runner deployment preview is in `docs/RUNNER_DEPLOYMENT.md`.

## Start the application

From the application directory:

```powershell
..\.venv-integration\Scripts\python.exe -m streamlit run app.py
```

Hot reload is deliberately off (`.streamlit/config.toml`). Restart the app after any code change.

## Everyday use

1. **Connect:** the first time, log in on the VM as the account the dashboard will use and run `sudo python3 fyp-pair-ubuntu.py` (download it from **Servers**; check it with `sha256sum`). Since 13 November 2026 it **sets the server up first**: it shows what it will do for this machine and that account, asks once (`[Y/n]`), removes older FYP tools, installs OpenSCAP with apt if missing (needs internet once: a NAT adapter beside the host-only one; without it the helper stops and changes nothing), then the collector and the runner. Same version already installed: skipped. A change still open on the server: setup skipped (settle it, then run the helper again). `--pair-only` skips setup. Then it shows the code: type it under **Servers > Add a server**, then the account and password. The VM's name, machine ID, address and SSH host key come from the VM's signed answer; nothing is typed but the code and the login. Later, pick the VM under **My servers** and type the password. The password is kept in memory only. The SSH host key is checked before login (the one pinned at pairing).
   **No Set up step on Servers** (removed 13 November 2026): the pairing helper sets the server up before it shows the code. To update the tools later (for example after an application update), run the new `fyp-pair-ubuntu.py` on the server again, then reconnect. The manual bundle under **Servers** stays as a documented alternative.
2. **Assess:** **Start agentic round** scans the server read-only, then the bounded agents rank findings and propose fixes. It needs the local model (Ollama with qwen3:8b). Fixes are proposed only in agentic rounds, and only for confirmed Non-Compliant controls. As on Windows, the next round is offered only once no fix in this one awaits a decision or execution (an expired approval does not count), so no approval is left behind. After a disconnect, **Resume earlier session** brings back the last session; while it has open fixes, it must be resumed before a new round. **New session** leaves a session (it can be resumed later). Comments and who approved or rejected each fix are shown in its row.
3. **Decide:** in **Fixes**, name the operator, then approve or reject each proposal. The approval screen shows the exact change, its impact and how to recover.
   - **Fixes** has the same layout as the Windows page: your name with **Approve all / Reject all undecided**, then one row per proposed fix, highest risk first (the change, why the Orchestrator chose it, and on the right Approve and Reject, or who approved it and until when, or the verified result). Controls the Orchestrator did not propose are listed under **Not proposed this round** with the reason. **Execute N approved fix(es)…** above the tabs opens the confirmation listing exactly those changes. There is no per-control restore (since 12 November 2026, as on Windows); package-list refresh and reboot are in the **Maintenance** box. The **Agent log** tab shows every agent step.
   - After a fix runs, a fresh re-scan runs automatically, and the fix's row shows its result. The Controls tab keeps showing the scan the plan was made from.
   - The orchestrator chooses what to propose (project decision D4); approve only the fixes you want to run now and leave the rest undecided. Round goals are disabled for Ubuntu and due for removal.
4. **Execute:** tick the confirmation, then **Execute approved fixes**. Each approved change runs at most once.
   - Since 13 November 2026 one verification scan runs when the whole execution has settled (not one per fix), and the fixes left after the first part run by code in plan order without a new AI step. The SSH and firewall changes are sent one after the other once each waits for its confirmation, then one fresh login confirms them all; each still has its own 10-minute rollback timer.
   - Supervised jobs (packages, GRUB, patches) and confirmations over a fresh login run behind the running animation (Orchestrator → Remediation → Scanner) since 13 November 2026: the page checks them every 5 seconds and goes on by itself. **Check status** appears only when something needs you (an outcome to reconcile). Package fixes are refused at once while apt's lock is held ("apt is busy: Ubuntu's automatic updates ..."); right after a snapshot restore that can last 30 minutes or more, so wait until `systemctl is-active apt-daily-upgrade.service` says inactive, then run the next round. A lock taken in between is waited for 5 minutes.
   - **SSH and UFW changes:** when one is waiting for confirmation, the dashboard logs in again over a new SSH connection with the account you connected with (kept in memory only, forgotten on Disconnect) and confirms it. That new login is the proof SSH still works. If it fails, nothing is confirmed and the server restores the change by itself within 10 minutes. By hand: disconnect, connect again, **Confirm change**.
5. **Verify:** after a change completes, a fresh scan runs automatically. A control counts as fixed only when that scan says so; nothing is retried automatically.
   - **Refresh status** (top of Fixes) redraws the page from the stored records and keeps the VM connection. A browser reload starts a new session and ends the connection, because the password lives only in that session.
   - **Run verification scan** appears when a change applied but has no re-scan yet, for example because the scan failed after Check status settled a job. It runs the read-only scan for exactly those changes and never re-runs a fix.
   - **Fixes that share a file can be approved and executed together** (since 11 November 2026), except UFW. Each fix on the kernel-settings file (1.5.1, 1.5.3, 3.3.1, 3.3.2, 3.3.8), the SSH drop-in (5.1.x), the sudoers drop-in (5.2.2, 5.2.3), `/etc/login.defs` and `/etc/shadow` (5.4.1.x) checks and restores only its own keys, lines or account fields, so one fix never makes another stale and a restore puts back only its own part. **UFW (4.1.3, 4.1.4, 4.1.7) still one at a time:** while one is approved and not executed, the others' Approve button is disabled and the row says why, because enabling the firewall depends on the allow rules. Execute the approved one, then start a new round for the next.
   - **Server decisions** (since 13 November 2026): once per server, on Agentic hardening, record whether UFW manages its firewall (needed for 4.1.3, 4.1.4, 4.1.7) and whether to keep avahi-daemon stopped and masked (2.1.2). Your name and the time are recorded; they take effect from the next round. The first lab VM's decisions are registered in the program. The panel disappears once both are made.
   - **Why a planned fix has no card:** "Not proposed this round" now shows the server's own reason. Package fixes (1.3.1.1, 6.3.1.1) need working package lists: click Refresh package lists in the Maintenance box; since 13 November a refresh that downloads nothing shows as failed (add a NAT adapter for internet). While it runs, the box shows a spinning status and updates by itself. A package install may upgrade the installed packages it needs (listed in its approval), never remove one. 4.1.3 adds the SSH allow rule (`ufw allow 22/tcp`) itself before turning UFW on; nothing is typed on the server. 4.1.4 and 4.1.7 follow in the round after 4.1.3, and can be approved and executed together in that round; 4.1.4 puts the loopback rules in front of that SSH rule (`ufw prepend`) when appending them would not comply.
   - **Complete hardening** (since 12 November 2026, as on Windows): offered once nothing of the latest round awaits a decision or execution and no change is open on the server. The panel lists what is still open in the newest scan; type a reason and **Accept as exception** for anything you keep as it is (your name is recorded). **Run final scan and complete** takes one read-only scan: if everything is Compliant or accepted, the session is completed, Overview says so, and the session becomes read-only (no decisions, execution or new round in it) with a **Completion report**; otherwise the panel says what is still open. **New session** checks the server again. Exceptions belong to one session and never count as compliant. Stored in `data/ubuntu/ubuntu_completion.sqlite3`.
   - **Check AI** (optional; since 12 November 2026), beside Start agentic round: sends a one-word request to qwen3:8b (this also loads the model for Ollama's 5-minute keep-alive), reads free laptop memory and whether the model is on the GPU, and says how long the check took. Badge: **AI ready**; **AI slow** (answer over 20 s, under 2 GB free, or the model partly on the CPU: free memory first); **AI not answering** (Start is disabled until you check again). It never runs by itself. During a round, a model request that times out is retried once per agent with the same request (the scan already done is kept); the Agent log and the round report show each step's model response time, and under the step bar each phase's time ("Assessment took 42 s (Scanner 11 s · Analysis 10 s · Orchestrator planning 21 s), within the 10-minute limit per phase."), as on Windows.
   - **Live validation register** (since 12 November 2026; on **Overview** since 13 November, shown once the server has an assessment): **Live validation register: N of 30 validated live on <server>** lists every control with its status (Validated live, Validated live and restored, Applied not verified, Refused, Fixture-tested only) and the evidence of the fix that proves it (time, approver, request). **Open the round** opens Agentic hardening on the session and round where a control was proven or last tried. The round report has the same table as section 7.
   - **One Execute click runs every approved fix** (since 12 November 2026). Fixes that finish at once run first; fixes that wait (package installs and GRUB as supervised jobs, SSH and UFW for their fresh-login confirmation) run after them, one at a time. When the one that waited has settled, the page sends the rest of the same execution by itself. It does not continue when a fix was approved after the click (click Execute for it), an approval has expired (start a new round), a change was rolled back or its outcome is unknown (check it first), or the agents stopped before anything ran (Confirm again, or **Execute remaining without AI**).
   - **2.1.2** keeps avahi-daemon installed and stops and masks its socket and service (site decision, recorded per machine in `system/config.py`).
   - **2.4.1.2** (`/etc/crontab` root:root, `chmod og-rwx`) replaced 1.2.2.1 in the selection on 2026-11-08. Scans from before then (catalogue v1) still open; their retired 1.2.2.1 row is not shown.

## Helper and runner updates

Every helper change requires a reinstall, and the app refuses scans from a different helper version.

```bash
cd ~/ubuntu-helper && sudo bash uninstall.sh
```

Copy the new `dist\ubuntu-helper` folder to the VM, then:

```bash
cd ~/ubuntu-helper && sudo bash install.sh && sudo bash install-runner.sh
```

- `uninstall.sh` also removes the runner stage, and refuses while a change is in progress.
- **Same code reinstalled:** earlier acceptance results still count.
- **New code:** click **Run safety check** on the Ubuntu page (about two to three minutes). It runs the confirm test, confirms it over its own fresh login, then runs the rollback test and waits for the server to restore it. The panel is shown only while the tests are needed; once both have passed for the deployed runner it is gone. Reinstalling the runner (a new runner digest) makes the check needed, and shown, again.
  - The separate **Run confirm scenario** / **Run rollback scenario** buttons were removed on 13 November 2026: **Run safety check** does both, with its own fresh login. A test left open can still be checked or confirmed from its row.

## Maintenance (Fixes tab)

- **Package-list refresh:** `apt-get update` only, bound to the exact apt sources. Use it before package fixes when the lists are old.
- **Reboot to complete applied changes:** for example GRUB `audit=1` or a kernel update. No reboot is offered for 6.3.1.3 since 13 November 2026 (the CIS check reads the boot entries, which comply at once). The VM restarts 60 s after the reboot runs. Keep **Agentic hardening** open: the page stays there (since 13 November 2026 it no longer moves to Servers or Overview), shows the running animation saying the server is restarting, checks its SSH port every 5 s (no login), logs in again with the account you connected with once the port answers twice, verifies the new boot ID and runs a fresh scan. If the server is not back within 10 minutes, or the page was not open when the connection dropped, connect again under **Servers > My servers**; the reboot is then checked by its boot ID.

## Recovery options, mildest first

1. **No per-control restore** (removed 12 November 2026 at the administrator's request, as on Windows). The page and the host no longer offer one; the runner on the server still has the restore operation (unchanged, so no new setup), but nothing sends it. Restores stored before that date stay in the history.
2. **Commit-confirm timers:** unconfirmed SSH and UFW changes restore themselves. After a reboot, `fyp-hardening-boot-rollback.service` does it before SSH starts.
3. **Remove the runner stage:** `sudo bash uninstall-runner.sh` on the VM console.
4. **VirtualBox snapshot:** take one before each live session (for example `Before_Live_Fixes_<date>`); it is the last resort.

## Back up and restore the stores

The stores under `data/` hold every scan, round, approval, receipt and the coordination ledger (`UNIFIED_ARCHITECTURE.md`, "Stores"). Back them up before each live session, next to the VirtualBox snapshot.

```powershell
..\.venv-integration\Scripts\python.exe -B -m tools.backup_stores backup
```

- This creates `..\store-backups\stores-<UTC time>\`, a consistent copy of every store taken with SQLite's backup API (safe while the app runs), plus `manifest.json` with each file's SHA-256 and integrity check. It then verifies the copy. Backups are git-ignored and contain no credentials.
- Check an older backup: `... -m tools.backup_stores verify ..\store-backups\stores-<time>`.
- **Restore:** stop the app. Restore into an empty folder, e.g. `... -m tools.backup_stores restore ..\store-backups\stores-<time> --into ..\restored-data`. Then rename the current `data` folder (keep it), rename `restored-data` to `data`, and start the app. The tool never writes into a folder that has content, so it cannot overwrite the live stores.
- A restored store must match the VM's current state: after a VM snapshot restore, use the backup taken with that snapshot. The app refuses approvals from another registration epoch.
- Drill, 2026-11-07: all 7 live stores backed up, verified and restored into an empty folder, with identical row counts in every table.

## Independent value cross-check (second reading)

Reads the same settings a second way on the VM, then compares them with the latest stored scan. Run it right after an assessment.

1. Copy `scripts\vm\ubuntu_cross_check_values.py` to the VM. It is read-only (checked by `test_ubuntu_cross_check_script`) and does not need the helper.
2. On the VM: `sudo python3 ubuntu_cross_check_values.py > crosscheck.json`. Root is needed only to read `/etc/shadow`, the audit rules and the account ages.
3. Copy `crosscheck.json` back to the laptop, then from the app directory: `..\.venv-integration\Scripts\python.exe -B -m tools.ubuntu_value_cross_check crosscheck.json --write`. The result goes to `docs/evaluation/VALUE_CROSS_CHECK.md`.

- A reading from another machine is refused. A gap of more than 60 minutes between the scan and the reading is flagged.
- Rows marked "same tool" (`sshd -T`, `auditctl -l`) share the collector's tool and are not independent.

## Troubleshooting

| Message or symptom | Meaning and action |
|---|---|
| "Ubuntu workflow binding required" | The app reloaded code under a live session. Restart the app (hot reload is now off). |
| Scan rejected or "helper differs" | The VM helper does not match this app. Reinstall the bundle. |
| "The server clock differs from this computer by N s" | Only then, Agentic hardening shows a **Clocks differ** box with **Sync server clock to this laptop**: the fix runner sets the server clock to this laptop's time (`date -u --set`), recorded in the ledger, refused while a change is open on the server. Needs the runner of 11 November 2026 or later (Servers → Set up this server). Without it, fix time sync on the server (`timedatectl`), then **Check again**. |
| "Execution acceptance pending: …" | Run the scenario(s) it names. |
| "runner is not deployed or refused the probe" | Run `sudo python3 fyp-pair-ubuntu.py` on the server again (it updates the tools, then shows a code you can ignore with Ctrl+C), then reconnect and run the safety check. |
| "This laptop recorded another SSH host key for <server>" | The server now offers another SSH host key (restored from an older snapshot, or reinstalled). Check it on the console: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. Then run `sudo python3 fyp-pair-ubuntu.py` there and use **Re-pair** on Servers: the signed pairing answer must name the key the login finds. The server is then recorded under a new registration (earlier approvals no longer count; run the safety check again). Refused while a change is still open on it. |
| "This server is not set up yet: the FYP helper is not installed" | Run `sudo python3 fyp-pair-ubuntu.py` on the server (download it from **Servers**), then reconnect. |
| "Confirmation needs a fresh login" or "not confirmed automatically" | Disconnect and connect again, then press Confirm before the timer restores the change. |
| "Another VM has a running or unresolved change" | Reconnect to that VM and settle its change first. |
| "Target or workflow has an unresolved operation" | Use **Check status** on the pending change; it settles from the VM's own record and never re-runs anything. |
| "the server could not read this change's state" | apt or dpkg is busy or was interrupted (for example a restart during an install). The page checks again by itself; if a restart interrupted dpkg, run `sudo dpkg --configure -a` on the server. |
| "the server has no record of this request" | The VM was restored from a snapshot (or reset) after the fix was sent. The fix is settled as not applied and nothing more of that execution runs; after rerunning the helper and the safety check, start a new round. |
| "A change is still open on this server; check its status first" (safety check) | Use **Check status** on the open change first; the safety check runs after it is settled. |
| "the server's status could not be read 3 times in a row" | The page left the running view. Use **Check status**, or connect again; the error shown says what failed. |

## What never happens automatically

- No fix runs without its own exact approval and confirmation.
- No failed or uncertain change is retried.
- The VM is never rebooted without an approved reboot.
- The development laptop is never hardened.
- Credentials are never stored.
