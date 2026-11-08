# Operations and recovery guide: Ubuntu hardening (FYP-Ubuntu2204)

This is the practical runbook for the one existing application. Development history is in `docs/INTEGRATION_PROGRESS.md`; the runner deployment preview is in `docs/RUNNER_DEPLOYMENT.md`.

## Start the application

From the application directory:

```powershell
..\.venv-integration\Scripts\python.exe -m streamlit run app.py
```

Hot reload is deliberately off (`.streamlit/config.toml`). Restart the app after any code change.

## Everyday use

1. **Connect:** the first time, run `sudo python3 fyp-pair-ubuntu.py` on the VM (download it from **Servers**), type its code under **Servers > Add a server**, then the account and password. The VM's name, machine ID, address and SSH host key come from the VM's signed answer; nothing is typed but the code and the login. Later, pick the VM under **My servers** and type the password. The password is kept in memory only. The SSH host key is checked before login (the one pinned at pairing).
   **New server, once:** on **Servers**, click **Set up this server**. The dashboard builds the helper bundle for exactly this server and copies it to `~/fyp-ubuntu-helper` over the SSH login (no root, nothing run). Then, on the server, run the one command it shows, `sudo bash ~/fyp-ubuntu-helper/setup.sh` (take a snapshot first). It asks before doing anything, then installs OpenSCAP (`libopenscap8`) if missing, `install.sh` and `install-runner.sh`, skipping what is already installed. Click **Check again**. Then run the two Execution acceptance tests.
2. **Assess:** **Assess without AI** runs a read-only, deterministic scan. **Start agentic round** also lets the bounded agents rank findings and propose fixes. Fixes are proposed only in agentic rounds, and only for confirmed Non-Compliant controls.
3. **Decide:** in **Fixes**, name the operator, then approve or reject each proposal. The approval screen shows the exact change, its impact and how to recover.
   - **Fixes** shows one expandable card per Non-Compliant control. The card title gives its current state (awaiting your decision, approved, running, *Fixed, re-scan: Compliant*, not applied, restored, deferred). Open a card to see the AI's decision, the reason, any analysis flag, the exact change and recovery, plus that control's Approve, Reject and Restore buttons. The **Agent log** tab shows every agent step.
   - After a fix runs, a fresh re-scan runs automatically, and the card shows its result. The Controls tab keeps showing the scan the plan was made from.
   - The orchestrator chooses what to propose (project decision D4); approve only the fixes you want to run now and leave the rest undecided. Round goals are disabled for Ubuntu and due for removal.
4. **Execute:** tick the confirmation, then **Execute approved fixes**. Each approved change runs at most once.
   - Supervised jobs (packages, GRUB, patches) appear above the tabs with **Check status**.
   - **SSH and UFW changes:** when the panel says "waiting for confirmation", **disconnect, reconnect, then press Confirm change** within 10 minutes. Without that, the VM restores the change by itself.
5. **Verify:** after a change completes, a fresh scan runs automatically. A control counts as fixed only when that scan says so; nothing is retried automatically.
   - **Refresh status** (top of Fixes) redraws the page from the stored records and keeps the VM connection. A browser reload starts a new session and ends the connection, because the password lives only in that session.
   - **Run verification scan** appears when a change applied but has no re-scan yet, for example because the scan failed after Check status settled a job. It runs the read-only scan for exactly those changes and never re-runs a fix.
   - **Fixes that change the same file cannot be approved together.** While one fix of a group is approved and not executed, the others' Approve button is disabled and the card says why. The groups are: the kernel-settings file (1.5.1, 1.5.3, 3.3.1, 3.3.2, 3.3.8), the sudoers drop-in (5.2.2, 5.2.3), `/etc/shadow` (5.4.1.x), the UFW files (4.1.x) and the SSH drop-in (5.1.x). Execute the approved one, then start a new round for the next.
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
- **New code:** run both acceptance scenarios again (**Execution acceptance** on the Ubuntu page). The panel appears only while it is needed: after a reinstall of new code, or while a scenario is still open. Once both have passed for the deployed runner it is hidden.
  - **Confirm scenario:** run it, Check status until it is waiting, disconnect, reconnect, Confirm (about 60 s window).
  - **Rollback scenario:** run it, do not confirm, wait about 90 s, then Check status until it shows `rolled_back`.

## Maintenance (Fixes tab)

- **Package-list refresh:** `apt-get update` only, bound to the exact apt sources. Use it before package fixes when the lists are old.
- **Reboot to complete applied changes:** for example GRUB `audit=1` or a kernel update. The VM restarts 60 s after the reboot runs. Reconnect when it is back, then Check status: the new boot ID is verified and a fresh scan follows.

## Recovery options, mildest first

1. **Approved restore:** **Prepare restore of <control>** for an applied fix, approve it, confirm, run. This restores the exact recorded before-state, and refuses if something changed it since.
   - Patch upgrades and reboots cannot be restored.
   - Package purges reinstall the recorded version, with default configuration.
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
| "The VM clock differs from this computer by N s" | Fix time sync on the VM (`timedatectl`), then reconnect. |
| "Execution acceptance pending: …" | Run the scenario(s) it names. |
| "runner is not deployed or refused the probe" | **Servers > Set up this server**, then the command it shows (or `install-runner.sh` by hand). |
| "This server is not set up yet: the FYP helper is not installed" | **Servers > Set up this server**, then the command it shows. |
| "Confirmation needs a fresh login" | Disconnect and reconnect, then press Confirm. |
| "Another VM has a running or unresolved change" | Reconnect to that VM and settle its change first. |
| "Target or workflow has an unresolved operation" | Use **Check status** on the pending change; it settles from the VM's own record and never re-runs anything. |

## What never happens automatically

- No fix runs without its own exact approval and confirmation.
- No failed or uncertain change is retried.
- The VM is never rebooted without an approved reboot.
- The development laptop is never hardened.
- Credentials are never stored.
