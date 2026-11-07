# Operations and recovery guide: Ubuntu hardening (FYP-Ubuntu2204)

This is the practical runbook for the one existing application. Development history is in `docs/INTEGRATION_PROGRESS.md`; the runner deployment preview is in `docs/RUNNER_DEPLOYMENT.md`.

## Start the application

From the application directory:

```powershell
..\.venv-integration\Scripts\python.exe -m streamlit run app.py
```

Hot reload is deliberately off (`.streamlit/config.toml`). Restart the app after any code change.

## Everyday use

1. **Connect:** enter the VM hostname, machine ID, address and user, then the password. The password is kept in memory only. The SSH host fingerprint is checked before login.
2. **Assess:** **Assess without AI** runs a read-only, deterministic scan. **Start agentic round** also lets the bounded agents rank findings and propose fixes. Fixes are proposed only in agentic rounds, and only for confirmed Non-Compliant controls.
3. **Decide:** in **Fixes**, name the operator, then approve or reject each proposal. The approval screen shows the exact change, its impact and how to recover.
   - The **AI plan** table at the top of Fixes lists every Non-Compliant control with the orchestrator's decision (fix proposed, deferred, not decided), its reason and any analysis flag. The **Agent log** tab shows every agent step.
   - The orchestrator chooses what to propose (project decision D4). To steer it, use **Goal for this round**, for example "Propose fixes for the sysctl controls 3.3.1, 3.3.2 and 3.3.8 only"; controls outside the goal are deferred as `outside_goal`.
4. **Execute:** tick the confirmation, then **Execute approved fixes**. Each approved change runs at most once.
   - Supervised jobs (packages, GRUB, patches) appear above the tabs with **Check status**.
   - **SSH and UFW changes:** when the panel says "waiting for confirmation", **disconnect, reconnect, then press Confirm change** within 10 minutes. Without that, the VM restores the change by itself.
5. **Verify:** after a change completes, a fresh scan runs automatically. A control counts as fixed only when that scan says so; nothing is retried automatically.

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
- **New code:** run both acceptance scenarios again (**Execution acceptance** on the Ubuntu page):
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

## Troubleshooting

| Message or symptom | Meaning and action |
|---|---|
| "Ubuntu workflow binding required" | The app reloaded code under a live session. Restart the app (hot reload is now off). |
| Scan rejected or "helper differs" | The VM helper does not match this app. Reinstall the bundle. |
| "The VM clock differs from this computer by N s" | Fix time sync on the VM (`timedatectl`), then reconnect. |
| "Execution acceptance pending: …" | Run the scenario(s) it names. |
| "runner is not deployed or refused the probe" | Run `install-runner.sh` (after its approval). |
| "Confirmation needs a fresh login" | Disconnect and reconnect, then press Confirm. |
| "Another VM has a running or unresolved change" | Reconnect to that VM and settle its change first. |
| "Target or workflow has an unresolved operation" | Use **Check status** on the pending change; it settles from the VM's own record and never re-runs anything. |

## What never happens automatically

- No fix runs without its own exact approval and confirmation.
- No failed or uncertain change is retried.
- The VM is never rebooted without an approved reboot.
- The development laptop is never hardened.
- Credentials are never stored.
