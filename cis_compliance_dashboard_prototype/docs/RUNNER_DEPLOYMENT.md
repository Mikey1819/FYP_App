# Ubuntu runner deployment: preview for approval

This is the concrete, target-bound preview for the **separately approved** runner stage. Nothing here has been run. The administrator runs it on the VM console, after reviewing this page and taking a VirtualBox snapshot.

## Target

| Fact | Value |
|---|---|
| VM | FYP-Ubuntu2204 (VirtualBox) |
| Hostname (checked by the script) | `FYP-Ubuntu2204` |
| Machine ID (checked by the script) | `f1d16ae7e6bc4d2488f9410fcd858e36` |
| Management user | `vboxuser` (SSH from the host-only network) |
| Prerequisite | `install.sh` from the **same** bundle already run (the script compares every installed helper file byte for byte) |

## What `sudo bash install-runner.sh` changes

1. Verifies identity, the bundle hashes (`SHA256SUMS`), that the installed helper is byte-identical to this bundle, and that `systemd-run` exists. Any failure: "nothing changed".
2. Installs `/etc/systemd/system/fyp-hardening-boot-rollback.service` and enables it, **without starting it** (no `--now`). At boot it restores every commit-confirm change that was never confirmed, before `ssh.service` starts.
3. Installs `/etc/sudoers.d/fyp-hardening-runner` (0440, validated with `visudo -cf`, then `visudo -c`; removed again if invalid):
   ```
   vboxuser ALL=(root) NOPASSWD: /usr/local/libexec/fyp-hardening/runner ""
   ```
   The `""` allows the fixed runner with **no arguments** only. The systemd-only operations (`job`, `rollback`, `boot-rollback`) need arguments plus systemd's `INVOCATION_ID`, which sudo removes, so this rule cannot reach them.

It changes **no security setting by itself**: no package, SSH, UFW, PAM, sudo policy (other than the rule above), audit or boot setting.

## What it enables, and what still guards every change

- The dashboard can ask the runner for a read-only **probe** and **preview**, and can dispatch approved requests.
- Fixes stay blocked by the execution gate until the deployed runner matches the application exactly **and** both acceptance scenarios pass on this VM.
- **Acceptance scenarios:** writes only `/var/lib/fyp-hardening/acceptance/marker`.
  - **Confirm scenario:** run, disconnect, reconnect, Confirm within about a minute.
  - **Rollback scenario:** run, do **not** confirm; the timer restores it after about 90 seconds; then Check status.
- After that, each CIS fix still needs its own exact-bytes approval. A named operator approves the exact change, it is shown before it runs, it runs once, and it is verified by a fresh scan. SSH and UFW fixes additionally need a confirmation over a fresh login, or they are rolled back automatically.

## Recovery

- **Undo this stage:** `sudo bash uninstall-runner.sh` removes the sudo rule first, then disables and removes the unit. It refuses while a change is in progress or unresolved (`/var/lib/fyp-hardening/runner/active`).
- **Helper reinstall:** `sudo bash uninstall.sh` now also removes the runner stage, so new runner code always needs a new deployment approval and new acceptance runs. It has the same in-progress refusal.
- **Last resort:** restore the VirtualBox snapshot taken before deployment.

## Steps (administrator, on the VM console)

1. Take a VirtualBox snapshot (for example `Before_Runner_Deployment_<date>`).
2. Reinstall the helper from the current bundle: `sudo bash uninstall.sh`, copy `dist\ubuntu-helper` to the VM, then `sudo bash install.sh`.
3. `sudo bash install-runner.sh` and report the two lines it prints (`enabled` and the `ls -l` of the rule).
4. In the dashboard, reconnect. Then open **Execution acceptance** and run both scenarios.
