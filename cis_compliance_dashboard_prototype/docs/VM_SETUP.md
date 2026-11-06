# Integration launch and target readiness

Run from the existing `cis_compliance_dashboard_prototype` directory:

```powershell
..\.venv-integration\Scripts\python.exe -m streamlit run app.py
```

This launches the original entry point with the additive integration environment. It uses isolated development stores under this app's `data/windows`, `data/ubuntu`, and `data/integration.sqlite3`. It does not select original live databases through `CIS_DASHBOARD_DB`. The original dependency file and existing environments are unchanged; tested integration dependencies are in the overlay and complete freeze lock. Python 3.13 is the tested host runtime; target helper source uses Python 3.10-compatible syntax.

Open the existing Agentic hardening page. Enter expected hostname, machine identity, host, port, username and password. Auto discovery probes only that endpoint without credentials. Advanced settings contain explicit transport, selected SSH key and independently verified host fingerprint. A verified connection does not start a scan. Passwords belong only in the application and are cleared from widgets after connection/failure.

On the Ubuntu console, obtain public identity facts with:

```sh
hostname
cat /etc/machine-id
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

The supplied target is `192.168.56.10:22`, `FYP-Ubuntu2204`, user `vboxuser`, machine ID `f1d16ae7e6bc4d2488f9410fcd858e36`. The supplied fingerprint is `SHA256:0qRovBYoeBMmpWGuLeFoEH3ZVngOgajNPorDT7CUUms`. A bounded SSH handshake matched that key without authenticating. Authenticated OS, privilege, package, firewall and helper inspection is still outstanding; these details are not inferred from the banner or hostname.

At this checkpoint Ubuntu connects and displays explicit setup limitations. Ubuntu scan and mutation buttons remain disabled while collector/source acceptance is incomplete. The source contains predicate/parser/evidence fixtures, not an installed helper. Do not copy helper files into a privileged location or grant sudo access as an implicit part of connecting. A concrete root-owned helper installation preview and separate setup approval must precede installation.

Live Windows mutation is also disabled pending the full coordination gate. Local fixtures may exercise the unchanged original executor. The app must not claim those tests changed a real VM.

Changed SSH keys, cloned machine identities or registration conflicts are refused. Deliberate re-enrolment and recovery workflows remain outstanding; editing a fingerprint cannot bypass the existing registration. No snapshot or console-recovery availability has been assumed.

## Proposed read-only collector provisioning (preview only — NOT performed, needs explicit approval)

Prepared 6 November 2026 for `FYP-Ubuntu2204` (`192.168.56.10:22`, machine ID `f1d16ae7e6bc4d2488f9410fcd858e36`). Nothing below has been run. It changes the VM, so it needs a recovery snapshot (or confirmed console access) and your exact approval first.

**Read-only prerequisite checks first.** These are the existing fixed probes, run after an authenticated connection: `python3 --version` (expect 3.10.x), `oscap --version`, and the helper `stat`. If `oscap` is missing, installing the `libopenscap8` package is a separate package change needing its own approval. A scan never installs it.

| Item | Path | Owner / mode | Content |
| --- | --- | --- | --- |
| Helper directory | `/usr/local/libexec/fyp-hardening/` | root:root 0755 | — |
| Helper package | `/usr/local/libexec/fyp-hardening/fyp_ubuntu/` | root:root 0755; files 0644 | exact bytes of `vm/ubuntu/*.py` (`__init__`, `cli`, `collection`, `collector`, `evidence_schema`, `inventory`, `probes`, `provenance`, `scap_results`, `spec`) |
| Launcher | `/usr/local/libexec/fyp-hardening/collect` | root:root 0755 | exact bytes of `vm/ubuntu/collect` |
| Pinned datastream | `/usr/local/share/fyp-hardening/ssg-ubuntu2204-ds.xml` | root:root 0644 | `catalogues/vendor/ssg-ubuntu2204-ds.xml`, SHA-256 `c8be1aa2…ca67` |
| Scan scratch root | `/var/lib/fyp-hardening/scans/` | root:root 0700 | empty; each scan makes and then removes its own request directory |
| Sudo rule | `/etc/sudoers.d/fyp-hardening-collect` | root:root 0440, checked with `visudo -cf` before install | `vboxuser ALL=(root) NOPASSWD: /usr/local/libexec/fyp-hardening/collect ""` (that one command, no arguments) |

- **Provenance check:** the host recomputes the helper-bundle digest from its own copy on every scan. Any byte difference in the installed copy makes the evidence rejected.
- **Effect on sudo assessment:** the sudo rule contains no `Defaults` line, so it does not change the 5.2.2/5.2.3 assessment. Being under `/etc/sudoers.d`, it is visible to that parser.
- **Impact:** the only change is these files plus one sudo permission for one fixed read-only command. No service, package, firewall, SSH or PAM change.
- **Recovery:** remove the sudo file first (re-check with `visudo -c`), then the three directories. A snapshot restore also works, but restoring needs explicit epoch renewal in the app.
- **Still required after provisioning:**
  - human source/site-policy review;
  - recording the observed `oscap` version in `catalogues/source-lock.json` and setting activation, which needs a separate review;
  - a reviewed UFW ownership registration, if 4.1.4/4.1.7 should be determinate.

  Until all of these are done, **Assess without AI** stays disabled for Ubuntu.
