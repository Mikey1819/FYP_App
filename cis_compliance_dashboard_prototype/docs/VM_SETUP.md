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
