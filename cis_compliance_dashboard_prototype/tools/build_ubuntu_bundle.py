"""Build the hash-checked Ubuntu collector provisioning bundle (the approved docs/VM_SETUP.md preview).

Usage (from the application directory):
    python -B -m tools.build_ubuntu_bundle --machine-id ID --hostname NAME --user ACCOUNT [output_dir]
ID and NAME are the paired server's /etc/machine-id and hostname, as the Servers page shows them (it prints this
command for each saved Ubuntu server); ACCOUNT is the server account the dashboard logs in with. The install scripts
refuse to run on any other machine, so a bundle is built for one server. Nothing is hardcoded for a particular VM.
Default output: ../dist/ubuntu-helper (git-ignored). Building runs nothing on any VM. The administrator copies
the bundle to the VM and runs `sudo bash install.sh` on the console after taking a recovery snapshot.
"""
import argparse
import hashlib
from pathlib import Path
import re
import shutil

APP = Path(__file__).resolve().parents[1]
DEFAULT = APP.parent / 'dist' / 'ubuntu-helper'
# Placeholders, filled in by build() with the checked values of the server the bundle is for.
MACHINE_ID, HOSTNAME, USER = '@MACHINE_ID@', '@HOSTNAME@', '@USER@'
DATASTREAM_SHA256 = 'c8be1aa2bf93284507b8810ea829f8904ab4552865f07d106561d5fd5d06ca67'
SUDOERS = f'{USER} ALL=(root) NOPASSWD: /usr/local/libexec/fyp-hardening/collect ""\n'
# Separately approved runner stage: the fixed runner with no arguments (systemd unit operations need argv and an
# INVOCATION_ID that sudo never passes, so they cannot be reached through this rule).
RUNNER_SUDOERS = f'{USER} ALL=(root) NOPASSWD: /usr/local/libexec/fyp-hardening/runner ""\n'

INSTALL = f'''#!/bin/bash
# FYP hardening read-only collector provisioning. Run on the VM console as: sudo bash install.sh
# Take a VirtualBox recovery snapshot first. Installs files and one sudo rule only: no packages,
# services, firewall, SSH or PAM changes. Reverse with: sudo bash uninstall.sh
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" -eq 0 ] || {{ echo "Run with sudo"; exit 1; }}
[ "$(cat /etc/machine-id)" = "{MACHINE_ID}" ] || {{ echo "Wrong machine identity; nothing changed"; exit 1; }}
[ "$(hostname)" = "{HOSTNAME}" ] || {{ echo "Wrong hostname; nothing changed"; exit 1; }}
case "$(python3 --version 2>&1)" in "Python 3.10."*) ;; *) echo "Python 3.10 required; nothing changed"; exit 1;; esac
sha256sum -c SHA256SUMS --quiet || {{ echo "Bundle hash mismatch; nothing changed"; exit 1; }}
for launcher in collect runner; do
  cmp -s "libexec/$launcher" "libexec/fyp_ubuntu/$launcher" || {{ echo "Launcher copy differs; nothing changed"; exit 1; }}
done
visudo -cf sudoers/fyp-hardening >/dev/null || {{ echo "Sudo rule invalid; nothing changed"; exit 1; }}
[ ! -e /etc/sudoers.d/fyp-hardening ] || {{ echo "Existing /etc/sudoers.d/fyp-hardening; review it first"; exit 1; }}
install -d -o root -g root -m 0755 /usr/local/libexec/fyp-hardening /usr/local/libexec/fyp-hardening/fyp_ubuntu
install -o root -g root -m 0644 libexec/fyp_ubuntu/* /usr/local/libexec/fyp-hardening/fyp_ubuntu/
install -o root -g root -m 0755 libexec/collect libexec/runner /usr/local/libexec/fyp-hardening/
install -d -o root -g root -m 0755 /usr/local/share/fyp-hardening
install -o root -g root -m 0644 share/ssg-ubuntu2204-ds.xml share/fyp-selected-tailoring.xml /usr/local/share/fyp-hardening/
install -d -o root -g root -m 0700 /var/lib/fyp-hardening /var/lib/fyp-hardening/scans /var/lib/fyp-hardening/runner
install -o root -g root -m 0440 sudoers/fyp-hardening /etc/sudoers.d/fyp-hardening
visudo -c >/dev/null || {{ rm -f /etc/sudoers.d/fyp-hardening; echo "Sudo configuration invalid; rule removed"; exit 1; }}
echo "Installed. Report these lines back:"
python3 --version
if command -v oscap >/dev/null; then
  version_output="$(oscap --version)"  # read fully: a closed pipe under pipefail would falsely report failure
  printf '%s\\n' "${{version_output%%$'\\n'*}}"
else
  echo "oscap: not installed (installing it is a separate approval)"
fi
'''

# Shipped hash-checked but NOT installed by install.sh: enabling it belongs to the separately approved runner
# deployment, with the runner sudo rule. Transient rollback timers do not survive a reboot; this oneshot rolls
# back every unconfirmed commit-confirm change at boot, before sshd starts reading its configuration.
BOOT_ROLLBACK_UNIT = '''[Unit]
Description=FYP hardening: roll back unconfirmed commit-confirm changes after a reboot
After=local-fs.target
Before=ssh.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/fyp-hardening/runner boot-rollback

[Install]
WantedBy=multi-user.target
'''

INSTALL_RUNNER = f'''#!/bin/bash
# FYP hardening runner deployment: a SEPARATELY APPROVED stage after install.sh.
# Run on the VM console as: sudo bash install-runner.sh  (take a VirtualBox recovery snapshot first)
# Installs one sudo rule for the fixed runner and enables the boot rollback unit. Changes no system setting
# by itself: every fix still needs its own approval in the dashboard. Reverse with: sudo bash uninstall-runner.sh
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" -eq 0 ] || {{ echo "Run with sudo"; exit 1; }}
[ "$(cat /etc/machine-id)" = "{MACHINE_ID}" ] || {{ echo "Wrong machine identity; nothing changed"; exit 1; }}
[ "$(hostname)" = "{HOSTNAME}" ] || {{ echo "Wrong hostname; nothing changed"; exit 1; }}
sha256sum -c SHA256SUMS --quiet || {{ echo "Bundle hash mismatch; nothing changed"; exit 1; }}
cmp -s libexec/runner /usr/local/libexec/fyp-hardening/runner || {{ echo "Run install.sh from this bundle first; nothing changed"; exit 1; }}
for file in libexec/fyp_ubuntu/*; do
  cmp -s "$file" "/usr/local/libexec/fyp-hardening/fyp_ubuntu/$(basename "$file")" || {{ echo "Installed helper differs from this bundle; run install.sh first; nothing changed"; exit 1; }}
done
command -v systemd-run >/dev/null || {{ echo "systemd-run is missing; nothing changed"; exit 1; }}
visudo -cf sudoers/fyp-hardening-runner >/dev/null || {{ echo "Runner sudo rule invalid; nothing changed"; exit 1; }}
[ ! -e /etc/sudoers.d/fyp-hardening-runner ] || {{ echo "Existing /etc/sudoers.d/fyp-hardening-runner; review it first"; exit 1; }}
install -o root -g root -m 0644 systemd/fyp-hardening-boot-rollback.service /etc/systemd/system/fyp-hardening-boot-rollback.service
systemctl daemon-reload
systemctl enable fyp-hardening-boot-rollback.service
install -o root -g root -m 0440 sudoers/fyp-hardening-runner /etc/sudoers.d/fyp-hardening-runner
visudo -c >/dev/null || {{ rm -f /etc/sudoers.d/fyp-hardening-runner; echo "Sudo configuration invalid; rule removed"; exit 1; }}
echo "Runner deployed. Report these lines back:"
systemctl is-enabled fyp-hardening-boot-rollback.service
ls -l /etc/sudoers.d/fyp-hardening-runner
'''

UNINSTALL_RUNNER = '''#!/bin/bash
# Reverse install-runner.sh: the runner sudo rule first, then the boot rollback unit. Refuses while a change is open.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo"; exit 1; }
[ ! -e /var/lib/fyp-hardening/runner/active ] || { echo "A change is in progress or unresolved; settle it in the dashboard first"; exit 1; }
rm -f /etc/sudoers.d/fyp-hardening-runner
visudo -c >/dev/null
systemctl disable fyp-hardening-boot-rollback.service 2>/dev/null || true
rm -f /etc/systemd/system/fyp-hardening-boot-rollback.service
systemctl daemon-reload
echo "Runner deployment removed."
'''

UNINSTALL = '''#!/bin/bash
# Reverse install.sh (and install-runner.sh): sudo rules first, then the boot unit, then the installed directories.
# A helper reinstall therefore also removes the runner deployment: new runner code needs a new approval.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo"; exit 1; }
[ ! -e /var/lib/fyp-hardening/runner/active ] || { echo "A change is in progress or unresolved; settle it in the dashboard first"; exit 1; }
rm -f /etc/sudoers.d/fyp-hardening-runner /etc/sudoers.d/fyp-hardening
visudo -c >/dev/null
if [ -e /etc/systemd/system/fyp-hardening-boot-rollback.service ]; then
  systemctl disable fyp-hardening-boot-rollback.service 2>/dev/null || true
  rm -f /etc/systemd/system/fyp-hardening-boot-rollback.service
  systemctl daemon-reload
fi
rm -rf /usr/local/libexec/fyp-hardening /usr/local/share/fyp-hardening /var/lib/fyp-hardening
echo "Removed."
'''


def target_values(machine_id, hostname, user):
    """The server the bundle is for, checked so that nothing but these exact words reaches the shell and sudo files."""
    if not re.fullmatch(r'[0-9a-f]{32}', str(machine_id)) or machine_id == '0' * 32:
        raise ValueError('machine id: the 32 lowercase hexadecimal characters of /etc/machine-id')
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,61}[A-Za-z0-9])?', str(hostname)):
        raise ValueError('hostname: letters, digits, dots and hyphens only')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', str(user)):
        raise ValueError('user: a Linux account name (lowercase letters, digits, _ and -)')
    return {MACHINE_ID: machine_id, HOSTNAME: hostname, USER: user}


def _fill(text, values):
    for placeholder, value in values.items():
        text = text.replace(placeholder, value)
    return text


def build(out=DEFAULT, *, machine_id, hostname, user):
    from vm.ubuntu.provenance import HELPER_FILES
    values = target_values(machine_id, hostname, user)
    out = Path(out)
    if out.exists():
        shutil.rmtree(out)
    package = out / 'libexec' / 'fyp_ubuntu'
    package.mkdir(parents=True)
    source = APP / 'vm' / 'ubuntu'
    for name in HELPER_FILES:
        (package / name).write_bytes((source / name).read_bytes())
    for launcher in ('collect', 'runner'):
        (out / 'libexec' / launcher).write_bytes((source / launcher).read_bytes())
    (out / 'share').mkdir()
    datastream = (APP / 'catalogues' / 'vendor' / 'ssg-ubuntu2204-ds.xml').read_bytes()
    if hashlib.sha256(datastream).hexdigest() != DATASTREAM_SHA256:
        raise ValueError('Pinned datastream bytes changed; refusing to build')
    (out / 'share' / 'ssg-ubuntu2204-ds.xml').write_bytes(datastream)
    from backends.ubuntu.scap_tailoring import build_tailoring
    from vm.ubuntu.spec import SCAP_TAILORING_SHA256
    tailoring = build_tailoring()
    if hashlib.sha256(tailoring).hexdigest() != SCAP_TAILORING_SHA256:
        raise ValueError('Generated tailoring differs from the pinned hash; refusing to build')
    (out / 'share' / 'fyp-selected-tailoring.xml').write_bytes(tailoring)
    (out / 'sudoers').mkdir()
    (out / 'sudoers' / 'fyp-hardening').write_bytes(_fill(SUDOERS, values).encode('ascii'))
    (out / 'sudoers' / 'fyp-hardening-runner').write_bytes(_fill(RUNNER_SUDOERS, values).encode('ascii'))
    (out / 'systemd').mkdir()
    (out / 'systemd' / 'fyp-hardening-boot-rollback.service').write_bytes(BOOT_ROLLBACK_UNIT.encode('ascii'))
    (out / 'install.sh').write_bytes(_fill(INSTALL, values).encode('ascii'))
    (out / 'uninstall.sh').write_bytes(_fill(UNINSTALL, values).encode('ascii'))
    (out / 'install-runner.sh').write_bytes(_fill(INSTALL_RUNNER, values).encode('ascii'))
    (out / 'uninstall-runner.sh').write_bytes(_fill(UNINSTALL_RUNNER, values).encode('ascii'))
    scripts = ('install.sh', 'uninstall.sh', 'install-runner.sh', 'uninstall-runner.sh')
    files = sorted(p for p in out.rglob('*') if p.is_file() and p.name not in scripts)
    sums = ''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out).as_posix()}\n' for p in files)
    (out / 'SHA256SUMS').write_bytes(sums.encode('ascii'))
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description='Build the Ubuntu helper bundle for one paired server.')
    parser.add_argument('--machine-id', required=True, help="the server's /etc/machine-id (Servers page)")
    parser.add_argument('--hostname', required=True, help="the server's hostname (Servers page)")
    parser.add_argument('--user', required=True, help='the server account the dashboard logs in with')
    parser.add_argument('output', nargs='?', type=Path, default=DEFAULT)
    args = parser.parse_args(argv)
    try:
        print(build(args.output, machine_id=args.machine_id, hostname=args.hostname, user=args.user))
    except ValueError as exc:
        parser.exit(2, f'Not built: {exc}' + chr(10))


if __name__ == '__main__':
    main()
