"""Build the hash-checked Ubuntu collector provisioning bundle (the approved docs/VM_SETUP.md preview).

Usage (from the application directory): python -B -m tools.build_ubuntu_bundle [output_dir]
Default output: ../dist/ubuntu-helper (git-ignored). Building runs nothing on any VM. The administrator copies
the bundle to the VM and runs `sudo bash install.sh` on the console after taking a recovery snapshot.
"""
import hashlib
from pathlib import Path
import shutil
import sys

APP = Path(__file__).resolve().parents[1]
DEFAULT = APP.parent / 'dist' / 'ubuntu-helper'
MACHINE_ID = 'f1d16ae7e6bc4d2488f9410fcd858e36'
HOSTNAME = 'FYP-Ubuntu2204'
USER = 'vboxuser'
DATASTREAM_SHA256 = 'c8be1aa2bf93284507b8810ea829f8904ab4552865f07d106561d5fd5d06ca67'
SUDOERS = f'{USER} ALL=(root) NOPASSWD: /usr/local/libexec/fyp-hardening/collect ""\n'

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

UNINSTALL = '''#!/bin/bash
# Reverse install.sh: the sudo rule first, then the installed directories.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo"; exit 1; }
rm -f /etc/sudoers.d/fyp-hardening
visudo -c >/dev/null
rm -rf /usr/local/libexec/fyp-hardening /usr/local/share/fyp-hardening /var/lib/fyp-hardening
echo "Removed."
'''


def build(out=DEFAULT):
    from vm.ubuntu.provenance import HELPER_FILES
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
    (out / 'sudoers' / 'fyp-hardening').write_bytes(SUDOERS.encode('ascii'))
    (out / 'systemd').mkdir()
    (out / 'systemd' / 'fyp-hardening-boot-rollback.service').write_bytes(BOOT_ROLLBACK_UNIT.encode('ascii'))
    (out / 'install.sh').write_bytes(INSTALL.encode('ascii'))
    (out / 'uninstall.sh').write_bytes(UNINSTALL.encode('ascii'))
    files = sorted(p for p in out.rglob('*') if p.is_file() and p.name not in ('install.sh', 'uninstall.sh'))
    sums = ''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out).as_posix()}\n' for p in files)
    (out / 'SHA256SUMS').write_bytes(sums.encode('ascii'))
    return out


if __name__ == '__main__':
    print(build(Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT))
