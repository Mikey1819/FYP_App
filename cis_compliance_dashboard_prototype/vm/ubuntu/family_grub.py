"""GRUB `audit=1` family for CIS 6.3.1.3. Python 3.10, stdlib only.

CIS: add audit=1 to GRUB_CMDLINE_LINUX in /etc/default/grub, then `update-grub`. Here the same variable is extended
through Ubuntu's sourced drop-in directory instead, so /etc/default/grub is never edited:
/etc/default/grub.d/60-fyp-hardening-cis.cfg holds `GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX audit=1"`.
Refused when any source sets audit=0, a later drop-in replaces GRUB_CMDLINE_LINUX without keeping its value, GRUB
is not the generator, there are no boot entries, or every entry already has audit=1. Runs as a supervised job
(update-grub can be slow); a failed update-grub removes the drop-in and regenerates. The VM is never rebooted:
the generated boot entries comply at once, and the running kernel audits early processes from the next boot.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
from .family_sysctl import HEADER

DROPIN = '/etc/default/grub.d/60-fyp-hardening-cis.cfg'
NAME = DROPIN.rsplit('/', 1)[1]
CONTENT = HEADER + b'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX audit=1"\n'
PARAMS = {'kernel_argument': 'audit=1'}
_ASSIGN = re.compile(r'^\s*(?:export\s+)?GRUB_CMDLINE_LINUX=(.*)$')
_HERE = Path(__file__).resolve().parent
IMPLEMENTATION_SHA256 = hashlib.sha256((_HERE / 'family_grub.py').read_bytes()).hexdigest()


def parse_entries(text):
    """The collector's reading of grub.cfg: the audit= arguments of each linux line."""
    entries = []
    for line in text.splitlines():
        tokens = shlex.split(line, comments=True)
        if tokens and tokens[0] in ('linux', 'linuxefi'):
            entries.append([arg if arg in ('audit=0', 'audit=1') else 'audit=other'
                            for arg in tokens[2:] if arg.startswith('audit=')] or ['audit=missing'])
    return entries


def _dump(state):
    return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')


class GrubAuditFamily:
    action_id = 'ubuntu.6.3.1.3.v1'
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 300
    supervision = 'job'

    def __init__(self, system):
        self.system = system

    def validate(self, params):
        if type(params) is not dict or params != PARAMS:
            raise ValueError('Only audit=1 is managed')

    def _dropin(self, sources):
        data = dict(sources['dropins']).get(NAME)
        if data is not None and not data.startswith(HEADER):
            raise ValueError('The managed GRUB drop-in holds content this family did not write')
        return data

    def read_state(self, params):
        dropin = self._dropin(self.system.grub_sources())
        return _dump({'dropin': dropin.decode('utf-8') if dropin is not None else None,
                      'entries': self.system.grub_entries()})

    def expected_after(self, params, before):
        state = json.loads(before)
        state['dropin'] = CONTENT.decode('utf-8')
        state['entries'] = [[a for a in entry if a != 'audit=missing'] + ['audit=1'] for entry in state['entries']]
        return _dump(state)

    def check_eligible(self, params):
        sources = self.system.grub_sources()
        if not sources['available']:
            raise ValueError('GRUB (update-grub and grub.cfg) is not the boot configuration generator')
        self._dropin(sources)
        texts = [('', sources['default'])] + [(n, d) for n, d in sources['dropins'] if n != NAME]
        for name, data in texts:
            text = data.decode('utf-8')
            if 'audit=0' in text:
                raise ValueError('A GRUB source disables auditing (audit=0); resolve it by hand')
            if name > NAME:
                for line in text.splitlines():
                    match = _ASSIGN.match(line.split('#', 1)[0])
                    if match and '$GRUB_CMDLINE_LINUX' not in match.group(1) and '${GRUB_CMDLINE_LINUX}' not in match.group(1):
                        raise ValueError('A later GRUB drop-in replaces GRUB_CMDLINE_LINUX and would drop audit=1')
        entries = self.system.grub_entries()
        if not entries:
            raise ValueError('grub.cfg has no boot entries')
        if all('audit=1' in entry and 'audit=0' not in entry for entry in entries):
            raise ValueError('Every boot entry already has audit=1')

    def summary(self, params, before):
        return {'dropin': DROPIN, 'line': CONTENT[len(HEADER):].decode('ascii').strip(),
                'regenerate': 'update-grub', 'entries': len(json.loads(before)['entries']),
                'reboot': 'Not performed. The boot entries comply at once; early-process auditing starts at the next '
                          'reboot, which stays the administrator’s decision.'}

    def apply(self, params):
        self.system.write_grub_dropin(CONTENT)

    def restore(self, params, before):
        dropin = json.loads(before)['dropin']
        self.system.write_grub_dropin(dropin.encode('utf-8') if dropin is not None else None)


class LinuxGrubIO:
    """Mixin: bounded reads of GRUB sources and grub.cfg; writes only the managed drop-in, then `update-grub`."""

    def grub_sources(self):
        available = Path('/usr/sbin/update-grub').exists() and Path('/boot/grub/grub.cfg').exists()
        default = self.io._bytes(Path('/etc/default/grub'), 1024 * 1024) if Path('/etc/default/grub').exists() else b''
        folder, dropins = Path('/etc/default/grub.d'), []
        if folder.is_dir():
            for path in sorted(folder.glob('*.cfg'))[:256]:
                dropins.append((path.name, self.io._bytes(path, 1024 * 1024)))
        return {'available': available, 'default': default, 'dropins': dropins}

    def grub_entries(self):
        return parse_entries(self.io._bytes(Path('/boot/grub/grub.cfg'), 4 * 1024 * 1024).decode('utf-8'))

    def _put_dropin(self, content):
        target = Path(DROPIN)
        if target.is_symlink() or target.parent.is_symlink():
            raise ValueError('Managed files must not be symlinks')
        if content is None:
            if target.exists():
                target.unlink()
            return
        target.parent.mkdir(mode=0o755, exist_ok=True)
        tmp = target.with_name('.' + NAME + '.tmp')  # not *.cfg: never sourced
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o644)
        try:
            os.write(fd, content)
            os.fchmod(fd, 0o644)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, target)

    def write_grub_dropin(self, content):
        target = Path(DROPIN)
        previous = target.read_bytes() if target.exists() and not target.is_symlink() else None
        self._put_dropin(content)
        if self.io._run(('/usr/sbin/update-grub',), 240).returncode != 0:
            self._put_dropin(previous)
            self.io._run(('/usr/sbin/update-grub',), 240)
            raise OSError('update-grub failed; the previous drop-in was put back and the configuration regenerated')
