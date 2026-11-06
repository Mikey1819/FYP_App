"""GRUB audit=1 family for CIS 6.3.1.3 (p.757): a grub.d drop-in plus update-grub; never reboots. IN-MEMORY model."""
import json
import re
import unittest

DEFAULT = b'GRUB_DEFAULT=0\nGRUB_CMDLINE_LINUX_DEFAULT="quiet splash"\nGRUB_CMDLINE_LINUX=""\n'
NAME = '60-fyp-hardening-cis.cfg'


class FakeGrub:
    """update-grub sources /etc/default/grub, then grub.d/*.cfg in order; every entry gets GRUB_CMDLINE_LINUX."""
    def __init__(self, default=DEFAULT, dropins=None, entries=2, available=True, update_fails=False):
        self.default, self.dropins, self.count = default, dict(dropins or {}), entries
        self.available, self.update_fails, self.calls = available, update_fails, []
        self.cfg = self._generate()

    def _cmdline(self):
        value = ''
        for text in [self.default] + [d for _, d in sorted(self.dropins.items())]:
            for line in text.decode().splitlines():
                match = re.fullmatch(r'GRUB_CMDLINE_LINUX="(.*)"', line.strip())
                if match:
                    value = match.group(1).replace('$GRUB_CMDLINE_LINUX', value).strip()
        return value

    def _generate(self):
        audit = [a for a in self._cmdline().split() if a.startswith('audit=')]
        return [list(audit) or ['audit=missing'] for _ in range(self.count)]

    def grub_sources(self):
        return {'available': self.available, 'default': self.default, 'dropins': sorted(self.dropins.items())}

    def grub_entries(self):
        return [list(e) for e in self.cfg]

    def write_grub_dropin(self, content):
        if self.update_fails:
            raise OSError('update-grub failed; the drop-in was removed and the configuration regenerated')
        self.calls.append('write' if content is not None else 'remove')
        if content is None:
            self.dropins.pop(NAME, None)
        else:
            self.dropins[NAME] = content
        self.cfg = self._generate()


class GrubAuditTests(unittest.TestCase):
    PARAMS = {'kernel_argument': 'audit=1'}

    def family(self, system):
        from vm.ubuntu.family_grub import GrubAuditFamily
        return GrubAuditFamily(system)

    def cycle(self, system):
        family = self.family(system)
        family.validate(self.PARAMS)
        family.check_eligible(self.PARAMS)
        before = family.read_state(self.PARAMS)
        expected = family.expected_after(self.PARAMS, before)
        family.apply(self.PARAMS)
        self.assertEqual(family.read_state(self.PARAMS), expected)
        return family, before

    def test_drop_in_puts_audit_1_on_every_entry_and_restore_regenerates(self):
        from backends.ubuntu.predicates import evaluate
        from tests.integration.ubuntu_fixtures import observation
        system = FakeGrub()
        family, before = self.cycle(system)
        self.assertEqual(system.default, DEFAULT)  # /etc/default/grub is never edited
        self.assertEqual(system.grub_entries(), [['audit=1'], ['audit=1']])
        facts = {'bootloader': observation('grub2'), 'boot_entries': observation(system.grub_entries()),
                 'current_audit_argument': observation('audit=missing')}
        self.assertEqual(evaluate('6.3.1.3', facts).status.value, 'Compliant')
        summary = family.summary(self.PARAMS, before)
        self.assertIn('reboot', json.dumps(summary).lower())
        family.restore(self.PARAMS, before)
        self.assertEqual((family.read_state(self.PARAMS), NAME in system.dropins), (before, False))

    def test_conflicting_or_unmodelled_boot_configuration_is_refused(self):
        for system in (FakeGrub(default=DEFAULT.replace(b'GRUB_CMDLINE_LINUX=""', b'GRUB_CMDLINE_LINUX="audit=0"')),
                       FakeGrub(dropins={'90-later.cfg': b'GRUB_CMDLINE_LINUX="console=ttyS0"\n'}),
                       FakeGrub(dropins={'10-x.cfg': b'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT audit=0"\n'}),
                       FakeGrub(available=False), FakeGrub(entries=0),
                       FakeGrub(default=DEFAULT.replace(b'GRUB_CMDLINE_LINUX=""', b'GRUB_CMDLINE_LINUX="audit=1"')),
                       FakeGrub(dropins={NAME: b'GRUB_CMDLINE_LINUX="x"\n'})):
            with self.subTest(default=system.default[-40:], dropins=sorted(system.dropins)), self.assertRaises(ValueError):
                self.family(system).check_eligible(self.PARAMS)
        # A later drop-in that appends keeps ours in effect.
        self.cycle(FakeGrub(dropins={'90-later.cfg': b'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX console=ttyS0"\n'}))

    def test_supervised_job_and_failed_update(self):
        family = self.family(FakeGrub())
        self.assertEqual((family.supervision, family.max_seconds), ('job', 300))
        with self.assertRaises(ValueError):family.validate({'kernel_argument': 'audit=0'})
        with self.assertRaises(OSError):self.family(FakeGrub(update_fails=True)).apply(self.PARAMS)

    def test_registry_agrees_and_planner_needs_grub2_entries(self):
        from backends.ubuntu.actions import FAMILIES
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_risk import evidence
        from tests.integration.ubuntu_fixtures import cases, observation, FAILURES
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        target, spec = build(FakeCoreSystem())['ubuntu.6.3.1.3.v1'], FAMILIES['ubuntu.6.3.1.3.v1']
        self.assertEqual((spec.version, spec.implementation_sha256), (target.version, target.implementation_sha256))
        ev = evidence(['6.3.1.3'])
        obs = cases()
        key, value = FAILURES['6.3.1.3']
        obs['6.3.1.3'][key] = observation(value)
        ev.raw = json.dumps({'observations': obs}).encode()
        self.assertEqual(spec.propose('6.3.1.3', ev), self.PARAMS)
        obs['6.3.1.3']['bootloader'] = {'state': 'missing', 'value': None}
        ev.raw = json.dumps({'observations': obs}).encode()
        self.assertIsNone(spec.propose('6.3.1.3', ev))
