"""Maintenance operations, target side: apt metadata refresh and approved reboot with boot-ID proof. IN-MEMORY fakes."""
import json
import tempfile
import unittest
from pathlib import Path
from tests.integration.test_ubuntu_supervision import FakeLauncher

NONCE, STAGED = 'd' * 32, ['e' * 32]


class FakeMaintenance:
    def __init__(self, sources=b'deb http://archive.ubuntu.com/ubuntu jammy main\n', update_ok=True):
        self.sources, self.update_ok, self.boot, self.stamps, self.calls = sources, update_ok, 'boot-1', {}, []

    def apt_sources_digest(self):
        import hashlib
        return hashlib.sha256(self.sources).hexdigest()

    def apt_update(self):
        self.calls.append('apt-get update')
        if not self.update_ok:
            raise OSError('apt-get update failed')

    def boot_id(self):
        return self.boot

    def read_stamp(self, name):
        return self.stamps.get(name)

    def write_stamp(self, name, content):
        self.stamps[name] = content

    def schedule_reboot(self, seconds):
        self.calls.append(('reboot in', seconds))


class AptRefreshTests(unittest.TestCase):
    PARAMS = {'nonce': NONCE}

    def family(self, system):
        from vm.ubuntu.family_maintenance import AptRefreshFamily
        return AptRefreshFamily(system)

    def test_successful_update_writes_the_stamp_and_binds_the_sources(self):
        system = FakeMaintenance()
        family = self.family(system)
        family.validate(self.PARAMS)
        before = family.read_state(self.PARAMS)
        expected = family.expected_after(self.PARAMS, before)
        family.apply(self.PARAMS)
        self.assertEqual(family.read_state(self.PARAMS), expected)
        self.assertEqual(json.loads(before)['repository_digest'], system.apt_sources_digest())
        self.assertEqual((family.action_id, family.supervision), ('maintenance.apt_refresh.v1', 'job'))
        system.sources += b'deb http://elsewhere jammy main\n'  # changed sources: a different before-state digest
        self.assertNotEqual(family.read_state(self.PARAMS), before)

    def test_failed_update_writes_no_stamp_and_restore_is_refused(self):
        system = FakeMaintenance(update_ok=False)
        family = self.family(system)
        with self.assertRaises(OSError):family.apply(self.PARAMS)
        self.assertEqual(system.stamps, {})
        with self.assertRaisesRegex(ValueError, 'no configuration'):family.restore(self.PARAMS, b'{}')
        for bad in ({}, {'nonce': 'x'}, {'nonce': NONCE, 'extra': 1}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):family.validate(bad)


class RebootTests(unittest.TestCase):
    PARAMS = {'nonce': NONCE, 'staged_request_ids': STAGED, 'maintenance_window': 'now'}

    def family(self, system):
        from vm.ubuntu.family_maintenance import RebootFamily
        return RebootFamily(system)

    def test_after_state_is_reached_only_on_a_new_boot(self):
        system = FakeMaintenance()
        family = self.family(system)
        family.validate(self.PARAMS)
        before = family.read_state(self.PARAMS)
        expected = family.expected_after(self.PARAMS, before)
        family.apply(self.PARAMS)
        self.assertIn(('reboot in', 60), system.calls)
        self.assertNotEqual(family.read_state(self.PARAMS), expected)  # scheduled, same boot: not yet
        system.boot = 'boot-2'
        self.assertEqual(family.read_state(self.PARAMS), expected)
        self.assertTrue(family.completes_after_reboot)
        with self.assertRaises(ValueError):family.restore(self.PARAMS, before)

    def test_parameters_are_bounded(self):
        family = self.family(FakeMaintenance())
        for bad in (dict(self.PARAMS, maintenance_window='03:00'), dict(self.PARAMS, staged_request_ids=[]),
                    dict(self.PARAMS, staged_request_ids=['e' * 32, 'e' * 32]), dict(self.PARAMS, staged_request_ids=['x'])):
            with self.subTest(bad=bad), self.assertRaises(ValueError):family.validate(bad)


class RebootRunnerTests(unittest.TestCase):
    """The runner holds a reboot as `awaiting_reboot` and settles it only when the boot ID changed."""

    def test_job_waits_for_the_new_boot_then_settles_applied(self):
        from vm.ubuntu.family_maintenance import RebootFamily
        from vm.ubuntu.runner import Runner
        from tests.integration.test_ubuntu_runner import Fixture
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        system, launcher = FakeMaintenance(), FakeLauncher()
        family = RebootFamily(system)
        runner = Runner(Path(folder.name), {family.action_id: family}, lambda: ('a' * 32, 'ubuntu-fixture'),
                        require_root_owned=False, launcher=launcher)
        rid = 'f' * 32
        directory = Path(folder.name) / 'requests' / rid
        directory.mkdir(parents=True)
        from vm.ubuntu.remediation_schema import canonical
        (directory / 'request.json').write_bytes(canonical(request_doc(rid, family, runner, self.PARAMS_SAFE)))
        (directory / 'claim').write_text(runner._stamp(), encoding='ascii')
        (directory / 'job').write_text('job', encoding='ascii')
        (directory / 'before_state').write_bytes(family.read_state(self.PARAMS_SAFE))
        (Path(folder.name) / 'active').write_text(rid, encoding='ascii')
        launcher.active.add(rid)
        runner.run_job(rid)
        launcher.active.discard(rid)
        self.assertEqual(json.loads(runner.reconcile(rid))['code'], 'awaiting_reboot')
        self.assertTrue((Path(folder.name) / 'active').exists())  # the lock is held until the new boot
        system.boot = 'boot-2'
        settled = json.loads(runner.reconcile(rid))
        self.assertEqual((settled['outcome'], settled['code']), ('applied', 'rebooted'))
        self.assertFalse((Path(folder.name) / 'active').exists())

    PARAMS_SAFE = {'nonce': NONCE, 'staged_request_ids': STAGED, 'maintenance_window': 'now'}


def request_doc(rid, family, runner, params):
    """A minimal valid request for the stored-request path (the runner parses it when loading the job)."""
    import hashlib
    from datetime import datetime, timedelta, timezone
    before = family.read_state(params)
    now = datetime.now(timezone.utc)
    return dict(namespace='ubuntu-remediation', schema_version=1, request_id=rid, proposal_id='1' * 32, platform='ubuntu',
                target_id='ubuntu:fixture', registration_epoch='epoch', hostname='ubuntu-fixture', machine_id='a' * 32,
                workflow_session_id='2' * 32, round_id='3' * 32, evidence_sha256='4' * 64,
                catalogue_version='ubuntu2204-cis2-selected30-v1', control_id='maintenance',
                predicate_id='ubuntu.maintenance.predicate.v1',
                action={'action_id': family.action_id, 'version': family.version,
                        'implementation_sha256': family.implementation_sha256},
                parameters=params, before_state_sha256=hashlib.sha256(before).hexdigest(),
                expected_after_sha256=hashlib.sha256(family.expected_after(params, before)).hexdigest(),
                before_state_collected_at=now.isoformat(), approver='fixture-operator', approved_at=now.isoformat(),
                expires_at=(now + timedelta(minutes=30)).isoformat(), job_deadline_seconds=60,
                recovery={'kind': 'manual_console', 'scope': ['VM console']})


class RegistryTests(unittest.TestCase):
    def test_both_operations_are_registered_on_the_target_and_as_host_auxiliaries(self):
        from backends.ubuntu.actions import AUXILIARY
        from vm.ubuntu.families import build
        from vm.ubuntu.remediation_schema import CONTROL_IDS
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        target = build(FakeCoreSystem())
        for action in ('maintenance.apt_refresh.v1', 'maintenance.reboot.v1'):
            self.assertEqual((AUXILIARY[action].version, AUXILIARY[action].implementation_sha256),
                             (target[action].version, target[action].implementation_sha256))
        self.assertIn('maintenance', CONTROL_IDS)
