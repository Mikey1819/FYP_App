"""The runner's restore operation (recovery.restore.v1) of an applied request to its exact before-state.

Since task 8 (administrator, 12 November 2026) the host no longer plans, approves or dispatches a per-control restore
(as on Windows). The runner on the server keeps the family unchanged, so no new setup is needed; these tests build a
TEST-ONLY host spec for it and check the runner still refuses anything but an exact restore. TEST-ONLY families."""
from datetime import timedelta
import json
import unittest
from tests.integration.runner_fixture import sha
from tests.integration.test_ubuntu_runner import Fixture, NOW


def restore_spec():
    """TEST-ONLY: the host spec the program used before task 8, to reach the runner's restore family directly."""
    from backends.ubuntu.actions import ActionSpec
    from backends.ubuntu.catalogue import EXPECTED_IDS
    from vm.ubuntu.family_restore import ACTION_ID, IMPLEMENTATION_SHA256, validate_params
    return ActionSpec(ACTION_ID, 1, IMPLEMENTATION_SHA256, tuple(sorted(EXPECTED_IDS)), validate_params, 60,
                      title='TEST-ONLY restore', recovery={'kind': 'manual_console', 'scope': ['VM console']})


class RestoreFixture(Fixture):
    def applied(self):
        original = self.approved()
        self.assertEqual(json.loads(self.runner().execute(original.raw))['outcome'], 'applied')
        return original

    def restore_request(self, original, runner=None):
        from backends.ubuntu.actions import plan_action
        from backends.ubuntu.approvals import approve
        from datetime import datetime
        runner = runner or self.runner(clock=lambda: NOW + timedelta(minutes=2))
        params = {'restores_request_id': original.request['request_id'], 'restores_request_sha256': original.sha256}
        preview = runner.preview('recovery.restore.v1', params)
        if 'refused' in preview:  # since 2026-11-13 an ineligible restore says why instead of failing silently
            raise ValueError(preview['refused'])
        r = original.request
        spec = restore_spec()
        plan = plan_action(spec, families={spec.action_id: spec}, parameters=params,
                           **{k: r[k] for k in ('target_id', 'registration_epoch', 'hostname', 'machine_id',
                                                'workflow_session_id', 'round_id', 'evidence_sha256', 'control_id',
                                                'predicate_id')},
                           before_state_sha256=preview['before_state_sha256'],
                           expected_after_sha256=preview['expected_after_sha256'],
                           before_state_collected_at=preview['collected_at'],
                           recovery={'kind': 'manual_console', 'scope': ['VM console and recovery snapshot']},
                           job_deadline_seconds=60)
        return preview, approve(plan, 'fixture-operator', datetime.fromisoformat(preview['collected_at']) + timedelta(seconds=1))


class RestoreTests(RestoreFixture):
    def test_restore_returns_exact_before_state_once(self):
        original = self.applied()
        self.assertEqual((self.work / 'alpha').read_bytes(), b'new')
        preview, restore = self.restore_request(original)
        self.assertEqual(preview['expected_after_sha256'], sha(b'old'))
        self.assertEqual(preview['summary']['restores_action_id'], self.family.action_id)
        runner = self.runner(clock=lambda: NOW + timedelta(minutes=3))
        self.assertEqual(json.loads(runner.execute(restore.raw))['outcome'], 'applied')
        self.assertEqual((self.work / 'alpha').read_bytes(), b'old')
        self.assertEqual(json.loads(runner.execute(restore.raw))['code'], 'already_claimed')

    def test_a_newer_change_since_the_fix_is_never_overwritten(self):
        original = self.applied()
        preview, restore = self.restore_request(original)
        (self.work / 'alpha').write_bytes(b'newer change by someone else')
        runner = self.runner(clock=lambda: NOW + timedelta(minutes=3))
        self.assertIn(json.loads(runner.execute(restore.raw))['code'], ('stale_read_set', 'not_eligible'))
        self.assertEqual((self.work / 'alpha').read_bytes(), b'newer change by someone else')
        with self.assertRaises(ValueError):self.restore_request(original)

    def test_only_an_applied_request_with_its_exact_bytes_can_be_restored(self):
        refused = self.approved(value='zzz')
        (self.work / 'alpha').write_bytes(b'moved on')
        self.assertEqual(json.loads(self.runner().execute(refused.raw))['outcome'], 'refused')  # never claimed
        with self.assertRaises((ValueError, OSError)):self.restore_request(refused)
        original = self.approved(value='new')
        self.runner().execute(original.raw)
        runner = self.runner(clock=lambda: NOW + timedelta(minutes=2))
        params = {'restores_request_id': original.request['request_id'], 'restores_request_sha256': 'f' * 64}
        # Other bytes than the applied request: not eligible, and since 2026-11-13 the preview says so (no plan).
        refused = runner.preview('recovery.restore.v1', params)
        self.assertIn('refused', refused)
        self.assertNotIn('before_state_sha256', refused)
        with self.assertRaises(ValueError):runner.preview('recovery.restore.v1', dict(params, extra=1))


class SysctlRestoreTests(unittest.TestCase):
    def test_restore_removes_a_new_managed_file_and_resets_runtime(self):
        from tests.integration.test_ubuntu_sysctl_family import FakeSystem, ASLR, MANAGED
        from vm.ubuntu.family_sysctl import SysctlFamily
        system = FakeSystem()
        family = SysctlFamily('1.5.1', system)
        before = family.read_state(ASLR)
        family.apply(ASLR)
        self.assertIn(MANAGED, system.files)
        family.restore(ASLR, before)
        self.assertNotIn(MANAGED, system.files)
        self.assertEqual(system.runtime_values['kernel.randomize_va_space'], 0)
        self.assertEqual(family.read_state(ASLR), before)
