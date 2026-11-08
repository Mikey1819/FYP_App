"""Maintenance operations, host side: request -> approve -> dispatch -> status, behind the same gates.
TEST-ONLY: in-process runner with a fake launcher and fake maintenance system; the VM is never contacted."""
import json
from unittest import mock
from tests.integration.test_ubuntu_maintenance_target import FakeMaintenance
from tests.integration.test_ubuntu_proposals import BackendRemediationTests
from tests.integration.test_ubuntu_supervision import FakeLauncher


class MaintenanceCase(BackendRemediationTests):
    def setUp(self):
        super().setUp()
        self.launcher, self.maintenance = FakeLauncher(), FakeMaintenance()

    def runner(self, family=None, *, identity=None, clock=None):
        from vm.ubuntu.family_maintenance import AptRefreshFamily, RebootFamily
        from vm.ubuntu.runner import Runner
        family = family or self.family
        families = {family.action_id: family, 'maintenance.apt_refresh.v1': AptRefreshFamily(self.maintenance),
                    'maintenance.reboot.v1': RebootFamily(self.maintenance)}
        return Runner(self.state, families, lambda: identity or ('a' * 32, 'ubuntu-fixture'), clock=clock or self.clock,
                      require_root_owned=False, launcher=self.launcher)

    def applied_fix(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        backend = self.backend(self.FIX)
        handle, snap = self.round(backend)
        workflow = handle.binding.workflow_session_id
        backend.decide('c', workflow, snap.proposals[0].reference, True, 'fixture-operator', '', 'op-d')
        snap = backend.snapshot('c', workflow)
        rid = snap.proposals[0].approved_request_id
        with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), open_gate():
            backend.execute_approved('c', workflow, snap.current_round_reference, (rid,), True, 'op-exec')
        return backend, workflow, rid

    def approve(self, backend, workflow, ref):
        backend.decide('c', workflow, ref, True, 'fixture-operator', '', 'op-approve-' + ref.record_id[:8])

    def dispatch(self, backend, workflow, ref):
        from tests.integration.test_ubuntu_live_path import open_gate
        with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), open_gate():
            return backend.dispatch_auxiliary('c', workflow, ref, 'op-run-' + ref.record_id[:8])

    def job(self, ref_request_id):
        self.runner().run_job(ref_request_id)
        self.launcher.active.discard(ref_request_id)

    def refresh(self, backend, workflow, round_ref):
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate():
            return backend.refresh_execution('c', workflow, round_ref, 'op-status')


class MetadataRefreshTests(MaintenanceCase):
    def test_refresh_is_proposed_approved_dispatched_and_completed_through_status(self):
        from system.contracts import AuxiliaryKind, MetadataRefreshInput
        backend, workflow, _ = self.applied_fix()
        ref = backend.request_auxiliary('c', workflow, AuxiliaryKind.METADATA_REFRESH, None, MetadataRefreshInput(''),
                                        'op-m')
        rows = {p.reference: p for p in backend.snapshot('c', workflow).proposals}
        self.assertEqual((rows[ref].kind, rows[ref].action_id, rows[ref].eligible_commands),
                         ('metadata_refresh', 'maintenance.apt_refresh.v1', ('approve', 'reject')))
        self.assertIn(self.maintenance.apt_sources_digest(), rows[ref].exact_preview)
        self.approve(backend, workflow, ref)
        handle = self.dispatch(backend, workflow, ref)
        self.assertEqual(handle.state, 'running')
        rid = backend.snapshot('c', workflow).proposals[-1].approved_request_id
        self.job(rid)
        self.assertEqual(self.refresh(backend, workflow, handle.round_reference).state, 'completed')
        self.assertIn('apt-get update', self.maintenance.calls)

    def test_a_different_repository_digest_is_refused(self):
        from system.contracts import AuxiliaryKind, MetadataRefreshInput
        backend, workflow, _ = self.applied_fix()
        with self.assertRaises(ValueError):
            backend.request_auxiliary('c', workflow, AuxiliaryKind.METADATA_REFRESH, None, MetadataRefreshInput('f' * 64),
                                      'op-m')


class RebootTests(MaintenanceCase):
    def test_reboot_needs_applied_changes_then_waits_for_the_new_boot(self):
        from system.contracts import AuxiliaryKind, RebootInput
        backend, workflow, fix_rid = self.applied_fix()
        for staged in ((), ('9' * 32,)):
            with self.subTest(staged=staged), self.assertRaises(ValueError):
                backend.request_auxiliary('c', workflow, AuxiliaryKind.REBOOT, None, RebootInput(staged, 'now'), 'op-r')
        with self.assertRaises(ValueError):
            backend.request_auxiliary('c', workflow, AuxiliaryKind.REBOOT, None, RebootInput((fix_rid,), '03:00'), 'op-r')
        ref = backend.request_auxiliary('c', workflow, AuxiliaryKind.REBOOT, None, RebootInput((fix_rid,), 'now'), 'op-r')
        rows = {p.reference: p for p in backend.snapshot('c', workflow).proposals}
        self.assertEqual(rows[ref].kind, 'reboot')
        self.approve(backend, workflow, ref)
        handle = self.dispatch(backend, workflow, ref)
        rid = backend.snapshot('c', workflow).proposals[-1].approved_request_id
        self.job(rid)
        self.assertIn(('reboot in', 60), self.maintenance.calls)
        self.assertEqual(self.refresh(backend, workflow, handle.round_reference).state, 'running')
        [row] = [r for r in backend.snapshot('c', workflow).results if r.proposal_reference == ref]
        self.assertIn('connect again', row.detail.lower())
        self.maintenance.boot = 'boot-2'  # the VM came back on a new boot
        self.assertEqual(self.refresh(backend, workflow, handle.round_reference).state, 'completed')

    def test_maintenance_never_joins_the_cis_fix_execution_set(self):
        from system.contracts import AuxiliaryKind, MetadataRefreshInput
        backend, workflow, fix_rid = self.applied_fix()
        ref = backend.request_auxiliary('c', workflow, AuxiliaryKind.METADATA_REFRESH, None, MetadataRefreshInput(''),
                                        'op-m')
        self.approve(backend, workflow, ref)
        snap = backend.snapshot('c', workflow)
        with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            # The approved CIS set is still exactly the one fix (already executed: nothing runs again).
            result = backend.execute_approved('c', workflow, snap.current_round_reference, (fix_rid,), True, 'op-x2')
        self.assertEqual(result.state, 'completed')
        self.assertNotIn('apt-get update', self.maintenance.calls)


for _name in [n for n in dir(BackendRemediationTests) if n.startswith('test')]:
    setattr(MaintenanceCase, _name, None)  # only the harness is inherited
del BackendRemediationTests
