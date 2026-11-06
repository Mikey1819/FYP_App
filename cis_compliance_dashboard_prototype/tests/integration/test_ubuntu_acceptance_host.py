"""Execution acceptance, host side: deployment probe, the two live scenarios, and the evidence-based execution gate.
TEST-ONLY harness: in-process runner, fake systemd launcher and marker; the VM is never contacted."""
from datetime import datetime, timedelta, timezone
from unittest import mock
from tests.integration.test_ubuntu_acceptance_target import FakeMarker, LauncherProbe
from tests.integration.test_ubuntu_supervised_backend import SupervisedBackendCase


class AcceptanceCase(SupervisedBackendCase):
    def setUp(self):
        super().setUp()
        self.launcher, self.marker = LauncherProbe(), FakeMarker()
        self.vm_offset = timedelta(0)  # how far the simulated VM clock runs ahead of the host

    def runner(self, family=None, *, identity=None, clock=None):
        from vm.ubuntu.family_acceptance import AcceptanceMarkerFamily
        from vm.ubuntu.runner import Runner
        family = family or self.family
        marker = AcceptanceMarkerFamily(self.marker)
        from vm.ubuntu.family_maintenance import AptRefreshFamily, RebootFamily
        from tests.integration.test_ubuntu_maintenance_target import FakeMaintenance
        maintenance = FakeMaintenance()  # a real runner registers every auxiliary the host expects
        return Runner(self.state, {family.action_id: family, marker.action_id: marker,
                       'maintenance.apt_refresh.v1': AptRefreshFamily(maintenance),
                       'maintenance.reboot.v1': RebootFamily(maintenance)},
                      lambda: identity or ('a' * 32, 'ubuntu-fixture'),
                      clock=lambda: datetime.now(timezone.utc) + self.vm_offset,  # the VM's own clock, always
                      require_root_owned=False, launcher=self.launcher)

    def deployed(self):
        backend = self.backend(self.FIX)
        backend.families = {}  # the deployment check covers the host registry it is given, plus auxiliaries
        return backend

    def vm_reports(self, **changes):
        from vm.ubuntu.runner import Runner
        original = Runner.probe
        return mock.patch.object(Runner, 'probe', lambda runner: dict(original(runner), **changes))

    def finish_job(self, rid):
        self.runner().run_job(rid)
        self.launcher.active.discard(rid)

    def reconnect(self, backend, *, at):
        fresh = super().reconnect(backend, at=at)
        fresh.families = {}
        return fresh

    def run_confirm(self, backend):
        run = backend.start_acceptance('c', 'confirm', 'fixture-operator', 'op-a1')
        self.finish_job(run.request_id)
        backend.acceptance_status('c')
        fresh = self.reconnect(backend, at=datetime.now(timezone.utc) + timedelta(seconds=1))
        return run, fresh, fresh.confirm_acceptance('c2', run.request_id)

    def run_rollback(self, backend):
        run = backend.start_acceptance('c', 'rollback', 'fixture-operator', 'op-a2')
        self.finish_job(run.request_id)
        backend.acceptance_status('c')
        self.runner().rollback(run.request_id)  # the rollback timer fires: nobody confirms
        return run, backend.acceptance_status('c')


class DeploymentTests(AcceptanceCase):
    def test_a_runner_that_is_not_deployed_keeps_the_gate_closed(self):
        from backends.ubuntu.adapter import execution_gate
        backend = self.deployed()
        refused = lambda data, **kw: (_ for _ in ()).throw(ValueError('runner refused'))
        with mock.patch.object(type(self.channel), 'invoke_runner', refused):
            status = backend.deployment_status('c')
            self.assertFalse(status.ok)
            self.assertIn('not deployed', ' '.join(status.reasons).lower())
            self.assertTrue(execution_gate(backend))
            with self.assertRaises(ValueError):
                backend.start_acceptance('c', 'confirm', 'fixture-operator', 'op-x')

    def test_a_deployed_runner_without_acceptance_still_keeps_the_gate_closed(self):
        from backends.ubuntu.adapter import execution_gate
        backend = self.deployed()
        status = backend.deployment_status('c')
        self.assertEqual((status.ok, status.reasons), (True, ()))
        reasons = ' '.join(execution_gate(backend)).lower()
        self.assertIn('confirm scenario', reasons)
        self.assertIn('rollback scenario', reasons)

    def test_a_disabled_boot_rollback_or_a_different_helper_fails_the_probe(self):
        backend = self.deployed()
        self.launcher.boot_rollback_state = lambda: 'not-enabled'
        self.assertIn('boot rollback', ' '.join(backend.deployment_status('c').reasons).lower())
        backend = self.deployed()
        self.launcher.boot_rollback_state = lambda: 'enabled'
        with self.vm_reports(collector_digest='f' * 64):  # only the VM side differs
            self.assertIn('helper', ' '.join(backend.deployment_status('c').reasons).lower())


class ScenarioTests(AcceptanceCase):
    def test_confirm_scenario_needs_a_fresh_login_and_is_recorded(self):
        backend = self.deployed()
        run = backend.start_acceptance('c', 'confirm', 'fixture-operator', 'op-a1')
        self.assertEqual(run.state, 'running')
        self.finish_job(run.request_id)
        [item] = backend.acceptance_status('c')
        self.assertEqual((item.scenario, item.code), ('confirm', 'awaiting_confirmation'))
        with self.assertRaisesRegex(ValueError, 'fresh login'):
            backend.confirm_acceptance('c', run.request_id)
        fresh = self.reconnect(backend, at=datetime.now(timezone.utc) + timedelta(seconds=1))
        done = fresh.confirm_acceptance('c2', run.request_id)
        self.assertEqual(done.outcome, 'confirmed')
        self.assertEqual(self.marker.content, 'confirm:' + done.nonce)

    def test_rollback_scenario_is_restored_by_the_timer_and_cannot_be_confirmed(self):
        backend = self.deployed()
        run = backend.start_acceptance('c', 'rollback', 'fixture-operator', 'op-a2')
        self.finish_job(run.request_id)
        backend.acceptance_status('c')
        fresh = self.reconnect(backend, at=datetime.now(timezone.utc) + timedelta(seconds=1))
        with self.assertRaises(ValueError):
            fresh.confirm_acceptance('c2', run.request_id)  # this scenario must prove the rollback path
        self.runner().rollback(run.request_id)
        [item] = backend.acceptance_status('c')
        self.assertEqual(item.outcome, 'rolled_back')
        self.assertIsNone(self.marker.content)

    def test_both_scenarios_open_the_gate_only_for_this_runner(self):
        from backends.ubuntu.adapter import execution_gate
        backend = self.deployed()
        self.run_confirm(backend)
        self.assertTrue(execution_gate(backend))  # one scenario is not enough
        self.run_rollback(backend)
        self.assertEqual(execution_gate(backend), ())
        backend.families = self.backend(self.FIX).families
        self.assertTrue(backend.capabilities('c').can_remediate)
        changed = self.deployed()
        with self.vm_reports(collector_digest='f' * 64), mock.patch('vm.ubuntu.provenance.collector_digest',
                                                                    return_value='f' * 64):
            self.assertTrue(changed.deployment_status('c').ok)  # an updated helper, properly reinstalled
            self.assertTrue(execution_gate(changed))  # ...still needs its own acceptance runs

    def test_an_acceptance_workflow_before_any_scan_does_not_break_the_pending_list(self):
        backend = self.deployed()  # no assessment yet: the Ubuntu store does not exist
        backend.start_acceptance('c', 'confirm', 'fixture-operator', 'op-a1')
        self.assertEqual(backend.pending_supervised('c'), ())

    def test_vm_clock_a_little_ahead_or_behind_still_runs(self):
        # Live 2026-11-07: the VM clock was ~1 s ahead at one moment and >5 s behind at another.
        for offset in (timedelta(seconds=10), timedelta(seconds=-20)):  # -20 s: refused under the old 5 s skew
            with self.subTest(offset=offset):
                self.vm_offset = offset
                backend = self.deployed()
                self.assertEqual(backend.deployment_status('c').reasons, ())
                run = backend.start_acceptance('c', 'confirm', 'fixture-operator', 'op-' + str(offset.seconds))
                self.assertEqual((run.state, run.code), ('running', 'job_started'))
                self.finish_job(run.request_id)
                self.runner().rollback(run.request_id)  # settle it so the next subtest may start
                backend.acceptance_status('c')

    def test_a_large_vm_clock_offset_is_reported_and_keeps_the_gate_closed(self):
        from backends.ubuntu.adapter import execution_gate
        self.vm_offset = timedelta(minutes=7)
        backend = self.deployed()
        status = backend.deployment_status('c')
        self.assertFalse(status.ok)
        self.assertIn('clock', ' '.join(status.reasons).lower())
        self.assertTrue(execution_gate(backend))

    def test_only_one_acceptance_run_at_a_time(self):
        backend = self.deployed()
        backend.start_acceptance('c', 'confirm', 'fixture-operator', 'op-a1')
        with self.assertRaisesRegex(ValueError, 'still open'):
            backend.start_acceptance('c', 'rollback', 'fixture-operator', 'op-a2')
        with self.assertRaises(ValueError):
            backend.start_acceptance('c', 'confirm', '   ', 'op-a3')
