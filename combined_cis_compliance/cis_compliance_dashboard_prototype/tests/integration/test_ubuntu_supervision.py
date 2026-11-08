"""systemd-supervised jobs and the commit-confirm rollback watchdog. TEST-ONLY families and a fake launcher; no VM."""
import io
import json
import unittest
from tests.integration.runner_fixture import FileValueFamily
from tests.integration.test_ubuntu_runner import Fixture, NOW


class JobFamily(FileValueFamily):
    supervision = 'job'


class ConfirmFamily(FileValueFamily):
    supervision, confirm_seconds = 'confirm', 300


class FailingConfirmFamily(ConfirmFamily):
    def apply(self, params):
        super().apply(params)
        raise OSError('service failed to restart')


class FakeLauncher:
    """Stands in for systemd-run/systemctl. `active` is what `systemctl is-active` would report."""
    def __init__(self, fail=()):
        self.calls, self.active, self.fail = [], set(), set(fail)

    def _call(self, name, *args):
        if name in self.fail:
            raise OSError(name + ' failed')
        self.calls.append((name,) + args)

    def arm_rollback(self, rid, seconds):
        self._call('arm_rollback', rid, seconds)

    def start_job(self, rid, seconds):
        self._call('start_job', rid, seconds); self.active.add(rid)

    def job_active(self, rid):
        return rid in self.active

    def stop_job(self, rid):
        self._call('stop_job', rid); self.active.discard(rid)

    def disarm_rollback(self, rid):
        self._call('disarm_rollback', rid)


def outcome(raw):
    doc = json.loads(raw)
    return doc['outcome'], doc['code']


class SupervisionCase(Fixture):
    FAMILY = JobFamily

    def setUp(self):
        super().setUp()
        self.family, self.launcher = self.FAMILY(self.work), FakeLauncher()

    def supervised(self, family=None):
        from vm.ubuntu.runner import Runner
        from datetime import timedelta
        family = family or self.family
        return Runner(self.state, {family.action_id: family}, lambda: ('a' * 32, 'ubuntu-fixture'),
                      clock=lambda: NOW + timedelta(minutes=1), require_root_owned=False, launcher=self.launcher)

    def start(self, family=None):
        a = self.approved()
        runner = self.supervised(family)
        return a, runner, runner.execute(a.raw)

    def job(self, runner, rid):
        """systemd starting the unit, the job running to its end, and the unit going inactive."""
        runner.run_job(rid)
        self.launcher.active.discard(rid)

    def value(self):
        return (self.work / 'alpha').read_bytes()


class JobTests(SupervisionCase):
    def test_execute_detaches_the_write_into_a_bounded_unit_and_status_follows_it(self):
        a, runner, first = self.start()
        rid = a.request['request_id']
        self.assertEqual(outcome(first), ('running', 'job_started'))
        self.assertEqual(self.launcher.calls, [('start_job', rid, 60)])  # RuntimeMaxSec = family max_seconds
        self.assertEqual((self.value(), self.writes()), (b'old', []))  # nothing written in the SSH session
        self.assertTrue((self.state / 'active').exists())
        self.assertEqual(outcome(runner.reconcile(rid)), ('running', 'job_running'))
        self.job(runner, rid)
        self.assertEqual(outcome(runner.reconcile(rid)), ('applied', 'expected_after_state'))
        self.assertFalse((self.state / 'active').exists())
        runner.run_job(rid)  # a duplicate start never writes twice
        self.assertEqual(self.writes(), ['alpha'])
        self.assertEqual(outcome(runner.execute(a.raw)), ('refused', 'already_claimed'))

    def test_a_job_that_died_without_a_receipt_is_reconciled_from_state_never_replayed(self):
        a, runner, _ = self.start()
        rid = a.request['request_id']
        self.launcher.active.discard(rid)  # the unit ended without ever writing
        self.assertEqual(outcome(runner.reconcile(rid)), ('reconciled_not_applied', 'before_state'))
        self.assertEqual(self.writes(), [])
        self.assertFalse((self.state / 'active').exists())

    def test_a_failed_launch_is_unresolved_and_keeps_the_fence(self):
        self.launcher.fail.add('start_job')
        a, runner, first = self.start()
        self.assertEqual(outcome(first), ('unresolved', 'job_start_failed'))
        self.assertTrue((self.state / 'active').exists())


class ConfirmTests(SupervisionCase):
    FAMILY = ConfirmFamily

    def test_the_rollback_timer_is_armed_before_the_job_and_confirm_settles_it(self):
        a, runner, first = self.start()
        rid = a.request['request_id']
        self.assertEqual(outcome(first), ('running', 'job_started'))
        self.assertEqual(self.launcher.calls, [('arm_rollback', rid, 360), ('start_job', rid, 60)])
        self.job(runner, rid)
        self.assertEqual(self.value(), b'new')
        self.assertEqual(outcome(runner.reconcile(rid)), ('running', 'awaiting_confirmation'))
        self.assertTrue((self.state / 'active').exists())
        self.assertEqual(outcome(runner.confirm(rid)), ('applied', 'confirmed'))
        self.assertIn(('disarm_rollback', rid), self.launcher.calls)
        self.assertFalse((self.state / 'active').exists())
        self.assertEqual(outcome(runner.rollback(rid)), ('applied', 'confirmed'))  # a late timer changes nothing
        self.assertEqual(self.value(), b'new')

    def test_no_confirmation_means_the_timer_restores_the_before_state(self):
        a, runner, _ = self.start()
        rid = a.request['request_id']
        self.job(runner, rid)
        self.assertEqual(outcome(runner.rollback(rid)), ('rolled_back', 'restored'))
        self.assertEqual(self.value(), b'old')
        self.assertFalse((self.state / 'active').exists())
        self.assertEqual(outcome(runner.confirm(rid)), ('rolled_back', 'restored'))  # too late: stays rolled back
        self.assertEqual(self.value(), b'old')

    def test_a_failed_apply_rolls_back_at_once(self):
        family = FailingConfirmFamily(self.work)
        a, runner, _ = self.start(family)
        rid = a.request['request_id']
        self.job(runner, rid)
        self.assertEqual(outcome(runner.reconcile(rid)), ('rolled_back', 'restored'))
        self.assertEqual(self.value(), b'old')

    def test_a_job_that_never_ran_is_rolled_back_by_status_and_a_late_start_does_nothing(self):
        a, runner, _ = self.start()
        rid = a.request['request_id']
        self.launcher.active.discard(rid)
        self.assertEqual(outcome(runner.reconcile(rid)), ('rolled_back', 'nothing_to_restore'))
        runner.run_job(rid)
        self.assertEqual((self.value(), self.writes()), (b'old', []))

    def test_rollback_stops_a_still_running_job_before_restoring(self):
        a, runner, _ = self.start()
        rid = a.request['request_id']
        runner.run_job(rid)  # applied, unit still reported active
        self.assertEqual(outcome(runner.rollback(rid)), ('rolled_back', 'restored'))
        names = [c[0] for c in self.launcher.calls]
        self.assertLess(names.index('start_job'), names.index('stop_job'))
        self.assertEqual(self.value(), b'old')

    def test_confirm_before_the_job_finished_is_not_accepted(self):
        a, runner, _ = self.start()
        rid = a.request['request_id']
        self.assertEqual(outcome(runner.confirm(rid)), ('running', 'job_running'))
        self.assertFalse((self.state / 'requests' / rid / 'decision').exists())

    def test_a_job_never_writes_after_a_rollback_decision_or_without_its_fence(self):
        a, runner, _ = self.start()
        rid = a.request['request_id']
        (self.state / 'requests' / rid / 'decision').write_bytes(b'rollback')  # a rollback that has not finished
        runner.run_job(rid)
        self.assertEqual(self.writes(), [])
        other = self.approved(value='two')
        (self.state / 'requests' / rid / 'decision').unlink()
        (self.state / 'active').write_text(other.request['request_id'], encoding='ascii')  # fence held by another
        (self.state / 'requests' / rid / 'job_started').unlink(missing_ok=True)
        runner.run_job(rid)
        self.assertEqual(self.writes(), [])

    def test_without_a_watchdog_nothing_is_written(self):
        self.launcher.fail.add('arm_rollback')
        a, runner, first = self.start()
        self.assertEqual(outcome(first), ('refused', 'watchdog_unavailable'))
        self.assertNotIn('start_job', [c[0] for c in self.launcher.calls])
        self.assertEqual(self.writes(), [])
        self.assertFalse((self.state / 'active').exists())

    def test_boot_recovery_rolls_back_unconfirmed_changes_only(self):
        a, runner, _ = self.start()
        rid = a.request['request_id']
        self.job(runner, rid)
        self.assertEqual(runner.boot_rollback(), [rid])
        self.assertEqual(self.value(), b'old')
        self.assertEqual(runner.boot_rollback(), [])


class CliTests(SupervisionCase):
    FAMILY = ConfirmFamily

    def main(self, runner, *, argv=(), environ=None, stdin=b''):
        from vm.ubuntu.runner_cli import main
        out, err = io.BytesIO(), io.BytesIO()
        code = main(io.BytesIO(stdin), out, err, runner_factory=lambda: runner, argv=list(argv),
                    environ={} if environ is None else environ)
        return code, out.getvalue()

    def test_unit_operations_need_systemd_and_confirm_comes_over_stdin(self):
        a, runner, _ = self.start()
        rid = a.request['request_id']
        self.assertEqual(self.main(runner, argv=['job', rid])[0], 2)  # not started by systemd (sudo resets env)
        for bad in (['job'], ['job', 'X' * 32], ['apply', rid], ['job', rid, 'extra']):
            with self.subTest(bad=bad):
                self.assertEqual(self.main(runner, argv=bad, environ={'INVOCATION_ID': 'f' * 32})[0], 2)
        self.assertEqual(self.main(runner, argv=['job', rid], environ={'INVOCATION_ID': 'f' * 32})[0], 0)
        self.assertEqual(self.value(), b'new')
        code, out = self.main(runner, stdin=json.dumps({'op': 'confirm', 'request_id': rid}).encode() + b'\n')
        self.assertEqual((code, outcome(out)), (0, ('applied', 'confirmed')))
        self.assertEqual(self.main(runner, argv=['boot-rollback'], environ={'INVOCATION_ID': 'f' * 32})[0], 0)
        self.assertEqual(self.value(), b'new')


class LauncherTests(unittest.TestCase):
    def test_entry_scripts_keep_lf_so_the_shebang_runs_on_linux(self):
        from pathlib import Path
        folder = Path(__file__).resolve().parents[2] / 'vm' / 'ubuntu'
        for name in ('runner', 'collect'):
            with self.subTest(name=name):
                data = (folder / name).read_bytes()
                self.assertTrue(data.startswith(b'#!/usr/bin/python3 -IB\n'))
                self.assertNotIn(b'\r', data)

    def test_fixed_systemd_argv(self):
        from vm.ubuntu.supervision import SystemdLauncher, RUNNER_PATH
        seen = []
        def run(argv):
            seen.append(argv); return 0
        launcher, rid = SystemdLauncher(run), 'a' * 32
        launcher.arm_rollback(rid, 360)
        launcher.start_job(rid, 60)
        self.assertEqual(seen[0], ['/usr/bin/systemd-run', '--quiet', '--collect', '--unit=fyp-hardening-rollback-' + rid,
                                   '--on-active=360s', '--timer-property=AccuracySec=1s', RUNNER_PATH, 'rollback', rid])
        # No --no-block: systemd-run returns once the unit is active, so status never sees a queued job as dead.
        self.assertEqual(seen[1], ['/usr/bin/systemd-run', '--quiet', '--collect',
                                   '--unit=fyp-hardening-job-' + rid, '--property=RuntimeMaxSec=60', RUNNER_PATH, 'job', rid])
        for bad in ('../x', 'A' * 32, 'a' * 31):
            with self.subTest(bad=bad), self.assertRaises(ValueError):launcher.start_job(bad, 60)
        with self.assertRaises(OSError):SystemdLauncher(lambda argv: 1).start_job(rid, 60)
        self.assertFalse(SystemdLauncher(lambda argv: 3).job_active(rid))


class HostTests(SupervisionCase):
    FAMILY = ConfirmFamily

    def setUp(self):
        super().setUp()
        from system.contracts import WorkflowBinding
        from system.ledger import CoordinationLedger
        self.ledger = CoordinationLedger(self.root / 'ledger.sqlite3')
        self.binding = self.ledger.add_binding(WorkflowBinding('1' * 32, 'ubuntu', 'ubuntu:fixture', 'epoch', 'b',
                                                               '2026-11-06T00:00:00+00:00'))

    def test_running_stays_running_then_confirm_completes_and_rollback_refuses(self):
        from backends.ubuntu.executor import confirm, execute, reconcile
        runner = self.supervised()
        for value, finish, expected in (('new', runner.confirm, 'completed'), ('two', runner.rollback, 'refused')):
            with self.subTest(value=value):
                a = self.approved(value=value)
                rid, op = a.request['request_id'], 'op-' + value
                first = execute(a, ledger=self.ledger, binding=self.binding, operation_id=op, dispatch=runner.execute, now=NOW)
                self.assertEqual((first.state, self.ledger.operation_state(op).state), ('running', 'running'))
                self.job(runner, rid)
                self.assertEqual(reconcile(a, ledger=self.ledger, operation_id=op, status=runner.reconcile).state, 'running')
                if finish == runner.confirm:
                    settled = confirm(a, ledger=self.ledger, operation_id=op, send=runner.confirm)
                else:
                    finish(rid)
                    settled = reconcile(a, ledger=self.ledger, operation_id=op, status=runner.reconcile)
                self.assertEqual((settled.state, self.ledger.operation_state(op).state), (expected, expected))
