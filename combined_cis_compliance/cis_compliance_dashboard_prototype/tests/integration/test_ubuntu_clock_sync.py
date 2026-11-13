"""Ubuntu: sync the server clock to this laptop in one click, as the Windows page does (administrator request
2026-11-11). The dashboard's account is not root on Ubuntu, so the root-owned fix runner sets the clock with one fixed
command, only on the administrator's click, never while a change is open on the server; the backend records it in the
ledger (account, server time before and after). TEST-ONLY: in-process runner, simulated VM clock; no VM, no real
clock change."""
from datetime import datetime, timedelta, timezone
import io
import json
import tempfile
import unittest
from pathlib import Path

from tests.integration import test_ubuntu_acceptance_host as host_tests
from tests.integration import test_ubuntu_acceptance_ui as ui_tests

BEHIND = timedelta(seconds=-317677)  # the live case: the server 3 days 16 h behind after a snapshot restore


class FakeClock:
    """A server clock that can be set: `now()` runs `offset` from the real time; `set(when)` moves it."""

    def __init__(self, offset=timedelta(0)):
        self.offset, self.calls = offset, []

    def now(self):
        return datetime.now(timezone.utc) + self.offset

    def set(self, when):
        self.calls.append(when)
        self.offset = when - datetime.now(timezone.utc)


class RunnerClockTests(unittest.TestCase):
    def runner(self, folder, clock):
        from vm.ubuntu.runner import Runner
        return Runner(folder, {}, lambda: ('a' * 32, 'ubuntu-fixture'), clock=clock.now, require_root_owned=False,
                      clock_setter=clock.set)

    def test_sets_the_clock_to_the_given_utc_time_and_reports_before_and_after(self):
        clock = FakeClock(BEHIND)
        with tempfile.TemporaryDirectory() as folder:
            wanted = datetime.now(timezone.utc)
            result = self.runner(folder, clock).set_clock(wanted.isoformat())
        self.assertEqual(result['outcome'], 'set')
        self.assertEqual(len(clock.calls), 1)
        self.assertLess(abs((clock.calls[0] - wanted).total_seconds()), 1)
        before, after = datetime.fromisoformat(result['before']), datetime.fromisoformat(result['after'])
        self.assertAlmostEqual((after - before).total_seconds(), -BEHIND.total_seconds(), delta=2)

    def test_refuses_while_a_change_is_open_and_never_sets_an_odd_time(self):
        clock = FakeClock(BEHIND)
        with tempfile.TemporaryDirectory() as folder:
            runner = self.runner(folder, clock)
            (Path(folder) / 'active').write_text('f' * 32)  # the fence: a change is open on the server
            self.assertEqual(runner.set_clock(datetime.now(timezone.utc).isoformat())['code'], 'change_open')
            (Path(folder) / 'active').unlink()
            for bad in ('2026-11-11T00:00:00', '2020-01-01T00:00:00+00:00', '2150-01-01T00:00:00+00:00',
                        '2026-11-11T08:00:00+08:00', 'tomorrow', 5):
                with self.subTest(bad=bad), self.assertRaises((ValueError, TypeError)):
                    runner.set_clock(bad)
        self.assertEqual(clock.calls, [])

    def test_the_runner_entry_point_takes_only_a_utc_time(self):
        from vm.ubuntu.runner_cli import main
        clock = FakeClock(BEHIND)
        with tempfile.TemporaryDirectory() as folder:
            factory = lambda: self.runner(folder, clock)

            def call(header, payload=b''):
                out, err = io.BytesIO(), io.BytesIO()
                code = main(stdin=io.BytesIO(json.dumps(header).encode() + b'\n' + payload), stdout=out, stderr=err,
                            runner_factory=factory)
                return code, out.getvalue()
            code, out = call({'op': 'set_clock', 'utc': datetime.now(timezone.utc).isoformat()})
            self.assertEqual((code, json.loads(out)['outcome']), (0, 'set'))
            for header, payload in (({'op': 'set_clock'}, b''), ({'op': 'set_clock', 'utc': 'x', 'extra': 1}, b''),
                                    ({'op': 'set_clock', 'utc': datetime.now(timezone.utc).isoformat()}, b'data')):
                with self.subTest(header=header):
                    self.assertEqual(call(header, payload)[0], 2)
        self.assertEqual(len(clock.calls), 1)


class BackendClockTests(host_tests.AcceptanceCase):
    def runner(self, family=None, *, identity=None, clock=None):
        runner = super().runner(family, identity=identity, clock=clock)
        runner.clock_setter = lambda when: setattr(self, 'vm_offset', when - datetime.now(timezone.utc))
        return runner

    def test_sync_sets_the_server_clock_records_it_and_clears_the_clock_problem(self):
        self.vm_offset = BEHIND
        backend = self.deployed()
        status = backend.deployment_status('c')
        self.assertFalse(status.ok)
        self.assertAlmostEqual(status.clock_offset, BEHIND.total_seconds(), delta=2)
        self.assertIn('Sync server clock to this laptop', ' '.join(status.reasons))
        result = backend.sync_clock('c', None, 'clock-1')
        self.assertAlmostEqual((result['after'] - result['before']).total_seconds(), -BEHIND.total_seconds(), delta=2)
        state = self.ledger.operation_state('clock-1')
        self.assertEqual(state.state, 'completed')
        record = json.loads(state.detail)
        self.assertEqual(set(record), {'account', 'server_before', 'server_after'})
        self.assertEqual(record['account'], backend.session.username)
        status = backend.deployment_status('c')  # measured again, not the cached probe
        self.assertEqual((status.ok, status.reasons), (True, ()))
        self.assertAlmostEqual(status.clock_offset, 0, delta=2)
        with self.assertRaises(ValueError):  # the same click again is never sent twice
            backend.sync_clock('c', None, 'clock-1')
        self.assertEqual(self.ledger.operation_state('clock-1').state, 'completed')

    def test_sync_is_refused_while_a_change_is_open_on_the_server(self):
        backend = self.deployed()
        backend.start_acceptance('c', 'confirm', 'fixture-operator', 'op-a1')  # a change now holds the server
        self.vm_offset = timedelta(minutes=7)  # and then the server clock jumps
        with self.assertRaises(ValueError):
            backend.sync_clock('c', None, 'clock-2')
        self.assertEqual(self.vm_offset, timedelta(minutes=7))  # the clock was not touched


class PageClockTests(ui_tests.AcceptanceUiTests):
    def setUp(self):
        super().setUp()
        self.vm_offset = BEHIND

    def now(self):  # the simulated server's clock, which the runner reads
        return datetime.now(timezone.utc) + self.vm_offset

    def runner(self, family=None, *, identity=None, clock=None):
        runner = super().runner(family, identity=identity, clock=clock)
        runner.clock_setter = lambda when: setattr(self, 'vm_offset', when - datetime.now(timezone.utc))
        return runner

    def test_the_page_offers_the_one_click_sync_and_the_box_clears(self):
        from streamlit.testing.v1 import AppTest
        from tests.integration.test_system_acceptance import existing_page
        from tests.integration.test_ubuntu_agents import call, team, scanner_ok, RankingAware
        from tests.integration.test_ubuntu_live_path import open_gate, TARGET as LIVE
        from tests.integration.pairing_fixture import paired_connect
        from backends.ubuntu.actions import ActionSpec
        from backends.ubuntu.adapter import UbuntuBackend
        from system.bootstrap import SERVICE_KEY
        from system.connection import ConnectionService
        from system.ledger import CoordinationLedger
        self.addCleanup(setattr, RankingAware, 'target', 'ubuntu:fixture')
        spec = ActionSpec(self.family.action_id, 1, self.family.implementation_sha256, ('1.5.1',), self.family.validate, 60)
        ledger = CoordinationLedger(self.root / 'integration.sqlite3')

        def backend_factory(session):
            clients = team([call('delegate_scanner')], scanner_ok(), RankingAware())
            return UbuntuBackend(self.root / 'ubuntu' / 'imports.sqlite3', session=session, ledger=ledger,
                                 families={spec.action_id: spec}, model_client_factory=clients.__getitem__,
                                 model_probe=lambda: True)

        service = ConnectionService(ledger, ssh_factory=lambda *a: self.make_channel(), backend_factory=backend_factory)
        app = AppTest.from_function(existing_page, default_timeout=60)
        app.session_state['fixture_database'] = str(self.root / 'windows' / 'imports.sqlite3')
        app.session_state[SERVICE_KEY] = service

        def keys():
            return {b.key for b in app.button if b.key}
        with open_gate():
            app.run()
            self.assertEqual(paired_connect(app, platform='ubuntu', hostname=LIVE[1], identity=LIVE[0],
                                            run=False).state, 'connected')
            app.run()
            self.assertIn('Clocks differ', self.text(app))
            self.assertIn('3 d 16 h 14 min behind this laptop', self.text(app))
            self.assertIn('ubuntu_clock_sync', keys())
            app.button(key='ubuntu_clock_sync').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertIn('Server clock set from', ' '.join(s.value for s in app.success))
            self.assertNotIn('ubuntu_clock_sync', keys())  # the clocks match now: no box, no button
            self.assertNotIn('Clocks differ', self.text(app))
        self.assertLess(abs(self.vm_offset.total_seconds()), 2)


for _name in [n for n in dir(host_tests.AcceptanceCase) if n.startswith('test')]:
    setattr(BackendClockTests, _name, None)  # only the harness is inherited
for _name in [n for n in dir(ui_tests.AcceptanceUiTests) if n.startswith('test')]:
    setattr(PageClockTests, _name, None)


if __name__ == '__main__':
    unittest.main()
