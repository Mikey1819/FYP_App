"""Page flow for maintenance, offered only when a fix of the round needs it (administrator request 2026-11-09):
a package-list refresh after a package fix could not be planned or run, a reboot after a fix that completes at the
next boot was applied. Each is prepared, approved, confirmed and run once.
TEST-ONLY: in-process runner, fake launcher and fake maintenance system; the VM is never contacted."""
import unittest
from types import SimpleNamespace
from unittest import mock
from tests.integration.test_ubuntu_fix_ui import FixUiTests
from tests.integration.test_ubuntu_maintenance_target import FakeMaintenance
from tests.integration.test_ubuntu_supervision import FakeLauncher
from tests.integration.pairing_fixture import paired_connect


class MaintenanceUiTests(FixUiTests):
    def setUp(self):
        super().setUp()
        self.launcher, self.maintenance = FakeLauncher(), FakeMaintenance()

    def runner(self, family=None, *, identity=None, clock=None):
        from vm.ubuntu.family_maintenance import AptRefreshFamily, RebootFamily
        from vm.ubuntu.runner import Runner
        family = family or self.family
        families = {family.action_id: family, 'maintenance.apt_refresh.v1': AptRefreshFamily(self.maintenance),
                    'maintenance.reboot.v1': RebootFamily(self.maintenance)}
        return Runner(self.state, families, lambda: identity or ('a' * 32, 'ubuntu-fixture'), clock=clock or self.now,
                      require_root_owned=False, launcher=self.launcher)

    def page(self):
        """A connected page whose round plans the TEST-ONLY fix for 1.5.1; returns (app, channel)."""
        from streamlit.testing.v1 import AppTest
        from tests.integration.test_system_acceptance import existing_page
        from tests.integration.test_ubuntu_agents import call, plan_call, team, scanner_ok, RankingAware, Scripted
        from tests.integration.test_ubuntu_live_path import TARGET as LIVE
        from backends.ubuntu.actions import ActionSpec
        from backends.ubuntu.adapter import UbuntuBackend
        from system.bootstrap import SERVICE_KEY
        from system.connection import ConnectionService
        from system.ledger import CoordinationLedger
        self.addCleanup(setattr, RankingAware, 'target', 'ubuntu:fixture')
        channel = self.make_channel()
        spec = ActionSpec(self.family.action_id, 1, self.family.implementation_sha256, ('1.5.1',), self.family.validate, 60,
                          propose=lambda cid, evidence: {'name': 'alpha', 'value': 'new'}, title='TEST-ONLY fixture value',
                          recovery={'kind': 'restore_backup', 'scope': ['fixture:alpha']})
        ledger = CoordinationLedger(self.root / 'integration.sqlite3')

        def backend_factory(session):
            fix = {'control_id': '1.5.1', 'decision': 'fix', 'action_id': spec.action_id, 'reason_code': 'highest_risk'}
            clients = team([call('delegate_scanner'), call('delegate_analysis'), plan_call([fix])],
                           scanner_ok(), RankingAware())
            for client in clients.values():
                if isinstance(client, Scripted):
                    for item in client.script:
                        item['tool_calls'][0]['function']['arguments']['target_id'] = session.target_id
            RankingAware.target = session.target_id
            return UbuntuBackend(self.root / 'ubuntu' / 'imports.sqlite3', session=session, ledger=ledger,
                                 families={spec.action_id: spec}, model_client_factory=clients.__getitem__,
                                 model_probe=lambda: getattr(self, 'model_up', True))

        service = ConnectionService(ledger, ssh_factory=lambda *a: channel, backend_factory=backend_factory)
        app = AppTest.from_function(existing_page, default_timeout=60)
        app.session_state['fixture_database'] = str(self.root / 'windows' / 'imports.sqlite3')
        app.session_state[SERVICE_KEY] = service
        app.run()
        self.assertEqual(paired_connect(app, platform='ubuntu', hostname=LIVE[1], identity=LIVE[0]).state, 'connected')
        return app, channel

    @staticmethod
    def keyed(app, prefix, exclude=None):
        return [b for b in app.button if b.key and b.key.startswith(prefix) and b.key != exclude]

    def keys(self, app):
        return {b.key for b in app.button if b.key}

    def run_maintenance(self, app):
        """Approve (operator named), confirm and run the one prepared maintenance step."""
        app.text_input(key='agentic_operator').input('fixture-operator').run()
        self.keyed(app, 'ubuntu_approve_', exclude='ubuntu_approve_all')[0].click().run()
        [run] = self.keyed(app, 'ubuntu_run_maintenance_')
        self.assertTrue(run.disabled)  # confirmation first
        [confirm] = [c for c in app.checkbox if c.key and c.key.startswith('ubuntu_confirm_maintenance_')]
        confirm.check().run()
        self.keyed(app, 'ubuntu_run_maintenance_')[0].click().run()
        self.assertFalse(list(app.error), [e.value for e in app.error])
        app.run()
        self.assertEqual(self.keyed(app, 'ubuntu_run_maintenance_'), [])  # dispatched once; never offered again

    def test_refresh_is_offered_only_after_a_package_fix_could_not_be_planned(self):
        from tests.integration.test_ubuntu_live_path import open_gate

        def unavailable(params):
            raise ValueError('Nothing to install, or a target package is unavailable from the configured sources')
        self.family.check_eligible = unavailable  # the read-only preview is refused, as apt's simulation would be
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), \
                mock.patch('hardening.agentic_view.REFRESH_HELPS', frozenset({'1.5.1'})):
            app, channel = self.page()
            app.button(key='agentic_run').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertNotIn('ubuntu_prepare_reboot', self.keys(app))  # nothing applied that needs a restart
            self.assertIn("1.5.1 could not be installed: the server's package lists may be out of date", self.text(app))
            app.button(key='ubuntu_prepare_refresh').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.run_maintenance(app)
            self.assertNotIn('ubuntu_prepare_refresh', self.keys(app))  # ran once in this round
            for rid in list(self.launcher.active):  # apt-get update finishes; until then the box says it is running
                self.runner().run_job(rid)
                self.launcher.active.discard(rid)
            app.run()
            self.assertIn('Start a new round', self.text(app))
        self.assertEqual(len([c for c in channel.runner_calls if c.startswith(b'{"op":"execute"}')]), 1)
        self.assertEqual(self.writes(), [])

    def test_a_failed_fix_outside_the_package_installs_offers_no_refresh(self):
        from tests.integration.test_ubuntu_live_path import open_gate

        def refused(params):
            raise ValueError('A later sysctl file overrides the value')
        self.family.check_eligible = refused
        with open_gate():
            app, _ = self.page()
            app.button(key='agentic_run').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertFalse({'ubuntu_prepare_refresh', 'ubuntu_prepare_reboot'} & self.keys(app))
            self.assertNotIn('Maintenance', self.text(app))

    def test_reboot_is_offered_only_after_a_fix_that_completes_at_the_next_boot_was_applied(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), \
                mock.patch('hardening.agentic_view.REBOOT_COMPLETES', frozenset({'1.5.1'})):
            app, channel = self.page()
            app.button(key='agentic_run').click().run()
            self.assertFalse({'ubuntu_prepare_refresh', 'ubuntu_prepare_reboot'} & self.keys(app))  # nothing applied
            app.text_input(key='agentic_operator').input('fixture-operator').run()
            self.keyed(app, 'ubuntu_approve_', exclude='ubuntu_approve_all')[0].click().run()
            self.model_up = False  # without the model, Confirm runs the fixes in plan order
            app.button(key='ubuntu_execute_review').click().run()
            app.button(key='ubuntu_execute').click().run()
            app.run()
            self.assertEqual(self.writes(), ['alpha'])
            self.assertNotIn('ubuntu_prepare_refresh', self.keys(app))  # the fix ran: lists were fine
            self.assertIn('The restart is optional', self.text(app))  # wording of 2026-11-13
            self.assertFalse(app.button(key='ubuntu_prepare_reboot').disabled)
            app.button(key='ubuntu_prepare_reboot').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertEqual(len(self.keyed(app, 'ubuntu_approve_', exclude='ubuntu_approve_all')), 1)  # its own approval
            self.assertTrue(app.button(key='ubuntu_prepare_reboot').disabled)  # one open reboot at a time
        self.assertEqual(len([c for c in channel.runner_calls if c.startswith(b'{"op":"execute"}')]), 1)

    def test_the_controls_tab_shows_the_verification_rescan_after_the_fixes(self):
        # As on Windows (user report 2026-11-12): the Controls tab used to keep the round's first scan, so a fixed
        # control still read Non-Compliant there.
        from tests.integration.test_ubuntu_live_path import open_gate

        def controls(app):
            return {r['Control']: r['Status'] for frame in app.dataframe for r in frame.value.to_dict('records')
                    if 'Applicability' in r}

        def line(app):
            return [c.value for c in app.caption if c.value.startswith(("Newest scan of this round", "This round's first"))]
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            app, _ = self.page()
            app.button(key='agentic_run').click().run()
            self.assertEqual(controls(app)['1.5.1'], 'Non-Compliant')
            self.assertTrue(line(app)[0].startswith("This round's first scan"), line(app))
            app.text_input(key='agentic_operator').input('fixture-operator').run()
            self.keyed(app, 'ubuntu_approve_', exclude='ubuntu_approve_all')[0].click().run()
            self.model_up = False  # without the model, Confirm runs the fixes in plan order, then the rescan
            app.button(key='ubuntu_execute_review').click().run()
            self.aslr = '2'  # The fake server reads compliant from here on, as after the fix (the fixture's write
            app.button(key='ubuntu_execute').click().run()  # goes to a TEST-ONLY file, not to this value).
            app.run()
            self.assertEqual(self.writes(), ['alpha'])
            self.assertEqual(controls(app)['1.5.1'], 'Compliant')
            self.assertTrue(line(app)[0].startswith('Newest scan of this round: the verification rescan after the fixes'),
                            line(app))
            # Results, as on Windows: "Execution results" by control and fix, never the internal proposal ID.
            self.assertIn('**Execution results**', [m.value for m in app.markdown])
            rows = [r for frame in app.dataframe for r in frame.value.to_dict('records') if 'Execution' in r]
            self.assertEqual([(r['Control'], r['Fix'], r['Execution']) for r in rows],
                             [('1.5.1', 'TEST-ONLY fixture value', 'Applied')])
            self.assertEqual(list(rows[0]), ['Control', 'Fix', 'Execution', 'Verification', 'Detail'])


class MaintenanceNeedsTests(unittest.TestCase):
    """Which maintenance a round's fix cards call for, from their states alone."""

    def card(self, control_id, state, applied_request=None):
        proposals = [SimpleNamespace(kind='control_remediation', reference=control_id,
                                     approved_request_id=applied_request)]
        return {'control_id': control_id, 'state': state, 'proposals': proposals}

    def needs(self, cards, applied=()):
        from hardening.agentic_view import _ubuntu_maintenance_needs
        return _ubuntu_maintenance_needs(cards, set(applied))

    def test_registered_controls_are_the_package_installs(self):
        from hardening.agentic_view import REBOOT_COMPLETES, REFRESH_HELPS
        self.assertEqual(REFRESH_HELPS, {'1.3.1.1', '6.3.1.1'})  # 1.5.4 purges from the local database
        self.assertEqual(REBOOT_COMPLETES, frozenset())  # 6.3.1.3 complies from the boot entries (2026-11-13)

    def test_refresh_follows_a_package_install_that_could_not_be_planned_or_run(self):
        from system.ui.components import NO_PLAN, SKIPPED
        for state in (NO_PLAN, SKIPPED, 'Not applied', 'Outcome unknown'):
            self.assertEqual(self.needs([self.card('6.3.1.1', state)]), (('6.3.1.1',), ()), state)
        for state in ('Awaiting your decision', 'Approved, ready to execute', 'Rejected', 'Running',
                      'Applied, re-scan pending', 'Fixed, re-scan: Compliant', 'Deferred'):
            self.assertEqual(self.needs([self.card('6.3.1.1', state)]), ((), ()), state)
        self.assertEqual(self.needs([self.card('1.5.4', NO_PLAN), self.card('1.5.1', 'Not applied')]), ((), ()))

    @mock.patch('hardening.agentic_view.REBOOT_COMPLETES', frozenset({'6.3.1.3'}))  # the mechanism, kept
    def test_reboot_names_only_the_applied_fixes_that_complete_at_the_next_boot(self):
        cards = [self.card('6.3.1.3', 'Applied, re-scan pending', 'r-grub'),
                 self.card('1.5.1', 'Fixed, re-scan: Compliant', 'r-sysctl')]
        self.assertEqual(self.needs(cards, applied=('6.3.1.3', '1.5.1')), ((), ('r-grub',)))
        self.assertEqual(self.needs([self.card('6.3.1.3', 'Restored to the before-state', 'r-grub')],
                                    applied=('6.3.1.3',)), ((), ()))
        self.assertEqual(self.needs([self.card('6.3.1.3', 'Approved, ready to execute', 'r-grub')]), ((), ()))


for _name in [n for n in dir(FixUiTests) if n.startswith('test')]:
    setattr(MaintenanceUiTests, _name, None)  # only the harness is inherited
del FixUiTests
