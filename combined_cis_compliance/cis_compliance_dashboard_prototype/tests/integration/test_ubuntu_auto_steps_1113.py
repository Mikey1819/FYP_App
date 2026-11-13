"""No manual console steps, and the page stays where the administrator is (administrator, 13 November 2026).

- 4.1.3 adds the SSH allow rule itself (`ufw allow 22/tcp`) before it turns UFW on, in the same approved,
  confirm-after-login change: SSH is open to everyone while UFW is off, so this widens nothing, and an unconfirmed
  change rolls both back. Before, it refused ("No SSH allow rule") and the administrator had to type a ufw command.
- A package install may upgrade the installed packages apt needs for it (for example libauparse0 for auditd), never
  remove one; the upgrades are listed in the plan. Before, it refused, and the administrator had to run apt upgrade.
- An Orchestrator plan that lists a control without an applicable fix among its fixes no longer sinks the whole round
  (live 13 November 05:36: three identical refused plans, no plan at all): code defers that control instead.
- A fresh SSH login made by the dashboard (safety check, confirmation, reconnect after a reboot) is the same server:
  the page no longer jumps to Overview.
- The package-list refresh settles by itself (no verification scan for a change that sets nothing), the Maintenance
  box says it is running until then, and Server decisions disappear once both are made.
Fakes only; the VM is never contacted.
"""
import json
import unittest
from unittest import mock

from tests.integration import test_ubuntu_ufw_enable_loopback as ufw_tests
from tests.integration import test_ubuntu_package_families as package_tests

SSH4, SSH6 = 'allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in', 'allow tcp 22 ::/0 any ::/0 in'


class UfwSshRuleTests(ufw_tests.Case):
    CLASS, PARAMS = 'UfwEnableFamily', {'enable': True}

    def firewall(self, **kwargs):
        system = ufw_tests.FakeFirewall(**kwargs)
        original = system.ufw

        def ufw(args):
            if tuple(args) in (('allow', '22/tcp'), ('delete', 'allow', '22/tcp')):
                system.calls.append(tuple(args))
                for key, line in (('rules4', SSH4), ('rules6', SSH6)):
                    if key == 'rules6' and not system.ipv6:
                        continue
                    rules = getattr(system, key)
                    rules.remove(line) if args[0] == 'delete' else rules.append(line)
                return
            return original(args)
        system.ufw = ufw
        return system

    def test_without_an_ssh_rule_it_adds_one_first_and_restore_takes_it_away(self):
        system = self.firewall(active=False, rules4=(), unit={'load': 'loaded', 'enabled': 'disabled', 'active': 'inactive'})
        family, before = self.cycle(system)  # before: refused with "No SSH allow rule"
        self.assertEqual(system.calls[0], ('allow', '22/tcp'))  # before ufw enable, so SSH is never cut
        self.assertLess(system.calls.index(('allow', '22/tcp')), system.calls.index(('--force', 'enable')))
        self.assertIn(SSH4, system.rules4)
        self.assertIn(SSH6, system.rules6)
        self.assertIn('ufw allow 22/tcp', ' '.join(family.summary(self.PARAMS, before)['steps']))
        family.restore(self.PARAMS, before)
        self.assertEqual(family.read_state(self.PARAMS), before)
        self.assertNotIn(SSH4, system.rules4)

    def test_an_existing_ssh_rule_is_kept_and_nothing_is_added(self):
        system = self.firewall(active=False, unit={'load': 'loaded', 'enabled': 'disabled', 'active': 'inactive'})
        family, before = self.cycle(system)
        self.assertNotIn(('allow', '22/tcp'), system.calls)
        family.restore(self.PARAMS, before)
        self.assertNotIn(('delete', 'allow', '22/tcp'), system.calls)  # the administrator's own rule stays
        self.assertEqual(family.read_state(self.PARAMS), before)

    def test_not_installed_or_already_on_is_still_refused(self):
        for system in (self.firewall(active=False, unit={'load': 'not-found', 'enabled': 'not-found', 'active': 'inactive'}),
                       self.firewall()):
            with self.subTest(unit=system.unit), self.assertRaises(ValueError):
                self.family(system).check_eligible(self.PARAMS)


class PackageUpgradeTests(package_tests.PackageCase):
    CONTROL, PARAMS = '6.3.1.1', {'packages': ['auditd', 'audispd-plugins']}

    def test_upgrades_apt_needs_are_allowed_listed_and_kept_on_restore(self):
        params = {'packages': ['auditd', 'audispd-plugins']}
        system = package_tests.FakeApt(installed={'libauparse0': '1:3.0.6'}, newer={'libauparse0': '1:3.0.7-1build1'})
        family = self.family(system)
        family.check_eligible(params)  # before: "The install would remove or upgrade existing packages"
        before = family.read_state(params)
        expected = family.expected_after(params, before)
        summary = family.summary(params, before)
        self.assertEqual(summary['will_upgrade'], ['libauparse0 1:3.0.6 -> 1:3.0.7-1build1'])
        self.assertNotIn('libauparse0=1:3.0.7-1build1', summary['will_install'])
        family.apply(params)
        self.assertEqual(family.read_state(params), expected)
        self.assertEqual(system.installed['libauparse0'], '1:3.0.7-1build1')
        family.restore(params, before)
        self.assertNotIn('auditd', system.installed)  # the added packages go
        self.assertIn('libauparse0', system.installed)  # the upgrade it needed stays (never downgraded)

    def test_a_removal_is_still_refused(self):
        params = {'packages': ['auditd', 'audispd-plugins']}
        system = package_tests.FakeApt()
        system.simulate = lambda mode, names: 'Inst auditd (1 x [amd64])\nRemv other [1]\n'
        with self.assertRaisesRegex(ValueError, 'remove'):
            self.family(system).check_eligible(params)


class PlanToleranceTests(unittest.TestCase):
    def test_a_fix_for_a_control_without_an_applicable_fix_is_deferred_not_fatal(self):
        from tests.integration.test_ubuntu_plan_errors import tools_for, LIVE_FAILING
        eligible = {'4.1.3': 'ubuntu.4.1.3.v1', '6.3.1.1': 'ubuntu.6.3.1.1.v1'}
        failing = sorted(set(LIVE_FAILING) | {'4.1.3', '4.1.4', '4.1.7', '6.3.1.1', '6.3.1.2'})
        tools = tools_for(failing, eligible)
        # The live 05:36 plan: 4.1.4 and 4.1.7 both as fixes and as no_registered_action deferrals.
        result = tools.call('submit_plan', {'target_id': 'ubuntu:fixture',
            'defers': {'control_id': ['4.1.4', '4.1.7', '6.3.1.2'], 'reason_code': 'no_registered_action'},
            'fixes': [{'action_id': 'ubuntu.4.1.3.v1', 'control_id': '4.1.3', 'reason_code': 'highest_risk'},
                      {'action_id': 'ubuntu.4.1.4.v1', 'control_id': '4.1.4', 'reason_code': 'highest_risk'},
                      {'action_id': 'ubuntu.4.1.7.v1', 'control_id': '4.1.7', 'reason_code': 'highest_risk'}]})
        self.assertEqual(result['status'], 'accepted')
        plan = tools.rounds.plan
        self.assertIn('4.1.3', [f['control_id'] for f in plan['fixes']])
        self.assertIn('6.3.1.1', [f['control_id'] for f in plan['fixes']])  # undeferred: proposed by code, as before
        deferred = {d['control_id']: d['reason_code'] for d in plan['decisions'] + plan['deferred_by_code']}
        self.assertEqual(deferred.get('4.1.4'), 'no_registered_action')
        self.assertEqual(deferred.get('4.1.7'), 'no_registered_action')
        self.assertNotIn('4.1.4', [f['control_id'] for f in plan['fixes']])

    def test_a_wrong_action_for_a_control_that_has_one_is_still_refused(self):
        from tests.integration.test_ubuntu_plan_errors import tools_for, LIVE_FAILING
        tools = tools_for(sorted(set(LIVE_FAILING) | {'4.1.3'}), {'4.1.3': 'ubuntu.4.1.3.v1'})
        with self.assertRaises(ValueError):
            tools.call('submit_plan', {'target_id': 'ubuntu:fixture', 'fixes': [
                {'action_id': 'ubuntu.9.9.9.v1', 'control_id': '4.1.3', 'reason_code': 'highest_risk'}]})


class StayOnPageTests(unittest.TestCase):
    def test_a_fresh_login_to_the_same_server_keeps_the_page(self):
        import tempfile
        from pathlib import Path
        from streamlit.testing.v1 import AppTest
        from streamlit.util import calc_hash
        from system.bootstrap import CONNECTION_KEY, SERVICE_KEY
        from system.config import IntegrationPaths
        from system.connection import ConnectionService
        from system.contracts import ConnectionRequest, Endpoint
        from system.ledger import CoordinationLedger
        from system.session import Credentials
        from tests.integration.pairing_fixture import paired_connect
        from tests.test_app_navigation import APP, FixtureSsh
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        data = Path(folder.name)
        paths = IntegrationPaths(APP.parent, data / 'windows' / 'imports.sqlite3', data / 'ubuntu' / 'imports.sqlite3',
                                 data / 'integration.sqlite3')
        for target in (mock.patch('system.config.PATHS', paths), mock.patch('hardening.reachability.answers',
                                                                            return_value=True)):
            target.start()
            self.addCleanup(target.stop)
        service = ConnectionService(CoordinationLedger(paths.coordination), ssh_factory=lambda *a: FixtureSsh())
        app = AppTest.from_file(str(APP), default_timeout=30)
        app.session_state[SERVICE_KEY] = service
        app.run()
        self.assertEqual(paired_connect(app, platform='ubuntu', hostname='ubuntu-web01', identity='b' * 32).state,
                         'connected')
        app._page_hash = calc_hash('history')
        app.run()
        self.assertEqual(app.title[0].value, 'History and configuration drift')
        old = app.session_state[CONNECTION_KEY]
        session = service.session(old)
        service.disconnect(old)  # what a fresh login does: the same server, a new connection
        reference = service.vault.put(Credentials('fixture-user', 'TEST-ONLY', None, None))
        result = service.connect(ConnectionRequest(Endpoint(session.host, session.port, 'ssh'), 'ubuntu-web01', 'b' * 32,
                                                   reference))
        self.assertEqual(result.state, 'connected')
        app.session_state[CONNECTION_KEY] = result.connection_session_id
        app.run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertEqual(app.title[0].value, 'History and configuration drift')  # before: Overview



from tests.integration import test_ubuntu_maintenance_host as maintenance_host
from tests.integration import test_ubuntu_maintenance_ui as maintenance_ui


class RefreshSettlesTests(maintenance_host.MaintenanceCase):
    def test_a_finished_refresh_settles_without_a_verification_scan(self):
        from system.contracts import AuxiliaryKind, MetadataRefreshInput
        backend, workflow, _ = self.applied_fix()
        ref = backend.request_auxiliary('c', workflow, AuxiliaryKind.METADATA_REFRESH, None, MetadataRefreshInput(''),
                                        'op-m')
        self.approve(backend, workflow, ref)
        handle = self.dispatch(backend, workflow, ref)
        store = backend._store()

        def scans():
            return len([r for r in store.rounds(handle.binding) if r.kind == 'verification'])
        before = scans()
        self.job(backend.snapshot('c', workflow).proposals[-1].approved_request_id)
        self.assertEqual(self.refresh(backend, workflow, handle.round_reference).state, 'completed')
        self.assertEqual(scans(), before)  # apt-get update sets nothing: no scan to wait for (before: one more)


class MaintenanceBoxTests(maintenance_ui.MaintenanceUiTests):
    def test_the_box_shows_the_refresh_running_until_it_settles_by_itself(self):
        from tests.integration.test_ubuntu_live_path import open_gate

        def unavailable(params):
            raise ValueError('Nothing to install, or a target package is unavailable from the configured sources')
        self.family.check_eligible = unavailable
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()),                 mock.patch('hardening.agentic_view.REFRESH_HELPS', frozenset({'1.5.1'})):
            app, _ = self.page()
            app.button(key='agentic_run').click().run()
            app.button(key='ubuntu_prepare_refresh').click().run()
            self.run_maintenance(app)
            running = [s for s in app.status if 'Package-list refresh is running' in s.label]
            self.assertEqual(len(running), 1)  # before: "Package lists refreshed" at once, while apt still ran
            self.assertNotIn('Package lists refreshed', self.text(app))
            for rid in list(self.launcher.active):  # apt-get update finishes on the server
                self.runner().run_job(rid)
                self.launcher.active.discard(rid)
            app.run()  # the page's own five-second check, no click
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertEqual([s for s in app.status if 'Package-list refresh is running' in s.label], [])
            self.assertIn('Package lists refreshed', self.text(app))
            self.assertFalse([b for b in app.button if b.key and b.key.startswith('ubuntu_status_')])

    def test_the_reboot_help_no_longer_asks_for_a_reconnect_by_hand(self):
        import inspect
        from hardening import agentic_view
        source = inspect.getsource(agentic_view._ubuntu_maintenance_actions)
        self.assertNotIn('connect again, then Check status', source)


class DecisionsHiddenTests(maintenance_ui.MaintenanceUiTests):
    def setUp(self):
        super().setUp()
        patch = mock.patch('backends.ubuntu.server_decisions.store_path', return_value=self.root / 'decisions.sqlite3')
        patch.start()
        self.addCleanup(patch.stop)

    def test_the_panel_disappears_once_both_decisions_are_made(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate():
            app, _ = self.page()
            app.text_input(key='ubuntu_decisions_operator').input('fixture-operator').run()
            app.button(key='ubuntu_decide_firewall_manager_ufw').click().run()
            self.assertTrue(any('1 to make' in e.label for e in app.expander))  # one still open: still shown
            app.button(key='ubuntu_decide_avahi_2_1_2_mask').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertEqual([e.label for e in app.expander if 'Server decisions' in e.label], [])  # before: "all made"


for _case in (MaintenanceBoxTests, DecisionsHiddenTests):
    for _name in [n for n in dir(maintenance_ui.MaintenanceUiTests) if n.startswith('test')]:
        setattr(_case, _name, None)  # only the harness is inherited
for _name in [n for n in dir(maintenance_host.MaintenanceCase) if n.startswith('test')]:
    setattr(RefreshSettlesTests, _name, None)

if __name__ == '__main__':
    unittest.main()
