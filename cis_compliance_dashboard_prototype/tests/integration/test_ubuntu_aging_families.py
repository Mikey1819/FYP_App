"""Account-aging families for CIS 5.4.1.1 (pp.653-655), 5.4.1.3 (pp.660-661), 5.4.1.5 (pp.665-666). IN-MEMORY fakes only."""
from copy import deepcopy
import json
import unittest
from tests.integration.ubuntu_fixtures import observation

TODAY = 20400
LOGIN_DEFS = b'# login.defs\nPASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nPASS_WARN_AGE\t5\nUMASK\t\t022\n'
USERADD = b'# useradd defaults\nSHELL=/bin/sh\n# INACTIVE=-1\n'


def account(name, uid, *, lastchg=TODAY - 10, minimum=0, maximum=99999, warning=7, inactive=-1, bearing=True):
    return dict(name=name, uid=uid, password_bearing=bearing, lastchg=lastchg, minimum=minimum, maximum=maximum,
                warning=warning, inactive=inactive)


def accounts():
    return [account('vboxuser', 1000, warning=3),
            account('analyst', 1001, maximum=90, inactive=30),
            account('daemon', 1, lastchg=100, bearing=False)]


class FakeAgingSystem:
    def __init__(self, records=None, login_defs=LOGIN_DEFS, useradd=USERADD, today=TODAY):
        self.records = records if records is not None else accounts()
        self.defs, self.useradd, self.now, self.calls = login_defs, useradd, today, []

    def account_records(self):
        return deepcopy(self.records)

    def today(self):
        return self.now

    def login_defs(self):
        return self.defs

    def write_login_defs(self, content):
        self.calls.append('login.defs'); self.defs = content

    def useradd_defaults(self):
        return self.useradd

    def write_useradd_defaults(self, content):
        self.calls.append('useradd'); self.useradd = content

    def chage(self, name, flag, value):
        field = {'--maxdays': 'maximum', '--warndays': 'warning', '--inactive': 'inactive'}[flag]
        self.calls.append((name, flag, value))
        next(r for r in self.records if r['name'] == name)[field] = value


def collected(system, control_id):
    """The facts the collector would report from this fake, evaluated by the real predicate."""
    from backends.ubuntu.predicates import evaluate
    defs = {line.split()[0]: int(line.split()[1]) for line in system.defs.decode().splitlines()
            if line.strip() and not line.startswith('#') and len(line.split()) == 2 and line.split()[1].lstrip('-').isdigit()}
    useradd = {k: v for k, v in (l.split('=', 1) for l in (system.useradd or b'').decode().splitlines()
                                 if '=' in l and not l.startswith('#'))}
    facts = {'account_inventory': observation('complete'),
             'accounts': observation([{k: v for k, v in r.items() if k != 'lastchg'} for r in system.records])}
    if control_id == '5.4.1.1':
        facts.update({'default.maximum': observation(defs['PASS_MAX_DAYS']), 'default.minimum': observation(defs['PASS_MIN_DAYS'])})
    elif control_id == '5.4.1.3':
        facts['default.warning'] = observation(defs['PASS_WARN_AGE'])
    else:
        facts['default.inactive'] = observation(int(useradd.get('INACTIVE', '-1')))
    return evaluate(control_id, facts).status.value


class AgingCase(unittest.TestCase):
    CONTROL, PARAMS = None, None

    def family(self, system):
        from vm.ubuntu.family_aging import AgingFamily
        return AgingFamily(self.CONTROL, system)

    def cycle(self, system):
        family = self.family(system)
        family.validate(self.PARAMS)
        family.check_eligible(self.PARAMS)
        before = family.read_state(self.PARAMS)
        expected = family.expected_after(self.PARAMS, before)
        family.apply(self.PARAMS)
        self.assertEqual(family.read_state(self.PARAMS), expected)
        return family, before

    def refused(self, system):
        with self.assertRaises(ValueError):self.family(system).check_eligible(self.PARAMS)


class MaxDaysTests(AgingCase):
    CONTROL, PARAMS = '5.4.1.1', {'maxdays': 365}

    def test_only_the_site_value_is_accepted(self):
        family = self.family(FakeAgingSystem())
        for bad in ({'maxdays': 366}, {'maxdays': 0}, {'maxdays': '365'}, {}, {'maxdays': 365, 'x': 1}, {'warndays': 7}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):family.validate(bad)

    def test_apply_fixes_the_default_and_only_failing_password_accounts(self):
        system = FakeAgingSystem()
        self.assertEqual(collected(system, '5.4.1.1'), 'Non-Compliant')
        self.cycle(system)
        self.assertEqual(collected(system, '5.4.1.1'), 'Compliant')
        self.assertEqual(system.defs, LOGIN_DEFS.replace(b'PASS_MAX_DAYS\t99999', b'PASS_MAX_DAYS\t365'))
        self.assertEqual([c for c in system.calls if type(c) is tuple], [('vboxuser', '--maxdays', 365)])

    def test_summary_names_each_account_change_and_restore_is_exact(self):
        system = FakeAgingSystem()
        family = self.family(system)
        summary = family.summary(self.PARAMS, family.read_state(self.PARAMS))
        self.assertEqual(summary['accounts'], {'vboxuser': [99999, 365]})
        self.assertEqual(summary['default'], ['PASS_MAX_DAYS', 99999, 365])
        family, before = self.cycle(system)
        family.restore(self.PARAMS, before)
        self.assertEqual(family.read_state(self.PARAMS), before)
        self.assertEqual(system.defs, LOGIN_DEFS)

    def test_no_change_may_expire_or_soon_expire_a_password(self):
        for lastchg in (TODAY - 400, TODAY - 340, 0, None):
            with self.subTest(lastchg=lastchg):
                self.refused(FakeAgingSystem([account('vboxuser', 1000, lastchg=lastchg)]))
        system = FakeAgingSystem([account('vboxuser', 1000, lastchg=TODAY - 300),
                                  account('locked', 1002, lastchg=1, bearing=False),
                                  account('compliant', 1004, maximum=90, lastchg=TODAY - 350)])  # untouched
        self.cycle(system)
        self.assertEqual([c for c in system.calls if type(c) is tuple], [('vboxuser', '--maxdays', 365)])

    def test_minimum_age_and_ambiguous_defaults_are_refused(self):
        for system in (FakeAgingSystem(login_defs=LOGIN_DEFS.replace(b'PASS_MIN_DAYS\t0', b'PASS_MIN_DAYS\t365')),
                       FakeAgingSystem([account('vboxuser', 1000, minimum=400)]),
                       FakeAgingSystem(login_defs=LOGIN_DEFS + b'PASS_MAX_DAYS 30\n'),
                       FakeAgingSystem(login_defs=LOGIN_DEFS.replace(b'PASS_MAX_DAYS\t99999\n', b''))):
            with self.subTest():self.refused(system)


class WarnDaysTests(AgingCase):
    CONTROL, PARAMS = '5.4.1.3', {'warndays': 7}

    def test_apply_restore_and_no_lockout_guard_needed(self):
        system = FakeAgingSystem(accounts() + [account('old', 1003, lastchg=TODAY - 900, warning=0)])
        self.assertEqual(collected(system, '5.4.1.3'), 'Non-Compliant')
        family, before = self.cycle(system)
        self.assertEqual(collected(system, '5.4.1.3'), 'Compliant')
        self.assertEqual(sorted(c for c in system.calls if type(c) is tuple),
                         [('old', '--warndays', 7), ('vboxuser', '--warndays', 7)])
        family.restore(self.PARAMS, before)
        self.assertEqual(family.read_state(self.PARAMS), before)


class InactiveTests(AgingCase):
    CONTROL, PARAMS = '5.4.1.5', {'inactive': 45}

    def test_apply_sets_the_useradd_default_and_failing_accounts(self):
        system = FakeAgingSystem()
        self.assertEqual(collected(system, '5.4.1.5'), 'Non-Compliant')
        family, before = self.cycle(system)
        self.assertEqual(collected(system, '5.4.1.5'), 'Compliant')
        self.assertEqual(system.useradd, USERADD + b'INACTIVE=45\n')
        self.assertEqual([c for c in system.calls if type(c) is tuple], [('vboxuser', '--inactive', 45)])
        family.restore(self.PARAMS, before)
        self.assertEqual((family.read_state(self.PARAMS), system.useradd), (before, USERADD))

    def test_missing_useradd_file_is_created_then_removed_on_restore(self):
        system = FakeAgingSystem(useradd=None)
        family, before = self.cycle(system)
        self.assertIn(b'INACTIVE=45\n', system.useradd)
        family.restore(self.PARAMS, before)
        self.assertIsNone(system.useradd)

    def test_expired_or_force_change_passwords_could_be_locked_so_are_refused(self):
        for record in (account('vboxuser', 1000, maximum=365, lastchg=TODAY - 380),
                       account('vboxuser', 1000, maximum=365, lastchg=TODAY - 350),
                       account('vboxuser', 1000, lastchg=0), account('vboxuser', 1000, lastchg=None)):
            with self.subTest(record=record):self.refused(FakeAgingSystem([record]))
        self.cycle(FakeAgingSystem([account('vboxuser', 1000, maximum=-1, lastchg=TODAY - 900)]))
        self.refused(FakeAgingSystem(useradd=USERADD + b'INACTIVE=30\nINACTIVE=60\n'))


class AccountParsingTests(unittest.TestCase):
    def test_records_never_carry_the_password_hash(self):
        from vm.ubuntu.family_aging import parse_accounts
        passwd = 'root:x:0:0:root:/root:/bin/bash\nvboxuser:x:1000:1000::/home/vboxuser:/bin/bash\n'
        shadow = 'root:!:19000:0:99999:7:::\nvboxuser:$y$j9T$secret$hash:20390:0:99999:7:::\n'
        records = parse_accounts(passwd, shadow)
        self.assertNotIn('secret', json.dumps(records))
        self.assertEqual([(r['name'], r['password_bearing'], r['lastchg']) for r in records],
                         [('root', False, 19000), ('vboxuser', True, 20390)])
        with self.assertRaises(ValueError):parse_accounts(passwd, shadow.splitlines()[0] + '\n')


class AgingRegistryTests(unittest.TestCase):
    def test_host_and_target_registries_agree_and_planners_need_a_complete_inventory(self):
        from backends.ubuntu.actions import FAMILIES
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_risk import evidence
        from tests.integration.ubuntu_fixtures import cases
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        target = build(FakeCoreSystem())
        expected = {'5.4.1.1': {'maxdays': 365}, '5.4.1.3': {'warndays': 7}, '5.4.1.5': {'inactive': 45}}
        ev = evidence(list(expected))
        obs = cases(); ev.raw = json.dumps({'observations': obs}).encode()
        for cid, params in expected.items():
            action = 'ubuntu.%s.v1' % cid
            self.assertEqual((FAMILIES[action].version, FAMILIES[action].implementation_sha256),
                             (target[action].version, target[action].implementation_sha256))
            self.assertEqual(FAMILIES[action].propose(cid, ev), params)
            obs[cid]['account_inventory'] = observation('incomplete')
            ev.raw = json.dumps({'observations': obs}).encode()
            self.assertIsNone(FAMILIES[action].propose(cid, ev))
