import json
from pathlib import Path
import unittest


class ScapPlanTests(unittest.TestCase):
    def test_selected_rules_only_no_remediation_or_remote_fetch(self):
        from backends.ubuntu.scap_plan import prepare_scan
        app=Path(__file__).resolve().parents[2]
        plan=prepare_scan(app/'catalogues','a'*32,engine_version='1.3.7',fixture=True)
        self.assertGreater(len(plan.rule_ids),30)
        # OpenSCAP 1.2.17 (observed on the VM) honours only one --rule; scope comes from the pinned tailoring file.
        self.assertNotIn('--rule',plan.argv)
        self.assertEqual(plan.argv[plan.argv.index('--tailoring-file')+1],'/usr/local/share/fyp-hardening/fyp-selected-tailoring.xml')
        self.assertNotIn('--remediate',plan.argv)
        self.assertNotIn('--fetch-remote-resources',plan.argv)
        self.assertEqual(plan.argv[-1],'/usr/local/share/fyp-hardening/ssg-ubuntu2204-ds.xml')
        self.assertFalse(plan.live_eligible)
        with self.assertRaises(ValueError):prepare_scan(app/'catalogues','../../escape',engine_version='1.3.7',fixture=True)
        with self.assertRaisesRegex(ValueError,'accepted'):prepare_scan(app/'catalogues','a'*32,engine_version='1.3.7')
        live=prepare_scan(app/'catalogues','a'*32,engine_version='1.2.17')  # observed and accepted on the VM
        self.assertTrue(live.live_eligible)

    def test_known_unselected_results_are_discarded_but_extra_evaluated_rule_refused(self):
        from backends.ubuntu.scap import parse_results
        xml=('<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2"><target>fixture</target><profile idref="p"/>'
             '<rule-result idref="selected"><result>pass</result></rule-result>'
             '<rule-result idref="other"><result>notselected</result></rule-result></TestResult>').encode()
        kwargs=dict(expected_target='fixture',expected_profile='p',rule_ids=('selected',),known_rule_ids=('selected','other'))
        self.assertEqual(parse_results(xml,**kwargs),{'selected':'pass'})
        with self.assertRaises(ValueError):parse_results(xml.replace(b'notselected',b'pass'),**kwargs)
