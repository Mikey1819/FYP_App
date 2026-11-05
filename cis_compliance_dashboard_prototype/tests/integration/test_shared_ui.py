import importlib.util
import unittest
from streamlit.testing.v1 import AppTest

def connection_form():
    from hardening.connection_view import render_connection
    render_connection(key='fixture')

def snapshot_panels():
    import streamlit as st
    from system.ui.components import render_snapshot_tabs
    render_snapshot_tabs(st.session_state['snapshot'])

class SharedUiTests(unittest.TestCase):
    def test_same_form_has_neutral_fields_and_advanced_transport(self):
        app=AppTest.from_function(connection_form,default_timeout=20).run()
        self.assertEqual(len(app.exception),0)
        labels=[x.label for x in app.text_input]
        self.assertIn('VM machine identity',labels)
        self.assertIn('VM IP address / host',labels)
        self.assertIn('Username',labels)
        self.assertEqual(app.selectbox(key='fixture_method').value,'Auto')
        self.assertTrue(app.button(key='fixture_connect').disabled)
        self.assertEqual(app.text_input(key='fixture_host').value,'')

    def test_same_tabs_display_platform_specific_counts(self):
        self.assertIsNotNone(importlib.util.find_spec('system.ui.components'))
        from system.contracts import RecordRef, TargetSummary, WorkspaceSnapshot, AssessmentSummary
        for platform,count in [('windows',32),('ubuntu',30)]:
            ref=RecordRef(platform,platform+':fixture','scan')
            snap=WorkspaceSnapshot(TargetSummary(ref,'FIXTURE','Test only','fixture','Synthetic','connected'),
                summary=AssessmentSummary.from_counts(ref,count,0,0,count,0,'fixture','2026-11-05T00:00:00+00:00'))
            app=AppTest.from_function(snapshot_panels,default_timeout=20)
            app.session_state['snapshot']=snap
            app.run()
            self.assertEqual(len(app.exception),0)
            self.assertEqual([tab.label for tab in app.tabs],['Fixes','Risk ranking','Controls','Results','Agent log'])
            self.assertTrue(any(str(count)+' selected' in c.value for c in app.caption))
