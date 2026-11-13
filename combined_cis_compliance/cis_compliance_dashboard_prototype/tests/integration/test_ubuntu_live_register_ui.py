"""Module 3: the live-validation register, read-only, from the stored approvals, receipts and verification scans of
this server; with "N of 30 validated live", each row's evidence, the round where a control was proven, and the same
table in the round report. Since 13 November 2026 (administrator) it is on Overview, shown once the server has an
assessment, and no longer on Agentic hardening. TEST-ONLY family and fake server; the VM is never contacted."""
from unittest import mock
from tests.integration import test_ubuntu_maintenance_ui as maintenance_ui


def overview_page():
    import streamlit as st
    from pathlib import Path
    from hardening.overview_view import render_overview
    render_overview(Path(st.session_state['fixture_database']))


class LiveRegisterUiTests(maintenance_ui.MaintenanceUiTests):
    def register(self, app):
        return {r['Control']: r for frame in app.dataframe for r in frame.value.to_dict('records')
                if 'Proven (MYT)' in r}

    def overview(self, agentic):
        """Overview in the same browser session as the Agentic hardening page `agentic`."""
        from streamlit.testing.v1 import AppTest
        from system.bootstrap import CONNECTION_KEY, SERVICE_KEY, WORKFLOW_KEY
        app = AppTest.from_function(overview_page, default_timeout=60)
        for key in ('fixture_database', SERVICE_KEY, CONNECTION_KEY, WORKFLOW_KEY):
            if key in agentic.session_state:
                app.session_state[key] = agentic.session_state[key]
        app.run()
        self.assertFalse(list(app.error), [e.value for e in app.error])
        return app

    def validated(self):
        """A round whose fix is approved, executed and verified Compliant; returns the Agentic hardening app."""
        app, _ = self.page()
        app.button(key='agentic_run').click().run()
        app.text_input(key='agentic_operator').input('fixture-operator').run()
        self.keyed(app, 'ubuntu_approve_', exclude='ubuntu_approve_all')[0].click().run()
        self.model_up = False
        app.button(key='ubuntu_execute_review').click().run()
        self.aslr = '2'  # the fake server reads 1.5.1 compliant from here on (the fixture's write is a TEST-ONLY file)
        app.button(key='ubuntu_execute').click().run()
        app.run()
        self.assertFalse(list(app.error), [e.value for e in app.error])
        return app

    def test_overview_shows_it_only_once_there_is_an_assessment(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            app, _ = self.page()
            self.assertEqual(self.register(self.overview(app)), {})  # nothing assessed yet: no register
            app.button(key='agentic_run').click().run()
            self.assertEqual(self.register(app), {})  # no longer on Agentic hardening
            over = self.overview(app)
            rows = self.register(over)
            self.assertEqual(len(rows), 30)
            self.assertEqual({r['Status'] for r in rows.values()}, {'Fixture-tested only'})
            self.assertTrue(any('0 of 30 validated live' in e.label for e in over.expander), [e.label for e in over.expander])

    def test_the_register_shows_what_was_proven_live_with_its_evidence(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            over = self.overview(self.validated())
            rows = self.register(over)
            self.assertEqual(rows['1.5.1']['Status'], 'Validated live')
            self.assertEqual(rows['1.5.1']['Approver'], 'fixture-operator')
            self.assertEqual(len(rows['1.5.1']['Request']), 8)  # the approved request, shortened
            self.assertNotEqual(rows['1.5.1']['Proven (MYT)'], '—')
            self.assertEqual(rows['3.3.2']['Status'], 'Fixture-tested only')
            self.assertTrue(any('1 of 30 validated live' in e.label for e in over.expander), [e.label for e in over.expander])

    def test_open_round_goes_to_agentic_hardening_on_the_round_where_it_was_proven(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        from hardening.agentic_view import GO_AGENTIC
        from system.bootstrap import WORKFLOW_KEY
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            app = self.validated()
            workflow = app.session_state[WORKFLOW_KEY]
            app.button(key='agentic_reset').click().run()  # New session: the register is about the server, not a session
            over = self.overview(app)
            over.selectbox(key='ubuntu_register_round').select('1.5.1').run()
            over.button(key='ubuntu_register_open').click().run()
            self.assertEqual(over.session_state[WORKFLOW_KEY], workflow)
            self.assertTrue(over.session_state[GO_AGENTIC])  # app.py then opens Agentic hardening

    def test_the_round_report_gets_the_same_register(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        import system.ui.round_report as report
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), \
                mock.patch.object(report, 'ubuntu_round_report', wraps=report.ubuntu_round_report) as built:
            self.validated()
        rows = {r['control_id']: r for r in built.call_args.kwargs['register']}
        self.assertEqual(rows['1.5.1']['status'], 'Validated live')
        self.assertEqual(len(rows), 30)


for _name in [n for n in dir(maintenance_ui.MaintenanceUiTests) if n.startswith('test')]:
    setattr(LiveRegisterUiTests, _name, None)  # only the harness is inherited
