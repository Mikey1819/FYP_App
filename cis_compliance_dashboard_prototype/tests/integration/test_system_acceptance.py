"""Same existing page, two simulated transports; never connects to a live VM."""
import sys
import tempfile
import unittest
from pathlib import Path
from streamlit.testing.v1 import AppTest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from test_agentic import FakeVm
from test_winrm_channel import target
from hardening.winrm_channel import LiveScanner
from system.connection import ConnectionService
from system.ledger import CoordinationLedger
from system.identity import VerifiedIdentity
from system.bootstrap import SERVICE_KEY, WORKFLOW_KEY
from backends.windows.adapter import WindowsBackend
from backends.ubuntu.adapter import UbuntuBackend


def existing_page():
    import streamlit as st
    from pathlib import Path
    from hardening.agentic_view import render_agentic
    render_agentic(Path(st.session_state['fixture_database']))

class FixtureSsh:
    def verify_identity(self,request):
        return VerifiedIdentity('ubuntu',request.expected_hostname,request.expected_machine_identity,'22.04','ssh','SHA256:'+'a'*43)
    def close(self):pass

class SameUiAcceptanceTests(unittest.TestCase):
    def test_windows_ubuntu_windows_resume_without_secret_or_workflow_leak(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);ledger=CoordinationLedger(path/'integration.sqlite3');vm=FakeVm()
            factory=lambda runtime,t:LiveScanner(runtime,t,session_factory=vm)
            def backend_factory(session):
                if session.identity.platform=='windows':
                    return WindowsBackend(path/'windows'/'imports.sqlite3',session=session,ledger=ledger,scanner_factory=factory)
                return UbuntuBackend(path/'ubuntu'/'imports.sqlite3',session=session,ledger=ledger)
            service=ConnectionService(ledger,windows_scanner_factory=factory,ssh_factory=lambda *a:FixtureSsh(),backend_factory=backend_factory)
            app=AppTest.from_function(existing_page,default_timeout=30)
            app.session_state['fixture_database']=str(path/'windows'/'imports.sqlite3')
            app.session_state[SERVICE_KEY]=service
            app.run()
            def connect(platform):
                t=target()
                app.text_input(key='agentic_hostname').input(t.hostname if platform=='windows' else 'UBUNTU-FIXTURE')
                app.text_input(key='agentic_uuid').input(t.machine_uuid if platform=='windows' else 'a'*32)
                app.text_input(key='agentic_host').input('fixture.invalid')
                app.number_input(key='agentic_port').set_value(55985 if platform=='windows' else 22)
                app.text_input(key='agentic_user').input('fixture-user')
                app.text_input(key='agentic_password').input('FIXTURE-SECRET-SENTINEL')
                app.selectbox(key='agentic_method').select('WinRM' if platform=='windows' else 'SSH')
                app.run()
                app.button(key='agentic_connect').click().run()
                self.assertEqual(len(app.exception),0,[e.value for e in app.exception])
                self.assertFalse(list(app.error),[e.value for e in app.error])
            connect('windows')
            self.assertEqual(len(vm.scripts),1,'Connect may run identity only')
            app.button(key='agentic_assess_without_ai').click().run()
            self.assertEqual(len(app.exception),0,[e.value for e in app.exception])
            self.assertFalse(list(app.error),[e.value for e in app.error])
            workflow=app.session_state[WORKFLOW_KEY]
            self.assertEqual([x.label for x in app.tabs],['Fixes','Risk ranking','Controls','Results','Agent log'])
            app.button(key='agentic_disconnect').click().run()
            self.assertNotIn(WORKFLOW_KEY,app.session_state)
            from unittest import mock
            with mock.patch('backends.ubuntu.adapter.assessment_gate', return_value=('Ubuntu assessment is not enabled (test-closed gate).',)):
                connect('ubuntu')
                self.assertTrue(app.button(key='agentic_assess_without_ai').disabled)
            self.assertEqual([x.label for x in app.tabs],['Fixes','Risk ranking','Controls','Results','Agent log'])
            self.assertNotIn(WORKFLOW_KEY,app.session_state)
            app.button(key='agentic_disconnect').click().run()
            connect('windows')
            app.button(key='agentic_resume').click().run()
            self.assertFalse(list(app.error),[e.value for e in app.error])
            self.assertEqual(app.session_state[WORKFLOW_KEY],workflow)
            self.assertEqual(vm.writes,[])
            for database in path.rglob('*.sqlite3'):
                self.assertNotIn(b'FIXTURE-SECRET-SENTINEL',database.read_bytes())
