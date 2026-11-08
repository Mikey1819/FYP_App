from types import SimpleNamespace
import unittest
from system.session import clear_target_state


class FormBindingTests(unittest.TestCase):
    def test_stale_form_edit_invalidates_backend_and_clears_workflow_authority(self):
        from system.bootstrap import active_backend, bind_form
        class Service:
            def __init__(self):self.closed = []
            def disconnect(self,identifier):self.closed.append(identifier)
            def backend_for(self,identifier):return 'fixture-backend'
        service = Service()
        state = dict(integration_connection_service=service,integration_connection_id='connection',
                     integration_workflow_id='workflow',agentic_host='original',agentic_confirm_requests=('approved',),
                     agentic_password='')
        bind_form(state,'agentic')
        self.assertEqual(active_backend(state),'fixture-backend')
        state['agentic_host'] = 'different'
        self.assertIsNone(active_backend(state))
        self.assertEqual(service.closed,['connection'])
        self.assertNotIn('integration_workflow_id',state)
        self.assertNotIn('agentic_confirm_requests',state)

    def test_disconnect_clears_platform_specific_history_widget_refs(self):
        state = {'history_before_shared':'ubuntu:old','history_after':'windows:old','overview_target':'old',
                 'integration_form_binding':('old',),'agentic_host':'public-profile'}
        clear_target_state(state)
        self.assertEqual(state,{'agentic_host':'public-profile'})
