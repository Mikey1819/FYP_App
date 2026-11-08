"""Per-session connection wiring. No authenticated objects in process-wide caches."""
from .config import PATHS
from .connection import ConnectionService
from .ledger import CoordinationLedger
from tools.baseline import verify_import_origin
from .session import clear_target_state

SERVICE_KEY = 'integration_connection_service'
CONNECTION_KEY = 'integration_connection_id'
WORKFLOW_KEY = 'integration_workflow_id'
FORM_KEY = 'integration_form_binding'
PUBLIC_FIELDS = ('hostname','uuid','host','port','user','method','auth','key_path','fingerprint')


def bind_form(state, prefix):
    state[FORM_KEY] = {prefix+'_'+name:state.get(prefix+'_'+name) for name in PUBLIC_FIELDS}


def invalidate_changed_form(state):
    binding = state.get(FORM_KEY)
    if not binding or not state.get(CONNECTION_KEY):
        return False
    # Hidden widgets may be removed by Streamlit; only a present, changed value is an edit.
    if any(key in state and state[key] != value for key,value in binding.items()):
        state[SERVICE_KEY].disconnect(state[CONNECTION_KEY])
        clear_target_state(state)
        return True
    return False


def connection_service(state):
    if SERVICE_KEY not in state:
        verify_import_origin(PATHS.app)
        PATHS.prepare()
        state[SERVICE_KEY] = ConnectionService(CoordinationLedger(PATHS.coordination))
    return state[SERVICE_KEY]


def active_backend(state):
    invalidate_changed_form(state)
    service = state.get(SERVICE_KEY)
    connection = state.get(CONNECTION_KEY)
    return service.backend_for(connection) if service and connection else None
