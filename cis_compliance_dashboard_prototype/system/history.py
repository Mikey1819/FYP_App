"""Target-scoped read facade; the UI never chooses another platform's store."""
from .bootstrap import active_backend


def active_history(state, limit=50):
    backend = active_backend(state)
    if backend is None:
        return None, ()
    session = backend.session
    rows = backend.history(session.target_id, limit=limit)
    if any((r.run_reference.platform, r.run_reference.target_id) !=
           (session.identity.platform, session.target_id) for r in rows):
        raise ValueError('History returned a record outside the verified target')
    return backend, rows
