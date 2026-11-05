"""Per-browser in-memory secrets. Never cache this module's instances globally."""
from dataclasses import dataclass, field
from uuid import uuid4


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str | None = field(default=None, repr=False)
    key_path: str | None = field(default=None, repr=False)
    sudo_password: str | None = field(default=None, repr=False)
    confirmed_fingerprint: str | None = None

    def __post_init__(self):
        if not self.username.strip() or bool(self.password) == bool(self.key_path):
            raise ValueError('Select exactly one password or SSH key authentication method')


class CredentialVault:
    def __init__(self):
        self._values = {}

    def put(self, credentials):
        key = uuid4().hex
        self._values[key] = credentials
        return key

    def take(self, key):
        try:
            return self._values.pop(key)
        except KeyError:
            raise ValueError('Credential reference is absent or expired') from None

    def clear(self):
        self._values.clear()


def clear_target_state(state):
    """Remove workflow/widget authority when disconnecting; retain only public form profiles."""
    for key in tuple(state):
        if key in ('vm_live_target', 'integration_connection_id', 'integration_workflow_id', 'integration_form_binding',
                   'overview_target') or key.startswith(
                ('agentic_session', 'agentic_confirm', 'agentic_round_view', 'agentic_tab', 'agentic_operator',
                 'agentic_comment', 'agentic_goal', 'agentic_password', 'agentic_sudo_password', 'history_')):
            state.pop(key, None)
