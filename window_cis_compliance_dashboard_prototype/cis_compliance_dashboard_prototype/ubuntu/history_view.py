"""Ubuntu History and drift page (placeholder until Ubuntu is linked; see ubuntu/__init__.py)."""
from .common import render_not_linked


def render_history():
    render_not_linked('History and configuration drift', key='ubuntu_history',
                      will_show='list this server\'s earlier scans and show which settings drifted between them.')
