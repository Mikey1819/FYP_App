"""Ubuntu Agentic hardening page (placeholder until Ubuntu is linked; see ubuntu/__init__.py)."""
from .common import render_not_linked


def render_agentic():
    render_not_linked('Agentic hardening', key='ubuntu_agentic',
                      will_show='run the agents on this server: scan, rank the findings, propose fixes from a fixed '
                                'list, and apply only the fixes you approve.')
