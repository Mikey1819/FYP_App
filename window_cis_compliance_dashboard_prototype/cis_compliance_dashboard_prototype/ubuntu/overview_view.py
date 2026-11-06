"""Ubuntu Overview page (placeholder until Ubuntu is linked; see ubuntu/__init__.py)."""
from .common import render_not_linked


def render_overview():
    render_not_linked('Overview', key='ubuntu_overview',
                      will_show='show this server\'s CIS compliance score and its highest-risk findings.')
