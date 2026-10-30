"""Small presentation helpers shared by the pages: local times, severity and verdict badges."""
from datetime import datetime
import re

VERDICT_COLOR = {'verified': 'green', 'refused': 'gray', 'uncertain': 'orange', 'failed': 'red'}  # agentic.verdict_kind
LEVEL_COLOR = {'Critical': 'red', 'High': 'orange', 'Moderate': 'yellow', 'Low': 'blue'}


def local_time(iso, *, seconds=False):
    """Stored times are UTC ISO strings; the dashboard runs on the administrator's laptop, so show local time."""
    moment = datetime.fromisoformat(iso).astimezone()
    return moment.strftime('%d %b %H:%M:%S' if seconds else '%d %b %H:%M')


def md_escape(text):
    """Evidence, names and stored reasons are data: render them literally inside Markdown."""
    return re.sub(r'([\\`*_{}\[\]()<>#+\-.!|~:$])', r'\\\1', str(text))


def badge(text, color='gray', icon=None):
    """Inline Markdown badge. `text` must be code-written: it is not escaped."""
    return f":{color}-badge[{(':material/' + icon + ': ') if icon else ''}{text}]"


def level_badge(level):
    return badge(level, LEVEL_COLOR.get(level, 'gray'))
