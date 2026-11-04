"""Small presentation helpers shared by the pages: Malaysia times, severity and verdict badges."""
from datetime import datetime, timedelta, timezone
import re

# Classic cartoon accents on top of .streamlit/config.toml: bold black outlines, a "pop" shadow and yellow
# highlights. Selectors are Streamlit's data-testid hooks; if one changes, only the decoration is lost.
CARTOON_CSS = """<style>
h1 [data-heading-text] { background: linear-gradient(transparent 62%, #FFC72C 62%); padding: 0 .15em; }
[data-testid="stLayoutWrapper"] > [data-testid="stVerticalBlock"], [data-testid="stTextInputRootElement"],
[data-testid="stExpander"] details { border-width: 2px; }
[data-testid^="stBaseButton-primary"], [data-testid^="stBaseButton-secondary"], [data-testid="stDownloadButton"] button {
  border: 2px solid #1C1C1C; box-shadow: 3px 3px 0 #1C1C1C; transition: transform .05s, box-shadow .05s; }
[data-testid^="stBaseButton-primary"]:active, [data-testid^="stBaseButton-secondary"]:active,
[data-testid="stDownloadButton"] button:active { transform: translate(2px, 2px); box-shadow: 1px 1px 0 #1C1C1C; }
button:disabled { box-shadow: none !important; border-color: #B8B0A0 !important; }
[data-testid="stMetric"] { background: #FFFFFF; border: 2px solid #1C1C1C; border-radius: 1rem;
  box-shadow: 4px 4px 0 #1C1C1C; padding: .75rem 1rem; }
[data-testid="stDataFrame"] { box-shadow: 4px 4px 0 #1C1C1C; border-radius: .75rem; }
[data-baseweb="tab-highlight"] { background-color: #FFC72C; height: 4px; }
[data-testid="stSidebarNavLink"][aria-current="page"] { background: #FFC72C; }
[data-testid="stSidebarNavLink"][aria-current="page"] * { color: #1C1C1C; }
</style>"""

VERDICT_COLOR = {'verified': 'green', 'refused': 'gray', 'uncertain': 'orange', 'failed': 'red'}  # agentic.verdict_kind
LEVEL_COLOR = {'Critical': 'red', 'High': 'orange', 'Moderate': 'yellow', 'Low': 'blue'}


# Malaysia is UTC+8 all year (no daylight saving), so a fixed offset is exact and needs no time zone database.
MYT = timezone(timedelta(hours=8), 'MYT')
FULL = '%Y-%m-%d %H:%M:%S'


def myt(value, fmt='%d %b %H:%M'):
    """A stored time (UTC ISO string or datetime) shown in Malaysia time. Storage stays UTC; only display converts,
    independent of the laptop's own time zone setting."""
    moment = datetime.fromisoformat(value) if isinstance(value, str) else value
    if moment.tzinfo is None:  # Stored times are UTC.
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(MYT).strftime(fmt)


def md_escape(text):
    """Evidence, names and stored reasons are data: render them literally inside Markdown."""
    return re.sub(r'([\\`*_{}\[\]()<>#+\-.!|~:$])', r'\\\1', str(text))


def badge(text, color='gray', icon=None):
    """Inline Markdown badge. `text` must be code-written: it is not escaped."""
    return f":{color}-badge[{(':material/' + icon + ': ') if icon else ''}{text}]"


def level_badge(level):
    return badge(level, LEVEL_COLOR.get(level, 'gray'))
