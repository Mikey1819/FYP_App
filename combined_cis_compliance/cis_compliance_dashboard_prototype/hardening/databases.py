"""Database locations shared by the dashboard pages."""
import os
from pathlib import Path

APP = Path(__file__).resolve().parents[1]


def imports_database():
    """Imported-evidence store. `CIS_DASHBOARD_DB` changes the base path; the default keeps the existing files."""
    database = Path(os.environ.get('CIS_DASHBOARD_DB', str(APP / 'data' / 'preview.sqlite3')))
    return database.with_name(database.stem + '_imports.sqlite3')
