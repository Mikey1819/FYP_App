"""Database locations shared by the dashboard pages."""
import os
from pathlib import Path

APP = Path(__file__).resolve().parents[1]


def imports_database():
    """Imported-evidence store. `CIS_DASHBOARD_DB` changes the base path; the default keeps the existing files."""
    database = Path(os.environ.get('CIS_DASHBOARD_DB', str(APP / 'data' / 'preview.sqlite3')))
    return database.with_name(database.stem + '_imports.sqlite3')


def servers_database():
    """Saved servers ("My servers"), next to the other databases and named after the imports file like them."""
    imports = imports_database()
    return imports.with_name(imports.stem + '_servers.sqlite3')
