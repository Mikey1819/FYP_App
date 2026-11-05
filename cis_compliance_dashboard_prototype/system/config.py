"""Integration data paths are explicit; legacy environment variables cannot select live data."""
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class IntegrationPaths:
    app: Path
    windows_imports: Path
    ubuntu_imports: Path
    coordination: Path

    @classmethod
    def for_app(cls, app):
        app = Path(app).resolve()
        data = app / 'data'
        return cls(app, data / 'windows' / 'integration_imports.sqlite3',
                   data / 'ubuntu' / 'integration_imports.sqlite3', data / 'integration.sqlite3')

    def prepare(self):
        for path in (self.windows_imports, self.ubuntu_imports, self.coordination):
            path.parent.mkdir(parents=True, exist_ok=True)


APP = Path(__file__).resolve().parents[1]
PATHS = IntegrationPaths.for_app(APP)
