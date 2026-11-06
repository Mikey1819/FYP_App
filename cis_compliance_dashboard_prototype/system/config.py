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


# Reviewed deployment facts, keyed by verified machine identity (never inferred from a running service).
# FYP-Ubuntu2204: user-reported 2026-11-06 - UFW active and enabled, nftables disabled, netfilter-persistent
# absent; registration approved by the user in chat. The collector still checks competing managers per scan.
UBUNTU_FIREWALL_REGISTRATIONS = {'f1d16ae7e6bc4d2488f9410fcd858e36': 'ufw'}
