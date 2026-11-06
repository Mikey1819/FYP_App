"""Streamlit must not hot-reload app modules under a live session.

Streamlit evicts every watched app module from sys.modules when any watched source file event passes its
change check, then re-imports them on the next rerun. Objects kept in st.session_state (the ledger inside
ConnectionService, the verified SSH session) keep the old classes, while modules imported afterwards get new
ones. On 2026-11-06 this made the Ubuntu store reject a ledger binding ("Ubuntu workflow binding required").
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest

APP = Path(__file__).resolve().parents[2]

REPRO = '''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from system.ledger import CoordinationLedger
ledger = CoordinationLedger(Path(sys.argv[2]) / 'ledger.sqlite3')
for name in [n for n in sys.modules if n.split('.')[0] in ('system', 'backends', 'vm', 'hardening')]:
    del sys.modules[name]
from backends.ubuntu.storage import UbuntuStore
try:
    UbuntuStore._check_binding(ledger.assessment_binding('ubuntu', 'ubuntu:x', 'epoch', 'op'), 'ubuntu:x', 'epoch')
    print('accepted')
except ValueError as exc:
    print('rejected: ' + str(exc))
'''


class StreamlitReloadTests(unittest.TestCase):
    def test_module_eviction_splits_classes_so_the_watcher_must_stay_off(self):
        # The mechanism itself: a ledger made before eviction yields bindings the re-imported store rejects.
        with tempfile.TemporaryDirectory() as folder:
            out = subprocess.run([sys.executable, '-B', '-c', REPRO, str(APP), folder], capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), 'rejected: Ubuntu workflow binding required', out.stderr[-500:])
        config = tomllib.loads((APP / '.streamlit' / 'config.toml').read_text(encoding='utf-8'))
        self.assertEqual(config.get('server', {}).get('fileWatcherType'), 'none')
        self.assertFalse(config.get('server', {}).get('runOnSave', False))
