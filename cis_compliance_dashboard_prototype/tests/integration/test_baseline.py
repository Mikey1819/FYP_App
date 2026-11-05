import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

class BaselineTests(unittest.TestCase):
    def test_protected_changes_and_authorized_edits_are_distinct(self):
        spec = importlib.util.find_spec('tools.baseline')
        self.assertIsNotNone(spec, 'baseline verifier must exist')
        from tools.baseline import verify_baseline, edit_report
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'engine.py').write_bytes(b'original')
            (root/'app.py').write_bytes(b'original')
            digest=hashlib.sha256(b'original').hexdigest()
            manifest={'files':{'engine.py':{'sha256':digest,'category':'protected'},
                               'app.py':{'sha256':digest,'category':'authorized_ui'}}}
            self.assertEqual(verify_baseline(root,manifest),())
            (root/'app.py').write_bytes(b'integrated')
            self.assertEqual(verify_baseline(root,manifest),())
            self.assertEqual(edit_report(root,manifest)['authorized_ui'],('app.py',))
            (root/'engine.py').write_bytes(b'changed')
            self.assertEqual(verify_baseline(root,manifest),('protected:engine.py',))
            (root/'engine.py').unlink()
            self.assertEqual(verify_baseline(root,manifest),('missing:engine.py',))

    def test_import_origin_rejects_shadow_package(self):
        spec=importlib.util.find_spec('tools.baseline')
        self.assertIsNotNone(spec, 'baseline verifier must exist')
        from tools.baseline import verify_import_origin
        app=Path(__file__).resolve().parents[2]
        verify_import_origin(app)
        with self.assertRaises(ValueError):
            verify_import_origin(app/'another-checkout')
