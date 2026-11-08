"""Source preservation gate. Never modifies a baseline or source file."""
import hashlib
import importlib
import json
from pathlib import Path


def content_sha256(path):
    """SHA-256 of a file's text with CRLF read as LF: a Windows checkout (CRLF) and a copy with LF line endings are
    the same source, so only a real edit shows as a change."""
    return hashlib.sha256(Path(path).read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def edit_report(root, manifest):
    root = Path(root).resolve()
    report = {'protected': [], 'authorized_ui': [], 'metadata': [], 'missing': []}
    for name, record in manifest['files'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root):
            raise ValueError('Manifest path escapes source root')
        if not path.is_file():
            report['missing'].append(name)
        elif content_sha256(path) != record['sha256']:
            report[record['category']].append(name)
    return {key: tuple(value) for key, value in report.items()}


def verify_baseline(root, manifest):
    report = edit_report(root, manifest)
    return tuple(f'{kind}:{name}' for kind in ('missing', 'protected') for name in report[kind])


def verify_import_origin(app):
    expected = Path(app).resolve() / 'hardening'
    package = importlib.import_module('hardening')
    if Path(package.__file__).resolve().parent != expected:
        raise ValueError('Windows package resolved outside this application')
    for name in ('agentic', 'winrm_channel', 'remediation', 'risk', 'domain'):
        module = importlib.import_module('hardening.' + name)
        if Path(module.__file__).resolve() != expected / (name + '.py'):
            raise ValueError('Protected Windows module was shadowed: ' + name)


if __name__ == '__main__':
    app = Path(__file__).resolve().parents[1]
    manifest = json.loads((app / 'baseline_manifest.json').read_text(encoding='utf-8'))
    verify_import_origin(app)
    print(json.dumps(edit_report(app.parent, manifest), indent=2))
    raise SystemExit(bool(verify_baseline(app.parent, manifest)))
