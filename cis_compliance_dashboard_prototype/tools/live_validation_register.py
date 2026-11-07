"""Live-validation register for the 30 Ubuntu controls, derived from stored records only (task 17).

A control is "Validated live" only when an administrator-approved fix was applied on the VM and the automatic
verification scan read the control Compliant. Restores are reported beside it. Everything is read from temporary
copies of the local stores; the stores and the VM are never opened for writing.

Usage (from the app directory):
  ..\\.venv-integration\\Scripts\\python.exe -B -m tools.live_validation_register            # print markdown
  ..\\.venv-integration\\Scripts\\python.exe -B -m tools.live_validation_register --write    # docs/evaluation/LIVE_VALIDATION.md
"""
from pathlib import Path
import argparse
import json
import shutil
import sqlite3
import tempfile

APP = Path(__file__).resolve().parents[1]
FINAL = ('applied', 'reconciled_applied', 'refused', 'rolled_back', 'reconciled_not_applied', 'unresolved')


def _final(receipts):
    """request -> its last non-running receipt."""
    latest = {}
    for r in sorted(receipts, key=lambda r: r['completed_at']):
        if r['outcome'] in FINAL:
            latest[r['request_id']] = r
    return latest


def _describe(receipt, verification):
    if receipt is None:
        return 'approved, no outcome recorded'
    text = '%s %s (request %s)' % (receipt['outcome'], receipt['completed_at'], receipt['request_id'])
    if receipt['outcome'] != 'applied':
        text = '%s (%s) %s (request %s)' % (receipt['outcome'], receipt['code'], receipt['completed_at'], receipt['request_id'])
    return text + (', verification: ' + verification if verification else '')


def register(controls, *, decisions, receipts, verifications):
    """One row per control: status, latest fix and latest restore, from approved decisions and their receipts."""
    final, rows = _final(receipts), []
    for cid in controls:
        mine = [d for d in decisions if d['control_id'] == cid]
        when = lambda d: (final.get(d['request_id']) or {}).get('completed_at', '')  # noqa: E731
        fixes = sorted((d for d in mine if d['action_id'].startswith('ubuntu.')), key=when)
        restores = sorted((d for d in mine if d['action_id'].startswith('recovery.')), key=when)
        fix = fixes[-1] if fixes else None
        receipt = final.get(fix['request_id']) if fix else None
        verified = verifications.get(fix['request_id']) if fix else None
        if fix is None:
            status = 'Not run live'
        elif receipt is not None and receipt['outcome'] in ('applied', 'reconciled_applied'):
            status = 'Validated live' if verified == 'Compliant' else 'Applied, not verified Compliant'
        elif receipt is None:
            status = 'Approved, not executed'
        else:
            status = 'Attempted, not applied'
        restore = restores[-1] if restores else None
        rows.append({'control_id': cid, 'status': status, 'attempts': len(fixes),
                     'fix': _describe(receipt, verified) if fix else '',
                     'restore': _describe(final.get(restore['request_id']), verifications.get(restore['request_id']))
                     if restore else ''})
    return rows


def _copy(path, folder):
    target = Path(folder) / path.name
    shutil.copyfile(path, target)
    return sqlite3.connect(target)


def collect_records():
    """Decisions, receipts and per-request verification statuses from temporary copies of the stores."""
    from backends.ubuntu.predicates import evaluate
    folder = tempfile.mkdtemp()
    try:
        agentic = _copy(APP / 'data' / 'ubuntu' / 'integration_imports_agentic.sqlite3', folder)
        imports = _copy(APP / 'data' / 'ubuntu' / 'integration_imports.sqlite3', folder)
        decisions = []
        for decided, payload in agentic.execute('SELECT decision, payload FROM rem_decisions'):
            if decided != 'approved':
                continue
            data = json.loads(payload)
            decisions.append({'request_id': data['request_id'], 'control_id': data['control_id'],
                              'action_id': data['action']['action_id']})
        receipts = [json.loads(p) for (p,) in agentic.execute('SELECT payload FROM rem_receipts')]
        controls_of = {d['request_id']: d['control_id'] for d in decisions}
        verifications = {}
        for (payload,) in agentic.execute('SELECT payload FROM agentic_rounds'):
            data = json.loads(payload)
            if data.get('kind') != 'verification':
                continue
            row = imports.execute('SELECT raw FROM imported_assessments WHERE digest=?', (data['evidence_sha256'],)).fetchone()
            if row is None:
                continue
            observations = json.loads(row[0])['observations']
            for request in data['details'].get('request_ids', []):
                cid = controls_of.get(request)
                if cid in observations:
                    verifications[request] = evaluate(cid, observations[cid]).status.value
        agentic.close(); imports.close()
        return decisions, receipts, verifications
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def markdown(rows):
    counts = {}
    for r in rows:
        counts[r['status']] = counts.get(r['status'], 0) + 1
    lines = ['# Ubuntu live-validation register', '',
             'Generated by `tools/live_validation_register.py` from the stored approvals, receipts and verification '
             'scans (temporary copies; nothing typed in). "Validated live" means an administrator-approved fix was '
             'applied on FYP-Ubuntu2204 and the automatic verification scan read the control Compliant. Every other '
             'control is unvalidated live, whatever its fixture tests show.', '',
             'Summary: ' + ', '.join('%s %d' % (k, v) for k, v in sorted(counts.items())), '',
             '| Control | Status | Fix attempts | Latest fix | Latest restore |', '| --- | --- | --- | --- | --- |']
    lines += ['| %s | %s | %d | %s | %s |' % (r['control_id'], r['status'], r['attempts'], r['fix'] or '-',
                                              r['restore'] or '-') for r in rows]
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--write', action='store_true', help='write docs/evaluation/LIVE_VALIDATION.md')
    args = parser.parse_args()
    from backends.ubuntu.adapter import _controls
    decisions, receipts, verifications = collect_records()
    text = markdown(register(sorted(_controls(), key=lambda c: [int(x) for x in c.split('.')]),
                             decisions=decisions, receipts=receipts, verifications=verifications))
    if args.write:
        (APP / 'docs' / 'evaluation' / 'LIVE_VALIDATION.md').write_text(text, encoding='utf-8')
    print(text)


if __name__ == '__main__':
    main()
