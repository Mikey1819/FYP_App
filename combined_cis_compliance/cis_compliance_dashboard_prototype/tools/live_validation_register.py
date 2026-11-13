"""Live-validation register, derived from stored records only (task 17). The same rules and words for both systems:
the 30 Ubuntu controls and the 32 Windows controls (each backend's live_validation gathers its own records).

A control is "Validated live" only when an administrator-approved fix was applied on the server and the automatic
verification scan read the control Compliant. Restores from before 12 November 2026 are listed by this command-line
tool beside it (the program no longer restores a control on either system). Everything is read from temporary copies
of the local stores; the stores and the VM are never opened for writing.

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


APPLIED = ('applied', 'reconciled_applied')
NOT_FIXES = ('recovery.', 'maintenance.', 'acceptance.')  # restores and auxiliary steps are never a control's fix
MANUAL = 'Manual on the server'
# What the statuses mean, in the same words on both systems' Overview and round reports.
NOTE = ('"Validated live": an approved fix was applied on this server and the automatic verification scan read the '
        'control Compliant. "Fixture-tested only": no live outcome is recorded, whatever the fixture tests show. '
        '"Manual on the server": this program never changes the control.')
STATUSES = ('Validated live', 'Applied, not verified', 'Refused', 'Fixture-tested only', MANUAL)


def register(controls, *, decisions, receipts, verifications, automated=None):
    """One row per control: status, the fix that proves it (or the latest attempt), the latest restore, and that fix's
    evidence (time, approver, request, round, workflow), from approved decisions and their receipts.

    A control is validated live when any approved fix of it was applied and the verification scan read it Compliant;
    a later failed attempt never hides that proof, nor does a later restore (no longer offered on either system, 12
    November 2026). Without any live outcome (no fix, or approved but never executed) it is fixture-tested only,
    whatever its fixture tests show; or, when `automated` (the controls this program has a fix for) leaves it out,
    "Manual on the server": this program never changes it (administrator, 14 November 2026: the same words on both
    systems)."""
    final, rows = _final(receipts), []
    when = lambda d: (final.get(d['request_id']) or {}).get('completed_at', '')  # noqa: E731
    for cid in controls:
        mine = [d for d in decisions if d['control_id'] == cid]
        fixes = sorted((d for d in mine if not d['action_id'].startswith(NOT_FIXES) and d['request_id'] in final),
                       key=when)
        restores = sorted((d for d in mine if d['action_id'].startswith('recovery.') and d['request_id'] in final),
                          key=when)
        proven = [d for d in fixes if final[d['request_id']]['outcome'] in APPLIED
                  and verifications.get(d['request_id']) == 'Compliant']
        fix = proven[-1] if proven else (fixes[-1] if fixes else None)
        receipt = final.get(fix['request_id']) if fix else None
        restore = restores[-1] if restores else None
        if fix is None:
            status = MANUAL if automated is not None and cid not in automated else 'Fixture-tested only'
        elif proven:
            status = 'Validated live'
        elif receipt['outcome'] in APPLIED or receipt['outcome'] == 'unresolved':
            status = 'Applied, not verified'  # applied without a Compliant scan, or its outcome is not known
        else:
            status = 'Refused'
        rows.append({'control_id': cid, 'status': status, 'attempts': len(fixes),
                     'fix': _describe(receipt, verifications.get(fix['request_id'])) if fix else '',
                     'restore': _describe(final.get(restore['request_id']), verifications.get(restore['request_id']))
                     if restore else '',
                     'evidence': {'time': receipt['completed_at'], 'approver': fix.get('approver'),
                                  'request_id': fix['request_id'], 'round_id': fix.get('round_id'),
                                  'workflow': fix.get('workflow')} if fix else None})
    return rows


def summary(rows):
    """"N of M validated live"."""
    validated = sum(r['status'] == 'Validated live' for r in rows)
    return '%d of %d validated live' % (validated, len(rows))


def _copy(path, folder):
    target = Path(folder) / path.name
    shutil.copyfile(path, target)
    return sqlite3.connect(target)


def collect_records():
    """Decisions, receipts and per-request verification statuses from temporary copies of the stores."""
    from backends.ubuntu.envelope import _avahi_retention
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
                              'action_id': data['action']['action_id'], 'approver': data.get('approver'),
                              'round_id': data.get('round_id'), 'workflow': data.get('workflow_session_id')})
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
            doc = json.loads(row[0])
            observations = doc['observations']
            for request in data['details'].get('request_ids', []):
                cid = controls_of.get(request)
                if cid in observations:
                    # As the app evaluates: with the machine's registered 2.1.2 retention review (live 17:57: the
                    # masked units read Compliant in the app but Unknown here without it).
                    verifications[request] = evaluate(cid, observations[cid],
                                                      reviewed_avahi_retention=_avahi_retention(doc)).status.value
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
             'Summary: ' + summary(rows) + ' (' + ', '.join('%s %d' % (k, v) for k, v in sorted(counts.items())) + ')', '',
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
