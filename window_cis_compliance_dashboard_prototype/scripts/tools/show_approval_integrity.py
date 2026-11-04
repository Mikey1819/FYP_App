"""Show, step by step, that an approval is bound to the exact request the VM runner executed.

    python scripts/tools/show_approval_integrity.py [--request ID_PREFIX]

Reads the dashboard database read-only. For every approved request it recalculates the SHA-256 of the
saved approval and compares it with the hash the VM runner calculated and returned in its receipt. It
then shows what one changed value does to the hash, that the saved approval cannot be edited (tested on
an in-memory copy, so the database is never changed), and the expiry. It writes the exact request bytes
to a temporary file so Windows' own Get-FileHash can confirm the hash independently.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'cis_compliance_dashboard_prototype'))
from hardening.databases import imports_database
from hardening.evidence_import import encode

VM_LEDGER = r'C:\ProgramData\FYP-ApprovedVmActions'


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def refused(db, sql, params=()):
    try:
        db.execute(sql, params)
    except sqlite3.DatabaseError as exc:
        return 'refused: ' + str(exc)
    return 'ACCEPTED (the audit trail is not protected)'


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--request', default='', help='request ID prefix to use for steps 2-5 (default: first approved)')
    args = parser.parse_args()
    imports = imports_database()
    path = imports.with_name(imports.stem + '_agentic.sqlite3')
    if not path.exists():
        sys.exit(f'No dashboard database at {path}')
    db = sqlite3.connect(f'{path.as_uri()}?mode=ro', uri=True)
    approved = db.execute("SELECT id, payload FROM rem_decisions WHERE decision='approved' ORDER BY rowid").fetchall()
    receipts = {i: (json.loads(p), v) for i, p, v in db.execute('SELECT id, payload, verdict FROM rem_receipts')}
    if not approved:
        sys.exit('No approved requests yet: approve a fix in the dashboard first.')
    print(f'Approval integrity check: {path}\n')

    print('[1] Each approved request, and the hash the VM runner calculated on the server')
    for request_id, raw in approved:
        request = json.loads(raw)
        receipt = receipts.get(request_id)
        print(f"  {request['control_id']:<16} approved {request['approved_at'][:16].replace('T', ' ')} UTC by "
              f"{request['approved_by']}: {request['expected_before']} -> {request['value']}")
        print(f'     recalculated now from the saved approval: {sha256(raw)}')
        if receipt and 'request_sha256' in receipt[0]:
            vm_hash = receipt[0]['request_sha256']
            print(f"     calculated by the runner on the VM:        {vm_hash}  "
                  f"{'MATCH' if vm_hash == sha256(raw) else 'DIFFERENT'}")
            print(f'     VM result: {receipt[1]}')
        else:
            print('     not executed on the VM' + (f' ({receipt[1]})' if receipt else ''))

    chosen = next(((i, r) for i, r in approved if i.startswith(args.request)), None)
    if chosen is None:
        sys.exit(f'No approved request starts with {args.request!r}')
    request_id, raw = chosen
    request = json.loads(raw)
    print(f"\n[2] The saved approval for {request['control_id']}, exactly as the runner receives it")
    print('  ' + raw.decode('ascii'))
    print(f'  re-encoded unchanged:            {sha256(encode(request))}  (same as saved: {encode(request) == raw})')
    if type(request['value']) is int:
        tampered = dict(request, value=request['value'] + 1)
        label = f"value changed {request['value']} -> {tampered['value']}:"
        print(f'  {label:<33}{sha256(encode(tampered))}')
    tampered = dict(request, hostname='OTHER-SERVER')
    print(f'  hostname changed to OTHER-SERVER: {sha256(encode(tampered))}')
    print('  One changed character gives a different hash, so the runner stops with '
          '"Request hash does not match the approved request." before writing anything.')

    print('\n[3] The saved approval cannot be edited (tried on an in-memory copy; your database is unchanged)')
    copy = sqlite3.connect(':memory:')
    db.backup(copy)
    print('  change the approved value:        ' + refused(copy, "UPDATE rem_decisions SET payload=? WHERE id=?",
                                                         (encode(dict(request, value=0)), request_id)))
    print('  delete the approval:              ' + refused(copy, 'DELETE FROM rem_decisions WHERE id=?', (request_id,)))
    print('  add a second decision:            ' + refused(copy, 'INSERT INTO rem_decisions VALUES (?,?,?)',
                                                         (request_id, 'rejected', b'{}')))

    print('\n[4] Expiry')
    expires = datetime.fromisoformat(request['expires_at'])
    print(f"  approved {request['approved_at']}\n  expires  {request['expires_at']} (one hour later)")
    if expires <= datetime.now(timezone.utc):
        print('  It has expired, so the runner would now refuse it: "Approval expired or clock is incorrect."')
    else:
        print('  Still valid now.')

    sample = Path(tempfile.gettempdir()) / f'approved_request_{request_id[:8]}.json'
    sample.write_bytes(raw)
    print('\n[5] Check it with Windows\' own tool, in PowerShell:')
    print(f"  Get-FileHash '{sample}' -Algorithm SHA256")
    print(f'  It must print {sha256(raw).upper()}')
    print('  Inside the VM, the runner kept the bytes it executed, so the same command there gives the same hash:')
    print(f"  Get-FileHash '{VM_LEDGER}\\{request_id}.attempt' -Algorithm SHA256")


if __name__ == '__main__':
    main()
