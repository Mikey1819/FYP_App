"""Independent cross-check of the dashboard's stored scan against values read another way in the VM.

    python scripts/cross_check_controls.py [--digest SHA256] [--out table.md]
    python scripts/cross_check_controls.py --file crosscheck.json

Default: compares the latest stored scan, connecting over WinRM to the VM that scan came from
(identity and administrator checks first, password typed here and never stored), and runs the
read-only scripts/Get-CrossCheckValues.ps1 there. With --file it uses JSON saved inside the VM
with that script's -OutFile instead. Reads the dashboard database only; prints a Markdown table.
"""
import argparse
from datetime import datetime
from getpass import getpass
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'cis_compliance_dashboard_prototype'))
from hardening.databases import imports_database
from hardening.import_storage import ImportedEvidenceStore
from hardening.winrm_channel import DEFAULT_HOST, DEFAULT_PORT, ChannelError, LiveScanner, WinRmTarget

SCRIPT = Path(__file__).resolve().with_name('Get-CrossCheckValues.ps1')
STALE_MINUTES = 60  # A setting may have changed between the scan and the cross-check.


def same(a, b):
    # Strict types, so a Guest-enabled False never matches a 0 from another control's reader.
    return type(a) is type(b) and a == b


def verdict(dashboard, checked):
    if dashboard is None and checked is None:
        return 'Agree (not set)'
    if same(dashboard, checked):
        return 'Agree'
    if dashboard is None:
        return 'Dashboard had no value'
    if checked is None:
        return 'Cross-check read no value'
    return '**Disagree**'


def compare(results, rows):
    found = {row['control_id']: row for row in rows}
    lines = []
    for result in results:
        row = found.get(result.control.control_id)
        if row is None:
            lines.append((result.control.control_id, result.evidence.value, None, 'missing from cross-check',
                          'Cross-check read no value'))
        else:
            lines.append((result.control.control_id, result.evidence.value, row['value'],
                          f"{row['raw']} ({row['method']})", verdict(result.evidence.value, row['value'])))
    return lines


def read_vm(assessment, args):
    target = WinRmTarget(assessment.hostname, assessment.target_id.removeprefix('windows:'), args.username,
                         getpass(f'Password for {args.username} on {assessment.hostname}: '), args.host, args.port)
    scanner = LiveScanner(None, target)
    scanner.identity()  # Right VM and an administrator token, before anything else runs there.
    output, had_errors, errors = scanner._run(SCRIPT.read_text(encoding='utf-8-sig'), {'EmitJson': True})
    if had_errors or len(output) != 1:
        raise ChannelError('channel_error', 'Cross-check failed inside the VM: ' + '; '.join(errors)[:300])
    return json.loads(output[0])


def show(value):
    return 'not set' if value is None else json.dumps(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--file', type=Path, help='JSON saved inside the VM by Get-CrossCheckValues.ps1 -OutFile')
    parser.add_argument('--digest', help='stored scan to compare (default: the latest)')
    parser.add_argument('--db', type=Path, default=imports_database())
    parser.add_argument('--out', type=Path, help='also write the Markdown table here')
    parser.add_argument('--host', default=DEFAULT_HOST)
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--username', default='Administrator')
    args = parser.parse_args()
    report = json.loads(args.file.read_text(encoding='utf-8-sig')) if args.file else None
    store = ImportedEvidenceStore(args.db)
    digest = args.digest or next((r['digest'] for r in store.recent() if report is None
                                  or r['hostname'].casefold() == report['hostname'].casefold()), None)
    if digest is None:
        parser.exit(2, f'No matching stored scan in {args.db}. Scan the VM from the dashboard first.\n')
    assessment = store.get(digest).assessment
    if report is None:
        try:
            report = read_vm(assessment, args)
        except ChannelError as exc:
            parser.exit(2, f'Not compared ({exc.state}): {exc.detail}\n')
    elif report['hostname'].casefold() != assessment.hostname.casefold():
        parser.exit(2, f"The cross-check is from {report['hostname']}, the scan from {assessment.hostname}.\n")
    checked_at = datetime.fromisoformat(report['collected_at'])
    gap = abs((checked_at - assessment.collected_at).total_seconds()) / 60
    lines = compare(sorted(assessment.results, key=lambda r: [int(p) for p in r.control.control_id.split('.')]),
                    report['rows'])
    agree = sum(line[4].startswith('Agree') for line in lines)
    table = [f"Dashboard scan `{digest[:12]}` at {assessment.collected_at:%Y-%m-%d %H:%M} UTC; cross-check of "
             f"{report['hostname']} at {checked_at:%Y-%m-%d %H:%M} UTC.", '',
             '| Control | Dashboard | Cross-check | Cross-check reading | Result |', '| --- | --- | --- | --- | --- |']
    table += [f'| {cid} | {show(d)} | {show(c)} | {raw} | {result} |' for cid, d, c, raw, result in lines]
    table += ['', f'**{agree} of {len(lines)} controls agree.**']
    if gap > STALE_MINUTES:
        table.append(f'Warning: the scan and the cross-check are {gap:.0f} minutes apart; '
                     'scan again just before the cross-check if any setting changed.')
    text = '\n'.join(table)
    print(text)
    if args.out:
        args.out.write_text(text + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
