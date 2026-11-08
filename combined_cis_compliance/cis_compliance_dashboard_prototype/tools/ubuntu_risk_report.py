"""Write docs/UBUNTU_RISK_DERIVATION.md from the risk manifest for human review.

Usage (from the application directory): python -B -m tools.ubuntu_risk_report
The report is generated, never edited by hand, and changes nothing about activation.
"""
from pathlib import Path
from backends.ubuntu.risk import derive, load_policy

APP = Path(__file__).resolve().parents[1]
OUTPUT = APP/'docs'/'UBUNTU_RISK_DERIVATION.md'


def render(policy):
    lines = ['# Ubuntu risk derivation (generated)', '',
             f'Policy: **{policy.version_label}**. Generated from `catalogues/ubuntu2204-risk.json` by '
             '`tools/ubuntu_risk_report.py`; do not edit by hand.', '',
             'Method: the Windows rubric `R = 6I + 5E + 4P + 3L + 2D`, reusing its category tables, likelihood mapping, '
             'surface baselines and bands (Low 20–39, Moderate 40–59, High 60–79, Critical 80–100). Only confirmed '
             'Non-Compliant findings are scored. L is a compatibility heuristic, not a measured exploit probability. '
             'E is the base surface exposure only; no Linux effective-context adjustment has been reviewed. '
             'D is 1 with no comparable prior, 3 for a persistent failure, 5 for a regression.', '',
             'Scores are withheld in the dashboard until a named reviewer approves this policy.', '',
             '## Linux extensions requiring review', '', '| Kind | Name | Score | Reason |', '| --- | --- | --- | --- |']
    for kind, table in policy.tables.items():
        for name, (score, reason) in table.items():
            if reason.startswith('Linux extension: '):
                lines.append(f'| {kind} | `{name}` | {score} | {reason[len("Linux extension: "):]} |')
    lines += ['', '## Per-control factors', '',
              '| Control | Consequence (I) | Privilege (P) | Surface (E) | L | Score D=1 / 3 / 5 | Rationale (paraphrase) |',
              '| --- | --- | --- | --- | --- | --- | --- |']
    for cid in sorted(policy.controls, key=lambda c: [int(p) for p in c.split('.')]):
        a, d = policy.controls[cid], derive(policy, cid)
        base = 6*d.impact + 5*d.surface_score + 4*d.privilege + 3*d.likelihood
        scores = ' / '.join(str(base + 2*drift) for drift in (1, 3, 5))
        lines.append(f"| {cid} | {a['consequence']} ({d.impact}) | {a['privilege_scope']} ({d.privilege}) | "
                     f"{a['surface']} ({d.surface_score}) | {d.likelihood} | {scores} | {a['rationale']} |")
    return '\n'.join(lines) + '\n'


def main():
    OUTPUT.write_text(render(load_policy()), encoding='utf-8')
    print(OUTPUT)


if __name__ == '__main__':
    main()
