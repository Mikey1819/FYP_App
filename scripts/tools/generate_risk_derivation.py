"""Write docs/design/RISK_DERIVATION.md from the risk engine itself, so the document cannot drift from the code.

Usage (from the Windows project folder):
  .\\cis_compliance_dashboard_prototype\\.venv\\Scripts\\python.exe scripts\\tools\\generate_risk_derivation.py
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'docs' / 'design' / 'RISK_DERIVATION.md'
sys.path.insert(0, str(ROOT / 'cis_compliance_dashboard_prototype'))
from hardening.risk import (ATTRIBUTES, BASELINE_VERSION, CONSEQUENCE, EFFECTIVE_PROTECTION, LIKELIHOOD,  # noqa: E402
                            PRIVILEGE_SCOPE, SURFACE_EXPOSURE, derive)
from hardening.server2022_catalogue import CATALOGUE  # noqa: E402


def main():
    lines = [
        '# Risk factor derivation', '',
        f'Generated from `hardening/risk.py` by `scripts/tools/generate_risk_derivation.py`; rule version `{BASELINE_VERSION}`. '
        'Do not edit by hand: change the attributes or rules in code and regenerate.', '',
        'The report formula is `R = 6I + 5E + 4P + 3L + 2D` (Section 4.6.2.4). No factor value is assigned directly. '
        'Each control records three attributes read from its CIS Stand-alone v2.0.0 entry, and fixed rules map them '
        'to I, P and L. The rules follow report Table 4.15, and the wording comes from the Table 4.14a/4.14c rubrics. '
        'E and D are determined at assessment time.', '',
        '## Rules', '',
        '**Security Impact (I).** Taken from the consequence stated in the benchmark Rationale/Impact text.', '',
        '| Consequence category | I | Rubric basis |', '| --- | --- | --- |',
        *[f'| `{k}` | {v[0]} | {v[1]} |' for k, v in CONSEQUENCE.items()], '',
        '**Privilege Impact (P).** Taken from the accounts, groups or rights the setting governs.', '',
        '| Privilege scope | P | Rubric basis |', '| --- | --- | --- |',
        *[f'| `{k}` | {v[0]} | {v[1]} |' for k, v in PRIVILEGE_SCOPE.items()], '',
        '**Likelihood (L).** Taken from the benchmark Profile Level and Assessment Status (Table 4.15).', '',
        '| Profile level | Assessment status | L |', '| --- | --- | --- |',
        *[f'| Level {lvl} | {"Automated" if auto else "Manual"} | {v} |' for (lvl, auto), v in LIKELIHOOD.items()], '',
        '**Exposure (E).** Base value from the exposure surface (Table 4.14b), plus 1 when the *collected* effective '
        'Public firewall state is disabled, for network-reachable surfaces. Surfaces: '
        + ', '.join(f'`{k}` = {v}' for k, v in SURFACE_EXPOSURE.items()) + '. '
        'Exception: for ' + ', '.join(EFFECTIVE_PROTECTION) + ', when the policy is Not configured but the collected '
        'effective local state shows the protection is on, E = 1 ("minimal exposure"). The finding stays '
        'Non-Compliant (decision D5) because CIS requires the policy itself.', '',
        '**Configuration State or Drift (D).** From the previous comparable assessment (Table 4.14e): 1 when there is '
        'none, 3 when the control was already non-compliant, 5 when it was compliant before (a regression). A scan '
        'that the Scanner Agent\'s own rescan replaced within the same round is not a previous assessment.', '',
        '## Per-control derivation', '',
        '| Control | Title | Consequence (I) | Privilege scope (P) | L | Surface (base E) | Base R with D=1 |',
        '| --- | --- | --- | --- | --- | --- | --- |',
    ]
    for control in CATALOGUE:
        a, d = ATTRIBUTES[control.control_id], derive(control.control_id)
        e = SURFACE_EXPOSURE[a.surface]
        score = 6 * d.impact + 5 * e + 4 * d.privilege + 3 * d.likelihood + 2
        lines.append(f'| {control.control_id} | {control.title} | `{a.consequence}` = {d.impact} | '
                     f'`{a.privilege_scope}` = {d.privilege} | {d.likelihood} | `{a.surface}` = {e} | {score} |')
    lines += ['', '## Limitations to state in the report', '',
              '- **L does not separate the selected controls.** All 32 are Level 1 and Automated, so L = 4 for every '
              'one; it adds a constant 12 to every score and has no effect on the ranking. This follows from applying '
              'Table 4.15 as written.',
              '- **Category assignment is a researcher judgement.** It is made once per control from the benchmark '
              'rationale and is recorded in code with a paraphrased rationale. It is not inferred at runtime, and the '
              'model never sets it.',
              '- **Exposure is configuration-based.** The NAT lab never establishes internet reachability, so E = 5 '
              'arises only from a collected disabled firewall.',
              '- **The score ranks findings; it does not predict anything.** It is not CVSS, not EPSS and not a '
              'probability of exploitation.', '']
    OUT.write_text('\n'.join(lines), encoding='utf-8')
    print('wrote', OUT)


if __name__ == '__main__':
    main()
