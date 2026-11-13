"""Reproduce the docs/design/BENCHMARK_MAPPING.md source review from the benchmark PDF.

For every candidate recommendation in the five selected security areas, the script extracts the title, the PDF and
printed page, the Profile Applicability and the Rationale, Impact and Audit text, and marks whether the control is one
of the 32 controls in the program's catalogue (hardening/server2022_catalogue.py). It ends with a check that every
catalogue control was found in the PDF. Read-only: the licensed PDF is not copied into the repository; pass its path.
First written on 26 October 2026 for the firewall, audit and Remote Desktop candidates; extended on 11 November 2026 to
cover all five areas and all 32 selected controls, with the Rationale and Impact text.

Usage (from the project folder; needs the PyMuPDF package):
  .\\.venv-integration\\Scripts\\python.exe scripts\\tools\\extract_benchmark_audit.py ^
      "C:\\...\\CIS_Microsoft_Windows_Server_2022_Stand-alone_Benchmark_v2.0.0.pdf" out.txt
"""
import hashlib
from pathlib import Path
import re
import sys

import pymupdf

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'cis_compliance_dashboard_prototype'))
from hardening.server2022_catalogue import BENCHMARK_SHA256, CATALOGUE  # noqa: E402

EXPECTED_SHA256 = '474f467dd90b5cd50598589e427c2360502b8d25e633f729efd89f44662c5d1d'
assert EXPECTED_SHA256 == BENCHMARK_SHA256, 'script and catalogue name different benchmark files'

# Candidate recommendations in the five areas: Account Policies (1.1, 1.2), Local Security Options (2.3.1, 2.3.10),
# Windows Defender Firewall (9.1-9.3), Advanced Audit Policy (17.1.1, 17.2, 17.5) and Remote Desktop (18.10.57.2.2,
# 18.10.57.3.9).
CONTROLS = re.compile(r'^(1\.[12]\.\d+|2\.3\.1\.\d+|2\.3\.10\.\d+|9\.[1-3]\.\d+|17\.(1\.1|2\.\d|5\.\d)'
                      r'|18\.10\.57\.(2\.2|3\.9\.\d))\s')
SELECTED = {c.control_id: c for c in CATALOGUE}


def section(text, start, ends):
    """Text between a heading such as 'Rationale:' and the next of the given headings."""
    m = re.search(start + r'\s*:(.*?)(?:' + '|'.join(e + r'\s*:' for e in ends) + '|$)', text, flags=re.S)
    return re.sub(r'\s+', ' ', m.group(1)).strip() if m else ''


def main(pdf_path, out_path):
    digest = hashlib.sha256(open(pdf_path, 'rb').read()).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit('Unexpected benchmark file: ' + digest)
    document = pymupdf.open(pdf_path)
    toc = document.get_toc()
    found = set()
    count = 0
    with open(out_path, 'w', encoding='utf-8') as out:
        out.write(f'Source SHA-256 {digest}\n')
        out.write(f'Candidates in the five areas; [SELECTED] marks the {len(SELECTED)} controls in the program catalogue.\n\n')
        for k, (_, title, page) in enumerate(toc):
            title = title.strip()
            if not CONTROLS.match(title):
                continue
            cid = title.split(' ')[0]
            if cid in found:
                continue
            next_page = next((p for _, _, p in toc[k + 1:] if p > page), page + 3)
            last = min(next_page, page + 5)
            text = ' '.join(document[i].get_text() for i in range(page - 1, last))
            text = re.sub(r'Page \d+', ' ', text).replace('\u2022', ' ')
            selected = cid in SELECTED
            if selected:
                found.add(cid)
            count += 1
            out.write(f"== {title} | PDF page {page} (printed {page - 1})"
                      + (f" [SELECTED: {SELECTED[cid].area}]" if selected else '') + '\n')
            out.write('   profile: ' + (section(text, 'Profile Applicability', ['Description']) or '?') + '\n')
            out.write('   rationale: ' + (section(text, 'Rationale', ['Impact', 'Audit']) or 'NOT FOUND') + '\n')
            out.write('   impact: ' + (section(text, 'Impact', ['Audit']) or 'NOT FOUND') + '\n')
            out.write('   audit: ' + (section(text, 'Audit', ['Remediation', 'Default Value'])
                                      or 'NOT FOUND')[:700] + '\n\n')
        missing = sorted(set(SELECTED) - found)
        out.write(f'Summary: {count} candidates extracted; {len(found)} of {len(SELECTED)} selected controls found'
                  + (f'; missing: {", ".join(missing)}' if missing else '') + '\n')
    print(f'{count} candidates, {len(found)} of {len(SELECTED)} selected controls found'
          + (f'; missing: {missing}' if missing else ''))


if __name__ == '__main__':
    main(*sys.argv[1:3])
