"""Reproduce the BENCHMARK_MAPPING.md source review: profile and audit text for selected controls.

Read-only. The licensed PDF is not copied into the repository; pass its path.
Usage (from the Windows project folder):
  .\\cis_compliance_dashboard_prototype\\.venv\\Scripts\\python.exe scripts\\extract_benchmark_audit.py ^
      "C:\\...\\CIS_Microsoft_Windows_Server_2022_Stand-alone_Benchmark_v2.0.0.pdf" out.txt
"""
import hashlib
import re
import sys

import pymupdf

EXPECTED_SHA256 = '474f467dd90b5cd50598589e427c2360502b8d25e633f729efd89f44662c5d1d'
CONTROLS = re.compile(r'^(1\.2\.3|2\.3\.1\.[34]|9\.[1-3]\.\d+|17\.(1\.1|2\.\d|5\.\d)|18\.10\.57\.(2\.2|3\.9\.\d))\s')


def main(pdf_path, out_path):
    digest = hashlib.sha256(open(pdf_path, 'rb').read()).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit('Unexpected benchmark file: ' + digest)
    document = pymupdf.open(pdf_path)
    with open(out_path, 'w', encoding='utf-8') as out:
        out.write(f'Source SHA-256 {digest}\n')
        for _, title, page in document.get_toc():
            if not CONTROLS.match(title.strip()):
                continue
            text = re.sub(r'\s+', ' ', document[page - 1].get_text() + ' ' + document[page].get_text())
            profile = re.search(r'Profile Applicability:(.*?)Description', text)
            audit = re.search(r'Audit:(.*?)(Remediation:|Default Value:)', text)
            out.write(f'== {title.strip()} | PDF page {page} (printed {page - 1})\n')
            out.write('   profile: ' + (profile.group(1).strip() if profile else '?') + '\n')
            out.write('   audit: ' + (audit.group(1).strip() if audit else 'NOT FOUND')[:700] + '\n')


if __name__ == '__main__':
    main(*sys.argv[1:3])
