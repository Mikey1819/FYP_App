"""Validate/evaluate a transferred file without changing the dashboard database."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cis_compliance_dashboard_prototype"))
from hardening.domain import summarise
from hardening.evidence_import import MAX_BYTES, load_evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--expected-hostname", required=True)
    parser.add_argument("--expected-machine-uuid", required=True)
    args = parser.parse_args()
    try:
        with args.file.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        assessment = load_evidence(raw, expected_hostname=args.expected_hostname,
                                   expected_machine_uuid=args.expected_machine_uuid)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Evidence rejected: {exc}\n")
    summary = summarise(assessment.results)
    output = {
        "mode": "Imported", "target_id": assessment.target_id, "hostname": assessment.hostname,
        "source_sha256": assessment.source_sha256, "collected_at": assessment.collected_at.isoformat(),
        "coverage": asdict(summary), "evaluated": summary.evaluated,
        "compliance_percent": summary.compliance_percent,
        "limitations": "Five-control subset; user-supplied evidence, not authenticated attestation. "
                       "No risk score, host changes or dashboard database writes.",
        "results": [{"control_id": r.control.control_id, "title": r.control.title,
                     "observed": r.evidence.value, "operator": r.control.rule.operator.value,
                     "expected": r.control.rule.expected, "status": r.status.value,
                     "detail": r.detail, "source": r.evidence.source,
                     "reference": r.control.source_reference} for r in assessment.results],
    }
    print(json.dumps(output, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
