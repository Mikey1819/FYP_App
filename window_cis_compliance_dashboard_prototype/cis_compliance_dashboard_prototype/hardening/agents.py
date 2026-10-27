"""Policy-driven assessment roles. No model calls or OS commands.

The first RemediationAgent capability is eligibility assessment, not execution.
The existing human-approved VM bridge still owns the execution exchange.
"""
from dataclasses import asdict

from .actions import ACTION_REGISTRY
from .domain import EvidenceMode, Status, summarise
from .evidence_import import load_evidence


class ScannerAgent:
    role = "Scanner Agent"
    operation = "assess_imported_evidence"

    def run(self, record):
        # Re-evaluate the stored source with the reviewed catalogue, rather than
        # accepting an externally supplied status or result snapshot as truth.
        mode = record.assessment.results[0].evidence.mode
        assessment = load_evidence(record.raw, expected_hostname=record.assessment.hostname,
            expected_machine_uuid=record.assessment.target_id.removeprefix("windows:"), mode=mode)
        if assessment != record.assessment:
            raise ValueError("Stored assessment differs from its validated source")
        return {"summary": asdict(summarise(assessment.results)),
                "controls": [{"control_id": r.control.control_id, "status": r.status.value}
                             for r in assessment.results],
                "collection": ("Collected live over WinRM by the Scanner Agent" if mode == EvidenceMode.LIVE
                               else "Imported file; no live scan performed")}


class AnalysisAgent:
    role = "Analysis Agent"
    operation = "classify_follow_up"

    def run(self, record):
        results = record.assessment.results
        return {
            "non_compliant": [r.control.control_id for r in results if r.status == Status.NON_COMPLIANT],
            "needs_evidence": [r.control.control_id for r in results if r.status in (Status.UNKNOWN, Status.ERROR)],
            "risk_score": None,
            "risk_status": "Unavailable: reviewed real-evidence factor mapping is not implemented",
            "ai_status": "Not invoked by this assessment stage",
        }


class RemediationAgent:
    role = "Remediation Agent"
    operation = "identify_eligible_actions"

    def run(self, record):
        candidates = []
        unsupported = []
        for result in record.assessment.results:
            actions = [a for a in ACTION_REGISTRY.values() if a.eligible(result)]
            candidates.extend({"action_id": a.action_id, "control_id": a.control_id,
                               "parameters": a.parameters, "impact": a.impact,
                               "requires_human_approval": True} for a in actions)
            if result.status == Status.NON_COMPLIANT and not actions:
                unsupported.append(result.control.control_id)
        return {"candidates": candidates, "assessment_only_findings": unsupported,
                "authorization": "None: eligibility is not a proposal, approval or execution"}
