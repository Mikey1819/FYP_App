"""Strict investigative tool boundary. No approval, execution or arbitrary code."""

from dataclasses import asdict

from .domain import EvidenceMode
from .storage import AssessmentStore, _encode_result
from .workflow import WorkflowStore


DESCRIPTIONS = {
    "get_control_reference": "Read the stored comparison rule and unverified benchmark reference.",
    "get_finding_evidence": "Read immutable observed evidence, status and fixed risk score.",
    "inspect_related_configuration": "Read synthetic RDP/client compatibility context before considering remediation.",
    "get_previous_results": "Read the previous compatible assessment result, if one exists.",
    "get_supported_remediation": "Read the permitted simulated action and exact parameters, if supported.",
    "submit_remediation_proposal": "Save a proposal for administrator review only, after checking evidence, reference, related context and supported action. Cannot approve or execute.",
}


class InvestigationTools:
    def __init__(self, store: AssessmentStore, assessment_id: str, *, scenario="compatible_clients"):
        if scenario not in ("compatible_clients", "legacy_clients"):
            raise ValueError("Unknown synthetic investigation scenario")
        self.store = store
        self.assessment_id = assessment_id
        self.snapshot = store.get(assessment_id)
        self.results = {r.control.control_id: r for r in self.snapshot.results}
        self.target_id = self.snapshot.results[0].evidence.target_id
        if self.target_id != "DEMO-SERVER-2022" or any(r.evidence.mode != EvidenceMode.SYNTHETIC for r in self.snapshot.results):
            raise ValueError("Investigation currently supports synthetic demo evidence only")
        self.scenario = scenario
        self.seen = set()
        self.proposal_id = None

    def schemas(self):
        definitions = []
        for name, description in DESCRIPTIONS.items():
            properties = {"target_id": {"type": "string", "enum": [self.target_id]},
                          "control_id": {"type": "string", "enum": list(self.results)}}
            if name == "submit_remediation_proposal":
                properties.update(action_id={"type": "string", "enum": ["DEMO-ENABLE-NLA"]},
                                  parameters={"type": "object", "properties": {"required": {"type": "boolean", "const": True}},
                                              "required": ["required"], "additionalProperties": False},
                                  reason={"type": "string", "maxLength": 2000})
            definitions.append({"type": "function", "function": {"name": name, "description": description,
                "parameters": {"type": "object", "properties": properties,
                               "required": list(properties), "additionalProperties": False}}})
        return definitions

    def call(self, name, arguments):
        if name not in DESCRIPTIONS:
            raise ValueError("Unknown or forbidden investigative tool")
        required = {"target_id", "control_id"}
        if name == "submit_remediation_proposal":
            required |= {"action_id", "parameters", "reason"}
        if type(arguments) is not dict or set(arguments) != required:
            raise ValueError("Tool arguments must match the exact schema")
        target, control_id = arguments["target_id"], arguments["control_id"]
        if type(target) is not str or target != self.target_id or type(control_id) is not str or control_id not in self.results:
            raise ValueError("Target or control is outside the selected assessment")
        result = self.results[control_id]
        if name == "get_control_reference":
            output = asdict(result.control)
        elif name == "get_finding_evidence":
            output = _encode_result(result)
            risk = next((r for r in self.snapshot.risks if r.control_id == control_id), None)
            output["fixed_risk_score"] = risk.factors.score if risk else None
        elif name == "get_previous_results":
            previous = self.store.previous_result(result)
            output = {"previous": _encode_result(previous) if previous else None}
        elif name == "inspect_related_configuration":
            output = {"mode": "Synthetic", "source": "Named investigation fixture: " + self.scenario,
                      "nla_client_compatibility": "supported" if self.scenario == "compatible_clients" else "legacy clients need review",
                      "operational_review_required": self.scenario == "legacy_clients",
                      "proposal_allowed": self.scenario == "compatible_clients",
                      "internet_exposure": "Unknown; not inferred from local settings"}
        elif name == "get_supported_remediation":
            if control_id == "DEMO-NLA" and self.scenario == "compatible_clients":
                output = {"action_id": "DEMO-ENABLE-NLA", "parameters": {"required": True},
                          "mode": "Simulated", "proposal_allowed": True}
            else:
                output = {"action_id": None, "proposal_allowed": False,
                          "reason": "Operational compatibility review required" if self.scenario == "legacy_clients" else "No supported action"}
        else:
            needed = {("get_control_reference", control_id), ("get_finding_evidence", control_id),
                      ("inspect_related_configuration", control_id), ("get_supported_remediation", control_id)}
            if self.proposal_id or not needed <= self.seen:
                raise ValueError("Proposal requires reference, evidence, context and action lookup; only one proposal per investigation")
            if self.scenario == "legacy_clients":
                raise ValueError("Synthetic legacy-client context requires operational review; proposal withheld")
            proposal = WorkflowStore(self.store).create_proposal(
                assessment_id=self.assessment_id, target_id=target, control_id=control_id,
                action_id=arguments["action_id"], parameters=arguments["parameters"], reason=arguments["reason"])
            self.proposal_id = proposal.proposal_id
            output = {"proposal_id": proposal.proposal_id, "state": "Awaiting Approval", "executed": False}
        self.seen.add((name, control_id))
        return {"evidence_reference": f"{self.assessment_id}/{control_id}/{name}", "data": output}
