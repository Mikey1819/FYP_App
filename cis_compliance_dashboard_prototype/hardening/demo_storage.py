"""Explicit, idempotent fixture seeding and projections from persisted evidence."""

from .demo import (
    CURRENT_RESULTS, PREVIOUS_RESULTS, RISK_INPUTS, TARGET_ID, EXPLANATIONS,
    display_rule, display_value,
)
from .domain import EvidenceMode, change_kind, summarise
from .storage import AssessmentStore, RiskInput


def load_demo(store: AssessmentStore) -> dict:
    store.save(PREVIOUS_RESULTS, initiated_by="demo-admin", allow_identical=True)
    inputs = {key: RiskInput(*values, source="Illustrative demo baseline and synthetic exposure context")
              for key, values in RISK_INPUTS.items()}
    store.save(CURRENT_RESULTS, initiated_by="demo-admin", risk_inputs=inputs, allow_identical=True)
    snapshot = store.get("1042")
    results = snapshot.results
    controls = [
        {"id": r.control.control_id, "title": r.control.title,
         "observed": display_value(r.control.control_id, r.evidence.value),
         "expected": display_rule(r.control), "status": r.status.value,
         "source": r.evidence.source, "assessed_at": r.evidence.collected_at.isoformat(),
         "reference": r.control.source_reference}
        for r in results
    ]
    by_id = {r.control.control_id: r for r in results}
    risks = {
        risk.control_id: {"title": by_id[risk.control_id].control.title,
                          "score": risk.factors.score, "level": risk.factors.level,
                          "factors": risk.factors.as_dict(), "source": risk.source,
                          "explanation": EXPLANATIONS[risk.control_id]}
        for risk in sorted(snapshot.risks, key=lambda risk: (-risk.factors.score, risk.control_id))
    }
    drift = []
    for current in results:
        previous = store.previous_result(current)
        kind = change_kind(previous, current)
        if kind in ("Unchanged", "No comparable evidence"):
            continue
        drift.append({"Control": current.control.control_id,
                      "Previous value": display_value(previous.control.control_id, previous.evidence.value),
                      "Current value": display_value(current.control.control_id, current.evidence.value),
                      "Description": kind, "Detected at": current.evidence.collected_at.isoformat()})
    history = [
        {"Assessment": item.results[0].assessment_id, "Initiated by": item.initiated_by,
         "Started": min(r.evidence.collected_at for r in item.results).isoformat(),
         "Status": "Completed snapshot"}
        for item in store.history(target_id=TARGET_ID, mode=EvidenceMode.SYNTHETIC)
    ]
    return {"controls": controls, "risks": risks, "drift": drift,
            "history": history, "summary": summarise(results)}
