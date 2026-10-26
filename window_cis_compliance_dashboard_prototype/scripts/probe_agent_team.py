"""Actual local-model team probe on synthetic files only; never runs VM commands."""
from pathlib import Path
from datetime import datetime, timezone
import json
import sys
from uuid import uuid4

APP = Path(__file__).resolve().parents[1] / 'cis_compliance_dashboard_prototype'
sys.path[:0] = [str(APP), str(APP / 'tests')]
from hardening.agent_team import AgentTeam
from hardening.framework import AssessmentOrchestrator
from hardening.import_storage import ImportedEvidenceStore
from hardening.lifecycle import RemediationLifecycle
from hardening.vm_bridge import BridgeStore, encode
from test_local_security_controls import local_security_fixture
from test_expanded_controls import observation
from test_evidence_import import MACHINE_UUID


def main():
    folder = APP / 'data' / 'team_probes' / uuid4().hex
    folder.mkdir(parents=True)
    doc = local_security_fixture()
    observation(doc, '1.1.4')['value'] = 0
    imports = ImportedEvidenceStore(folder / 'imports.sqlite3')
    runtime = AssessmentOrchestrator(imports)
    bridge = BridgeStore(folder / 'bridge.sqlite3', imports)
    lifecycle = RemediationLifecycle(runtime, bridge)
    run = runtime.start(encode(doc), expected_hostname='FIXTURE-SERVER', expected_machine_uuid=MACHINE_UUID)
    runtime.complete_assessment(run.run_id)
    lifecycle.save_context(run.run_id, compatibility='compatible', operator='Synthetic evaluation fixture',
                           note='Synthetic compatible provisioning; no claim about any real VM.')
    team = AgentTeam(lifecycle, run.run_id)
    team.scenario = 'Synthetic fixture multi-agent evaluation; not real VM evidence'
    (folder / 'started.json').write_text(json.dumps(dict(team_id=team.team_id, framework_run_id=run.run_id,
        provenance=team.scenario, started_at=datetime.now(timezone.utc).isoformat()), indent=2), encoding='utf-8')
    print(str(folder), flush=True)
    result = team.run()
    traces = team.traces(bridge, run.run_id, team.team_id)
    output = dict(provenance=team.scenario, team_id=team.team_id, framework_run_id=run.run_id,
                  result=result['events'][-1]['data'], traces=traces,
                  lifecycle=lifecycle.get(run.run_id))
    (folder / 'result.json').write_text(json.dumps(output, indent=2), encoding='utf-8')
    print(json.dumps(dict(folder=str(folder), result=output['result'],
        agents=[dict(role=t['agent_role'], result=t['events'][-1]['data']) for t in traces]), indent=2), flush=True)


if __name__ == '__main__':
    main()
