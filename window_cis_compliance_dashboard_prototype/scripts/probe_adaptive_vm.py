"""Actual local-model evaluation on labelled synthetic fixtures. No approval/execution."""
import argparse
import json
from pathlib import Path
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'cis_compliance_dashboard_prototype'
sys.path.insert(0, str(APP))
sys.path.insert(0, str(APP / 'tests'))
from test_evidence_import import export_fixture, MACHINE_UUID
from hardening.framework import AssessmentOrchestrator
from hardening.import_storage import ImportedEvidenceStore
from hardening.investigation import Coordinator, Limits
from hardening.lifecycle import RemediationLifecycle
from hardening.ollama_client import OllamaClient
from hardening.vm_bridge import BridgeStore, encode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenarios', nargs='+', choices=['compatible', 'unknown', 'incompatible', 'compliant'],
                        default=['unknown', 'compatible', 'incompatible'])
    args = parser.parse_args()
    folder = APP / 'data' / 'adaptive_probes' / uuid4().hex
    folder.mkdir(parents=True)
    imports = ImportedEvidenceStore(folder / 'imports.sqlite3')
    runtime = AssessmentOrchestrator(imports)
    bridge = BridgeStore(folder / 'bridge.sqlite3', imports)
    service = RemediationLifecycle(runtime, bridge)
    summaries = []
    for scenario in args.scenarios:
        doc = export_fixture()
        doc['observations'][0]['value'] = 14 if scenario == 'compliant' else 0
        run = runtime.start(encode(doc), expected_hostname='FIXTURE-SERVER', expected_machine_uuid=MACHINE_UUID)
        runtime.complete_assessment(run.run_id)
        if scenario in ('compatible', 'incompatible'):
            service.save_context(run.run_id, compatibility=scenario, operator='SYNTHETIC FIXTURE',
                note=('Fixture provisioning scripts support passwords of at least 14 characters.' if scenario == 'compatible'
                      else 'Fixture legacy provisioning script truncates passwords to eight characters; update it first.'))
        tools = service.investigation_tools(run.run_id)
        tools.evidence_mode = 'Synthetic fixture using imported-evidence schema'
        tools.scenario = 'SYNTHETIC FIXTURE: ' + scenario
        print(f'Starting {scenario}; local qwen3:8b, no approval or execution. Output: {folder}', flush=True)
        trace = Coordinator(OllamaClient(), tools, limits=Limits()).run()
        (folder / (trace['run_id'] + '.json')).write_text(json.dumps(trace, indent=2), encoding='utf-8')
        finished = trace['events'][-1]['data']
        actual = (finished.get('outcome') or {}).get('outcome')
        # Explicit fixed-rule comparator, not a model trace or independent ground truth.
        baseline = {'unknown': 'awaiting_context', 'compatible': 'awaiting_approval',
                    'incompatible': 'deferred', 'compliant': 'no_action'}[scenario]
        summary = dict(scenario=scenario, run_id=trace['run_id'], framework_run_id=run.run_id,
            baseline_outcome=baseline, actual_outcome=actual, matches_baseline=actual == baseline,
            tools=[e['data']['name'] for e in trace['events'] if e['kind'] == 'tool'],
            rejected_tools=sum(e['kind'] == 'tool_rejected' for e in trace['events']), **finished)
        summaries.append(summary)
        (folder / 'summary.json').write_text(json.dumps(summaries, indent=2), encoding='utf-8')
        print(json.dumps(summary), flush=True)
        # An unavailable service/model is an external blocker, not a reason for repeated unchanged requests.
        if finished['status'] == 'Unavailable':
            break
    print('Saved evaluation: ' + str(folder / 'summary.json'), flush=True)


if __name__ == '__main__':
    main()
