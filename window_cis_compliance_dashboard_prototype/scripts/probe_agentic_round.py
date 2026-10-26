"""Real local-model agentic round against the SIMULATED VM (tests/test_agentic.FakeVm).

Exercises qwen3:8b as Orchestrator and Scanner with the production prompts and tools.
Never contacts the real VM; writes isolated databases under data/agentic_probes/.
Usage (from the Windows project folder):
  .\\cis_compliance_dashboard_prototype\\.venv\\Scripts\\python.exe -B scripts\\probe_agentic_round.py
"""
from pathlib import Path
import json
import sys
import time
import uuid

APP = Path(__file__).resolve().parents[1] / 'cis_compliance_dashboard_prototype'
sys.path[:0] = [str(APP), str(APP / 'tests')]

from hardening.agentic import AgenticHardening  # noqa: E402
from hardening.framework import AssessmentOrchestrator  # noqa: E402
from hardening.import_storage import ImportedEvidenceStore  # noqa: E402
from hardening.remediation import RemediationStore  # noqa: E402
from hardening.winrm_channel import LiveScanner  # noqa: E402
from test_agentic import LAB_STATE, FakeVm  # noqa: E402
from test_winrm_channel import target  # noqa: E402


def main():
    folder = APP / 'data' / 'agentic_probes' / uuid.uuid4().hex
    folder.mkdir(parents=True)
    imports = ImportedEvidenceStore(folder / 'imports.sqlite3')
    runtime = AssessmentOrchestrator(imports)
    store = RemediationStore(folder / 'agentic.sqlite3', imports)
    # Realistic for the lab VM: Windows default audit (Success only) and unconfigured firewall/RDP policies.
    state = dict(LAB_STATE, **{'17.1.1': 1, '17.2.3': 1, '17.5.1': 1},
                 **{c: None for c in ('9.2.1', '9.2.2', '9.2.6', '9.2.7', '9.3.2', '9.3.6', '9.3.7', '18.10.57.2.2',
                                      '18.10.57.3.9.1', '18.10.57.3.9.3', '18.10.57.3.9.5')})
    vm = FakeVm(state)
    hardening = AgenticHardening(runtime, store, LiveScanner(runtime, target(), session_factory=vm))
    started = time.monotonic()
    result = hardening.run_round()
    summary = dict(seconds=round(time.monotonic() - started, 1), outcome=result['outcome'],
                   proposals=[{k: r['proposal'][k] for k in ('rank', 'control_id', 'action_id', 'reason')}
                              for r in store.for_run(result['framework_run_id'] or '')],
                   vm_writes=vm.writes, agents=[])
    for trace in hardening.traces(result['round_id']):
        finished = next((e['data'] for e in reversed(trace['events']) if e['kind'] == 'finished'), {})
        summary['agents'].append(dict(agent=trace['agent_role'], status=finished.get('status'),
            calls=[(e['kind'], e['data'].get('name'), e['data'].get('error')) for e in trace['events']
                   if e['kind'] in ('tool', 'tool_rejected')]))
    (folder / 'summary.json').write_text(json.dumps(summary, indent=2, default=str), encoding='utf-8')
    print(json.dumps(summary, indent=2, default=str))


if __name__ == '__main__':
    main()
