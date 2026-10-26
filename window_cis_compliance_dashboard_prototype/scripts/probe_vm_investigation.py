"""Local Ollama probe using an explicitly selected imported VM file. Never approves or executes."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cis_compliance_dashboard_prototype"))
from hardening.import_storage import ImportedEvidenceStore
from hardening.investigation import Coordinator
from hardening.ollama_client import OllamaClient
from hardening.vm_bridge import BridgeStore
from hardening.vm_investigation import VmInvestigationTools


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--uuid", required=True)
    args = parser.parse_args()
    folder = ROOT / "cis_compliance_dashboard_prototype/data/vm_model_probe"
    imports = ImportedEvidenceStore(folder / "imports.sqlite3")
    record, _ = imports.save(args.evidence.read_bytes(), expected_hostname=args.hostname,
                             expected_machine_uuid=args.uuid)
    store = BridgeStore(folder / "bridge.sqlite3", imports)
    print("Starting local qwen3:8b imported-evidence investigation; no approval or execution.", flush=True)
    run = Coordinator(OllamaClient(), VmInvestigationTools(store, record.assessment.source_sha256)).run()
    path = folder / (run["run_id"] + ".json")
    path.write_text(json.dumps(run, indent=2), encoding="utf-8")
    print(json.dumps({"run_id": run["run_id"], "evidence_mode": run["evidence_mode"],
                      "tools": [e["data"]["name"] for e in run["events"] if e["kind"] == "tool"],
                      **run["events"][-1]["data"]}, indent=2), flush=True)
    print("Saved trace: " + str(path), flush=True)


if __name__ == "__main__":
    main()
