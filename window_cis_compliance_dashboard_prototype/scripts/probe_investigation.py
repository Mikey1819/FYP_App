"""Run a bounded local-model investigation against labelled fixtures only."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cis_compliance_dashboard_prototype"))

from hardening.demo_storage import load_demo
from hardening.investigation import Coordinator
from hardening.investigation_tools import InvestigationTools
from hardening.ollama_client import OllamaClient
from hardening.storage import AssessmentStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=("compatible_clients", "legacy_clients"), required=True)
    args = parser.parse_args()
    path = ROOT / "cis_compliance_dashboard_prototype" / "data" / "investigation_probe.sqlite3"
    store = AssessmentStore(path)
    load_demo(store)
    print(f"Starting local qwen3:8b investigation: {args.scenario}; synthetic evidence only", flush=True)
    run = Coordinator(OllamaClient(), InvestigationTools(store, "1042", scenario=args.scenario)).run()
    result = {"run_id": run["run_id"], "scenario": run["scenario"], "model": run["model"],
              "provenance": run["provenance"], "tools": [event["data"]["name"] for event in run["events"] if event["kind"] == "tool"],
              **run["events"][-1]["data"]}
    print(json.dumps(result, indent=2), flush=True)
    # Keep failed and successful runs separately; never overwrite previous evidence.
    (path.parent / f"probe_{args.scenario}_{run['run_id']}.json").write_text(json.dumps(run, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
