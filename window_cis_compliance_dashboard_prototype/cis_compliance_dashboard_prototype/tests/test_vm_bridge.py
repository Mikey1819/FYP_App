"""Offline boundary tests. Never launch real collection or security commands."""
import base64
from copy import deepcopy
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from hardening.evidence_import import CONTEXT_SOURCES, load_evidence, effective_context
from hardening.import_storage import ImportedEvidenceStore
from hardening.investigation import Coordinator
from hardening.vm_bridge import BridgeStore, encode
from hardening.vm_investigation import VmInvestigationTools
from hardening.vm_paths import workspace_path, runner_command
from test_evidence_import import export_fixture, MACHINE_UUID, NOW, load
from test_investigation import MockClient


class ContextTests(unittest.TestCase):
    def fixture(self):
        data = export_fixture()
        data.update(schema_version=2, collector_id="server2022-readonly-v2")
        data["effective_context"] = [dict(control_id=k, source=s, state="ok", value=v, error=None,
            collected_at=data["observations"][0]["collected_at"]) for (k, s), v in
            zip(CONTEXT_SOURCES.items(), [True, 1, 0])]
        for row in data["observations"][3:]:
            row.update(state="missing", value=None)
        return data

    def test_enabled_effective_state_does_not_rewrite_missing_policy(self):
        data = self.fixture()
        result = load(data)
        self.assertEqual([r.status.value for r in result.results[3:]], ["Unknown", "Unknown"])
        self.assertEqual(len(effective_context(encode(data))), 3)
        self.assertEqual(effective_context(encode(export_fixture())), [])

    def test_context_types_provenance_duplicates_and_failure_states(self):
        for field, value in (("value", "True"), ("value", 1), ("source", "invented"),
                             ("collected_at", "2020-01-01T00:00:00Z"), ("state", "guess")):
            data = self.fixture()
            data["effective_context"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                load(data)
        data = self.fixture()
        data["effective_context"][0].update(state="error", value=None, error="timeout")
        load(data)
        data["effective_context"][1] = deepcopy(data["effective_context"][0])
        with self.assertRaises(ValueError):
            load(data)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.imports = ImportedEvidenceStore(Path(folder.name) / "imports.sqlite3")
        data = export_fixture()
        data["observations"][0]["value"] = 0
        self.raw = encode(data)
        self.saved, _ = self.imports.save(self.raw, expected_hostname="FIXTURE-SERVER",
                                         expected_machine_uuid=MACHINE_UUID, now=NOW)
        self.store = BridgeStore(Path(folder.name) / "bridge.sqlite3", self.imports)
        self.digest = self.saved.assessment.source_sha256

    def approved(self):
        identifier = self.store.propose(self.digest)
        request = self.store.decide(identifier, approve=True, operator="fixture-admin", now=NOW)
        return identifier, request

    def receipt(self, identifier, request, value=14, status="applied"):
        evidence = []
        for offset, minimum in ((1, 0), (2, value)):
            data = export_fixture()
            start = NOW + timedelta(minutes=offset)
            data["started_at"] = start.isoformat()
            data["completed_at"] = (start + timedelta(seconds=30)).isoformat()
            for row in data["observations"]:
                row["collected_at"] = (start + timedelta(seconds=15)).isoformat()
            data["observations"][0]["value"] = minimum
            evidence.append(base64.b64encode(encode(data)).decode())
        return dict(schema_version=1, request_id=identifier,
                    request_sha256=hashlib.sha256(request).hexdigest(), status=status,
                    before_evidence=evidence[0], after_evidence=evidence[1])

    def test_rejection_no_request_and_decision_cannot_be_reused(self):
        identifier = self.store.propose(self.digest)
        self.assertIsNone(self.store.decide(identifier, approve=False, operator="fixture"))
        self.assertIsNone(self.store.get(identifier)["request"])
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.decide(identifier, approve=True, operator="fixture")

    def test_verified_receipt_is_bound_persistent_and_idempotent_preserves_original(self):
        identifier, request = self.approved()
        raw = encode(self.receipt(identifier, request))
        verdict = self.store.accept_receipt(raw, now=NOW + timedelta(hours=1))
        self.assertEqual(verdict, "Verified compliant")
        reopened = BridgeStore(self.store.path, self.imports)
        self.assertEqual(reopened.accept_receipt(raw, now=NOW + timedelta(hours=1)), verdict)
        self.assertEqual(reopened.get(identifier)["verdict"], verdict)
        self.assertEqual(self.imports.get(self.digest).raw, self.raw)
        self.assertEqual(len(self.imports.recent()), 3)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.decide(identifier, approve=True, operator="again")

    def test_failed_postcheck_and_execution_are_not_success(self):
        for value, status, expected in ((0, "applied", "Verification failed"),
                                         (14, "execution_failed", "Unresolved: execution_failed")):
            identifier, request = self.approved()
            verdict = self.store.accept_receipt(encode(self.receipt(identifier, request, value, status)),
                                               now=NOW + timedelta(hours=1))
            self.assertEqual(verdict, expected)

    def test_mismatched_hash_target_precondition_time_and_unapproved_receipts_rejected(self):
        identifier, request = self.approved()
        base = self.receipt(identifier, request)
        bad = deepcopy(base); bad["request_sha256"] = "0" * 64
        cases = [bad]
        for slot, key, value in (("before_evidence", "value", 5),
                                 ("after_evidence", "uuid", "cb095a4c-5a1c-48fe-b199-fda775b130a8"),
                                 ("after_evidence", "time", "2020-01-01T00:00:00+00:00")):
            bad = deepcopy(base)
            doc = json.loads(base64.b64decode(bad[slot]))
            if key == "value": doc["observations"][0]["value"] = value
            elif key == "uuid": doc["target"]["machine_uuid"] = value
            else: doc["started_at"] = value
            bad[slot] = base64.b64encode(encode(doc)).decode()
            cases.append(bad)
        bad = deepcopy(base); bad["after_evidence"] = None; cases.append(bad)
        bad = deepcopy(base); bad["request_id"] = self.store.propose(self.digest); cases.append(bad)
        for bad in cases:
            with self.assertRaises(ValueError):
                self.store.accept_receipt(encode(bad), now=NOW + timedelta(hours=1))
        self.assertIsNone(self.store.get(identifier)["verdict"])

    def test_unknown_and_compliant_password_findings_cannot_propose(self):
        for state, value in (("missing", None), ("ok", 14)):
            data = export_fixture()
            data["observations"][0].update(state=state, value=value)
            saved, _ = self.imports.save(encode(data), expected_hostname="FIXTURE-SERVER",
                                        expected_machine_uuid=MACHINE_UUID, now=NOW)
            with self.assertRaises(ValueError):
                self.store.propose(saved.assessment.source_sha256)

    def test_imported_ai_proposal_requires_evidence_and_cannot_approve(self):
        tools = VmInvestigationTools(self.store, self.digest,
            operational_context=dict(compatibility='compatible', source='Synthetic fixture'))
        arguments = dict(target_id=tools.target_id, control_id="1.1.4")
        with self.assertRaises(ValueError):
            tools.call("submit_remediation_proposal", {**arguments, "reason": "skip checks"})
        with self.assertRaises(ValueError):
            tools.call("approve", arguments)
        names = ['get_finding_evidence', 'get_operational_context', 'get_supported_remediation',
                 'submit_remediation_proposal']
        responses = [{"tool_calls": [{"function": {"name": name, "arguments":
                     {**arguments, **({"reason": "Reviewed imported finding"} if name == names[-1] else {})}}}]}
                     for name in names]
        client = MockClient(responses + [{"content": "Awaiting human review."}])
        run = Coordinator(client, tools).run()
        self.assertEqual(run["evidence_mode"], "Imported")
        self.assertEqual(run["events"][-1]["data"]["status"], "Completed")
        self.assertIsNone(self.store.get(tools.proposal_id)["decision"])
        self.assertIn("imported Windows Server", client.received[0][0]["content"])

    def test_per_device_workspaces_survive_restart_without_altering_approval(self):
        identifier, raw = self.approved()
        self.assertIsNone(self.store.workspace(self.digest))
        directory = r"D:\Server Lab\Mikey's $VM`Workspace"
        self.store.save_workspace(self.digest, directory)
        other = export_fixture()
        other_uuid = 'cb095a4c-5a1c-48fe-b199-fda775b130a8'
        other['target']['machine_uuid'] = other_uuid
        saved, _ = self.imports.save(encode(other), expected_hostname="FIXTURE-SERVER",
                                     expected_machine_uuid=other_uuid, now=NOW)
        self.assertIsNone(self.store.workspace(saved.assessment.source_sha256))
        self.store.save_workspace(saved.assessment.source_sha256, r"E:\Other VM")
        reopened = BridgeStore(self.store.path, self.imports)
        self.assertEqual(reopened.workspace(self.digest), directory)
        self.assertEqual(reopened.workspace(saved.assessment.source_sha256), r"E:\Other VM")
        self.assertEqual(reopened.get(identifier)["request"], raw)
        command = runner_command(raw, directory)
        self.assertIn("'D:\\Server Lab\\Mikey''s $VM`Workspace\\Invoke-ApprovedVmAction.ps1'", command)
        self.assertNotIn("C:\\FYP", command)
        self.assertIn(hashlib.sha256(raw).hexdigest(), command)
        for bad in ("", "relative", "C:relative", "\\rooted", r"\\server\share",
                    "C:\\unsafe\ncommand", r"D:\..\escape", r"D:\bad|name", r"D:\NUL"):
            with self.subTest(path=bad), self.assertRaises(ValueError):
                workspace_path(bad)

    def test_python_request_powershell_mock_receipt_and_python_verification(self):
        script = Path(__file__).resolve().parents[2] / "scripts" / "fixture_vm_exchange.ps1"
        # All files and callbacks are fixtures. This invokes helper functions only.
        for value, expected in ((14, "Verified compliant"), (0, "Verification failed")):
            identifier, request = self.approved()
            expected_receipt = self.receipt(identifier, request, value=value)
            folder = self.store.path.parent / ("Exchange with spaces " + identifier)
            folder.mkdir()
            (folder / "request.json").write_bytes(request)
            for key, name in (("before_evidence", "before.json"), ("after_evidence", "after.json")):
                (folder / name).write_bytes(base64.b64decode(expected_receipt[key]))
            completed = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(script), "-FixtureRequestPath", str(folder / "request.json"),
                "-BeforePath", str(folder / "before.json"), "-AfterPath", str(folder / "after.json"),
                "-ReceiptPath", str(folder / "receipt.json")], capture_output=True, text=True, timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("Pre-action check", completed.stdout)
            self.assertIn("Post-action check", completed.stdout)
            self.assertNotIn("No hardening applied", completed.stdout)
            receipt = (folder / "receipt.json").read_bytes()
            self.assertEqual(self.store.accept_receipt(receipt, now=NOW + timedelta(hours=1)), expected)
