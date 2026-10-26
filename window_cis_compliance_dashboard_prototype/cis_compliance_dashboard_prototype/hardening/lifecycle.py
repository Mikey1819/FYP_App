"""Durable assessment-to-bridge links. No model approval or command execution."""
import base64
import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from .framework import AssessmentOrchestrator
from .vm_bridge import BridgeStore, encode


class RemediationLifecycle:
    """The bridge owns approval/receipt truth; this service owns run association."""

    def __init__(self, runtime: AssessmentOrchestrator, bridge: BridgeStore):
        if runtime.imports.path.resolve() != bridge.imports.path.resolve():
            raise ValueError("Framework and bridge must use the same imported evidence store")
        self.runtime, self.bridge = runtime, bridge
        with bridge._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""CREATE TABLE IF NOT EXISTS framework_proposals (
                run_id TEXT NOT NULL, attempt INTEGER NOT NULL, proposal_id TEXT UNIQUE NOT NULL,
                PRIMARY KEY (run_id, attempt))""")
            if 'context_id' not in {row[1] for row in db.execute('PRAGMA table_info(framework_proposals)')}:
                db.execute('ALTER TABLE framework_proposals ADD COLUMN context_id TEXT')
            db.execute('''CREATE TABLE IF NOT EXISTS framework_context (
                context_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, revision INTEGER NOT NULL,
                payload TEXT NOT NULL, UNIQUE(run_id, revision))''')
            for operation in ('UPDATE', 'DELETE'):
                db.execute(f'''CREATE TRIGGER IF NOT EXISTS context_no_{operation}
                    BEFORE {operation} ON framework_context
                    BEGIN SELECT RAISE(ABORT, 'Operational context is immutable'); END''')
            db.execute('''CREATE TRIGGER IF NOT EXISTS context_no_replace
                BEFORE INSERT ON framework_context WHEN EXISTS (SELECT 1 FROM framework_context
                    WHERE context_id=NEW.context_id OR (run_id=NEW.run_id AND revision=NEW.revision))
                BEGIN SELECT RAISE(ABORT, 'Operational context already exists'); END''')
            for operation in ('UPDATE', 'DELETE'):
                db.execute(f"""CREATE TRIGGER IF NOT EXISTS framework_proposals_no_{operation}
                    BEFORE {operation} ON framework_proposals
                    BEGIN SELECT RAISE(ABORT, 'Framework proposal links are immutable'); END""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS framework_proposals_no_replace
                BEFORE INSERT ON framework_proposals WHEN EXISTS (
                    SELECT 1 FROM framework_proposals WHERE proposal_id=NEW.proposal_id
                    OR (run_id=NEW.run_id AND attempt=NEW.attempt))
                BEGIN SELECT RAISE(ABORT, 'Framework proposal link already exists'); END""")

    def _run(self, run_id):
        run = self.runtime.get(run_id)
        if run.state not in ('ready_for_review', 'needs_review', 'assessment_complete'):
            raise ValueError("Complete assessment before reviewing remediation")
        return run

    def context(self, run_id):
        self._run(run_id)
        with self.bridge._connection() as db:
            return self._context(db, run_id)

    @staticmethod
    def _context(db, run_id):
        row = db.execute('''SELECT payload FROM framework_context WHERE run_id=?
            ORDER BY revision DESC LIMIT 1''', (run_id,)).fetchone()
        return json.loads(row[0]) if row else dict(context_id=None, run_id=run_id, revision=0,
            compatibility='unknown', operator=None, note='No provisioning compatibility report supplied.',
            source='Unavailable', recorded_at=None)

    def save_context(self, run_id, *, compatibility, operator, note):
        self._run(run_id)
        if compatibility not in ('unknown', 'compatible', 'incompatible'):
            raise ValueError('Unknown compatibility classification')
        if (type(operator) is not str or not operator.strip() or len(operator) > 100 or
                type(note) is not str or not note.strip() or len(note) > 500):
            raise ValueError('Supply an operator name and a concise compatibility note (maximum 500 characters)')
        with self.bridge._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            latest = db.execute('''SELECT p.proposal_id,d.decision FROM framework_proposals p
                LEFT JOIN decisions d ON d.id=p.proposal_id WHERE p.run_id=?
                ORDER BY p.attempt DESC LIMIT 1''', (run_id,)).fetchone()
            if latest and latest[1] != 'rejected':
                raise ValueError('Context is frozen for this proposal; reject a pending proposal or start a new test')
            old = self._context(db, run_id)
            payload = dict(context_id=uuid4().hex, run_id=run_id, revision=old['revision'] + 1,
                compatibility=compatibility, operator=operator.strip(), note=note.strip(),
                source='Administrator report; not collected VM evidence or approval',
                recorded_at=datetime.now(timezone.utc).isoformat())
            db.execute('INSERT INTO framework_context VALUES (?, ?, ?, ?)',
                       (payload['context_id'], run_id, payload['revision'], json.dumps(payload)))
        return payload

    def prepare(self, run_id, *, expected_previous_id=None, expected_context_id=None,
                reason="Deterministic recommendation from the reviewed minimum-length rule."):
        run = self._run(run_id)
        if run.state != 'ready_for_review':
            raise ValueError("Assessment has no supported remediation candidate")
        with self.bridge._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute('''SELECT proposal_id,attempt FROM framework_proposals
                WHERE run_id=? ORDER BY attempt DESC LIMIT 1''', (run_id,)).fetchone()
            if previous:
                item = self.bridge.get(previous[0])
                # A rerun of initial preparation reopens its undecided proposal.
                if expected_previous_id is None and item['decision'] is None:
                    return previous[0]
                if previous[0] != expected_previous_id:
                    raise ValueError('Stale proposal request; review the current run')
                if item['decision'] != 'rejected':
                    raise ValueError('An approved or pending attempt cannot be retried; start a new test')
            elif expected_previous_id is not None:
                raise ValueError('Previous proposal does not belong to this run')
            context = self._context(db, run_id)
            if context['compatibility'] != 'compatible':
                raise ValueError('Provisioning compatibility is unknown or blocked; clarification/review is required')
            if expected_context_id is not None and context['context_id'] != expected_context_id:
                raise ValueError('Operational context changed during investigation; investigate again')
            payload = self.bridge._proposal_payload(run.evidence_sha256, reason)
            identifier = payload['request_id']
            db.execute('INSERT INTO proposals VALUES (?, ?, ?)',
                       (identifier, run.evidence_sha256, encode(payload)))
            db.execute('INSERT INTO framework_proposals (run_id,attempt,proposal_id,context_id) VALUES (?, ?, ?, ?)',
                       (run_id, previous[1] + 1 if previous else 1, identifier, context['context_id']))
        return identifier

    def _bound(self, run_id, identifier):
        run = self._run(run_id)
        with self.bridge._connection() as db:
            row = db.execute('SELECT run_id FROM framework_proposals WHERE proposal_id=?',
                             (identifier,)).fetchone()
        if row is None or row[0] != run_id:
            raise ValueError('Proposal belongs to a different test request or is not linked to this run')
        item = self.bridge.get(identifier)
        proposal = item['proposal']
        if (proposal['evidence_sha256'] != run.evidence_sha256 or
                'windows:' + proposal['machine_uuid'] != run.target_id):
            raise ValueError('Linked proposal does not match the assessment evidence/target')
        return item

    def decide(self, run_id, identifier, *, approve, operator, now=None):
        self._bound(run_id, identifier)
        if approve:
            with self.bridge._connection() as db:
                row = db.execute('SELECT context_id FROM framework_proposals WHERE proposal_id=?', (identifier,)).fetchone()
                context = self._context(db, run_id)
            if row[0] is None or row[0] != context['context_id'] or context['compatibility'] != 'compatible':
                raise ValueError('Proposal lacks matching compatible operational context; reject it and prepare a new proposal')
        return self.bridge.decide(identifier, approve=approve, operator=operator, now=now)

    def accept_receipt(self, run_id, identifier, raw, *, now=None):
        self._bound(run_id, identifier)
        self.bridge.accept_receipt(raw, expected_request_id=identifier, now=now)
        return self.get(run_id)

    def get(self, run_id):
        run = self._run(run_id)
        with self.bridge._connection() as db:
            rows = db.execute('''SELECT proposal_id,attempt,context_id FROM framework_proposals
                WHERE run_id=? ORDER BY attempt''', (run_id,)).fetchall()
        attempts = []
        for identifier, number, context_id in rows:
            item = self._bound(run_id, identifier)
            outcome = ('rejected' if item['decision'] == 'rejected' else
                       'awaiting_receipt' if item['decision'] == 'approved' else 'awaiting_approval')
            before_digest = after_digest = receipt_digest = None
            if item['receipt'] is not None:
                receipt_digest = hashlib.sha256(item['receipt']).hexdigest()
                receipt = json.loads(item['receipt'].decode('utf-8-sig'))
                before_digest = hashlib.sha256(base64.b64decode(receipt['before_evidence'], validate=True)).hexdigest()
                if receipt['after_evidence'] is not None:
                    after_digest = hashlib.sha256(base64.b64decode(receipt['after_evidence'], validate=True)).hexdigest()
                # Do not show completion if receipt import was interrupted before
                # its independent snapshots were saved. Re-import repairs that.
                missing = False
                for digest in (before_digest, after_digest):
                    if digest is not None:
                        try:
                            self.runtime.imports.get(digest)
                        except KeyError:
                            missing = True
                outcome = 'verified' if item['verdict'] == 'Verified compliant' else 'unresolved'
                if missing:
                    outcome = 'receipt_import_incomplete'
            attempts.append(dict(proposal_id=identifier, attempt=number, outcome=outcome, context_id=context_id,
                decision=item['decision'], decision_record=item['decision_record'], verdict=item['verdict'],
                receipt_sha256=receipt_digest, before_evidence_sha256=before_digest,
                verification_evidence_sha256=after_digest))
        return dict(run_id=run_id, target_id=run.target_id, evidence_sha256=run.evidence_sha256,
                    assessment_state=run.state, outcome=attempts[-1]['outcome'] if attempts else run.state,
                    attempts=attempts)

    def investigation_tools(self, run_id, *, expected_previous_id=None):
        # Import lazily; the lifecycle itself has no Streamlit/model dependency.
        from .vm_investigation import VmInvestigationTools
        run = self._run(run_id)
        context = self.context(run_id)
        return VmInvestigationTools(self.bridge, run.evidence_sha256,
            proposal_factory=lambda reason: self.prepare(run_id,
                expected_previous_id=expected_previous_id, expected_context_id=context['context_id'], reason=reason),
            framework_run_id=run_id, operational_context=context)
