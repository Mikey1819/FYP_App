"""Assessment history and configuration drift (report FR12/FR13, UC07, Section 4.6.4).

Every assessment run stays an immutable snapshot. Drift compares a run with the previous
run of the same target, control by control, and stores each detected change once as a
ConfigurationDrift record (previous run, current run, control, before/after, kind).
"""
from datetime import datetime, timezone
import hashlib
import json

from .domain import change_kind, summarise


def describe_change(prior, current):
    """Change kind for one control; status transitions involving Unknown/Error are named explicitly."""
    change = change_kind(prior, current)
    if change == 'No comparable evidence' and prior.status != current.status:
        return prior.status.value + ' -> ' + current.status.value
    return change


class HistoryService:
    def __init__(self, runtime, store):
        self.runtime, self.store = runtime, store

    def _record(self, run_id):
        return self.runtime.imports.get(self.runtime.get(run_id).evidence_sha256)

    def runs(self, target_id=None):
        """Assessment runs (oldest first) with their summaries."""
        with self.runtime._connection() as db:
            rows = db.execute('SELECT run_id,digest,target_id,created_at FROM framework_runs '
                              + ('WHERE target_id=? ' if target_id else '') + 'ORDER BY created_at, rowid',
                              (target_id,) if target_id else ()).fetchall()
        history = []
        for run_id, digest, target, created in rows:
            record = self.runtime.imports.get(digest)
            summary = summarise(record.assessment.results)
            history.append(dict(run_id=run_id, created_at=created, target_id=target, hostname=record.assessment.hostname,
                                evidence=record.assessment.results[0].evidence.mode.value,
                                controls=summary.selected, compliant=summary.compliant,
                                non_compliant=summary.non_compliant, unknown=summary.unknown, error=summary.errors,
                                compliance_percent=summary.compliance_percent))
        return history

    def targets(self):
        seen = {}
        for run in self.runs():
            seen[run['target_id']] = run['hostname']
        return seen

    def compare(self, previous_run_id, current_run_id):
        earlier = {r.control.control_id: r for r in self._record(previous_run_id).assessment.results}
        rows = []
        for current in self._record(current_run_id).assessment.results:
            prior = earlier[current.control.control_id]  # Every stored scan holds the whole catalogue.
            rows.append(dict(control_id=current.control.control_id, title=current.control.title,
                             before=prior.evidence.value, after=current.evidence.value,
                             status_before=prior.status.value, status_after=current.status.value,
                             change=describe_change(prior, current)))
        return rows

    def previous_records(self, run_id, limit=10, *, exclude=()):
        """Earlier assessments of the same target, newest first (input for the drift factor D).

        A scan that a rescan replaced within its own round is not an earlier assessment: counting it would turn
        "no history" (D=1) into "already non-compliant" (D=3) for every finding of a round with a rescan.
        `exclude` names such scans of a round still in progress; stored rounds name theirs.
        """
        skip = set(exclude) | self.store.superseded_runs()
        records, current = [], run_id
        while len(records) < limit and (current := self.previous_run(current)) is not None:
            if current not in skip:
                records.append(self._record(current))
        return records

    def previous_run(self, run_id):
        with self.runtime._connection() as db:
            created, target = db.execute('SELECT created_at,target_id FROM framework_runs WHERE run_id=?',
                                         (run_id,)).fetchone()
            row = db.execute('''SELECT run_id FROM framework_runs WHERE target_id=? AND run_id<>?
                AND (created_at<? OR (created_at=? AND rowid<(SELECT rowid FROM framework_runs WHERE run_id=?)))
                ORDER BY created_at DESC, rowid DESC LIMIT 1''', (target, run_id, created, created, run_id)).fetchone()
        return row[0] if row else None

    def record_drift(self, run_id):
        """Store each change against the target's previous run. Idempotent; returns the changes."""
        previous = self.previous_run(run_id)
        if previous is None:
            return []
        changes = [c for c in self.compare(previous, run_id)
                   if c['change'] not in ('Unchanged', 'No comparable evidence')]
        target = self.runtime.get(run_id).target_id
        detected = datetime.now(timezone.utc).isoformat()
        with self.store._connection() as db:
            for change in changes:
                key = hashlib.sha256(f'{previous}|{run_id}|{change["control_id"]}'.encode()).hexdigest()
                if db.execute('SELECT 1 FROM drift_records WHERE id=?', (key,)).fetchone():
                    continue
                db.execute('INSERT INTO drift_records VALUES (?,?,?,?,?)', (key, target, run_id, change['control_id'],
                    json.dumps(dict(previous_run_id=previous, current_run_id=run_id, detected_at=detected, **change))))
        return changes

    def drift_records(self, target_id):
        with self.store._connection() as db:
            rows = db.execute('SELECT payload FROM drift_records WHERE target_id=? ORDER BY rowid DESC',
                              (target_id,)).fetchall()
        return [json.loads(raw) for (raw,) in rows]
