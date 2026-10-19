"""Additive workflow and investigation audit tables for schema versions 2/3."""


def create_workflow_tables(connection):
    connection.execute("""CREATE TABLE IF NOT EXISTS workflow_proposals (
        proposal_id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL,
        created_at TEXT NOT NULL, binding TEXT NOT NULL, payload TEXT NOT NULL,
        FOREIGN KEY (assessment_id) REFERENCES assessment_snapshots(assessment_id)
    )""")
    connection.execute("""CREATE TABLE IF NOT EXISTS workflow_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        proposal_id TEXT NOT NULL, kind TEXT NOT NULL, created_at TEXT NOT NULL,
        payload TEXT NOT NULL, UNIQUE(proposal_id, kind),
        CHECK(kind IN ('decision', 'attempt', 'execution', 'verification')),
        FOREIGN KEY (proposal_id) REFERENCES workflow_proposals(proposal_id)
    )""")
    connection.execute("""CREATE TABLE IF NOT EXISTS investigation_runs (
        run_id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL,
        FOREIGN KEY (assessment_id) REFERENCES assessment_snapshots(assessment_id)
    )""")
    connection.execute("""CREATE TABLE IF NOT EXISTS investigation_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, kind TEXT NOT NULL,
        created_at TEXT NOT NULL, payload TEXT NOT NULL,
        FOREIGN KEY (run_id) REFERENCES investigation_runs(run_id)
    )""")
    for table, identity in (("workflow_proposals", "proposal_id"), ("workflow_events", "sequence"),
                            ("investigation_runs", "run_id"), ("investigation_events", "sequence")):
        for operation in ("UPDATE", "DELETE"):
            connection.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()}
                BEFORE {operation} ON {table} BEGIN
                SELECT RAISE(ABORT, 'Workflow audit records are immutable'); END""")
        connection.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_no_replace
            BEFORE INSERT ON {table} WHEN EXISTS
            (SELECT 1 FROM {table} WHERE {identity} = NEW.{identity})
            BEGIN SELECT RAISE(ABORT, 'Workflow audit records are immutable'); END""")
    connection.execute("""CREATE TRIGGER IF NOT EXISTS workflow_events_no_kind_replace
        BEFORE INSERT ON workflow_events WHEN EXISTS
        (SELECT 1 FROM workflow_events WHERE proposal_id = NEW.proposal_id AND kind = NEW.kind)
        BEGIN SELECT RAISE(ABORT, 'Workflow event already exists'); END""")
