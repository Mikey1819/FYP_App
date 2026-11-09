"""Long agent work (a round, or executing approved fixes) runs in a background worker, so changing page never stops it.

Streamlit runs a page's script again whenever the administrator clicks anything, another page in the sidebar included,
and stops the run in progress at its next Streamlit call. Work done inside the page's own run could stop half-way, with
its ledger claim left open, so the next start is refused ("reconciliation is required"). Here the work runs in a thread
of its own with no Streamlit context: no page can stop it, every page shows that it is running, and it ends with its
records settled exactly as before.

One job per server at a time, held in this dashboard process, so a second browser tab sees the same job. The worker
never touches st.session_state: the page reads what the work needs before it starts, and when it has finished the page
takes the job back (take_finished) and applies what the page must remember (the job's `after`).
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
import threading

log = logging.getLogger(__name__)


@dataclass(eq=False)
class Job:
    key: str                  # The server: '<system>:<machine identity>'.
    label: str                # What is running, in the administrator's terms.
    started_at: datetime
    after: object = None      # Called on the page as after(result, error); returns True when it handled the error.
    result: object = None
    error: Exception | None = None
    finished_at: datetime | None = None
    _done: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def done(self):
        return self._done.is_set()

    def wait(self, seconds):
        """Wait up to `seconds` for the work to finish; True if it has."""
        return self._done.wait(seconds)


_jobs = {}
_lock = threading.Lock()


def start(key, label, work, *, after=None):
    """Run work() in the background for this server. Refused while another job runs on the same server."""
    if not key:
        raise ValueError('No server is connected.')
    with _lock:
        held = _jobs.get(key)
        if held is not None and not held.done:
            raise ValueError(f'{held.label} is still running on this server. Wait until it has finished.')
        job = Job(key, label, datetime.now(timezone.utc), after)
        _jobs[key] = job
    threading.Thread(target=_run, args=(job, work), name='fyp-job-' + key, daemon=True).start()
    return job


def _run(job, work):
    try:
        job.result = work()
    except Exception as exc:  # Kept for the page to show; the work settles its own ledger records as before.
        log.exception('Background job failed: %s', job.label)
        job.error = exc
    finally:
        job.finished_at = datetime.now(timezone.utc)
        job._done.set()


def running(key):
    """The job still running on this server, or None."""
    job = _jobs.get(key) if key else None
    return job if job is not None and not job.done else None


def take_finished(key):
    """The finished job of this server, removed from the list so it is applied once; None if there is none."""
    with _lock:
        job = _jobs.get(key) if key else None
        if job is None or not job.done:
            return None
        del _jobs[key]
    return job


def finished(key):
    """The finished job of this server that its page has not taken back yet, or None (read-only)."""
    job = _jobs.get(key) if key else None
    return job if job is not None and job.done else None
