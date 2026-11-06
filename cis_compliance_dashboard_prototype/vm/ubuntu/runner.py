"""Root-owned target runner: fence -> validate -> fresh read-set -> atomic claim -> step check -> write -> receipt.

At most one forward execution per request. The persistent fence (`active`) is created atomically and
removed only after a clean terminal outcome; a crash, exception or unexpected after-state leaves it in
place, blocking every later request until `reconcile` proves what happened. Nothing expires on time.
Python 3.10, standard library only. Families are fixed registered implementations (see families.py).
"""
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
import uuid
from .remediation_schema import parse_request, receipt, utc

CLOCK_SKEW_SECONDS = 5


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class Runner:
    def __init__(self, state_dir, families, identity, *, clock=None, require_root_owned=True):
        self.state, self.families, self.identity = Path(state_dir), dict(families), identity
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        if require_root_owned:
            info = self.state.lstat()
            if self.state.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                raise ValueError('Runner state directory must be a root-owned private directory')
        self.fence = self.state / 'active'
        from .family_restore import ACTION_ID, RestoreFamily
        self.families.setdefault(ACTION_ID, RestoreFamily(self))

    # ---- small durable primitives --------------------------------------------------------
    def _write_atomic(self, path, data):
        tmp = path.with_name(path.name + '.tmp-' + uuid.uuid4().hex)
        with open(tmp, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)

    def _create(self, path, data=b''):
        """Atomic exclusive create; FileExistsError means another holder exists."""
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _stamp(self):
        return self.clock().astimezone(timezone.utc).isoformat()

    def _directory(self, request_id):
        return self.state / 'requests' / request_id

    # ---- execution ------------------------------------------------------------------------
    def execute(self, raw):
        started, digest = self._stamp(), _sha(raw) if type(raw) is bytes else '0' * 64
        try:
            request = parse_request(raw)
        except (ValueError, TypeError):
            return receipt(None, digest, 'refused', 'invalid_request', None, None, started, self._stamp())
        rid = request['request_id']
        refuse = lambda code, before=None: receipt(rid, digest, 'refused', code, before, None, started, self._stamp())
        try:
            self._create(self.fence, rid.encode('ascii'))
        except FileExistsError:
            return refuse('target_fenced')
        release = True
        try:
            code = self._validate(request)
            if code:
                return refuse(code)
            family, params = self.families[request['action']['action_id']], request['parameters']
            directory = self._directory(rid)
            directory.mkdir(parents=True, exist_ok=True)
            stored = directory / 'request.json'
            if stored.exists() and stored.read_bytes() != raw:
                return refuse('request_conflict')
            if (directory / 'claim').exists():
                return refuse('already_claimed')
            current = family.read_state(params)
            before = _sha(current)
            if before != request['before_state_sha256']:
                return refuse('stale_read_set', before)
            # The family's own deterministic result must match the approved after-state: a request whose
            # parameters were altered in transit, or planned inconsistently, is refused before any write.
            if _sha(family.expected_after(params, current)) != request['expected_after_sha256']:
                return refuse('inconsistent_request', before)
            check = getattr(family, 'check_eligible', None)
            if check is not None:
                try:
                    check(params)
                except (ValueError, OSError):
                    return refuse('not_eligible', before)
            if not stored.exists():
                self._write_atomic(stored, raw)
            self._write_atomic(directory / 'before_state', current)  # exact bytes for approved recovery
            try:
                self._create(directory / 'claim', started.encode('ascii'))
            except FileExistsError:
                return refuse('already_claimed', before)
            release = False  # Claimed: from here only a clean terminal outcome releases the fence.

            def finish(outcome, code, after=None):
                data = receipt(rid, digest, outcome, code, before, after, started, self._stamp())
                self._write_atomic(directory / 'receipt.json', data)
                return data
            if _sha(family.read_state(params)) != before:  # step-relevant re-read immediately before writing
                release = True
                return finish('refused', 'changed_after_claim')
            try:
                family.apply(params)
            except Exception:
                return finish('unresolved', 'apply_failed')
            after = _sha(family.read_state(params))
            if after != request['expected_after_sha256']:
                return finish('unresolved', 'unexpected_after_state', after)
            release = True
            return finish('applied', 'expected_after_state', after)
        finally:
            if release:
                self.fence.unlink()

    def _validate(self, request):
        machine, hostname = self.identity()
        if (request['machine_id'], request['hostname'].casefold()) != (machine, hostname):
            return 'identity_mismatch'
        now = self.clock()
        if now >= utc(request['expires_at']):
            return 'expired'
        if (utc(request['approved_at']) - now).total_seconds() > CLOCK_SKEW_SECONDS:
            return 'not_yet_valid'
        family = self.families.get(request['action']['action_id'])
        if family is None:
            return 'unknown_action'
        if (family.version, family.implementation_sha256) != (request['action']['version'],
                                                               request['action']['implementation_sha256']):
            return 'implementation_mismatch'
        try:
            family.validate(request['parameters'])
        except (ValueError, TypeError, KeyError):
            return 'invalid_parameters'
        if request['job_deadline_seconds'] > family.max_seconds:
            return 'invalid_parameters'
        return None

    # ---- read-only preview ----------------------------------------------------------------
    def preview(self, action_id, params):
        """The digests a plan must carry and a sanitized change summary. Reads only; takes no fence."""
        family = self.families.get(action_id)
        if family is None:
            raise ValueError('Unregistered action family')
        family.validate(params)
        check = getattr(family, 'check_eligible', None)
        if check is not None:
            check(params)
        current = family.read_state(params)
        return {'action_id': action_id, 'before_state_sha256': _sha(current),
                'expected_after_sha256': _sha(family.expected_after(params, current)),
                'collected_at': self._stamp(), 'summary': family.summary(params, current)}

    # ---- reconciliation -------------------------------------------------------------------
    def reconcile(self, request_id):
        """Decide a claimed request's outcome from current state; never re-executes anything."""
        if type(request_id) is not str or not re.fullmatch(r'[0-9a-f]{32}', request_id):
            raise ValueError('Invalid request ID')
        directory, now = self._directory(request_id), self._stamp()
        holder = self.fence.read_text(encoding='ascii') if self.fence.exists() else None
        existing = directory / 'receipt.json'
        if existing.exists():
            data = existing.read_bytes()
            from .remediation_schema import parse_receipt
            if parse_receipt(data)['outcome'] != 'unresolved':
                if holder == request_id:
                    self.fence.unlink()
                return data
        stored = directory / 'request.json'
        if not (directory / 'claim').exists():
            # Never claimed: nothing was written. A fence left by a crash before the claim is safe to release.
            if holder == request_id:
                self.fence.unlink()
            raw = stored.read_bytes() if stored.exists() else b''
            return receipt(request_id, _sha(raw) if raw else '0' * 64, 'refused', 'not_claimed', None, None, now, now)
        raw = stored.read_bytes()
        request = parse_request(raw)
        family = self.families.get(request['action']['action_id'])
        if family is None:
            return receipt(request_id, _sha(raw), 'unresolved', 'unknown_action', None, None, now, now)
        state = _sha(family.read_state(request['parameters']))
        before = request['before_state_sha256']
        if state == before:
            outcome, code = 'reconciled_not_applied', 'before_state'
        elif state == request['expected_after_sha256']:
            outcome, code = 'reconciled_applied', 'expected_after_state'
        else:
            outcome, code = 'unresolved', 'state_unknown'
        data = receipt(request_id, _sha(raw), outcome, code, before, state, now, self._stamp())
        self._write_atomic(existing, data)
        if outcome != 'unresolved' and holder == request_id:
            self.fence.unlink()
        return data
