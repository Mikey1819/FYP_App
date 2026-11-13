"""Root-owned target runner: fence -> validate -> fresh read-set -> atomic claim -> step check -> write -> receipt.

At most one forward execution per request. The persistent fence (`active`) is created atomically and
removed only after a clean terminal outcome; a crash, exception or unexpected after-state leaves it in
place, blocking every later request until `reconcile` proves what happened. Nothing expires on time.

One exception (administrator, 13 November 2026, so one fresh login confirms all the SSH/UFW changes of an
execution): a commit-confirm request may be stacked on commit-confirm changes that are applied and waiting for
their confirmation. It records the request beneath it (`below`) and takes the fence; each stacked change keeps its
own rollback timer and before-state. Its fresh read-set check runs after the others were applied, so their files
are disjoint and their rollbacks independent. When the fence holder settles, the fence passes to the nearest open
change beneath it, or is removed. Never on a change still running, and never a job or in-session write.
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

# VirtualBox guest clocks drift and are corrected in jumps (live 2026-11-07: >5 s behind, then ~1 s ahead).
# The host reports offsets above 30 s as a deployment problem; this only tolerates the remainder.
CLOCK_SKEW_SECONDS = 60
CLOCK_YEARS = (2026, 2099)  # a laptop time outside these years is a fault, never set
MAX_STACK = 8  # commit-confirm changes waiting for one confirmation login at most
LOCK_STALE_SECONDS = 30


def _set_system_clock(when):
    """Set the system clock (UTC, whole seconds) with one fixed command; nothing else changes."""
    import subprocess
    result = subprocess.run(('/usr/bin/date', '-u', '--set=@%d' % int(when.timestamp())), capture_output=True,
                            timeout=20, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    if result.returncode != 0:
        raise OSError('date --set failed')


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _mode(family):
    """None (in-session write), 'job' (systemd-supervised) or 'confirm' (supervised + rollback unless confirmed)."""
    mode = getattr(family, 'supervision', None)
    if mode not in (None, 'job', 'confirm'):
        raise ValueError('Unregistered supervision mode')
    if mode == 'confirm' and (type(getattr(family, 'confirm_seconds', None)) is not int
                              or not 60 <= family.confirm_seconds <= 1800):
        raise ValueError('A commit-confirm family needs a bounded confirmation window')
    return mode


class Runner:
    def __init__(self, state_dir, families, identity, *, clock=None, require_root_owned=True, launcher=None,
                 clock_setter=None):
        self.state, self.families, self.identity = Path(state_dir), dict(families), identity
        self.launcher = launcher  # systemd supervision (supervision.py); required only by supervised families
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.clock_setter = clock_setter or _set_system_clock
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

    # ---- the fence: one holder, or commit-confirm changes stacked on waiting ones ------------------
    def _locked(self, work):
        """Run `work` holding the short fence lock, so taking, stacking and passing the fence never interleave
        (the SSH session, the job units and the rollback timers run separately). A lock older than 30 s is left
        by a crash and is removed."""
        import time
        lock = self.state / 'fence.lock'
        for _ in range(200):
            try:
                self._create(lock)
                break
            except FileExistsError:
                try:
                    if time.time() - lock.stat().st_mtime > LOCK_STALE_SECONDS:
                        lock.unlink()
                        continue
                except FileNotFoundError:
                    continue
                time.sleep(0.05)
        else:
            raise OSError('Runner fence lock is busy')
        try:
            return work()
        finally:
            lock.unlink()

    def _holder(self):
        return self.fence.read_text(encoding='ascii') if self.fence.exists() else None

    def _below(self, request_id):
        path = self._directory(request_id) / 'below'
        value = path.read_text(encoding='ascii') if path.exists() else ''
        return value if re.fullmatch(r'[0-9a-f]{32}', value) else None

    def _waiting_confirmation(self, request_id):
        """A commit-confirm change applied and waiting for its confirmation, with no decision yet."""
        directory = self._directory(request_id)
        job = directory / 'job'
        return (job.exists() and job.read_bytes() == b'confirm' and (directory / 'awaiting').exists()
                and not (directory / 'decision').exists() and self._final(directory) is None)

    def _stack(self, request_id, request):
        """Take the fence above waiting commit-confirm changes; False when this request may not be stacked."""
        family = self.families.get(request['action']['action_id'])
        if family is None or _mode(family) != 'confirm':
            return False

        def work():
            holder, chain = self._holder(), []
            current = holder
            while current is not None and len(chain) <= MAX_STACK:
                if self._final(self._directory(current)) is None:
                    chain.append(current)
                current = self._below(current)
            if holder is None or not chain or len(chain) >= MAX_STACK or holder == request_id:
                return False
            if not all(self._waiting_confirmation(r) for r in chain):
                return False
            directory = self._directory(request_id)
            directory.mkdir(parents=True, exist_ok=True)
            if (directory / 'claim').exists() or (directory / 'below').exists():
                return False
            self._write_atomic(directory / 'below', holder.encode('ascii'))
            self._write_atomic(self.fence, request_id.encode('ascii'))
            return True
        return self._locked(work)

    def _release(self, request_id):
        """Release the fence if `request_id` holds it: to the nearest open change beneath it, else remove it."""
        def work():
            if self._holder() != request_id:
                return
            below = self._below(request_id)
            while below is not None and self._final(self._directory(below)) is not None:
                below = self._below(below)
            if below is None:
                self.fence.unlink()
            else:
                self._write_atomic(self.fence, below.encode('ascii'))
        self._locked(work)

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
            if not self._stack(rid, request):
                return refuse('target_fenced')
        release = True
        try:
            code = self._validate(request)
            if code:
                return refuse(code)
            family, params = self.families[request['action']['action_id']], request['parameters']
            mode = _mode(family)
            if mode is not None and self.launcher is None:
                return refuse('supervisor_unavailable')
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
            if mode is not None:
                # Supervised: the write runs in a systemd unit, never in this SSH session. A commit-confirm
                # family's rollback timer is armed first; without it nothing is started.
                self._write_atomic(directory / 'job', mode.encode('ascii'))
                if mode == 'confirm':
                    try:
                        self.launcher.arm_rollback(rid, family.max_seconds + family.confirm_seconds)
                    except Exception:
                        release = True
                        return finish('refused', 'watchdog_unavailable')
                try:
                    self.launcher.start_job(rid, family.max_seconds)
                except Exception:
                    return finish('unresolved', 'job_start_failed')
                return receipt(rid, digest, 'running', 'job_started', before, None, started, self._stamp())
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
                self._release(rid)

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

    # ---- read-only deployment probe --------------------------------------------------------
    def probe(self):
        """What is deployed: helper digest, registered families, systemd launcher and boot rollback. Reads only."""
        from .provenance import collector_digest
        launcher = self.launcher
        return {'collector_digest': collector_digest(), 'now': self._stamp(),
                'families': {aid: [f.version, f.implementation_sha256] for aid, f in sorted(self.families.items())},
                'launcher': bool(launcher is not None and getattr(launcher, 'available', lambda: True)()),
                'boot_rollback': getattr(launcher, 'boot_rollback_state', lambda: 'unknown')() if launcher else 'unknown'}

    # ---- clock sync (administrator's click) -------------------------------------------------
    def set_clock(self, laptop_utc):
        """Set the server's clock to the dashboard laptop's time (UTC), on the administrator's click (administrator
        request 2026-11-11, as the Windows page does). Changes only the clock. Refused while a change is open (the
        fence), so no running job, confirmation window or rollback sees the jump. Returns the time before and after."""
        wanted = utc(laptop_utc)
        if not CLOCK_YEARS[0] <= wanted.year <= CLOCK_YEARS[1]:
            raise ValueError('Implausible laptop time')
        before = self._stamp()
        if self.fence.exists():
            return {'outcome': 'refused', 'code': 'change_open', 'before': before, 'after': before}
        self.clock_setter(wanted)
        return {'outcome': 'set', 'code': 'clock_set', 'before': before, 'after': self._stamp()}

    # ---- read-only preview ----------------------------------------------------------------
    def preview(self, action_id, params):
        """The digests a plan must carry and a sanitized change summary. Reads only; takes no fence."""
        family = self.families.get(action_id)
        if family is None:
            raise ValueError('Unregistered action family')
        family.validate(params)
        check = getattr(family, 'check_eligible', None)
        if check is not None:
            try:
                check(params)
            except ValueError as refusal:
                # Not eligible on this server now: say why (a fixed sentence the family wrote; printable ASCII, at
                # most 200 characters) instead of refusing silently, so the dashboard can show it (2026-11-13).
                reason = ''.join(ch for ch in str(refusal) if ' ' <= ch <= '~')[:200] or 'not eligible'
                return {'action_id': action_id, 'refused': reason}
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
                    self._release(request_id)
                return data
        if (directory / 'job').exists() and (directory / 'claim').exists():
            supervised = self._supervised_status(request_id)
            if supervised is not None:
                return supervised
        stored = directory / 'request.json'
        if not (directory / 'claim').exists():
            # Never claimed: nothing was written. A fence left by a crash before the claim is safe to release.
            if holder == request_id:
                self._release(request_id)
            raw = stored.read_bytes() if stored.exists() else b''
            return receipt(request_id, _sha(raw) if raw else '0' * 64, 'refused', 'not_claimed', None, None, now, now)
        raw = stored.read_bytes()
        request = parse_request(raw)
        family = self.families.get(request['action']['action_id'])
        if family is None:
            return receipt(request_id, _sha(raw), 'unresolved', 'unknown_action', None, None, now, now)
        try:
            state = _sha(family.read_state(request['parameters']))
        except Exception:
            # The state cannot be read now (live 13 November 2026: apt's read-only simulation refuses while dpkg is
            # interrupted, after a restart during an install). Said as such, nothing settled or re-run; asked again.
            return receipt(request_id, _sha(raw), 'unresolved', 'state_unreadable', request['before_state_sha256'],
                           None, now, self._stamp())
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
            self._release(request_id)
        return data

    # ---- systemd-supervised jobs and the commit-confirm watchdog ------------------------------------
    def _load(self, request_id):
        if type(request_id) is not str or not re.fullmatch(r'[0-9a-f]{32}', request_id):
            raise ValueError('Invalid request ID')
        directory = self._directory(request_id)
        if not (directory / 'job').exists() or not (directory / 'claim').exists():
            raise ValueError('No supervised job for this request')
        raw = (directory / 'request.json').read_bytes()
        request = parse_request(raw)
        family = self.families[request['action']['action_id']]
        return directory, raw, request, family, (directory / 'job').read_text(encoding='ascii')

    def _final(self, directory):
        """The stored receipt when it is terminal; None while the outcome is open."""
        existing = directory / 'receipt.json'
        if existing.exists():
            data = existing.read_bytes()
            from .remediation_schema import parse_receipt
            if parse_receipt(data)['outcome'] != 'unresolved':
                return data
        return None

    def _settle(self, request_id, directory, raw, request, outcome, code, after, *, release):
        started = (directory / 'claim').read_text(encoding='ascii')
        data = receipt(request_id, _sha(raw), outcome, code, request['before_state_sha256'], after, started, self._stamp())
        self._write_atomic(directory / 'receipt.json', data)
        if release:
            self._release(request_id)
        return data

    def _running(self, request_id, code):
        directory, raw, request, _, _ = self._load(request_id)
        started = (directory / 'claim').read_text(encoding='ascii')
        return receipt(request_id, _sha(raw), 'running', code, request['before_state_sha256'], None, started, self._stamp())

    def run_job(self, request_id):
        """Entry of the systemd unit. Writes at most once; a decided, settled or unfenced request is left alone."""
        directory, raw, request, family, mode = self._load(request_id)
        if self._final(directory) is not None:
            return
        if not self.fence.exists() or self.fence.read_text(encoding='ascii') != request_id:
            return
        try:
            self._create(directory / 'job_started', self._stamp().encode('ascii'))
        except FileExistsError:
            return
        if (directory / 'decision').exists():
            return
        params, expected = request['parameters'], request['expected_after_sha256']
        try:
            family.apply(params)
            failed = False
        except Exception:
            failed = True
        try:
            after = _sha(family.read_state(params))
        except Exception:
            after = None
        if mode == 'job':
            if failed:
                self._settle(request_id, directory, raw, request, 'unresolved', 'apply_failed', after, release=False)
            elif after != expected and getattr(family, 'completes_after_reboot', False):
                # Scheduled: the after-state needs a new boot. Keep the lock; status settles it on the new boot.
                self._write_atomic(directory / 'awaiting_reboot', self._stamp().encode('ascii'))
            elif after != expected:
                self._settle(request_id, directory, raw, request, 'unresolved', 'unexpected_after_state', after, release=False)
            else:
                self._settle(request_id, directory, raw, request, 'applied', 'expected_after_state', after, release=True)
            return
        if failed or after != expected:
            self._roll_back(request_id, stop=False)  # never stop our own unit; restore at once
            return
        self._write_atomic(directory / 'awaiting', after.encode('ascii'))

    def confirm(self, request_id):
        """Sent over a fresh SSH login after a commit-confirm change: proof the channel survived it."""
        directory, raw, request, family, mode = self._load(request_id)
        if mode != 'confirm':
            raise ValueError('Not a commit-confirm request')
        final = self._final(directory)
        if final is not None:
            return final
        if not (directory / 'awaiting').exists():
            return self._running(request_id, 'job_running')
        if _sha(family.read_state(request['parameters'])) != request['expected_after_sha256']:
            return self._running(request_id, 'awaiting_rollback')  # drifted: the timer restores it
        try:
            self._create(directory / 'decision', b'confirmed')
        except FileExistsError:
            return self._final(directory) or self._running(request_id, 'rollback_in_progress')
        return self._finish_confirm(request_id)

    def _finish_confirm(self, request_id):
        directory, raw, request, family, _ = self._load(request_id)
        after = _sha(family.read_state(request['parameters']))
        if after != request['expected_after_sha256']:
            return self._restore_now(request_id)
        data = self._settle(request_id, directory, raw, request, 'applied', 'confirmed', after, release=True)
        try:
            self.launcher.disarm_rollback(request_id)  # the timer would find the decision and stop anyway
        except Exception:
            pass
        return data

    def rollback(self, request_id):
        """Entry of the rollback timer unit."""
        directory, _, _, _, mode = self._load(request_id)
        if mode != 'confirm':
            raise ValueError('Not a commit-confirm request')
        return self._final(directory) or self._roll_back(request_id, stop=True)

    def _roll_back(self, request_id, *, stop, resume=False):
        directory = self._directory(request_id)
        try:
            self._create(directory / 'decision', b'rollback')
        except FileExistsError:
            final = self._final(directory)
            if final is not None:
                return final
            if not resume or (directory / 'decision').read_bytes() != b'rollback':
                return self._running(request_id, 'rollback_in_progress')
        if stop and self.launcher.job_active(request_id):
            self.launcher.stop_job(request_id)
        return self._restore_now(request_id)

    def _restore_now(self, request_id):
        directory, raw, request, family, _ = self._load(request_id)
        params, before = request['parameters'], request['before_state_sha256']
        try:
            if _sha(family.read_state(params)) == before:
                outcome, code = 'rolled_back', 'nothing_to_restore'
            else:
                family.restore(params, (directory / 'before_state').read_bytes())
                outcome, code = ('rolled_back', 'restored') if _sha(family.read_state(params)) == before else (
                    'unresolved', 'rollback_failed')
            after = _sha(family.read_state(params))
        except Exception:
            outcome, code, after = 'unresolved', 'rollback_failed', None
        return self._settle(request_id, directory, raw, request, outcome, code, after, release=outcome == 'rolled_back')

    def _supervised_status(self, request_id):
        """Status of a supervised request without a terminal receipt; None means decide from state as usual."""
        directory, raw, request, family, mode = self._load(request_id)
        if (directory / 'awaiting_reboot').exists():
            after = _sha(family.read_state(request['parameters']))
            if after == request['expected_after_sha256']:
                return self._settle(request_id, directory, raw, request, 'applied', 'rebooted', after, release=True)
            return self._running(request_id, 'awaiting_reboot')
        decision = directory / 'decision'
        if decision.exists():
            if decision.read_bytes() == b'confirmed':
                return self._finish_confirm(request_id)  # a confirmation interrupted before its receipt
            return self._running(request_id, 'rollback_in_progress')
        if (directory / 'awaiting').exists():
            return self._running(request_id, 'awaiting_confirmation')
        if self.launcher is not None and self.launcher.job_active(request_id):
            return self._running(request_id, 'job_running')
        if mode == 'confirm':
            return self._roll_back(request_id, stop=False)  # the job ended without a change to confirm
        return None

    def boot_rollback(self):
        """At boot (transient timers do not survive a reboot): restore every unconfirmed commit-confirm change."""
        restored, requests = [], self.state / 'requests'
        if not requests.is_dir():
            return restored
        for directory in sorted(requests.iterdir()):
            job = directory / 'job'
            if not re.fullmatch(r'[0-9a-f]{32}', directory.name) or not job.exists() or job.read_bytes() != b'confirm':
                continue
            decision = directory / 'decision'
            if self._final(directory) is not None or (decision.exists() and decision.read_bytes() == b'confirmed'):
                continue
            self._roll_back(directory.name, stop=False, resume=True)
            restored.append(directory.name)
        return restored
