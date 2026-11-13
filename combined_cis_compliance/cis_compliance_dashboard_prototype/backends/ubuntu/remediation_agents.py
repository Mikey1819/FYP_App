"""Ubuntu remediation phase after the administrator approved fixes: the Remediation Agent and the AI Agent
Orchestrator's review, over the unchanged Windows Coordinator (hardening/investigation.py).

The Orchestrator delegates the Remediation Agent, then a verification scan by the Scanner Agent, then decides the next
step (finish, next round or remediation review) with a reason code that code checks against the recorded results.
The Remediation Agent prechecks the approved requests read-only, skips what is not ready, executes the ready ones in
the order it chooses and, after a refused fix, decides whether to go on or stop. It acts only on approved requests and
names them by control ID; it never approves, never chooses a value and never writes a command. Every hard guard stays
in code and on the server: the exact approved bytes and their expiry (approvals.verify), one ledger claim per request
(never dispatched twice), the runner's identity, hash and before-state checks, and no further fix after an outcome
that may be unconfirmed. Every sentence the administrator sees is written by code from the recorded results.

The backend supplies a `Phase`: the open approved requests and four callables (precheck, execute, skip, verify).
"""
import time

from hardening.investigation import Limits
from system.contracts import ComplianceStatus
from .agents import (COMMON, coordinate, ORCHESTRATOR, ORCHESTRATOR_REQUEST_SECONDS, PHASE_SECONDS, SCANNER, ScannerTools,
                     _Round, _tool)

REMEDIATION = 'remediation'
REVIEW_ROLE = 'orchestrator (review)'
MAX_PRECHECKS = 2
# The executor's settled states, as the agents see them.
KIND = {'completed': 'applied', 'refused': 'refused', 'unresolved': 'uncertain', 'running': 'running'}
SKIP_REASONS = {'precondition_changed': 'the server changed since approval (its before-state differs from the plan)',
                'expired': 'the approval has expired',
                'preview_refused': 'the read-only preview on the server was refused',
                'stop_after_failure': 'stopped after a refused fix: the remaining fixes would likely fail the same way'}
NEXT_STEP = {
    'finish': {'all_verified': 'every applied fix was verified Compliant by the fresh scan',
               'nothing_fixable': 'the fresh scan shows no remaining failure with a registered fix',
               'nothing_executed': 'nothing was executed and nothing is left open'},
    'next_round': {'remaining_findings': 'failures with a registered fix remain ({remaining}); a new round plans them',
                   'unblocked_findings': 'the applied fixes made {unblocked} fixable; a new round plans them'},
    'remediation_review': {'verification_failed': '{failed} did not verify Compliant; review before any new plan',
                           'verification_unavailable': 'no verification scan covers {unverified} yet',
                           'fix_refused': 'the server refused {refused}; nothing was written for it',
                           'uncertain_outcome': 'the outcome of {uncertain} is uncertain; check its status first',
                           'awaiting_confirmation': '{running} waits for its confirmation over a fresh login (the '
                                                    'dashboard does this by itself), or for the reboot',
                           'remediation_incomplete': '{not_attempted} was not attempted'}}
# What a fix waits for once the server has run it (the family's supervision). Nothing more runs while one waits, so
# code runs the fixes that wait after those that do not: problem 5 (live 11 November), where an SSH fix ran first and
# the other approved fixes never did.
WAITS = {None: 'no', 'job': 'supervised job', 'confirm': 'confirmation after a fresh login'}
WAIT_ORDER = {None: 0, 'job': 1, 'confirm': 2}
FACT_LISTS = ('failed', 'unverified', 'refused', 'uncertain', 'running', 'not_attempted', 'remaining', 'unblocked')

REMEDIATION_PROMPT = COMMON + (
    'You are the Remediation Agent. You act only on fixes the administrator approved; you never approve, choose values '
    'or write commands. 1) Call precheck to check the server read-only (list_approved is optional). 2) Decide each '
    'request once: skip_fix (with a reason_code from its skip_codes) every request precheck shows not ready, and '
    'execute_fixes with the ready ones in the order you choose (the listed order unless a prerequisite needs another '
    'first); code runs the fixes that wait (waits is not "no") after the others. Execution pauses after a refused fix: judge whether the remaining requests would fail the same way, then '
    'continue with execute_fixes or call stop_execution. After must_stop execute nothing more. 3) Finish with '
    'report_results (target_id only: code records every result).')
REVIEW_PROMPT = COMMON + (
    'You are the AI Agent Orchestrator after the administrator approved fixes. You never execute, approve or retry '
    'yourself. 1) Call delegate_remediation. 2) If any fix was applied, call delegate_verification so the Scanner '
    'Agent rescans the server. 3) Call submit_review once with next_step finish, next_round or remediation_review and '
    'a reason_code from next_step_codes for that step.')


class Phase:
    """What the backend hands the remediation phase. `requests`: the open approved fixes in plan order, as dicts with
    request_id, control_id, action_id, title, expires_at, rank (or None) and optionally waits (None, 'job' or
    'confirm': what the fix waits for after it ran). `precheck(request_id)` returns the
    read-only facts {expired, precondition_changed, preview_refused} and raises only when the server cannot be reached;
    `execute(request_id)` dispatches once and returns (state, code), state one of KIND; `skip(request_id, reason)`
    records a durable skip; `verify(request_ids)` runs and records the verification scan, returning (run_id,
    evidence); `eligible(evidence)` maps failures to their registered action; `before` is the assessed scan."""
    team_prefix = 'ubuntu-remediation:'  # + the assessment round ID: how the phase's agent runs are found again

    def __init__(self, *, target_id, round_id, log_store, requests, precheck, execute, skip, verify, eligible, before,
                 clock=time.monotonic):
        self.target_id, self.round_id, self.store = target_id, round_id, log_store
        self.requests = [dict(r) for r in requests]
        self.precheck, self.execute, self.skip, self.verify = precheck, execute, skip, verify
        self.eligible, self.before, self.clock = eligible, before, clock
        self.team_id = self.team_prefix + round_id


class _PhaseTools:
    """The attributes the Coordinator and its log read from a tools object, for a remediation-phase role."""
    names = ()
    repeatable = ()
    nudge = True
    proposal_id = None
    evidence_mode = 'Live (SSH)'

    def __init__(self, phase, role, prompt, scenario):
        self.phase, self.agent_role, self.system_prompt, self.scenario = phase, role, prompt, scenario
        self.store, self.target_id = phase.store, phase.target_id
        self.assessment_id = self.team_id = phase.team_id
        self.terminal_outcome = None

    def available(self):
        return self.names

    def schemas(self):
        everything = self._schemas()
        return [everything[name] for name in self.available()]

    def _args(self, name, arguments, *keys):
        if name not in self.available():
            raise ValueError('Tool not available now: ' + str(name)[:80])
        if type(arguments) is not dict or set(arguments) != {'target_id', *keys}:
            raise ValueError(name + ' takes exactly: target_id' + ''.join(', ' + k for k in keys))
        if arguments['target_id'] != self.target_id:
            raise ValueError('Calls must name the verified target')
        return arguments


class RemediationTools(_PhaseTools):
    names = ('list_approved', 'precheck', 'execute_fixes', 'skip_fix', 'stop_execution', 'report_results')
    repeatable = ('precheck',)  # At most twice, e.g. to re-check after an execution (bounded below).

    def __init__(self, phase):
        super().__init__(phase, REMEDIATION, REMEDIATION_PROMPT, 'ubuntu-remediation')
        self.requests = {r['request_id']: r for r in phase.requests}
        self.request_for = {r['control_id']: r['request_id'] for r in phase.requests}
        self.checks, self.facts, self.results, self.skipped, self.stopped, self.seen = 0, {}, [], [], None, set()
        self.initial_message = (f'{len(self.requests)} administrator-approved fix(es) wait for target {self.target_id}: '
                                f'{", ".join(self.request_for)}. Start with precheck.')

    def open(self):
        handled = {r['request_id'] for r in self.results} | {s['request_id'] for s in self.skipped}
        return {i: r for i, r in self.requests.items() if i not in handled}

    def _failed(self):
        return any(r['result'] == 'refused' for r in self.results)

    def _skip_codes(self, request_id):
        facts = self.facts.get(request_id, {})
        return [c for c in SKIP_REASONS if (self._failed() if c == 'stop_after_failure' else facts.get(c))]

    def available(self):
        if not self.open() or self.stopped:
            return ('report_results',)
        if not self.checks:
            return ('precheck',) if 'list_approved' in self.seen else ('list_approved', 'precheck')
        return (('execute_fixes', 'skip_fix') + (('stop_execution',) if self._failed() else ())
                + (('precheck',) if self.checks < MAX_PRECHECKS else ()))

    def _schemas(self):
        t = self.target_id
        controls = [r['control_id'] for r in self.open().values()]
        ids = {'type': 'string', **({'enum': controls} if controls else {})}
        return {'list_approved': _tool('list_approved', 'The approved, not yet executed fixes in plan order.', t),
                'precheck': _tool('precheck', 'Check the server read-only now: is each approved fix still ready (server '
                                  'unchanged since approval, preview accepted, approval not expired)?', t),
                'execute_fixes': _tool('execute_fixes', 'Execute ready approved fixes (by control_id) once each, in the '
                                       'given order; the server verifies each. Stops at an uncertain outcome.', t,
                                       control_ids={'type': 'array', 'minItems': 1, 'maxItems': 40, 'items': ids}),
                'skip_fix': _tool('skip_fix', 'Leave one approved fix unexecuted, with a reason code from its '
                                  'skip_codes.', t, control_id=ids,
                                  reason_code={'type': 'string', 'enum': sorted(SKIP_REASONS)}),
                'stop_execution': _tool('stop_execution', 'After a refused fix: leave every remaining fix unexecuted '
                                        'and finish; code records why.', t),
                'report_results': _tool('report_results', 'Finish once every fix is executed or skipped, or after '
                                        'must_stop. Takes target_id only: code writes the report.', t)}

    def _row(self, request_id):
        r = self.requests[request_id]
        return {'control_id': r['control_id'], 'action_id': r['action_id'], 'title': r['title'], 'rank': r['rank'],
                'approval_expires_at': r['expires_at'], 'waits': WAITS[r.get('waits')]}

    def _wait(self, request_id):
        return WAIT_ORDER[self.requests[request_id].get('waits')]

    def _open_request(self, control_id):
        request_id = self.request_for.get(control_id) if type(control_id) is str else None
        if request_id is None or request_id not in self.open():
            raise ValueError('Not an open approved fix: ' + str(control_id)[:40])
        return request_id

    def _precheck(self):
        if self.checks >= MAX_PRECHECKS:
            raise ValueError(f'precheck runs at most {MAX_PRECHECKS} times')
        self.checks += 1
        rows = []
        for request_id, r in self.open().items():
            try:
                facts = self.phase.precheck(request_id)
            except Exception as exc:  # The server could not be reached: nothing is skipped and nothing runs.
                self.facts, self.stopped = {}, 'the server could not be checked'
                return {'state': 'unavailable', 'detail': type(exc).__name__, 'must_stop': True}
            self.facts[request_id] = {k: bool(facts.get(k)) for k in ('precondition_changed', 'expired',
                                                                     'preview_refused')}
            ready = not any(self.facts[request_id].values())
            rows.append({'control_id': r['control_id'], 'ready': ready, 'waits': WAITS[r.get('waits')],
                         **({} if ready else {'skip_codes': self._skip_codes(request_id)})})
        return {'state': 'checked', 'requests': rows}

    def _execute_all(self, control_ids):
        """Validate the whole list first, so a refused list executes nothing; then run it in the agent's order."""
        if type(control_ids) is not list or not control_ids or len(set(map(str, control_ids))) != len(control_ids):
            raise ValueError('control_ids must be a non-empty list without repeats')
        request_ids = []
        for control_id in control_ids:
            request_id = self._open_request(control_id)
            facts = self.facts.get(request_id)
            if facts is None:
                raise ValueError('Call precheck before executing ' + str(control_id)[:40])
            if any(facts.values()):
                raise ValueError(f"{control_id} is not ready ({', '.join(c for c, v in facts.items() if v)}); "
                                 'use skip_fix')
            request_ids.append(request_id)
        # The fixes that wait run last (stable: the agent's order within each kind), and none may start while a ready
        # fix that does not wait is left out of the list: nothing more would run until it settles.
        request_ids.sort(key=self._wait)
        if self._wait(request_ids[0]):
            ready = [r['control_id'] for i, r in self.open().items() if i not in request_ids and not self._wait(i)
                     and i in self.facts and not any(self.facts[i].values())]
            if ready:
                raise ValueError('Execute the fixes that do not wait first (' + ', '.join(ready) + '): nothing more '
                                 'runs while ' + self.requests[request_ids[0]]['control_id'] + ' waits for '
                                 + WAITS[self.requests[request_ids[0]].get('waits')])
        results = []
        for request_id in request_ids:
            if self.stopped or (results and results[-1]['result'] == 'refused'):
                break  # Uncertain or running: the rest stay open. Refused: the agent decides how to go on.
            results.append(self._execute(request_id))
        output = {'results': results, 'must_stop': self.stopped is not None}
        if self.stopped:
            output['next'] = 'report_results with target_id only; these results are already recorded'
        elif results[-1]['result'] == 'refused' and self.open():
            output.update(paused_after_failure=True, remaining=[r['control_id'] for r in self.open().values()],
                          next='execute_fixes to continue with the remaining fixes, or stop_execution')
        return output

    def _execute(self, request_id):
        r = self.requests[request_id]
        state, code = self.phase.execute(request_id)
        kind = KIND.get(state, 'uncertain')
        if kind == 'uncertain':
            self.stopped = 'uncertain outcome'  # Never act again before a person reviews a possible write.
        elif kind == 'running':
            self.stopped = 'waiting for confirmation or a reboot'  # Nothing more until it settles.
        entry = {'request_id': request_id, 'control_id': r['control_id'], 'result': kind, 'code': str(code)[:80]}
        self.results.append(entry)
        return {k: entry[k] for k in ('control_id', 'result', 'code')}

    def _close(self, request_id, code):
        r = self.requests[request_id]
        self.phase.skip(request_id, SKIP_REASONS[code])
        self.skipped.append({'request_id': request_id, 'control_id': r['control_id'], 'reason_code': code})

    def outcome(self, finished):
        """Written by code from the recorded results; also used when the agent stopped without reporting."""
        by_kind = {k: [r['control_id'] for r in self.results if r['result'] == k] for k in set(KIND.values())}
        not_attempted = [r['control_id'] for r in self.open().values()]
        parts = []
        for kind, words in (('applied', 'Applied'), ('refused', 'Refused by the server (nothing written)'),
                            ('uncertain', 'Outcome uncertain'), ('running', 'Waiting for confirmation or reboot')):
            if by_kind[kind]:
                parts.append(words + ': ' + ', '.join(by_kind[kind]) + '.')
        if self.skipped:
            parts.append('Skipped by the Remediation Agent: ' + '; '.join(
                f"{s['control_id']} ({SKIP_REASONS[s['reason_code']]})" for s in self.skipped) + '.')
        if not_attempted:
            parts.append('Not attempted' + (f' ({self.stopped})' if self.stopped else '') + ': '
                         + ', '.join(not_attempted) + '.')
        return {'outcome': 'remediation_reported' if finished else 'incomplete',
                'reason': ' '.join(parts) or 'Nothing was executed.', 'results': list(self.results),
                'skipped': list(self.skipped), 'not_attempted': not_attempted}

    def call(self, name, arguments):
        if name in ('list_approved', 'precheck', 'report_results', 'stop_execution'):
            self._args(name, arguments)
            if name == 'list_approved':
                output = {'requests': [self._row(i) for i in self.open()]}
            elif name == 'precheck':
                output = self._precheck()
            elif name == 'stop_execution':
                if not self._failed() or self.stopped:
                    raise ValueError('stop_execution is for after a refused fix; nothing was refused')
                for request_id in list(self.open()):
                    self._close(request_id, 'stop_after_failure')
                self.terminal_outcome = self.outcome(finished=True)
                return dict(self.terminal_outcome)
            else:
                if self.open() and self.stopped is None:
                    raise ValueError('Decide every open fix first (execute_fixes or skip_fix): '
                                     + ', '.join(r['control_id'] for r in self.open().values()))
                self.terminal_outcome = self.outcome(finished=True)
                return dict(self.terminal_outcome)
        elif name == 'execute_fixes':
            output = self._execute_all(self._args(name, arguments, 'control_ids')['control_ids'])
        elif name == 'skip_fix':
            arguments = self._args(name, arguments, 'control_id', 'reason_code')
            request_id, code = self._open_request(arguments['control_id']), arguments['reason_code']
            if code not in SKIP_REASONS:
                raise ValueError(f"{str(code)[:30]} is not a skip reason_code; use one of {', '.join(sorted(SKIP_REASONS))}")
            if code not in self._skip_codes(request_id):
                raise ValueError(f"reason_code {code} does not fit {arguments['control_id']}"
                                 + ('; call precheck first' if request_id not in self.facts else ''))
            self._close(request_id, code)
            output = {'control_id': arguments['control_id'], 'reason_code': code, 'reason': SKIP_REASONS[code]}
        else:
            raise ValueError('Tool is outside this agent role')
        self.seen.add(name)
        return output


class ReviewTools(_PhaseTools):
    """The Orchestrator's remediation phase: Remediation Agent, verification by the Scanner Agent, next step."""
    names = ('delegate_remediation', 'delegate_verification', 'submit_review')
    # A refused review may be resubmitted (as a refused plan may, live 06:52-07:11); it is checked and refused again,
    # bounded by the Coordinator's invalid-call limit, and an accepted review ends the phase.
    repeatable = ('submit_review',)

    def __init__(self, phase, client_factory):
        super().__init__(phase, REVIEW_ROLE, REVIEW_PROMPT, 'ubuntu-remediation-review')
        self.client_factory, self.started = client_factory, phase.clock()
        self.initial_message = (f'The administrator approved {len(phase.requests)} fix(es) for target '
                                f'{self.target_id}. Start by delegating the Remediation Agent.')
        self.remediation = self.verification = None
        self.children = {}

    def remaining(self):
        return PHASE_SECONDS - (self.phase.clock() - self.started)

    def _run(self, role, tools, *, steps, calls, seconds, request):
        seconds = int(min(seconds, self.remaining()))
        if seconds < 5:
            raise ValueError('Phase deadline reached; no further delegation')
        child = coordinate(self.client_factory(role), tools, clock=self.phase.clock,
                           limits=Limits(steps=steps, calls=calls, seconds=seconds,
                                         request_seconds=min(request, seconds), invalid=2))
        return child['run_id'], child['events'][-1]['data']

    def applied(self):
        return [r for r in (self.remediation or {}).get('results', ()) if r['result'] == 'applied']

    def available(self):
        if self.remediation is None:
            return ('delegate_remediation',)
        if self.applied() and self.verification is None:
            return ('delegate_verification',)
        return ('submit_review',)

    def _schemas(self):
        t = self.target_id
        return {'delegate_remediation': _tool('delegate_remediation', 'Delegate the approved fixes to the Remediation '
                                              'Agent.', t),
                'delegate_verification': _tool('delegate_verification', 'Delegate a verification rescan of the server '
                                               'to the Scanner Agent.', t),
                'submit_review': _tool('submit_review', 'Decide the next step once, with a reason code that fits the '
                                       'results.', t, next_step={'type': 'string', 'enum': sorted(NEXT_STEP)},
                                       reason_code={'type': 'string', 'enum': sorted(
                                           {c for codes in NEXT_STEP.values() for c in codes})})}

    def facts(self):
        """Which next-step codes are true, from the recorded results and the verification scan, never model text."""
        remediation = self.remediation or {'results': [], 'not_attempted': []}
        kinds = {k: [r['control_id'] for r in remediation['results'] if r['result'] == k] for k in set(KIND.values())}
        scan = self.verification if self.verification and self.verification.get('run_id') else None
        status = scan['status'] if scan else {}
        applied = kinds['applied']
        failed = [c for c in applied if scan and status.get(c) != ComplianceStatus.COMPLIANT.value]
        unverified = [] if scan else list(applied)
        remaining, unblocked = (scan['remaining'], scan['unblocked']) if scan else ([], [])
        facts = {'failed': failed, 'unverified': unverified, 'refused': kinds['refused'], 'uncertain': kinds['uncertain'],
                 'running': kinds['running'], 'not_attempted': list(remediation['not_attempted']),
                 'remaining': remaining, 'unblocked': unblocked}
        clean = not any(facts[k] for k in ('failed', 'unverified', 'refused', 'uncertain', 'running', 'not_attempted'))
        truth = {'finish': {'all_verified': bool(applied) and bool(scan) and clean,
                            'nothing_fixable': bool(scan) and not remaining and clean,
                            'nothing_executed': not applied and clean},
                 'next_round': {'remaining_findings': bool(scan) and clean and bool(remaining),
                                'unblocked_findings': bool(scan) and clean and bool(unblocked)},
                 'remediation_review': {'verification_failed': bool(failed), 'verification_unavailable': bool(unverified),
                                        'fix_refused': bool(facts['refused']), 'uncertain_outcome': bool(facts['uncertain']),
                                        'awaiting_confirmation': bool(facts['running']),
                                        'remediation_incomplete': bool(facts['not_attempted'])}}
        facts['codes'] = {step: [c for c, true in codes.items() if true] for step, codes in truth.items()}
        return facts

    def _scan_facts(self, run_id, evidence):
        statuses = {a.control_id: a.status.value for a in evidence.assessments}
        now = set(self.phase.eligible(evidence))
        before = set(self.phase.eligible(self.phase.before)) if self.phase.before is not None else set()
        return {'run_id': run_id, 'status': statuses, 'remaining': sorted(now), 'unblocked': sorted(now - before)}

    def call(self, name, arguments):
        if name == 'delegate_remediation':
            self._args(name, arguments)
            if not self.phase.requests:
                raise ValueError('No approved, unexecuted fixes for this round')
            tools = RemediationTools(self.phase)
            run_id, finished = self._run(REMEDIATION, tools, steps=12, calls=16, seconds=360, request=150)
            self.children[REMEDIATION] = run_id
            self.remediation = tools.terminal_outcome or tools.outcome(finished=False)
            output = {'agent': REMEDIATION, 'status': finished['status'],
                      'results': [{k: r[k] for k in ('control_id', 'result', 'code')} for r in self.remediation['results']],
                      'skipped': [{k: s[k] for k in ('control_id', 'reason_code')} for s in self.remediation['skipped']],
                      'not_attempted': self.remediation['not_attempted']}
            if not self.applied():
                output['next_step_codes'] = self.facts()['codes']
            return output
        if name == 'delegate_verification':
            self._args(name, arguments)
            applied = [r['request_id'] for r in self.applied()]
            rounds = _Round(client_factory=self.client_factory, collect=lambda: self.phase.verify(applied),
                            log_store=self.store, target_id=self.target_id, titles={}, rank=lambda *a: None, goal=None,
                            clock=self.phase.clock)
            tools = ScannerTools(rounds, allow_rescan=False, verification=True)
            tools.assessment_id = tools.team_id = self.team_id
            run_id, finished = self._run(SCANNER, tools, steps=6, calls=8, seconds=180, request=120)
            self.children['verification'] = run_id
            if rounds.evidence is not None:  # Collected evidence counts even if the agent did not hand off.
                self.verification = self._scan_facts(rounds.run_id, rounds.evidence)
            else:
                self.verification = {'run_id': None, 'reason': 'the verification scan did not complete ('
                                     + str(finished['status'])[:80] + ')'}
            facts = self.facts()
            return {'agent': SCANNER, 'status': finished['status'], 'verification_run_id': self.verification['run_id'],
                    **{k: facts[k] for k in ('failed', 'unverified', 'remaining', 'unblocked')},
                    'next_step_codes': facts['codes']}
        if name == 'submit_review':
            arguments = self._args(name, arguments, 'next_step', 'reason_code')
            step, code = arguments['next_step'], arguments['reason_code']
            if step not in NEXT_STEP:
                raise ValueError(f"next_step must be one of {', '.join(sorted(NEXT_STEP))}")
            facts = self.facts()
            if code not in facts['codes'][step]:
                true = '; '.join(f"{s}: {', '.join(c)}" for s, c in facts['codes'].items() if c)
                raise ValueError(f'reason_code {str(code)[:30]} does not fit {step} for these results; true codes: {true}')
            sentence = NEXT_STEP[step][code].format(**{k: ', '.join(facts[k]) for k in FACT_LISTS})
            parts = [self.remediation['reason']]
            if self.verification and self.verification.get('run_id'):
                parts.append('Verification scan by the Scanner Agent: '
                             + ('; '.join(f"{c} {self.verification['status'].get(c, 'not assessed')}"
                                          for c in [r['control_id'] for r in self.applied()]) or 'done') + '.')
            elif self.verification:
                parts.append('Verification: ' + self.verification['reason'] + '.')
            parts.append('Next step (' + step.replace('_', ' ') + '): ' + sentence + '.')
            self.terminal_outcome = {'outcome': step, 'reason_code': code, 'reason': ' '.join(parts),
                                     'verification_run_id': (self.verification or {}).get('run_id')}
            return dict(self.terminal_outcome)
        raise ValueError('Tool is outside this agent role')


def settled_review(*, results, status, unverified, remaining):
    """The next step once every fix of an execution has settled, decided by code from the recorded outcomes and the
    final verification scan (administrator, 13 November 2026): the Orchestrator's own review was written while a fix
    still waited ("waits for its confirmation over a fresh login"), and the dashboard then carried on by itself.
    `results`: control -> applied / refused / uncertain; `status`: control -> status in the final scan;
    `unverified`: applied controls no scan covered; `remaining`: failures a registered fix can still plan."""
    kinds = {k: sorted(c for c, v in results.items() if v == k) for k in ('applied', 'refused', 'uncertain')}
    if not status:  # no final scan stored: every applied fix is unverified, none has failed
        unverified = set(unverified) | set(kinds['applied'])
    facts = {'failed': [c for c in kinds['applied'] if c not in unverified and status.get(c) != 'Compliant'],
             'unverified': sorted(unverified), 'refused': kinds['refused'], 'uncertain': kinds['uncertain'],
             'running': [], 'not_attempted': [], 'remaining': sorted(remaining), 'unblocked': []}
    order = (('remediation_review', 'verification_failed', facts['failed']),
             ('remediation_review', 'verification_unavailable', facts['unverified']),
             ('remediation_review', 'fix_refused', facts['refused']),
             ('remediation_review', 'uncertain_outcome', facts['uncertain']),
             ('next_round', 'remaining_findings', facts['remaining']),
             ('finish', 'all_verified', kinds['applied']))
    step, code = next(((s, c) for s, c, true in order if true), ('finish', 'nothing_executed'))
    parts = ['Every approved fix of this execution has run.']
    for kind, words in (('applied', 'Applied'), ('refused', 'Refused by the server (nothing written)'),
                        ('uncertain', 'Outcome uncertain')):
        if kinds[kind]:
            parts.append(words + ': ' + ', '.join(kinds[kind]) + '.')
    if status and kinds['applied']:
        parts.append('Final verification scan: ' + '; '.join(f'{c} {status.get(c, "not assessed")}'
                                                             for c in kinds['applied']) + '.')
    sentence = NEXT_STEP[step][code].format(**{k: ', '.join(facts[k]) for k in FACT_LISTS})
    parts.append('Next step (' + step.replace('_', ' ') + '): ' + sentence + '.')
    return {'next_step': step, 'reason_code': code, 'reason': ' '.join(parts)}


def run_remediation_phase(phase, *, client_factory):
    """One remediation phase. Returns the review's run, the Remediation Agent's recorded results, the verification
    scan (if any) and the next-step decision (None when the Orchestrator stopped without one)."""
    tools = ReviewTools(phase, client_factory)
    result = coordinate(client_factory(ORCHESTRATOR), tools, clock=phase.clock,
                        limits=Limits(steps=8, calls=10, seconds=PHASE_SECONDS,
                                      request_seconds=ORCHESTRATOR_REQUEST_SECONDS, invalid=3))
    return {'orchestrator_run_id': result['run_id'], 'status': result['events'][-1]['data']['status'],
            'remediation': tools.remediation, 'verification': tools.verification, 'review': tools.terminal_outcome,
            'children': dict(tools.children)}
