"""Module 2 (Ubuntu): is the local AI ready before a round, and can a round survive one slow model answer?

Live 11 November 13:42: the scan succeeded, then the Scanner's and the Orchestrator's second model requests timed out
(about 1.8 GB of 16 GB laptop memory free), so the round ended without analysis or plan.
- A **Check AI** button (the administrator's choice: never by itself) sends a tiny timed request to qwen3:8b (which
  also loads it), reads free laptop memory and asks Ollama whether the model is on the GPU or CPU. Badge: AI ready, AI
  slow (over 20 s, under 2 GB free, or partly on the CPU), AI not answering (Start disabled until checked again).
- A timed-out model step is retried once per agent run, with the same request (the scan already done is kept and the
  Scanner is not sent again), only while the run's time budget allows.
- Each step's model response time is recorded and shown in the Agent log and the round report.
Fakes only: no Ollama, no VM.
"""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as N
from unittest import mock

from tests.integration import test_ubuntu_agents as agents
from tests.integration.test_ubuntu_agents import Scripted, analysis_ok, call, plan_call, team


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class CheckTests(unittest.TestCase):
    def check(self, *, seconds=1.2, answer=True, available=True, size_vram=6, free=6.0, ps=True):
        from backends.ubuntu.ai_readiness import check
        clock = Clock()

        def chat():
            clock.now += seconds
            if answer is not True:
                raise answer
        processes = (lambda: {'models': [{'name': 'qwen3:8b', 'size': 6, 'size_vram': size_vram}]}) if ps else None
        return check(chat=chat, available=lambda: available, processes=processes or (lambda: (_ for _ in ()).throw(OSError())),
                     free_memory=lambda: free, clock=clock)

    def test_a_fast_answer_on_the_gpu_with_memory_free_is_ready(self):
        result = self.check()
        self.assertEqual((result.state, result.seconds, result.processor, result.free_gb), ('ready', 1.2, '100% GPU', 6.0))
        self.assertIn('AI ready', result.text)

    def test_any_of_the_three_signs_makes_it_slow_and_says_why(self):
        for kwargs, words in (({'seconds': 25.0}, 'answered in 25'), ({'free': 1.8}, '1.8 GB'),
                              ({'size_vram': 3}, '50% CPU / 50% GPU')):
            with self.subTest(**kwargs):
                result = self.check(**kwargs)
                self.assertEqual(result.state, 'slow')
                self.assertIn(words, result.text)
                self.assertIn('free memory', result.text)

    def test_no_model_a_failed_or_too_slow_answer_is_not_answering(self):
        for kwargs in ({'available': False}, {'answer': TimeoutError()}, {'answer': ConnectionRefusedError()},
                       {'seconds': 61.0}):
            with self.subTest(**{k: type(v).__name__ if isinstance(v, Exception) else v for k, v in kwargs.items()}):
                result = self.check(**kwargs)
                self.assertEqual(result.state, 'down')
                self.assertIn('AI not answering', result.text)

    def test_unknown_memory_or_processor_never_makes_it_slow_by_itself(self):
        result = self.check(free=None, ps=False)
        self.assertEqual((result.state, result.processor, result.free_gb), ('ready', 'unknown', None))


class RetryTests(agents.AgentRoundTests):
    def test_a_timed_out_step_is_retried_once_and_the_round_keeps_its_scan(self):
        fix = [{'control_id': '1.5.1', 'decision': 'defer', 'reason_code': 'no_registered_action'},
               {'control_id': '5.1.20', 'decision': 'defer', 'reason_code': 'no_registered_action'}]
        scanner = Scripted([call('scan_target'), TimeoutError('slow'), call('read_coverage'),
                            call('handoff_analysis', reason='Coverage read.')])
        orchestrator = Scripted([call('delegate_scanner'), TimeoutError('slow'), call('delegate_analysis'),
                                 plan_call(fix)])
        result = self.run_round(team(orchestrator, scanner, analysis_ok()))
        self.assertIsNotNone(result['plan'])  # before: Unavailable, no analysis, no plan
        self.assertEqual(len(self.collected), 1)  # the scan already done was kept; the Scanner was not sent again
        timing = self.timing(result['children']['scanner'])
        self.assertEqual([s['retried'] for s in timing], [False, True, False])
        self.assertTrue(all(type(s['seconds']) is float for s in timing))
        self.assertTrue(any(s['retried'] for s in self.timing(result['orchestrator_run_id'])))

    def test_only_one_retry_per_agent_run(self):
        scanner = Scripted([call('scan_target'), TimeoutError('slow'), TimeoutError('slow again')])
        result = self.run_round(team(Scripted([call('delegate_scanner')]), scanner, ()))
        finished = self.events(result['children']['scanner'])
        self.assertIn('did not answer (TimeoutError)', [e for e in finished if e['kind'] == 'finished'][0]['data']['summary'])
        self.assertEqual(len(self.collected), 1)

    def test_no_retry_when_the_time_budget_is_spent(self):
        from backends.ubuntu.agents import _Labelled
        clock = Clock()
        client = _Labelled(Scripted([TimeoutError('slow'), call('read_coverage')]), clock=clock, seconds=60)
        clock.now = 50.0  # 10 s left: too little for a retry
        with self.assertRaises(TimeoutError):
            client.chat([], [], timeout=10)
        self.assertEqual(client.timings[-1]['retried'], False)

    def timing(self, run_id):
        from hardening.investigation import InvestigationLog
        [event] = [e for e in InvestigationLog(self.log).get(run_id)['events'] if e['kind'] == 'model_timing']
        return event['data']['steps']


class StepTimeTests(unittest.TestCase):
    def test_each_step_of_the_agent_log_and_the_report_carries_its_model_time(self):
        from system.contracts import AgentEvent
        from system.ui.round_report import ubuntu_round_report
        from hardening.agentic_view import _ubuntu_step_rows
        events = [AgentEvent('run-1', 'scanner', 'tool', 'scan_target', '{}', '{}', '', 't1', 'Local Ollama (qwen3:8b)',
                             'Assessment phase', model_seconds=3.5),
                  AgentEvent('run-1', 'scanner', 'tool', 'read_coverage', '{}', '{}', '', 't2', 'Local Ollama (qwen3:8b)',
                             'Assessment phase', model_seconds=95.2, model_retried=True),
                  AgentEvent('run-1', 'scanner', 'finished', '', '', 'Completed: done', 'handoff', 't3',
                             'Local Ollama (qwen3:8b)', 'Assessment phase', 2, 120.0, model_seconds=1.0)]
        rows = _ubuntu_step_rows(events)
        self.assertEqual([r['Model seconds'] for r in rows], ['3.5', '95.2 (retried once)', '1.0'])
        snapshot = N(summary=None, current_round_reference=None, plan=(), findings=(), controls=(), proposals=(),
                     results=(), events=events, target=N(hostname='UBUNTU-FIXTURE'))
        html = ubuntu_round_report(snapshot, (), None, None)
        self.assertIn('Model seconds per step', html)
        self.assertIn('3.5, 95.2 (retried), 1.0', html)

    def test_the_backend_attaches_each_requests_time_to_the_events_it_produced(self):
        from backends.ubuntu.adapter import _step_times
        events = [{'kind': 'request', 'data': {'step': 1}}, {'kind': 'tool', 'data': {}},
                  {'kind': 'tool', 'data': {}},  # a second call from the same answer: no time of its own
                  {'kind': 'request', 'data': {'step': 2}}, {'kind': 'tool_rejected', 'data': {}},
                  {'kind': 'request', 'data': {'step': 3}}, {'kind': 'finished', 'data': {}},
                  {'kind': 'model_timing', 'data': {'steps': [{'seconds': 2.0, 'retried': False},
                                                             {'seconds': 40.5, 'retried': True},
                                                             {'seconds': 1.5, 'retried': False}]}}]
        self.assertEqual(_step_times(events), {1: (2.0, False), 4: (40.5, True), 6: (1.5, False)})


class BadgeUiTests(unittest.TestCase):
    """The Check AI button and its badge on the Ubuntu page (MaintenanceUiTests' connected fake page)."""

    def run_page(self, readiness):
        from tests.integration import test_ubuntu_maintenance_ui as maintenance_ui
        from tests.integration.test_ubuntu_live_path import open_gate
        case = maintenance_ui.MaintenanceUiTests('test_refresh_is_offered_only_after_a_package_fix_could_not_be_planned')
        case.setUp()
        self.addCleanup(case.doCleanups)
        checks = []

        def fake_check():
            checks.append(1)
            return readiness
        with open_gate(), mock.patch('backends.ubuntu.ai_readiness.check', side_effect=fake_check):
            app, _ = case.page()
            text = ' '.join(e.value for kind in (app.caption, app.markdown) for e in kind)
            start_before = app.button(key='agentic_run').disabled
            self.assertEqual(checks, [])  # never by itself
            self.assertIn('Optional: Check AI', text)  # short, and says it is optional (2026-11-13)
            app.button(key='ubuntu_ai_check').click().run()
            self.assertEqual(checks, [1])
            return app, start_before

    def readiness(self, state, text):
        from backends.ubuntu.ai_readiness import Readiness
        return Readiness(state, 1.0, 6.0, '100% GPU', (), text)

    def shown(self, app):
        return ' '.join(e.value for kind in (app.markdown, app.caption, app.success, app.warning, app.error)
                        for e in kind)

    def test_not_answering_disables_start_until_checked_again(self):
        app, before = self.run_page(self.readiness('down', 'AI not answering: TEST-ONLY.'))
        self.assertFalse(before)
        self.assertTrue(app.button(key='agentic_run').disabled)
        self.assertIn('AI not answering', self.shown(app))

    def test_slow_warns_and_leaves_start_enabled(self):
        app, _ = self.run_page(self.readiness('slow', 'AI slow: TEST-ONLY. Close other programs to free memory.'))
        self.assertFalse(app.button(key='agentic_run').disabled)
        self.assertIn('AI slow', ' '.join(w.value for w in app.warning))

    def test_ready_says_so(self):
        app, _ = self.run_page(self.readiness('ready', 'AI ready: TEST-ONLY.'))
        self.assertFalse(app.button(key='agentic_run').disabled)
        self.assertIn('AI ready', self.shown(app))
        self.assertIn('check took', self.shown(app))  # how long the check itself took


for _name in [n for n in dir(agents.AgentRoundTests) if n.startswith('test')]:
    setattr(RetryTests, _name, None)  # only the harness is inherited
