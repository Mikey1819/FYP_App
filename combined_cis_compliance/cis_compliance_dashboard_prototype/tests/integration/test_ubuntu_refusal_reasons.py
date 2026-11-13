"""Group 3 of the 12 November round (user report, 13 November): two package-list refreshes "succeeded", yet 1.3.1.1
and 6.3.1.1 never got a fix plan, and the page could not say why.

- `apt-get update` exits 0 even when every download fails; the refresh now runs `apt-get update --error-on=any`, so a
  refresh that fetched nothing fails, with its reason, instead of reading `applied`.
- The runner's read-only preview now returns the reason a fix is not eligible on this server (a fixed sentence the fix
  code wrote, printable ASCII, at most 200 characters) instead of refusing silently; bad input and unknown fixes are
  still refused silently. The round records each reason; the page shows it, with what to do for the package case.
TEST-ONLY families, fake target I/O; the VM is never contacted.
"""
import json
import unittest
from tests.integration import test_ubuntu_proposals as proposals
from tests.integration.runner_fixture import FileValueFamily


class RefusingFamily(FileValueFamily):
    reason = 'Nothing to install, or a target package is unavailable from the configured sources'

    def check_eligible(self, params):
        raise ValueError(self.reason)


class RefreshTests(unittest.TestCase):
    def test_the_refresh_fails_when_apt_fetched_nothing(self):
        from vm.ubuntu.family_maintenance import LinuxMaintenanceIO

        class Target(LinuxMaintenanceIO):
            _APT = ('/usr/bin/apt-get', '-q', '-o', 'DPkg::Lock::Timeout=120')

            def __init__(self):
                self.commands = []

            def _exec(self, argv, seconds):
                self.commands.append(argv)
                return (100 if '--error-on=any' in argv else 0), ''  # what apt does with no route to the mirror
        target = Target()
        with self.assertRaisesRegex(OSError, 'apt-get update failed'):
            target.apt_update()
        self.assertEqual(target.commands[-1][-2:], ['update', '--error-on=any'])


class RunnerPreviewTests(unittest.TestCase):
    def runner(self, family):
        import tempfile
        from pathlib import Path
        from vm.ubuntu.runner import Runner
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        return Runner(Path(folder.name), {family.action_id: family}, lambda: ('a' * 32, 'ubuntu-fixture'),
                      require_root_owned=False)

    def test_an_ineligible_fix_returns_its_reason_instead_of_a_silent_refusal(self):
        import tempfile
        from pathlib import Path
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        family = RefusingFamily(Path(folder.name))
        preview = self.runner(family).preview(family.action_id, {'name': 'alpha', 'value': 'new'})
        self.assertEqual(preview, {'action_id': family.action_id, 'refused': RefusingFamily.reason})

    def test_the_reason_is_bounded_printable_text(self):
        import tempfile
        from pathlib import Path
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        family = RefusingFamily(Path(folder.name))
        family.reason = 'café\nnext line ' + 'x' * 400
        reason = self.runner(family).preview(family.action_id, {'name': 'alpha', 'value': 'new'})['refused']
        self.assertLessEqual(len(reason), 200)
        self.assertTrue(all(' ' <= ch <= '~' for ch in reason), reason)

    def test_bad_input_and_unknown_fixes_are_still_refused_silently(self):
        import tempfile
        from pathlib import Path
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        family = RefusingFamily(Path(folder.name))
        runner = self.runner(family)
        with self.assertRaises(ValueError):
            runner.preview(family.action_id, {'name': 'BAD NAME', 'value': 'new'})
        with self.assertRaises(ValueError):
            runner.preview('fixture.unknown.v1', {})


class HostConsumerTests(unittest.TestCase):
    """Every host path that reads a preview treats the refusal document as a refusal, never as a full preview."""

    def backend(self):
        from types import SimpleNamespace as N
        from backends.ubuntu.adapter import UbuntuBackend
        backend = UbuntuBackend.__new__(UbuntuBackend)
        refusal = {'refused': 'TEST-ONLY not eligible'}
        backend.session = N(channel=N(invoke_runner=lambda data: json.dumps(
            dict(refusal, action_id=json.loads(data.split(b'\n', 1)[0])['action_id'])).encode()))
        return backend

    def test_the_remediation_agents_precheck_reads_it_as_a_refused_preview(self):
        from types import SimpleNamespace as N
        proposal = N(payload={'fields': {'parameters': {}, 'before_state_sha256': 'a' * 64,
                                         'expected_after_sha256': 'b' * 64}, 'action': {'action_id': 'ubuntu.1.5.1.v1'}},
                     approved_raw=json.dumps({'expires_at': '2099-01-01T00:00:00+00:00'}).encode())
        facts = self.backend()._precheck(proposal)
        self.assertEqual((facts['preview_refused'], facts['precondition_changed']), (True, False))

    def test_a_refused_maintenance_preview_is_a_clear_refusal(self):
        from unittest import mock
        from types import SimpleNamespace as N
        from system.contracts import AuxiliaryKind, MetadataRefreshInput
        backend = self.backend()
        store = N(proposals=lambda binding, round_id: [])
        with mock.patch.object(backend, '_store', return_value=store, create=True), \
                mock.patch.object(backend, '_latest', return_value=N(round_id='r', evidence_sha256='e'), create=True):
            with self.assertRaisesRegex(ValueError, 'TEST-ONLY not eligible'):
                backend._request_maintenance('binding', AuxiliaryKind.METADATA_REFRESH, MetadataRefreshInput(''), 'op')


class RoundRecordsReasonTests(proposals.BackendRemediationTests):
    def setUp(self):
        super().setUp()
        self.family = RefusingFamily(self.work)

    def test_the_round_keeps_the_reason_and_the_plan_row_shows_it_with_what_to_do(self):
        backend = self.backend(self.FIX)
        handle, snap = self.round(backend)
        self.assertEqual(snap.proposals, ())  # no fix plan, as before
        details = [r for r in backend._store().rounds(handle.binding) if r.kind == 'assessment'][-1].details
        self.assertEqual(details['preview_refused'], {'1.5.1': RefusingFamily.reason})
        [row] = [r for r in snap.plan if r.control_id == '1.5.1']
        self.assertEqual(row.decision, 'Fix proposed')
        self.assertIn('refused its read-only check: ' + RefusingFamily.reason, row.reason)
        self.assertIn('Refresh package lists', row.reason)  # what to do, for the package case
        self.assertIn('NAT', row.reason)


for _name in [n for n in dir(proposals.BackendRemediationTests) if n.startswith('test')]:
    setattr(RoundRecordsReasonTests, _name, None)  # only the harness is inherited


if __name__ == '__main__':
    unittest.main()
