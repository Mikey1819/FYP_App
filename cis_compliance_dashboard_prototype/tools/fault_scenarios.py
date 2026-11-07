"""Task 17 fault-scenario matrix: each required scenario, the fixture tests that exercise it, run now.

Every listed test is located and executed; a missing or failing test is reported as such, never assumed. These are
fixture results (fake channels, temporary stores and state directories), not live VM evidence: live evidence is in
docs/evaluation/LIVE_VALIDATION.md.

Usage (from the app directory):
  ..\\.venv-integration\\Scripts\\python.exe -B -m tools.fault_scenarios            # print markdown
  ..\\.venv-integration\\Scripts\\python.exe -B -m tools.fault_scenarios --write    # docs/evaluation/FAULT_SCENARIOS.md
"""
from pathlib import Path
import argparse
import inspect
import io
import sys
import unittest

APP = Path(__file__).resolve().parents[1]

# (scenario, what must hold, [(module, test method)]) - in the order the plan lists them.
SCENARIOS = [
    ('Wrong OS or identity', 'Unsupported OS, wrong platform, changed host key or another machine never reach a backend or a write', [
        ('test_routing', 'test_windows_connection_rejects_wrong_os_before_routing'),
        ('test_identity', 'test_os_release_is_data_not_shell_and_duplicates_rejected'),
        ('test_identity', 'test_host_key_change_requires_reenrolment_and_no_tofu'),
        ('test_ubuntu_runner', 'test_identity_expiry_family_hash_and_tampering_refused_without_writes')]),
    ('Model offline', 'No AI round starts without the model; Assess without AI calls no model', [
        ('test_ubuntu_agents', 'test_model_offline_runs_no_scan_and_keeps_the_orchestrator_record'),
        ('test_ubuntu_agents', 'test_deterministic_mode_with_model_stopped_calls_no_model_and_labels_system_activity')]),
    ('Stale, rejected or duplicate requests', 'Expired, forged, rejected, superseded or repeated requests write nothing and dispatch at most once', [
        ('test_ubuntu_runner', 'test_expired_or_tampered_approval_is_refused_before_any_dispatch'),
        ('test_ubuntu_runner', 'test_applied_completes_once_and_a_second_operation_cannot_redispatch'),
        ('test_ubuntu_proposals', 'test_rejection_writes_nothing_and_cannot_be_executed'),
        ('test_ubuntu_concurrency', 'test_two_clients_executing_the_same_approved_set_at_once_dispatch_once'),
        ('test_ubuntu_concurrency', 'test_a_double_click_on_approve_records_one_decision'),
        ('test_ubuntu_concurrency', 'test_commands_against_an_earlier_round_are_refused_after_a_newer_round'),
        ('test_ubuntu_concurrency', 'test_an_expired_connection_session_can_no_longer_command')]),
    ('Partial collection', 'Incomplete evidence is never treated as complete; a collection error allows one bounded rescan', [
        ('test_provenance', 'test_envelope_refuses_incomplete_or_invalid_observations_and_bad_times'),
        ('test_provenance', 'test_mixed_probe_states_are_partial_not_ok'),
        ('test_privileged_inventory', 'test_permission_failure_and_deadline_never_return_partial_inventory'),
        ('test_ubuntu_agents', 'test_investigation_flag_and_rescan_limits'),
        ('test_ubuntu_agents', 'test_scan_failure_ends_round_without_evidence')]),
    ('Host crash', 'A crash at any point is reconciled from recorded state, never replayed or invented', [
        ('test_ubuntu_runner', 'test_crash_after_claim_before_write_reconciles_to_not_applied'),
        ('test_ubuntu_runner', 'test_process_death_after_write_reconciles_to_applied_and_releases_fence'),
        ('test_ubuntu_storage', 'test_crash_after_evidence_recovers_idempotently_without_fresh_claim_or_invented_round')]),
    ('Channel loss', 'A dropped connection leaves the change unresolved and fenced, then settles without a second dispatch', [
        ('test_ubuntu_runner', 'test_lost_receipt_is_unresolved_then_reconciled_without_replay'),
        ('test_routing', 'test_running_change_allows_disconnect_and_reconnect_to_the_same_vm_only')]),
    ('Lost receipt', 'A missing or foreign receipt is never trusted; the outcome comes from the target record', [
        ('test_ubuntu_runner', 'test_receipt_for_another_request_is_not_trusted'),
        ('test_ubuntu_supervision', 'test_a_job_that_died_without_a_receipt_is_reconciled_from_state_never_replayed'),
        ('test_ubuntu_supervision', 'test_a_failed_launch_is_unresolved_and_keeps_the_fence')]),
    ('Package timeout', 'Long jobs run under a systemd RuntimeMaxSec bound; a job killed without a receipt is reconciled', [
        ('test_ubuntu_supervision', 'test_execute_detaches_the_write_into_a_bounded_unit_and_status_follows_it'),
        ('test_ubuntu_supervision', 'test_a_job_that_died_without_a_receipt_is_reconciled_from_state_never_replayed'),
        ('test_ubuntu_supervision', 'test_rollback_stops_a_still_running_job_before_restoring')]),
    ('Immutable audit configuration', 'Locked (-e 2), wiping or unparseable audit rules are refused before any write', [
        ('test_ubuntu_audit_rules_family', 'test_locked_missing_wiping_or_unparseable_configurations_are_refused')]),
    ('Reboot', 'A reboot needs an applied change, completes only on a new boot ID, and boot recovery restores unconfirmed changes', [
        ('test_ubuntu_maintenance_host', 'test_reboot_needs_applied_changes_then_waits_for_the_new_boot'),
        ('test_ubuntu_proposals', 'test_a_reboot_naming_no_applied_change_is_refused'),
        ('test_ubuntu_supervision', 'test_boot_recovery_rolls_back_unconfirmed_changes_only')]),
    ('Snapshot and registration epoch', 'Evidence and approvals from another epoch are refused; the host epoch check stops pre-restore approvals', [
        ('test_ubuntu_runner', 'test_an_approval_from_an_earlier_registration_epoch_is_refused_before_any_dispatch'),
        ('test_ubuntu_backend_history', 'test_scope_epoch_identity_and_corruption')]),
]


def _locate(module_name, method):
    module = __import__('tests.integration.' + module_name, fromlist=['*'])
    for _, cls in inspect.getmembers(module, inspect.isclass):
        if issubclass(cls, unittest.TestCase) and method in vars(cls):
            return cls(method)
    return None


def run():
    sys.path.insert(0, str(APP))
    rows = []
    for scenario, holds, tests in SCENARIOS:
        results = []
        for module_name, method in tests:
            case = _locate(module_name, method)
            if case is None:
                results.append((module_name, method, 'missing'))
                continue
            outcome = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(case)
            results.append((module_name, method, 'pass' if outcome.wasSuccessful() else 'FAIL'))
        rows.append((scenario, holds, results))
    return rows


def markdown(rows):
    total = sum(len(r) for _, _, r in rows)
    passed = sum(state == 'pass' for _, _, r in rows for *_, state in r)
    lines = ['# Ubuntu fault-scenario matrix (task 17)', '',
             'Generated by `tools/fault_scenarios.py`, which locates and runs every listed test. These are **fixture** '
             'results (fake channels, temporary stores and state directories), not live VM evidence; live evidence is '
             'in `LIVE_VALIDATION.md`.', '', 'Result: %d of %d listed tests pass.' % (passed, total), '']
    for scenario, holds, results in rows:
        lines += ['## %s' % scenario, '', holds + '.', '']
        lines += ['- %s `%s.%s`' % ('pass' if state == 'pass' else '**%s**' % state, module, method)
                  for module, method, state in results]
        lines.append('')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--write', action='store_true', help='write docs/evaluation/FAULT_SCENARIOS.md')
    args = parser.parse_args()
    rows = run()
    text = markdown(rows)
    if args.write:
        (APP / 'docs' / 'evaluation' / 'FAULT_SCENARIOS.md').write_text(text, encoding='utf-8')
    print(text)
    if any(state != 'pass' for _, _, r in rows for *_, state in r):
        sys.exit(1)


if __name__ == '__main__':
    main()
