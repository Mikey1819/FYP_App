"""Scan queue UI: operator starts the read-only worker inside the VM once."""
import hashlib
import json
import os
import sqlite3
import streamlit as st

from .framework import AssessmentOrchestrator
from .import_storage import ImportedEvidenceStore
from .scan_exchange import ScanExchange, DEFAULT_EXCHANGE, COLLECTOR, worker_status
from .vm_paths import scan_worker_command
from .winrm_channel import DEFAULT_HOST, DEFAULT_PORT, ChannelError, LiveScanner, WinRmTarget

LIVE_TARGET = 'vm_live_target'


def scan_exchange(runtime):
    return ScanExchange(runtime, os.environ.get('CIS_SCAN_EXCHANGE', str(DEFAULT_EXCHANGE)))


def collection_channel(runtime):
    """The Scanner Agent's tool: live WinRM when connected this session, else the file queue."""
    target = st.session_state.get(LIVE_TARGET)
    return LiveScanner(runtime, target) if target is not None else scan_exchange(runtime)


def _open_run(result):
    # Fresh run, fresh operational report/approval; never overwrite the old snapshot.
    for key in list(st.session_state):
        if key.startswith(('vm_cycle_', 'vm_context_')):
            del st.session_state[key]
    st.session_state['vm_cycle_digest'] = result['evidence_sha256']
    st.session_state['vm_cycle_framework_run'] = result['framework_run_id']
    st.rerun()


def render_connection(hostname, machine_uuid, *, key):
    """Connect form shared by both pages. Returns the verified target, or None."""
    st.caption('The agents reach the VM themselves over PowerShell Remoting (see VM_CONNECTION.md). '
               'The password stays in this browser session’s memory only; it is never saved, logged or sent to the model.')
    left, right = st.columns(2)
    host = left.text_input('WinRM host (laptop side of the port forward)', value=DEFAULT_HOST, key=key + '_host')
    port = right.number_input('WinRM port', value=DEFAULT_PORT, min_value=1, max_value=65535, key=key + '_port')
    username = st.text_input('VM administrator account', value='Administrator', key=key + '_user')
    password = st.text_input('Password', type='password', key=key + '_password')
    ready = all(value.strip() for value in (hostname, machine_uuid, host, username, password))
    if st.button('Connect and check identity', key=key + '_connect', disabled=not ready):
        target = WinRmTarget(hostname.strip(), machine_uuid.strip(), username.strip(), password,
                             host.strip(), int(port))
        status = LiveScanner(None, target).worker_status(target.hostname, target.machine_uuid)
        if status['state'] == 'ready':
            st.session_state[LIVE_TARGET] = target
        else:
            st.session_state.pop(LIVE_TARGET, None)
            st.error('Not connected (' + status['state'] + '): ' + status['detail'])
    target = st.session_state.get(LIVE_TARGET)
    if target is None:
        return None
    if (target.hostname.casefold() != hostname.strip().casefold()
            or target.machine_uuid.casefold() != machine_uuid.strip().casefold()):
        st.warning('The live connection belongs to a different VM registration. Connect again.')
        return None
    st.success('Connected to ' + target.hostname + ' as ' + target.username + ' via '
               + target.host + ':' + str(target.port) + '.')
    return target


def render_live_scan(database_path, hostname, machine_uuid, *, origin_run_id=None):
    with st.expander('Scanner live connection — PowerShell Remoting (WinRM)', expanded=True):
        try:
            target = render_connection(hostname, machine_uuid, key='vm_live')
            if target is None:
                return
            if st.button('Scan VM now', key='vm_live_scan'):
                runtime = AssessmentOrchestrator(ImportedEvidenceStore(database_path))
                with st.spinner('Scanner Agent collecting evidence inside the VM…'):
                    result = LiveScanner(runtime, target).request(target.hostname, target.machine_uuid,
                                                                  origin_run_id=origin_run_id)
                _open_run(result)
        except ChannelError as exc:
            st.error('Live scan failed (' + exc.state + '): ' + exc.detail + ' No assessment was created.')
        except (ValueError, OSError, sqlite3.Error) as exc:
            st.error('Live scan: ' + str(exc))


def render_scan_queue(database_path, hostname, machine_uuid, *, origin_run_id=None):
    with st.expander('Fallback: shared-folder scan queue (manual VM worker)'):
        st.caption('Start Watch-ScanRequests.ps1 as Administrator inside the VM, using the shared scan_queue folder. '
                   'The worker accepts only read-only collection jobs and stops after its configured time limit. '
                   'See SCANNER_CONNECTION.md for the one-time setup command.')
        st.caption('Host queue: ' + os.environ.get('CIS_SCAN_EXCHANGE', str(DEFAULT_EXCHANGE)))
        st.caption('Collector SHA-256: ' + hashlib.sha256(COLLECTOR.read_bytes()).hexdigest())
        try:
            st.caption('Worker setup: these are paths inside the VM. Copy both scripts there, then run the generated command in VM PowerShell as Administrator.')
            directory = st.text_input('VM script directory', value=r'C:\FYP', key='vm_worker_directory')
            queue_directory = st.text_input('Shared scan queue inside the VM', value=r'Z:\scan_queue', key='vm_worker_queue')
            if hostname.strip() and machine_uuid.strip():
                command = scan_worker_command(hostname.strip(), machine_uuid.strip(),
                    hashlib.sha256(COLLECTOR.read_bytes()).hexdigest(), directory, queue_directory)
                st.code(command, language='powershell')
                st.button('Refresh worker status', key='vm_worker_refresh')
                report = worker_status(os.environ.get('CIS_SCAN_EXCHANGE', str(DEFAULT_EXCHANGE)),
                                       hostname.strip(), machine_uuid.strip())
                message = 'Worker report: ' + report['state'] + '. ' + report['detail']
                if report['state'] in ('ready', 'busy', 'not_seen'):
                    st.info(message)
                else:
                    st.warning(message)
            if st.button('Request fresh VM scan', key='vm_request_scan', disabled=not(hostname.strip() and machine_uuid.strip())):
                exchange = scan_exchange(AssessmentOrchestrator(ImportedEvidenceStore(database_path)))
                queued = exchange.request(hostname.strip(), machine_uuid.strip(), origin_run_id=origin_run_id)
                st.session_state['vm_cycle_scan_id'] = queued['request_id']
            resume = st.text_input('Recover a scan by request ID', key='vm_scan_resume_id')
            if st.button('Load scan request', key='vm_resume_scan', disabled=not resume.strip()):
                exchange = scan_exchange(AssessmentOrchestrator(ImportedEvidenceStore(database_path)))
                request = json.loads(exchange.get(resume.strip()))
                if request['hostname'].casefold() != hostname.strip().casefold() or request['machine_uuid'].casefold() != machine_uuid.strip().casefold():
                    raise ValueError('Scan request does not match the selected hostname and UUID')
                st.session_state['vm_cycle_scan_id'] = resume.strip()
            identifier = st.session_state.get('vm_cycle_scan_id')
            if not identifier:
                return
            st.code(identifier, language=None)
            st.caption('A queued request is not a completed scan. Keep the VM worker running, then check for its response.')
            if st.button('Check scan response', key='vm_check_scan'):
                exchange = scan_exchange(AssessmentOrchestrator(ImportedEvidenceStore(database_path)))
                request = json.loads(exchange.get(identifier))
                if request['hostname'].casefold() != hostname.strip().casefold() or request['machine_uuid'].casefold() != machine_uuid.strip().casefold():
                    raise ValueError('Selected target differs from this scan request')
                result = exchange.poll(identifier)
                if result['state'] == 'assessment_ready':
                    _open_run(result)
                elif result['state'] == 'expired':
                    st.warning('Scan request expired without a response. Start the VM worker and request a new scan.')
                elif result['state'] == 'collection_failed':
                    st.warning('VM collection failed: ' + result['error'] + '. No assessment was created.')
                else:
                    st.info('Awaiting VM worker response. No fresh evidence has been received yet.')
        except (ValueError, OSError, sqlite3.Error) as exc:
            st.error('Scan connection: ' + str(exc))
