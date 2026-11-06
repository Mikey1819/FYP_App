"""Paired laptops on a connected server: list them, disconnect one, or close every laptop's access.

These run the server access helper's own fixed text (scripts/server_access/FYP-ServerAccess.ps1) over the WinRM
channel, with typed parameters only, exactly like the collector. The server's identity is checked first, so these
actions only ever reach the saved server. The helper answers one JSON line; it is checked strictly before use.
"""
import ipaddress
import json
import re
from uuid import UUID

from .server_access import SCRIPTS
from .winrm_channel import ChannelError, LiveScanner, _run_script

HELPER = SCRIPTS / 'FYP-ServerAccess.ps1'
_HEX32 = re.compile(r'[0-9a-f]{32}')


def _report(output, had_errors, errors, target):
    """The helper's answer, type-checked: who the server is and which laptops it lets in."""
    if had_errors or len(output) != 1:
        detail = (errors[0] if errors else 'The server access helper gave no answer.')[:300]
        raise ChannelError('channel_error', detail)
    try:
        report = json.loads(output[0])
        pairings = report['pairings']
        if (type(report) is not dict or set(report) != {'hostname', 'machine_uuid', 'pairings', 'helper_enabled_remoting'}
                or type(report['helper_enabled_remoting']) is not bool or type(pairings) is not list
                or type(report['hostname']) is not str or len(report['hostname']) > 63):
            raise ValueError
        machine_uuid = str(UUID(report['machine_uuid']))
        checked = []
        for p in pairings:
            if (type(p) is not dict or set(p) != {'pairing_id', 'laptop_address', 'laptop_name', 'paired_at'}
                    or not all(type(v) is str for v in p.values()) or not _HEX32.fullmatch(p['pairing_id'])
                    or len(p['laptop_name']) > 63 or len(p['paired_at']) > 40):
                raise ValueError
            ipaddress.IPv4Address(p['laptop_address'])
            checked.append(dict(p))
    except (ValueError, KeyError, TypeError):
        raise ChannelError('channel_error', 'The server access helper answered in an unexpected format.') from None
    if machine_uuid != target.machine_uuid.lower():
        raise ChannelError('wrong_target', 'The helper answered for another machine.')
    return dict(hostname=report['hostname'], machine_uuid=machine_uuid, pairings=checked,
                helper_enabled_remoting=report['helper_enabled_remoting'])


def _helper(target, parameters, session_factory=None):
    LiveScanner(None, target, session_factory=session_factory).identity()  # Only ever the saved server.
    text = HELPER.read_text(encoding='utf-8-sig')
    return _report(*_run_script(target, session_factory, text, parameters), target)


def paired_laptops(target, *, session_factory=None):
    """{hostname, machine_uuid, pairings: [...], helper_enabled_remoting}. Changes nothing on the server."""
    return _helper(target, {'Action': 'ListPairings'}, session_factory)


def disconnect_laptop(target, pairing_id, *, session_factory=None):
    """Remove one paired laptop: the server stops letting its address reach WinRM. Returns the new report."""
    if type(pairing_id) is not str or not _HEX32.fullmatch(pairing_id):
        raise ValueError('Invalid pairing id')
    return _helper(target, {'Action': 'RemovePairing', 'PairingId': pairing_id}, session_factory)


def close_access(target, *, session_factory=None):
    """Remove every paired laptop. PowerShell Remoting itself is turned off only by Revert on the server, because
    doing it over this session would cut the session midway. Returns the new report."""
    return _helper(target, {'Action': 'CloseAccess'}, session_factory)
