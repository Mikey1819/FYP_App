"""Exact allowlisted normalized evidence shapes. No raw files, stderr or model fields."""
from copy import deepcopy
import json
import re
from .spec import PACKAGES, SYSCTL, SSH, IDENTITY_PATHS, SCAP_RESULTS, SCAP_RULES


def enum(*values):
    return lambda value: type(value) is str and value in values


def integer(value):
    return type(value) is int and -1 <= value <= 2**31-1


def natural(value):
    return integer(value) and value >= 0


def boolean(value):
    return type(value) is bool


def token(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9_.@*-]{1,128}', value) is not None


def path(value):
    return (type(value) is str and 1 <= len(value) <= 1024 and value.startswith('/')
            and not set(value) & set('\x00\r\n') and '..' not in value.split('/'))


def array(check, max_items=4096):
    return lambda value: type(value) is list and len(value) <= max_items and all(check(v) for v in value)


def mapping(value):
    return type(value) is dict and len(value) <= 4096 and all(token(k) and integer(v) for k,v in value.items())


def record(schema):
    return lambda value: type(value) is dict and set(value) == set(schema) and all(schema[k](v) for k,v in value.items())


ACCOUNT = record(dict(name=token,uid=natural,password_bearing=boolean,minimum=integer,maximum=integer,warning=integer,inactive=integer))
AUDIT_RULE = record(dict(action=enum('watch','always,exit','never,exit'),path=lambda v: v == '' or path(v),
    syscalls=array(token,512),arch=enum('','b32','b64'),permissions=lambda v: type(v) is str and set(v) <= set('rwax'),
    key=token,auid_min=integer,exclude_unset=boolean,unrestricted=boolean))
RESOLUTION = enum('complete','unsupported','incomplete')
PACKAGE = enum('installed','absent','incomplete')
ENABLED = enum('enabled','disabled','masked','static','indirect','not-found')
ACTIVE = enum('active','inactive','failed','activating','deactivating','unknown')


def schemas():
    result = {
        '1.2.2.1': dict(metadata_fresh=boolean,pending_updates=natural,held_packages=natural,reboot_required=boolean),
        '2.1.2': {'package.avahi-daemon':PACKAGE},
        '5.3.3.2.2': {'pam_resolution':RESOLUTION,'effective_minlen':mapping},
        '5.2.2': {'sudoers_syntax_valid':boolean,'sudoers_resolution':RESOLUTION,
                  'sudoers_use_pty':array(enum('enabled','negated'))},
        '5.2.3': {'sudoers_syntax_valid':boolean,'sudoers_resolution':RESOLUTION,'sudoers_logfiles':array(path)},
        '4.1.3': {'package.ufw':PACKAGE,'ufw.service.enabled':ENABLED,'ufw.service.active':ACTIVE,'ufw.active':boolean},
        '4.1.4': {'firewall_manager':enum('ufw','nftables','iptables','other'),'ufw.active':boolean,
                  'ipv6_enabled':boolean,'ufw_rule_resolution':RESOLUTION},
        '4.1.7': {'firewall_manager':enum('ufw','nftables','iptables','other'),'ufw.active':boolean},
        '6.3.1.2': {'auditd.enabled':ENABLED,'auditd.active':ACTIVE},
        '6.3.1.3': {'bootloader':enum('grub2','other'), 'boot_entries':array(array(enum('audit=0','audit=1','audit=other','audit=missing'),16),128),
                    'current_audit_argument':enum('audit=0','audit=1','audit=other','audit=missing')},
        '6.3.3.4': {'audit_architectures':array(enum('b32','b64'),2)},
        '6.3.3.8': {'identity_paths':array(lambda v: type(v) is str and v in IDENTITY_PATHS,8)},
        '6.3.3.6': {'privileged_inventory':RESOLUTION,'privileged_paths':array(path),'uid_min':natural},
    }
    for cid, packages in PACKAGES.items():
        result[cid] = {'package.'+p:PACKAGE for p in packages}
    for cid, keys in dict(SYSCTL, **{'1.5.3':{'fs.suid_dumpable':0}}).items():
        result[cid] = {source+'.'+key:integer for source in ('runtime','persistent') for key in keys}
        result[cid]['sysctl_resolution'] = RESOLUTION
        if any('ipv6' in key for key in keys): result[cid]['ipv6_enabled'] = boolean
    result['1.5.3'].update(hard_core_limits=mapping,systemd_coredump_installed=boolean,
                          coredump_storage=enum('none','external','journal'),coredump_process_size_max=natural)
    for unit in ('avahi-daemon.service','avahi-daemon.socket'):
        result['2.1.2'][unit+'.active'], result['2.1.2'][unit+'.enabled'] = ACTIVE, ENABLED
    for cid, field in (('5.4.1.1','maximum'),('5.4.1.3','warning'),('5.4.1.5','inactive')):
        result[cid] = {'default.'+field:integer,'account_inventory':RESOLUTION,'accounts':array(ACCOUNT)}
    result['5.4.1.1']['default.minimum'] = integer
    for family in ('ipv4','ipv6'):
        for traffic in ('loopback_in','loopback_out','spoofed_in'):
            result['4.1.4']['ufw.'+family+'.'+traffic] = enum('allow','deny','reject','unresolved')
    for direction in ('incoming','outgoing','routed'):
        result['4.1.7']['ufw.default.'+direction] = enum('allow','deny','reject','disabled')
    for cid in ('6.3.3.4','6.3.3.8','6.3.3.6'):
        result[cid].update(persistent_audit_rules=array(AUDIT_RULE),loaded_audit_rules=array(AUDIT_RULE))
    for cid, options in SSH.items():
        schema = {'context_id':token}
        schema.update({option:natural if option in ('maxauthtries','clientaliveinterval','clientalivecountmax')
                       else enum('yes','no','prohibit-password','forced-commands-only') for option in options})
        result[cid] = {'ssh_context_resolution':RESOLUTION,'ssh_contexts':array(record(schema),256)}
    # Sanitized selected-rule results: exactly the control's pinned rules, raw result tokens only.
    for cid, rules in SCAP_RULES.items():
        result[cid]['scap_rules'] = lambda value, rules=frozenset(rules): (
            type(value) is dict and set(value) == rules and all(type(v) is str and v in SCAP_RESULTS for v in value.values()))
    return result


SCHEMAS = schemas()


def validate_observations(control_id, observations):
    if control_id not in SCHEMAS:
        raise ValueError('Unregistered control evidence')
    schema = SCHEMAS[control_id]
    if type(observations) is not dict or not set(observations) <= set(schema):
        raise ValueError('Unexpected evidence field')
    try:
        if len(json.dumps(observations,allow_nan=False).encode('utf-8')) > 256*1024:
            raise ValueError('Observation size exceeds limit')
        for key, observation in observations.items():
            if type(observation) is not dict or set(observation) != {'state','value'}:
                raise ValueError('Unexpected observation shape')
            state, value = observation['state'], observation['value']
            if state not in ('ok','missing','error','conflict'):
                raise ValueError('Invalid observation state')
            if (state == 'ok' and not schema[key](value)) or (state != 'ok' and value is not None):
                raise ValueError('Invalid normalized evidence value')
    except (TypeError, OverflowError, RecursionError):
        raise ValueError('Malformed normalized evidence') from None
    # Caller mutation cannot change the observations while predicates consume them.
    return deepcopy(observations)
