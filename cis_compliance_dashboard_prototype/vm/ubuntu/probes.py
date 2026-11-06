"""Pure parsers for fixed read-only probes. No commands execute during import.

Unsupported syntax raises a safe error, never a guessed compliant value. Raw account,
configuration and tool text is retained only within the target helper process.
"""
import fnmatch
import re
import shlex


def _bounded(text, maximum=4*1024*1024):
    if type(text) is not str or len(text.encode('utf-8')) > maximum or '\x00' in text:
        raise ValueError('Probe input is malformed or exceeds limit')
    return text


def _integer(value):
    if not re.fullmatch(r'-?\d{1,10}',value) or not -1 <= int(value) <= 2**31-1:
        raise ValueError('Invalid numeric probe value')
    return int(value)


def resolve_sysctl(cat_config, name, *, ufw=None):
    value = None
    for text in (cat_config,ufw):
        if text is None: continue
        for line in _bounded(text).splitlines():
            line = line.strip()
            if not line or line.startswith(('#',';')): continue
            if '=' not in line:
                if name in line or any(char in line for char in '*?[]'):
                    raise ValueError('Unsupported sysctl exclusion')
                continue
            key, raw = (p.strip() for p in line.split('=',1))
            key = key.lstrip('-').replace('/','.')
            if any(char in key for char in '*?[]') and fnmatch.fnmatchcase(name,key):
                raise ValueError('Wildcard sysctl precedence requires explicit resolver support')
            if key == name:
                value = _integer(raw)
    if value is None: raise ValueError('Required persistent sysctl setting is absent')
    return value


def account_aging(passwd_text, shadow_text):
    accounts, result, seen = {}, [], set()
    for line in _bounded(passwd_text).splitlines():
        fields = line.split(':')
        if len(fields) != 7 or fields[0] in accounts or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}',fields[0]):
            raise ValueError('Unsupported account database')
        uid = _integer(fields[2])
        if uid < 0: raise ValueError('Invalid UID')
        accounts[fields[0]] = uid
    for line in _bounded(shadow_text).splitlines():
        fields = line.split(':')
        if len(fields) != 9 or fields[0] not in accounts or fields[0] in seen:
            raise ValueError('Incomplete or inconsistent account inventory')
        seen.add(fields[0])
        # The secret field is consumed only to classify applicability, never returned.
        bearing = bool(fields[1]) and fields[1][0] not in ('!','*')
        result.append(dict(name=fields[0],uid=accounts[fields[0]],password_bearing=bearing,
            minimum=_integer(fields[3]) if fields[3] else -1,
            maximum=_integer(fields[4]) if fields[4] else -1,
            warning=_integer(fields[5]) if fields[5] else -1,
            inactive=_integer(fields[6]) if fields[6] else -1))
    if set(accounts) != seen:
        raise ValueError('Local account databases do not match; external identity requires review')
    return result


def ssh_context(text, context_id, options):
    result = {'context_id':context_id}
    for line in _bounded(text).splitlines():
        parts = line.split(None,1)
        if not parts or parts[0] not in options: continue
        if len(parts) != 2 or parts[0] in result: raise ValueError('Ambiguous sshd output')
        name, value = parts
        if name in ('maxauthtries','clientaliveinterval','clientalivecountmax'):
            value = _integer(value)
        elif value == 'without-password':
            value = 'prohibit-password'  # sshd -T prints the legacy alias (observed on Ubuntu 22.04)
        elif value not in ('no','yes','prohibit-password','forced-commands-only'):
            raise ValueError('Unsupported effective SSH value')
        result[name] = value
    if set(result) != {'context_id',*options}: raise ValueError('Incomplete sshd effective context')
    return result


def password_minlen(dropins, main, pam):
    effective = 8  # libpwquality default; never interpreted as a compliant project minimum.
    for name,text in sorted(dropins,key=lambda row:row[0]) + [('',main)]:
        for line in _bounded(text).splitlines():
            line = line.split('#',1)[0].strip()
            if re.match(r'^minlen\b',line):
                match = re.fullmatch(r'minlen\s*=\s*(-?\d+)',line)
                if not match: raise ValueError('Unsupported pwquality setting')
                effective = _integer(match.group(1))
    modules = []
    for line in _bounded(pam).splitlines():
        tokens = shlex.split(line,comments=True)
        if tokens and tokens[0] in ('@include','include','substack'):
            raise ValueError('Unresolved PAM include')
        if not tokens or tokens[0] != 'password': continue
        if 'pam_pwquality.so' not in tokens:
            if not modules:raise ValueError('PAM flow before password quality requires review')
            continue
        position = tokens.index('pam_pwquality.so')
        if position != 2 or tokens[1] not in ('requisite','required'):
            raise ValueError('Unsupported PAM control flow')
        value = effective
        for option in tokens[position+1:]:
            if option.startswith('minlen='): value = _integer(option.split('=',1)[1])
            elif option.startswith(('conf=','enforcing=','local_users_only')):
                raise ValueError('PAM applicability/config override needs explicit review')
        modules.append(value)
    if len(modules) != 1: raise ValueError('Exactly one effective enforcing pwquality module required')
    return modules[0]


def audit_rules(text):
    rows = []
    for line in _bounded(text).splitlines():
        tokens = shlex.split(line,comments=True)
        if not tokens or tokens == ['No','rules']: continue
        if tokens == ['-D']:
            rows.clear()
            continue
        if len(tokens) == 2 and tokens[0] in ('-b','-f','-e','--backlog_wait_time'):
            _integer(tokens[1])
            continue
        row = dict(action='',path='',syscalls=[],arch='',permissions='',key='',auid_min=-1,
                   exclude_unset=False,unrestricted=True)
        seen = set()
        index = 0
        while index < len(tokens):
            if index+1 >= len(tokens): raise ValueError('Truncated audit rule')
            flag, value = tokens[index:index+2];index += 2
            if flag not in ('-a','-A','-w','-p','-k','-S','-F'):
                raise ValueError('Unsupported audit rule syntax')
            if flag in ('-a','-A'):
                if value in ('always,exit','exit,always'): row['action'] = 'always,exit'
                else: raise ValueError('Audit suppressions or unsupported filter list require review')
            elif flag == '-w': row.update(action='watch',path=value)
            elif flag == '-p': row['permissions'] = value
            elif flag == '-k': row['key'] = value
            elif flag == '-S': row['syscalls'].extend(value.split(','))
            elif flag == '-F':
                if value.startswith('arch='):
                    arch = value[5:]
                    row['arch'] = {'x86_64':'b64','i386':'b32','b64':'b64','b32':'b32','c000003e':'b64','40000003':'b32'}.get(arch,'')
                    if not row['arch']: raise ValueError('Unsupported audit architecture')
                elif value.startswith('path='): row['path'] = value[5:]
                elif value.startswith('perm='): row['permissions'] = value[5:]
                elif value.startswith('key='): row['key'] = value[4:]
                elif value.startswith('auid>='): row['auid_min'] = _integer(value[6:])
                elif value in ('auid!=unset','auid!=-1','auid!=4294967295'): row['exclude_unset'] = True
                else: raise ValueError('Unsupported audit filter; coverage cannot be inferred')
            unique = flag if flag != '-F' else value.split('=',1)[0]
            if unique in seen and flag != '-S': raise ValueError('Ambiguous duplicate audit token')
            seen.add(unique)
        if not row['action'] or not row['key']:
            raise ValueError('Incomplete audit rule')
        if row['auid_min'] != -1 or row['exclude_unset']:
            # Such a filtered rule cannot satisfy unrestricted time/identity requirements.
            row['unrestricted'] = False
        rows.append(row)
    return rows
