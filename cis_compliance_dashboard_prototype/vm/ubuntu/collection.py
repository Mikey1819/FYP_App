"""Read-only observation assembly; no compliance/risk decision runs on the target.

Only fixed I/O methods are called. Missing/unsupported collection remains explicit,
and no installation, metadata refresh, service change or repair is attempted.
"""
import re
import shlex
from .probes import account_aging, audit_rules, password_minlen, resolve_sysctl, ssh_context, ufw_loopback, ufw_tuples
from .evidence_schema import validate_observations
from .scap_results import result_path
from .spec import SCAP_RULES

IDS = tuple('1.2.2.1 1.3.1.1 1.5.1 1.5.3 1.5.4 2.1.2 5.3.3.2.2 5.4.1.1 5.4.1.3 5.4.1.5 5.2.2 5.2.3 3.3.1 3.3.2 3.3.8 4.1.3 4.1.4 4.1.7 6.3.1.1 6.3.1.2 6.3.1.3 6.3.3.4 6.3.3.8 6.3.3.6 5.1.20 5.1.19 5.1.16 5.1.7 5.1.10 5.1.21'.split())
SYSCTLS = {'1.5.1':('kernel.randomize_va_space',),'1.5.3':('fs.suid_dumpable',),
    '3.3.1':('net.ipv4.ip_forward','net.ipv6.conf.all.forwarding'),
    '3.3.2':('net.ipv4.conf.all.send_redirects','net.ipv4.conf.default.send_redirects'),
    '3.3.8':tuple('net.'+family+'.conf.'+scope+'.accept_source_route' for family in ('ipv4','ipv6') for scope in ('all','default'))}
SSH = {'5.1.20':('permitrootlogin',),'5.1.19':('permitemptypasswords',),'5.1.16':('maxauthtries',),
    '5.1.7':('clientaliveinterval','clientalivecountmax'),'5.1.10':('hostbasedauthentication',),'5.1.21':('permituserenvironment',)}


def _ok(value):return {'state':'ok','value':value}
def _error():return {'state':'error','value':None}
def _missing():return {'state':'missing','value':None}


def collect_observations(io, *, registered_firewall_manager=None, scap_request=None):
    if not io._verified: raise ValueError('Verified target preflight is required')
    if registered_firewall_manager not in (None,'ufw'):
        raise ValueError('Unsupported registered firewall manager')
    if scap_request is not None:
        request_id, engine = scap_request
        result_path(request_id)
        if type(engine) is not str or not re.fullmatch(r'\d+\.\d+\.\d+',engine):
            raise ValueError('Invalid accepted OpenSCAP version')
    result = {cid:{} for cid in IDS}
    commands = {}
    def command(key):
        if key not in commands:
            value = io.command(key)
            if value.returncode != 0:raise ValueError('Fixed probe command failed')
            commands[key] = value.stdout
        return commands[key]
    def set_fact(cid,key,operation):
        try:result[cid][key] = _ok(operation())
        except FileNotFoundError:result[cid][key] = _missing()
        except (OSError,ValueError,KeyError,TimeoutError):result[cid][key] = _error()
    def optional_file(name):
        try:return io.read_file(name)
        except FileNotFoundError:return ''
    def packages():
        parsed = {}
        for line in command('packages').splitlines():
            parts = line.split('\t')
            if len(parts) != 2:raise ValueError('Invalid package database response')
            name,state = parts;name=name.split(':',1)[0]
            if state not in ('installed','not-installed','config-files','half-installed','unpacked','half-configured','triggers-awaited','triggers-pending'):
                raise ValueError('Unknown package state')
            normalized = 'installed' if state == 'installed' else 'absent' if state in ('not-installed','config-files') else 'incomplete'
            if name in parsed and parsed[name] != normalized:raise ValueError('Ambiguous multiarch package state')
            parsed[name] = normalized
        if not parsed:raise ValueError('Empty package database cannot prove package absence')
        return parsed
    package_map = None
    try:package_map = packages()
    except (OSError,ValueError,TimeoutError):pass
    for cid,names in {'1.3.1.1':('apparmor','apparmor-utils'),'1.5.4':('prelink',),
            '2.1.2':('avahi-daemon',),'4.1.3':('ufw',),'6.3.1.1':('auditd','audispd-plugins')}.items():
        for name in names:result[cid]['package.'+name] = _ok(package_map.get(name,'absent')) if package_map is not None else _error()
    def unit(name,field):
        values=dict(line.split('=',1) for line in command('unit.'+name).splitlines() if '=' in line)
        if values.get('LoadState') == 'not-found':
            # A unit that is not installed: systemctl reports an empty unit-file state (observed on the target).
            return 'not-found' if field == 'UnitFileState' else values.get(field) or 'inactive'
        if field not in values:raise ValueError('Missing unit state')
        return values[field]
    for name in ('avahi-daemon.service','avahi-daemon.socket'):
        for short,field in (('active','ActiveState'),('enabled','UnitFileState')):
            set_fact('2.1.2',name+'.'+short,lambda n=name,f=field:unit(n,f))
    for cid,name,prefix in (('4.1.3','ufw.service','ufw.service'),('6.3.1.2','auditd.service','auditd')):
        for short,field in (('active','ActiveState'),('enabled','UnitFileState')):
            set_fact(cid,prefix+'.'+short,lambda n=name,f=field:unit(n,f))
    def ipv6():
        value=io.read_file('/sys/module/ipv6/parameters/disable').strip()
        if value not in ('0','1'):raise ValueError('Invalid IPv6 state')
        return value=='0'
    def persistent(key):
        ufw = None
        defaults = optional_file('/etc/default/ufw')
        for line in defaults.splitlines():
            if re.match(r'^\s*IPT_SYSCTL\s*=',line):
                tokens=shlex.split(line.split('=',1)[1],comments=True)
                if tokens != ['/etc/ufw/sysctl.conf']:raise ValueError('Unsupported UFW sysctl source')
                ufw=io.read_file(tokens[0])
        return resolve_sysctl(command('sysctl_config'),key,ufw=ufw)
    for cid,keys in SYSCTLS.items():
        if any('ipv6' in key for key in keys):set_fact(cid,'ipv6_enabled',ipv6)
        for key in keys:
            set_fact(cid,'runtime.'+key,lambda k=key:int(command('sysctl.'+k).strip()))
            set_fact(cid,'persistent.'+key,lambda k=key:persistent(k))
        # Resolution failure is already explicit per setting; it never defaults to complete.
        complete = all(result[cid]['persistent.'+k]['state']=='ok' for k in keys
                       if 'ipv6' not in k or result[cid].get('ipv6_enabled',{}).get('value') is not False)
        result[cid]['sysctl_resolution'] = _ok('complete' if complete else 'incomplete')
    def core_limits():
        limits={}
        for text in [optional_file('/etc/security/limits.conf')]+[text for _,text in io.files('limits')]:
            for line in text.splitlines():
                tokens=shlex.split(line,comments=True)
                if len(tokens)==4 and tokens[1] in ('hard','-') and tokens[2]=='core':
                    limits[tokens[0]]=-1 if tokens[3]=='unlimited' else int(tokens[3])
        return limits
    set_fact('1.5.3','hard_core_limits',core_limits)
    result['1.5.3']['systemd_coredump_installed'] = (_ok(package_map.get('systemd-coredump')=='installed')
                                                   if package_map is not None else _error())
    if result['1.5.3']['systemd_coredump_installed'].get('value'):
        # Default values do not establish restrictive policy. Full load order comes from systemd itself.
        def coredump(option):
            selected=False;value=None
            for line in command('coredump_config').splitlines():
                line=line.strip()
                if not line or line.startswith(('#',';')):continue
                if line.startswith('['):selected=line=='[Coredump]';continue
                if selected and '=' in line:
                    key,item=(p.strip() for p in line.split('=',1))
                    if key==option:value=item
            if value is None:raise ValueError('Coredump policy unresolved')
            return int(value) if option=='ProcessSizeMax' else value
        set_fact('1.5.3','coredump_storage',lambda:coredump('Storage'))
        set_fact('1.5.3','coredump_process_size_max',lambda:coredump('ProcessSizeMax'))
    aging = None
    try:aging=account_aging(io.read_file('/etc/passwd'),io.read_file('/etc/shadow'))
    except (OSError,ValueError,KeyError,TimeoutError):pass
    def login_default(name):
        values=[line.split()[1] for line in io.read_file('/etc/login.defs').splitlines()
                if line.strip() and not line.lstrip().startswith('#') and line.split()[0]==name and len(line.split())==2]
        if len(values)!=1:raise ValueError('Ambiguous account default')
        return int(values[0])
    for cid,field,name in (('5.4.1.1','maximum','PASS_MAX_DAYS'),('5.4.1.3','warning','PASS_WARN_AGE'),('5.4.1.5','inactive','INACTIVE')):
        result[cid]['accounts']=_ok(aging) if aging is not None else _error()
        result[cid]['account_inventory']=_ok('complete' if aging is not None else 'incomplete')
        if field=='inactive':
            def inactive():
                values=dict(line.split('=',1) for line in command('account_defaults').splitlines() if '=' in line)
                return int(values['INACTIVE'])
            set_fact(cid,'default.inactive',inactive)
        else:set_fact(cid,'default.'+field,lambda n=name:login_default(n))
    set_fact('5.4.1.1','default.minimum',lambda:login_default('PASS_MIN_DAYS'))
    set_fact('5.3.3.2.2','effective_minlen',lambda:{'common-password':password_minlen(io.files('pwquality'),
        optional_file('/etc/security/pwquality.conf'),io.read_file('/etc/pam.d/common-password'))})
    result['5.3.3.2.2']['pam_resolution']=_ok('complete' if result['5.3.3.2.2']['effective_minlen']['state']=='ok' else 'unsupported')
    try:
        lines=io.read_file('/etc/sudoers').splitlines()
        for line in tuple(lines):
            if line.strip() in ('@includedir /etc/sudoers.d','#includedir /etc/sudoers.d'):
                for name,text in io.files('sudoers'):
                    if '.' not in name and not name.endswith('~'):lines.extend(text.splitlines())
            elif re.match(r'^\s*[@#]include',line):raise ValueError('Unsupported sudo include')
        pty,logs=[],[];global_pty=False
        for line in lines:
            if re.match(r'^\s*[@#]include',line):
                if line.strip() not in ('@includedir /etc/sudoers.d','#includedir /etc/sudoers.d'):raise ValueError('Nested sudo include unsupported')
                continue
            if not line.lstrip().startswith('Defaults'):continue
            tokens=shlex.split(line,comments=True)
            if len(tokens)<2:raise ValueError('Malformed sudo default')
            options=' '.join(tokens[1:]).split(',')
            for option in options:
                option=option.strip()
                if option in ('use_pty','!use_pty'):
                    pty.append('enabled' if option=='use_pty' else 'negated')
                    if tokens[0]=='Defaults' and option=='use_pty':global_pty=True
                if option.startswith('logfile=') and tokens[0]=='Defaults':logs.append(option.split('=',1)[1])
        for cid in ('5.2.2','5.2.3'):
            result[cid]['sudoers_syntax_valid']=_ok(io.command('sudoers_syntax').returncode==0)
            result[cid]['sudoers_resolution']=_ok('complete')
        result['5.2.2']['sudoers_use_pty']=_ok(pty)
        if pty and not global_pty and 'negated' not in pty:result['5.2.2']['sudoers_resolution']=_ok('unsupported')
        result['5.2.3']['sudoers_logfiles']=_ok(logs)
    except (OSError,ValueError,KeyError,TimeoutError):
        for cid in ('5.2.2','5.2.3'):result[cid]['sudoers_resolution']=_error()
    try:
        config='\n'.join([io.read_file('/etc/ssh/sshd_config')]+[text for _,text in io.files('ssh')])
        supported=True
        for line in config.splitlines():
            tokens=shlex.split(line,comments=True)
            if not tokens:continue
            if tokens[0].lower()=='match':supported=False
            if tokens[0].lower()=='include' and tokens[1:]!=['/etc/ssh/sshd_config.d/*.conf']:supported=False
        for cid,options in SSH.items():
            result[cid]['ssh_context_resolution']=_ok('complete' if supported else 'unsupported')
            set_fact(cid,'ssh_contexts',lambda opts=options:[ssh_context(command('ssh_global'),'global',opts)])
    except (OSError,ValueError,KeyError,TimeoutError):
        for cid in SSH:result[cid]['ssh_context_resolution']=_error()
    try:
        ufw=command('ufw_status')
        active=re.search(r'^Status: (active|inactive)$',ufw,re.M)
        if not active:raise ValueError('Unknown UFW status')
        for cid in ('4.1.3','4.1.4','4.1.7'):result[cid]['ufw.active']=_ok(active.group(1)=='active')
        # Require explicit deployment registration as well as observed service state.
        # A successful ufw command alone cannot establish management ownership.
        manager = None
        if registered_firewall_manager == 'ufw':
            try:
                competing = any(unit(name,'ActiveState') != 'inactive' or unit(name,'UnitFileState') == 'enabled'
                    for name in ('nftables.service','netfilter-persistent.service','firewalld.service'))
                if not competing:manager='ufw'
            except (OSError,ValueError,KeyError,TimeoutError):pass
        for cid in ('4.1.4','4.1.7'):result[cid]['firewall_manager']=_ok(manager) if manager else _missing()
        defaults=re.search(r'^Default: (deny|reject|allow) \(incoming\), (deny|reject|allow) \(outgoing\), (deny|reject|allow|disabled) \(routed\)',ufw,re.M)
        if defaults:
            for direction,value in zip(('incoming','outgoing','routed'),defaults.groups()):result['4.1.7']['ufw.default.'+direction]=_ok(value)
        set_fact('4.1.4','ipv6_enabled',ipv6)
    except (OSError,ValueError,KeyError,TimeoutError):
        for cid in ('4.1.3','4.1.4','4.1.7'):result[cid]['ufw.active']=_error()
    try:
        # CIS 4.1.4 audits the user rules in order; resolve each traffic class over ufw's own records.
        resolved=ufw_loopback(ufw_tuples(io.read_file('/etc/ufw/user.rules')),ufw_tuples(io.read_file('/etc/ufw/user6.rules')))
        for family,classes in resolved.items():
            for traffic,action in classes.items():result['4.1.4']['ufw.'+family+'.'+traffic]=_ok(action)
        result['4.1.4']['ufw_rule_resolution']=_ok('complete')
    except ValueError:
        result['4.1.4']['ufw_rule_resolution']=_ok('unsupported')
    except (OSError,KeyError,TimeoutError):
        result['4.1.4']['ufw_rule_resolution']=_error()
    def boot_entries():
        entries=[]
        for line in io.read_file('/boot/grub/grub.cfg').splitlines():
            tokens=shlex.split(line,comments=True)
            if tokens and tokens[0] in ('linux','linuxefi'):
                entries.append([arg if arg in ('audit=0','audit=1') else 'audit=other' for arg in tokens[2:] if arg.startswith('audit=')]
                               or ['audit=missing'])
        return entries
    set_fact('6.3.1.3','boot_entries',boot_entries)
    result['6.3.1.3']['bootloader']=_ok('grub2') if result['6.3.1.3']['boot_entries']['state']=='ok' else _missing()
    def current_audit():
        values=[arg for arg in shlex.split(io.read_file('/proc/cmdline')) if arg.startswith('audit=')]
        return values[0] if len(values)==1 and values[0] in ('audit=0','audit=1') else 'audit=other' if values else 'audit=missing'
    set_fact('6.3.1.3','current_audit_argument',current_audit)
    for cid in ('6.3.3.4','6.3.3.8','6.3.3.6'):
        set_fact(cid,'persistent_audit_rules',lambda:audit_rules('\n'.join(text for _,text in io.files('audit'))))
        set_fact(cid,'loaded_audit_rules',lambda:audit_rules(command('audit_rules')))
    def architectures():
        if command('architecture').strip()!='x86_64':raise ValueError('Unsupported audit architecture')
        return ['b32','b64']
    set_fact('6.3.3.4','audit_architectures',architectures)
    set_fact('6.3.3.8','identity_paths',lambda:command('identity_paths').splitlines())
    set_fact('6.3.3.6','uid_min',lambda:login_default('UID_MIN'))
    if hasattr(io,'privileged_paths'):
        set_fact('6.3.3.6','privileged_paths',lambda:list(io.privileged_paths()))
    result['6.3.3.6']['privileged_inventory']=_ok('complete' if result['6.3.3.6'].get('privileged_paths',{}).get('state')=='ok' else 'incomplete')
    # Fresh signed repository metadata is not implemented here yet. The Manual
    # updates recommendation retains missing evidence and requires a human review.
    # Explicit missing facts: an empty set would hide the gap from probe provenance.
    result['1.2.2.1'] = {key:_missing() for key in ('metadata_fresh','pending_updates','held_packages','reboot_required')}
    if scap_request is not None:
        # One selected-rule evaluation for all controls; any engine failure is explicit per control.
        try:scap=io.scap_results(*scap_request)
        except (OSError,ValueError,KeyError,TimeoutError):scap=None
        for cid,rules in SCAP_RULES.items():
            ok = type(scap) is dict and all(rule in scap for rule in rules)
            result[cid]['scap_rules'] = _ok({rule:scap[rule] for rule in rules}) if ok else _error()
    for cid,facts in result.items():
        for key,observation in tuple(facts.items()):
            try:validate_observations(cid,{key:observation})
            except ValueError:facts[key]=_error()
        # Validate aggregate size as well as individual values before any serialization.
        try:validate_observations(cid,facts)
        except ValueError:result[cid]={key:_error() for key in facts}
    return result
