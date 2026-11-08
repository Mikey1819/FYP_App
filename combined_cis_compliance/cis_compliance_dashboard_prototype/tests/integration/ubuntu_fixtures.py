"""Synthetic normalized facts, not data collected from the user's VM."""
from copy import deepcopy


def observation(value):
    return {'state':'ok', 'value':value}


def rule(path='', syscalls=(), arch='', permissions='wa', *, uid_min=-1, exclude=False):
    return dict(action='always,exit' if syscalls or permissions == 'x' else 'watch', path=path,
                syscalls=list(syscalls), arch=arch, permissions=permissions, key='fixture',
                auid_min=uid_min, exclude_unset=exclude, unrestricted=True)


def cases(*, legacy=False):
    """Compliant facts for the current selection (catalogue v2); legacy=True gives catalogue v1, which held the
    retired 1.2.2.1 instead of 2.4.1.2 (stored scans before 2026-11-08)."""
    values = {
        '2.4.1.2': {'package.cron':'installed','crontab.mode':0o600,'crontab.uid':0,'crontab.gid':0},
        '1.3.1.1': {'package.apparmor':'installed','package.apparmor-utils':'installed'},
        '1.5.4': {'package.prelink':'absent'},
        '2.1.2': {'package.avahi-daemon':'absent'},
        '5.3.3.2.2': {'pam_resolution':'complete','effective_minlen':{'common-password':14}},
        '5.2.2': {'sudoers_syntax_valid':True,'sudoers_resolution':'complete','sudoers_use_pty':['enabled']},
        '5.2.3': {'sudoers_syntax_valid':True,'sudoers_resolution':'complete','sudoers_logfiles':['/var/log/sudo.log']},
        '4.1.3': {'package.ufw':'installed','ufw.service.enabled':'enabled','ufw.service.active':'active','ufw.active':True},
        '4.1.4': {'firewall_manager':'ufw','ufw.active':True,'ipv6_enabled':True,'ufw_rule_resolution':'complete'},
        '4.1.7': {'firewall_manager':'ufw','ufw.active':True,'ufw.default.incoming':'deny','ufw.default.outgoing':'reject','ufw.default.routed':'disabled'},
        '6.3.1.1': {'package.auditd':'installed','package.audispd-plugins':'installed'},
        '6.3.1.2': {'auditd.enabled':'enabled','auditd.active':'active'},
        '6.3.1.3': {'bootloader':'grub2','boot_entries':[['audit=1'],['audit=1']],'current_audit_argument':'audit=0'},
    }
    sysctls = {
        '1.5.1': {'kernel.randomize_va_space':2},
        '1.5.3': {'fs.suid_dumpable':0},
        '3.3.1': {'net.ipv4.ip_forward':0,'net.ipv6.conf.all.forwarding':0},
        '3.3.2': {'net.ipv4.conf.all.send_redirects':0,'net.ipv4.conf.default.send_redirects':0},
        '3.3.8': {'net.ipv4.conf.all.accept_source_route':0,'net.ipv4.conf.default.accept_source_route':0,
                  'net.ipv6.conf.all.accept_source_route':0,'net.ipv6.conf.default.accept_source_route':0},
    }
    for cid, settings in sysctls.items():
        values[cid] = {mode+'.'+key:value for mode in ('runtime','persistent') for key,value in settings.items()}
        values[cid]['sysctl_resolution'] = 'complete'
        if any('ipv6' in k for k in settings): values[cid]['ipv6_enabled'] = True
    values['1.5.3'].update(hard_core_limits={'*':0},systemd_coredump_installed=True,
                          coredump_storage='none',coredump_process_size_max=0)
    account = dict(name='fixtureuser',uid=1000,password_bearing=True,minimum=1,maximum=365,warning=7,inactive=45)
    for cid, field, value in (('5.4.1.1','maximum',365),('5.4.1.3','warning',7),('5.4.1.5','inactive',45)):
        values[cid] = {'default.'+field:value,'account_inventory':'complete','accounts':[deepcopy(account)]}
    values['5.4.1.1']['default.minimum'] = 1
    for family in ('ipv4','ipv6'):
        for traffic, action in (('loopback_in','allow'),('loopback_out','allow'),('spoofed_in','deny')):
            values['4.1.4']['ufw.'+family+'.'+traffic] = action
    time_rules = [rule(syscalls=['adjtimex','settimeofday','clock_settime'],arch=arch) for arch in ('b32','b64')]
    time_rules.append(rule('/etc/localtime'))
    values['6.3.3.4'] = dict(audit_architectures=['b32','b64'],persistent_audit_rules=time_rules,loaded_audit_rules=deepcopy(time_rules))
    paths = ['/etc/group','/etc/passwd','/etc/gshadow','/etc/shadow','/etc/security/opasswd','/etc/nsswitch.conf','/etc/pam.conf','/etc/pam.d']
    values['6.3.3.8'] = dict(identity_paths=paths,persistent_audit_rules=[rule(p) for p in paths],loaded_audit_rules=[rule(p) for p in paths])
    privileged = [rule('/usr/bin/passwd',permissions='x',uid_min=1000,exclude=True)]
    values['6.3.3.6'] = dict(privileged_inventory='complete',privileged_paths=['/usr/bin/passwd'],uid_min=1000,
                            persistent_audit_rules=privileged,loaded_audit_rules=deepcopy(privileged))
    for cid, options in {'5.1.20':{'permitrootlogin':'no'},'5.1.19':{'permitemptypasswords':'no'},
            '5.1.16':{'maxauthtries':4},'5.1.7':{'clientaliveinterval':15,'clientalivecountmax':3},
            '5.1.10':{'hostbasedauthentication':'no'},'5.1.21':{'permituserenvironment':'no'}}.items():
        values[cid] = {'ssh_context_resolution':'complete','ssh_contexts':[dict(context_id='global',**options),dict(context_id='management',**options)]}
    if legacy:
        del values['2.4.1.2']
        values['1.2.2.1'] = dict(metadata_fresh=True,pending_updates=0,held_packages=0,reboot_required=False)
    return {cid:{key:observation(value) for key,value in facts.items()} for cid,facts in values.items()}


FAILURES = {
    '2.4.1.2': ('crontab.mode',0o644), '1.3.1.1': ('package.apparmor-utils','absent'),
    '1.5.1': ('persistent.kernel.randomize_va_space',0), '1.5.3': ('coredump_process_size_max',1),
    '1.5.4': ('package.prelink','installed'), '2.1.2': ('package.avahi-daemon','installed'),
    '5.3.3.2.2': ('effective_minlen',{'common-password':13}), '5.4.1.1': ('default.maximum',366),
    '5.4.1.3': ('default.warning',6), '5.4.1.5': ('default.inactive',-1),
    '5.2.2': ('sudoers_use_pty',['enabled','negated']), '5.2.3': ('sudoers_logfiles',[]),
    '3.3.1': ('runtime.net.ipv6.conf.all.forwarding',1), '3.3.2': ('persistent.net.ipv4.conf.default.send_redirects',1),
    '3.3.8': ('runtime.net.ipv6.conf.default.accept_source_route',1), '4.1.3': ('ufw.service.active','inactive'),
    '4.1.4': ('ufw.ipv6.spoofed_in','allow'), '4.1.7': ('ufw.default.outgoing','allow'),
    '6.3.1.1': ('package.audispd-plugins','absent'), '6.3.1.2': ('auditd.enabled','disabled'),
    '6.3.1.3': ('boot_entries',[['audit=0']]), '6.3.3.4': ('loaded_audit_rules',[]),
    '6.3.3.8': ('persistent_audit_rules',[]), '6.3.3.6': ('loaded_audit_rules',[]),
    '5.1.20': ('ssh_contexts',[{'context_id':'match','permitrootlogin':'prohibit-password'}]),
    '5.1.19': ('ssh_contexts',[{'context_id':'match','permitemptypasswords':'yes'}]),
    '5.1.16': ('ssh_contexts',[{'context_id':'match','maxauthtries':5}]),
    '5.1.7': ('ssh_contexts',[{'context_id':'match','clientaliveinterval':0,'clientalivecountmax':3}]),
    '5.1.10': ('ssh_contexts',[{'context_id':'match','hostbasedauthentication':'yes'}]),
    '5.1.21': ('ssh_contexts',[{'context_id':'global','permituserenvironment':'yes'}]),
}
