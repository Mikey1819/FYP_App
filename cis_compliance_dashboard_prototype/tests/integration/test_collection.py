"""Orchestration over a simulated read-only target, no live VM or shell calls."""
from types import SimpleNamespace
import unittest


class FakeIO:
    _verified = True
    def __init__(self):self.calls=[]
    def command(self,key):
        self.calls.append(key)
        if key == 'packages':
            return SimpleNamespace(returncode=0,stdout='apparmor\tinstalled\napparmor-utils\tinstalled\nauditd\tinstalled\naudispd-plugins\tinstalled\nufw\tinstalled\n')
        if key.startswith('sysctl.'):
            return SimpleNamespace(returncode=0,stdout='2\n' if key.endswith('randomize_va_space') else '0\n')
        if key == 'sysctl_config':
            from vm.ubuntu.collector import SYSCTL_KEYS
            return SimpleNamespace(returncode=0,stdout='\n'.join(k+' = '+('2' if k.endswith('randomize_va_space') else '0') for k in SYSCTL_KEYS))
        if key.startswith('unit.'):
            if key in ('unit.nftables.service','unit.netfilter-persistent.service','unit.firewalld.service'):
                return SimpleNamespace(returncode=0,stdout='ActiveState=inactive\nUnitFileState=disabled\n')
            return SimpleNamespace(returncode=0,stdout='ActiveState=active\nUnitFileState=enabled\n')
        if key == 'account_defaults':return SimpleNamespace(returncode=0,stdout='INACTIVE=45\n')
        if key == 'sudoers_syntax':return SimpleNamespace(returncode=0,stdout='parsed OK')
        if key == 'ssh_global':
            return SimpleNamespace(returncode=0,stdout='permitrootlogin no\npermitemptypasswords no\nmaxauthtries 4\nclientaliveinterval 15\nclientalivecountmax 3\nhostbasedauthentication no\npermituserenvironment no\n')
        if key == 'ufw_status':return SimpleNamespace(returncode=0,stdout='Status: active\nDefault: deny (incoming), deny (outgoing), disabled (routed)\n')
        raise OSError('Unimplemented fixture command')
    def read_file(self,path):
        return {'/etc/default/ufw':'IPT_SYSCTL=/etc/ufw/sysctl.conf\n','/etc/ufw/sysctl.conf':'',
            '/sys/module/ipv6/parameters/disable':'0\n','/etc/security/limits.conf':'* hard core 0\n',
            '/etc/passwd':'fixture:x:1000:1000::/home/fixture:/bin/bash\n',
            '/etc/shadow':'fixture:$6$SECRET-SENTINEL:20000:1:365:7:45::\n',
            '/etc/login.defs':'PASS_MAX_DAYS 365\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\nUID_MIN 1000\n',
            '/etc/security/pwquality.conf':'minlen = 14\n','/etc/pam.d/common-password':'password requisite pam_pwquality.so\n',
            '/etc/ssh/sshd_config':'Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n',
            '/etc/sudoers':'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\n@includedir /etc/sudoers.d\n',
            '/boot/grub/grub.cfg':'linux /vmlinuz root=SECRET-SENTINEL audit=1\n',
            '/proc/cmdline':'root=SECRET-SENTINEL audit=1',
        }[path]
    def files(self,group):return ()


class CollectionTests(unittest.TestCase):
    def test_fixed_collection_produces_30_sanitized_control_fact_sets(self):
        from vm.ubuntu.collection import collect_observations
        from backends.ubuntu.predicates import evaluate
        io=FakeIO();facts=collect_observations(io,registered_firewall_manager='ufw')
        self.assertEqual(len(facts),30)
        self.assertNotIn('SECRET-SENTINEL',repr(facts))
        for cid in ('1.3.1.1','1.5.1','1.5.3','1.5.4','2.1.2','5.3.3.2.2','5.4.1.1','5.4.1.3',
                    '5.4.1.5','5.2.2','5.2.3','3.3.1','3.3.2','3.3.8','4.1.3','4.1.7','6.3.1.1','6.3.1.2',
                    '6.3.1.3','5.1.20','5.1.19','5.1.16','5.1.7','5.1.10','5.1.21'):
            with self.subTest(control=cid):self.assertEqual(evaluate(cid,facts[cid]).status.value,'Compliant')
        self.assertEqual(io.calls.count('packages'),1)

    def test_firewall_applicability_requires_registration_and_no_competing_manager(self):
        from vm.ubuntu.collection import collect_observations
        from backends.ubuntu.predicates import evaluate
        io=FakeIO()
        self.assertEqual(evaluate('4.1.7',collect_observations(io)['4.1.7']).status.value,'Unknown')
        original=io.command
        io.command=lambda key:SimpleNamespace(returncode=0,stdout='ActiveState=active\nUnitFileState=enabled\n') if key=='unit.nftables.service' else original(key)
        self.assertEqual(evaluate('4.1.7',collect_observations(io,registered_firewall_manager='ufw')['4.1.7']).status.value,'Unknown')

    def test_failed_package_database_cannot_establish_package_absence(self):
        from vm.ubuntu.collection import collect_observations
        from backends.ubuntu.predicates import evaluate
        io=FakeIO();original=io.command
        io.command=lambda key:SimpleNamespace(returncode=2,stdout='') if key=='packages' else original(key)
        result=collect_observations(io)
        self.assertEqual(evaluate('1.5.4',result['1.5.4']).status.value,'Error')

    def test_match_configuration_is_not_silently_treated_as_global_coverage(self):
        from vm.ubuntu.collection import collect_observations
        from backends.ubuntu.predicates import evaluate
        io=FakeIO();original=io.read_file
        io.read_file=lambda path:original(path)+'\nMatch User someone\n PermitRootLogin yes\n' if path=='/etc/ssh/sshd_config' else original(path)
        result=collect_observations(io)
        self.assertEqual(evaluate('5.1.20',result['5.1.20']).status.value,'Unknown')

    def test_invalid_normalized_content_is_removed_on_target_before_export(self):
        from vm.ubuntu.collection import collect_observations
        io=FakeIO();original=io.read_file
        io.read_file=lambda path:'Defaults logfile="SECRET-SENTINEL"\n' if path=='/etc/sudoers' else original(path)
        result=collect_observations(io)
        self.assertNotIn('SECRET-SENTINEL',repr(result))
        self.assertEqual(result['5.2.3']['sudoers_logfiles']['state'],'error')
