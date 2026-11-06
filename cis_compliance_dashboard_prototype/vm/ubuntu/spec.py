"""Portable fixed observation vocabulary shared by host and root-owned target helper."""
SYSCTL = {
    '1.5.1': {'kernel.randomize_va_space': 2},
    '3.3.1': {'net.ipv4.ip_forward': 0, 'net.ipv6.conf.all.forwarding': 0},
    '3.3.2': {'net.ipv4.conf.all.send_redirects': 0, 'net.ipv4.conf.default.send_redirects': 0},
    '3.3.8': {f'net.{family}.conf.{scope}.accept_source_route': 0
              for family in ('ipv4', 'ipv6') for scope in ('all', 'default')},
}
PACKAGES = {'1.3.1.1': ('apparmor', 'apparmor-utils'), '1.5.4': ('prelink',),
            '6.3.1.1': ('auditd', 'audispd-plugins')}
SSH = {'5.1.20': ('permitrootlogin',), '5.1.19': ('permitemptypasswords',),
       '5.1.16': ('maxauthtries',), '5.1.7': ('clientaliveinterval','clientalivecountmax'),
       '5.1.10': ('hostbasedauthentication',), '5.1.21': ('permituserenvironment',)}
IDENTITY_PATHS = frozenset(('/etc/group','/etc/passwd','/etc/gshadow','/etc/shadow',
    '/etc/security/opasswd','/etc/nsswitch.conf','/etc/pam.conf','/etc/pam.d'))

# Pinned selected XCCDF rules (ComplianceAsCode v0.1.80) shipped inside the digest-pinned helper,
# so the host cannot pass arbitrary rule IDs to the scanner. A test keeps this equal to the catalogue.
SCAP_PROFILE = 'xccdf_org.ssgproject.content_profile_cis_level2_server'
SCAP_DATASTREAM_SHA256 = 'c8be1aa2bf93284507b8810ea829f8904ab4552865f07d106561d5fd5d06ca67'
SCAP_RULE_PREFIX = 'xccdf_org.ssgproject.content_rule_'
# OpenSCAP 1.2.17 honours one --rule only: scope comes from a pinned tailored profile extending SCAP_PROFILE.
SCAP_TAILORED_PROFILE = 'xccdf_org.fyphardening_profile_cis_level2_server_selected30'
SCAP_TAILORING_SHA256 = '56d77459b9184b60726e68163e297d57785916aaa46e632cd763c4efe0ef800a'

SCAP_RULES = {
    '1.3.1.1': tuple(SCAP_RULE_PREFIX + r for r in ('package_apparmor_installed', 'package_apparmor-utils_installed',)),
    '1.5.1': tuple(SCAP_RULE_PREFIX + r for r in ('sysctl_kernel_randomize_va_space',)),
    '1.5.3': tuple(SCAP_RULE_PREFIX + r for r in ('disable_users_coredumps', 'sysctl_fs_suid_dumpable',)),
    '1.5.4': tuple(SCAP_RULE_PREFIX + r for r in ('package_prelink_removed',)),
    '2.1.2': tuple(SCAP_RULE_PREFIX + r for r in ('package_avahi_removed', 'service_avahi-daemon_disabled',)),
    '5.3.3.2.2': tuple(SCAP_RULE_PREFIX + r for r in ('accounts_password_pam_minlen',)),
    '5.4.1.1': tuple(SCAP_RULE_PREFIX + r for r in ('accounts_maximum_age_login_defs', 'accounts_password_set_max_life_existing',)),
    '5.4.1.3': tuple(SCAP_RULE_PREFIX + r for r in ('accounts_password_warn_age_login_defs',)),
    '5.4.1.5': tuple(SCAP_RULE_PREFIX + r for r in ('account_disable_post_pw_expiration', 'accounts_set_post_pw_existing',)),
    '5.2.2': tuple(SCAP_RULE_PREFIX + r for r in ('sudo_add_use_pty',)),
    '5.2.3': tuple(SCAP_RULE_PREFIX + r for r in ('sudo_custom_logfile',)),
    '3.3.1': tuple(SCAP_RULE_PREFIX + r for r in ('sysctl_net_ipv6_conf_all_forwarding', 'sysctl_net_ipv4_ip_forward',)),
    '3.3.2': tuple(SCAP_RULE_PREFIX + r for r in ('sysctl_net_ipv4_conf_all_send_redirects', 'sysctl_net_ipv4_conf_default_send_redirects',)),
    '3.3.8': tuple(SCAP_RULE_PREFIX + r for r in ('sysctl_net_ipv6_conf_all_accept_source_route', 'sysctl_net_ipv6_conf_default_accept_source_route', 'sysctl_net_ipv4_conf_all_accept_source_route', 'sysctl_net_ipv4_conf_default_accept_source_route',)),
    '4.1.3': tuple(SCAP_RULE_PREFIX + r for r in ('check_ufw_active', 'service_ufw_enabled',)),
    '4.1.4': tuple(SCAP_RULE_PREFIX + r for r in ('set_ufw_loopback_traffic',)),
    '4.1.7': tuple(SCAP_RULE_PREFIX + r for r in ('set_ufw_default_rule',)),
    '6.3.1.1': tuple(SCAP_RULE_PREFIX + r for r in ('package_audit_installed', 'package_audit-audispd-plugins_installed',)),
    '6.3.1.2': tuple(SCAP_RULE_PREFIX + r for r in ('service_auditd_enabled',)),
    '6.3.1.3': tuple(SCAP_RULE_PREFIX + r for r in ('grub2_audit_argument', 'zipl_audit_argument',)),
    '6.3.3.4': tuple(SCAP_RULE_PREFIX + r for r in ('audit_rules_time_adjtimex', 'audit_rules_time_clock_settime', 'audit_rules_time_settimeofday', 'audit_rules_time_watch_localtime',)),
    '6.3.3.8': tuple(SCAP_RULE_PREFIX + r for r in ('audit_rules_usergroup_modification_group', 'audit_rules_usergroup_modification_gshadow', 'audit_rules_usergroup_modification_opasswd', 'audit_rules_usergroup_modification_passwd', 'audit_rules_usergroup_modification_shadow', 'audit_rules_usergroup_modification_nsswitch_conf', 'audit_rules_usergroup_modification_pam_conf', 'audit_rules_usergroup_modification_pamd',)),
    '6.3.3.6': tuple(SCAP_RULE_PREFIX + r for r in ('audit_rules_privileged_commands',)),
    '5.1.20': tuple(SCAP_RULE_PREFIX + r for r in ('sshd_disable_root_login',)),
    '5.1.19': tuple(SCAP_RULE_PREFIX + r for r in ('sshd_disable_empty_passwords',)),
    '5.1.16': tuple(SCAP_RULE_PREFIX + r for r in ('sshd_set_max_auth_tries',)),
    '5.1.7': tuple(SCAP_RULE_PREFIX + r for r in ('sshd_set_idle_timeout', 'sshd_set_keepalive',)),
    '5.1.10': tuple(SCAP_RULE_PREFIX + r for r in ('disable_host_auth',)),
    '5.1.21': tuple(SCAP_RULE_PREFIX + r for r in ('sshd_do_not_permit_user_env',)),
}
SCAP_RESULTS = frozenset(('pass', 'fail', 'error', 'unknown', 'notapplicable', 'notchecked', 'notselected',
                          'informational', 'fixed'))
