"""Reproduce the draft manifest from inspected local inputs; never approves or activates it.

Run from the existing application after downloading the exact official release to the
isolated cache. XML is parsed as data; upstream remediation content is never executed.
"""
import hashlib
import json
from pathlib import Path
import re
import zipfile
from defusedxml import ElementTree as ET

APP = Path(__file__).resolve().parents[1]
COMMIT = 'a1b32362394c7739a7a94426c61c7cb24449d9a0'
BENCHMARK = '37b8d91eadb5621656ff38d24c39ac34b9589087a3f3a9fbba2c8a2dd665b6da'
NAMESPACE = {'x': 'http://checklists.nist.gov/xccdf/1.2'}
GAPS = {
    '2.4.1.2': 'Upstream rules check owner, group and mode separately; the direct probe reads all three with stat -L and the cron package state, so cron absence is not mistaken for compliance.',
    '1.3.1.1': 'Both package states must be installed; package presence does not establish profile enforcement.',
    '1.5.1': 'Resolve effective persistence and UFW IPT_SYSCTL overrides as well as runtime.',
    '1.5.3': 'Mapped rules omit conditional systemd-coredump Storage=none and ProcessSizeMax=0; also resolve hard limits and sysctl precedence.',
    '1.5.4': 'Package-query failure cannot establish absence; prelink reversal requires separate approved package/binary recovery.',
    '2.1.2': 'PDF allows package retention only when needed as a dependency and approved by local policy. Package removal and disabled service are alternative paths, not an unconditional AND.',
    '5.3.3.2.2': 'Resolve PAM arguments and pwquality precedence; a matching minlen file does not establish effective policy.',
    '5.4.1.1': 'Default and every applicable account must satisfy 1..365 and exceed minimum age. PDF remediation prose says 356 once; audit and example specify 365.',
    '5.4.1.3': 'Upstream mapping covers default only; direct observation must include every applicable existing password-bearing account.',
    '5.4.1.5': 'Default and applicable accounts require 0..45 days after password expiry, not inactivity since last login.',
    '5.2.2': 'PDF audit requires use_pty and no !use_pty. Apply the stricter PDF audit predicate rather than accepting an overridden negation.',
    '5.2.3': 'PDF requires a dedicated sudo logfile; /var/log/sudo.log is an example/project policy. Upstream exact path cannot silently narrow benchmark compliance.',
    '3.3.1': 'Require runtime and precedence-resolved persistence. IPv6 exclusion needs affirmative disabled evidence; router/cloud/container dependencies block mutation.',
    '3.3.2': 'Both all/default IPv4 keys, runtime and effective persistent values including UFW overrides, are required.',
    '3.3.8': 'All/default IPv4 and enabled IPv6 keys require runtime plus persistence. Missing IPv6 observations do not prove disabled.',
    '4.1.3': 'Package, systemd enabled/active, and UFW active state are separate checks. Do not switch an existing firewall manager.',
    '4.1.4': 'Require semantic and ordered loopback acceptance plus anti-spoofing for IPv4 and applicable IPv6; preserve unrelated rules.',
    '4.1.7': 'PDF allows deny/reject/disabled for incoming, outgoing and routed. Project deny/deny/deny is a separate unapproved target policy.',
    '6.3.1.1': 'Both auditd and audispd-plugins installation states are required.',
    '6.3.1.2': 'Verify enabled and active separately; no service start/restart during assessment.',
    '6.3.1.3': 'Registered GRUB-only implementation checks nonempty generated kernel entries. zipl mapping exists upstream but is outside the initial supported bootloader. Runtime audit=1 is reported separately until approved reboot.',
    '6.3.3.4': 'Check semantic union of all applicable syscall architectures plus /etc/localtime wa watch in persistent and loaded rules; immutable rules require reboot for activation.',
    '6.3.3.8': 'Eight required paths in persistent and loaded rules. Missing optional PAM/history files require explicit applicability handling; never create a password database to satisfy a watch.',
    '6.3.3.6': 'Bind bounded privileged-file inventory, eligible filesystems, UID_MIN, perm=x and unset auid exclusion. Substring path matches are insufficient; incomplete traversal is Unknown/Error.',
    '5.1.20': 'Check sshd -T and registered Match contexts; preserve proven non-root administration before a write.',
    '5.1.19': 'Check effective sshd values and registered Match contexts, not an arbitrary appended drop-in.',
    '5.1.16': 'Positive MaxAuthTries <=4; preserve stricter valid policy and use only the selected authentication method.',
    '5.1.7': 'PDF requires both values >0; 15/3 is only an example/site policy. Upstream selector is 300/3. Direct effective predicate controls benchmark status; these detect unresponsive connections, not keyboard inactivity.',
    '5.1.10': 'Effective HostbasedAuthentication=no for every audited context.',
    '5.1.21': 'Effective PermitUserEnvironment=no; do not delete environment files.',
}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def main():
    cache, dest = APP.parent / '.integration-tmp', APP / 'catalogues'
    archive_path = cache / 'scap-security-guide-0.1.80.zip'
    digest = hashlib.sha512(archive_path.read_bytes()).hexdigest()
    if digest != (cache / 'scap-security-guide-0.1.80.zip.sha512').read_text().split()[0].lower():
        raise ValueError('Official release SHA512 mismatch')
    vendor = dest / 'vendor'
    vendor.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as archive:
        for name in ('ssg-ubuntu2204-ds.xml', 'LICENSE'):
            (vendor / name).write_bytes(archive.read('scap-security-guide-0.1.80/' + name))
    source = (cache / 'cis_ubuntu2204-upstream.yml').read_bytes()
    (vendor / 'cis_ubuntu2204.yml').write_bytes(source)
    upstream = source.decode('utf-8')
    stream = (vendor / 'ssg-ubuntu2204-ds.xml').read_bytes()
    root = ET.fromstring(stream, forbid_dtd=True)
    rule_ids = {r.get('id') for r in root.findall('.//x:Rule', NAMESPACE)}
    values = {v.get('id'): {s.get('selector'): s.text for s in v.findall('x:value', NAMESPACE)}
              for v in root.findall('.//x:Value', NAMESPACE)}
    attached = (APP / 'docs/inputs/2026-11-05-unified-system-ubuntu-control-catalogue.md').read_text(encoding='utf-8')
    areas = re.findall(r'^### [A-E]\. (.+)$', attached, re.M)
    rows = re.findall(r'^\| (\d+) \| \*\*([\d.]+)\*\*, p\.(\d+), L([12]) (Automated|Manual) \| (.+?) \| (.+?) \|$', attached, re.M)
    if len(rows) != 30 or len(areas) != 5:
        raise ValueError('Unexpected input catalogue structure')
    controls = []
    for number, cid, page, level, kind, predicate, remediation in rows:
        match = re.search(r'^    - id: '+re.escape(cid)+r'\n(.*?)(?=^    - id: |\Z)', upstream, re.S | re.M)
        if not match:
            raise ValueError('Missing upstream mapping: ' + cid)
        block = match.group(1)
        title = re.search(r'^      title: (.+)$', block, re.M).group(1)
        mapped, variables = [], {}
        rule_block = block.split('      rules:\n', 1)[-1] if '      rules:\n' in block else ''
        for short in re.findall(r'^          - (.+)$', rule_block, re.M):
            if '=' in short:
                key, selector = short.split('=', 1)
                actual = [i for i in values if i.endswith('_value_' + key)]
                if len(actual) != 1 or selector not in values[actual[0]]:
                    raise ValueError('Unknown source variable/selector: ' + short)
                variables[actual[0]] = {'selector': selector, 'value': values[actual[0]][selector]}
            else:
                actual = [i for i in rule_ids if i.endswith('_rule_' + short)]
                if len(actual) != 1:
                    raise ValueError('Unresolved actual datastream rule: ' + short)
                mapped.append(actual[0])
        controls.append(dict(control_id=cid, platform='ubuntu', title=title.rsplit(' (', 1)[0],
            area=areas[(int(number)-1)//6], server_level=int(level), cis_assessment_type=kind,
            source_pages=[int(page)], benchmark_sha256=BENCHMARK, predicate_id='ubuntu.'+cid+'.predicate.v1',
            predicate_version=1, assessment_contract=predicate, remediation_contract=remediation,
            scap_rule_ids=mapped, scap_variable_values=variables,
            direct_probe_ids=['ubuntu.'+cid+'.effective.v1'], direct_probe_reason=GAPS[cid],
            authoritative_source_policy='PDF v2.0.0 compound predicate; reviewed effective-state probes override narrower SCAP examples. Conflict remains visible.',
            action_ids=['ubuntu.'+cid+'.v1'], review_status='pending_human_review',
            coverage={stage:'not_implemented' for stage in ('assessment','remediation','refusal','verification','recovery')},
            live_validation='not_run'))
    lock = dict(schema_version=1, benchmark_id='CIS Ubuntu Linux 22.04 LTS Benchmark', benchmark_version='2.0.0',
        benchmark_sha256=BENCHMARK, content_release='v0.1.80', content_commit=COMMIT,
        release_url='https://github.com/ComplianceAsCode/content/releases/tag/v0.1.80',
        release_archive_sha512=digest, mapping_source_url=f'https://github.com/ComplianceAsCode/content/blob/{COMMIT}/controls/cis_ubuntu2204.yml',
        mapping_source_path='vendor/cis_ubuntu2204.yml', mapping_source_sha256=hashlib.sha256(source).hexdigest(),
        datastream_path='vendor/ssg-ubuntu2204-ds.xml', datastream_sha256=hashlib.sha256(stream).hexdigest(),
        profile_id='xccdf_org.ssgproject.content_profile_cis_level2_server',
        selection_policy='Only the explicit mapped rules for the 30 selected controls; never whole-profile remediation.',
        openscap_version=None, openscap_validation='Awaiting authenticated VM inspection and compatible engine validation.',
        review_status='pending_human_review', activation_ready=False)
    write_json(dest / 'source-lock.json', lock)
    write_json(dest / 'ubuntu2204.json', dict(schema_version=1, catalogue_version='ubuntu2204-cis2.0.0-project-v1-draft', controls=controls))
    print('Draft inventory: 30 controls. Activation remains disabled; no implementation or human-review claims added.')


if __name__ == '__main__':
    main()
