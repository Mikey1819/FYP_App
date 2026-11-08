"""Fixed read-only target I/O primitives. Deployment/CLI activation is not enabled yet.

This module has no executable main and performs no I/O on import. Approved installation
must place this helper and its dependencies under a verified root-owned directory.
All command execution requires Linux/Ubuntu/machine-identity preflight first.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import platform
import queue
import shlex
import stat
import subprocess
import threading
import time


SYSCTL_KEYS = ('kernel.randomize_va_space','fs.suid_dumpable','net.ipv4.ip_forward','net.ipv6.conf.all.forwarding',
    'net.ipv4.conf.all.send_redirects','net.ipv4.conf.default.send_redirects',
    'net.ipv4.conf.all.accept_source_route','net.ipv4.conf.default.accept_source_route',
    'net.ipv6.conf.all.accept_source_route','net.ipv6.conf.default.accept_source_route')
UNITS = ('avahi-daemon.service','avahi-daemon.socket','ufw.service','auditd.service',
         'nftables.service','netfilter-persistent.service','firewalld.service')
COMMANDS = {
    'packages':('/usr/bin/dpkg-query','-W','-f=${binary:Package}\t${db:Status-Status}\n'),
    'sysctl_config':('/usr/lib/systemd/systemd-sysctl','--cat-config'),
    'coredump_config':('/usr/bin/systemd-analyze','cat-config','systemd/coredump.conf'),
    'ssh_global':('/usr/sbin/sshd','-T'),
    'ssh_syntax':('/usr/sbin/sshd','-t'),
    'sudoers_syntax':('/usr/sbin/visudo','-c'),
    'ufw_status':('/usr/sbin/ufw','status','verbose'),
    'audit_rules':('/usr/sbin/auditctl','-l'),
    'crontab_stat':('/usr/bin/stat','-Lc','%a %u %g','/etc/crontab'),
    'audit_status':('/usr/sbin/auditctl','-s'),
    'architecture':('/usr/bin/uname','-m'),
    'openscap_version':('/usr/bin/oscap','--version'),
    'mounts':('/usr/bin/findmnt','--json','--list','--kernel','--output','TARGET,FSTYPE,OPTIONS'),
    'account_defaults':('/usr/sbin/useradd','-D'),
    'identity_paths':('/usr/bin/stat','-c','%n','/etc/group','/etc/passwd','/etc/gshadow','/etc/shadow',
                      '/etc/security/opasswd','/etc/nsswitch.conf','/etc/pam.conf','/etc/pam.d'),
}
COMMANDS.update({'sysctl.'+key:('/usr/sbin/sysctl','-n',key) for key in SYSCTL_KEYS})
COMMANDS.update({'unit.'+unit:('/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,UnitFileState','--no-pager') for unit in UNITS})
IDENTITY_FILES = frozenset(('/etc/os-release','/etc/machine-id','/proc/sys/kernel/hostname'))
FILES = IDENTITY_FILES | frozenset(('/etc/passwd','/etc/shadow','/etc/login.defs','/etc/default/useradd',
    '/etc/default/ufw','/etc/ufw/sysctl.conf','/etc/ufw/user.rules','/etc/ufw/user6.rules','/sys/module/ipv6/parameters/disable','/etc/security/limits.conf',
    '/etc/systemd/coredump.conf','/etc/security/pwquality.conf','/etc/pam.d/common-password',
    '/etc/ssh/sshd_config','/etc/sudoers','/etc/default/grub','/boot/grub/grub.cfg','/proc/cmdline','/proc/filesystems','/run/reboot-required'))
GROUPS = {
    'limits':('/etc/security/limits.d','*.conf'),
    'pwquality':('/etc/security/pwquality.conf.d','*.conf'),
    'coredump':('/etc/systemd/coredump.conf.d','*.conf'),
    'ssh':('/etc/ssh/sshd_config.d','*.conf'),
    'audit':('/etc/audit/rules.d','*.rules'),
    'sudoers':('/etc/sudoers.d','*'),
}


CHUNK = 65536


def trusted_owner(info):
    """Root-owned and not writable by others; group write only when the group is root (grub.cfg is 0664 root:root)."""
    return info.st_uid == 0 and not info.st_mode & 0o002 and (not info.st_mode & 0o020 or info.st_gid == 0)


def read_bounded(stream, limit):
    """Read to EOF in small chunks, refusing more than the limit in bytes.

    One large read fails on /proc/sys files (they allocate a buffer of the requested size; observed
    ENOMEM for 4 MiB on the target), so the size limit is enforced across chunks instead.
    """
    data = bytearray()
    while True:
        chunk = stream.read(min(CHUNK, limit + 1 - len(data)))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError('File exceeds the read limit')


@dataclass(frozen=True)
class CommandOutput:
    returncode: int
    stdout: str


class FixedProbeIO:
    def __init__(self, deadline_seconds=300):
        if not 0 < deadline_seconds <= 600: raise ValueError('Invalid collection deadline')
        self.deadline = time.monotonic()+deadline_seconds
        self._verified = False

    def _ready(self):
        if not self._verified or platform.system() != 'Linux':
            raise ValueError('Verified Ubuntu preflight is required')
        if time.monotonic() >= self.deadline: raise TimeoutError('Collection deadline exceeded')

    def command(self, key):
        if key not in COMMANDS: raise ValueError('Unregistered read-only command')
        self._ready()
        return self._run(COMMANDS[key], 20)

    def _run(self, argv, seconds):
        timeout = min(self.deadline,time.monotonic()+seconds)
        # An explicit environment prevents remote-user PATH/pager/locale command injection.
        proc = subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            shell=False,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C','SYSTEMD_PAGER':'',
                             'SYSTEMD_COLORS':'0'},close_fds=True)
        chunks = queue.Queue(maxsize=32)
        stop = threading.Event()
        def pump(stream, channel):
            try:
                while not stop.is_set():
                    data = stream.read(4096)
                    if not data: break
                    while not stop.is_set():
                        try: chunks.put((channel,data),timeout=.05);break
                        except queue.Full: pass
            finally:
                while not stop.is_set():
                    try: chunks.put((channel,None),timeout=.05);break
                    except queue.Full: pass
        threads = [threading.Thread(target=pump,args=(stream,name),daemon=True)
                   for stream,name in ((proc.stdout,'out'),(proc.stderr,'err'))]
        for thread in threads: thread.start()
        done, output, total = set(),bytearray(),0
        try:
            while len(done) < 2:
                if time.monotonic() >= timeout: raise TimeoutError('Read-only command deadline exceeded')
                try: channel,data = chunks.get(timeout=.05)
                except queue.Empty: continue
                if data is None: done.add(channel);continue
                total += len(data)
                if total > 4*1024*1024: raise ValueError('Read-only command output exceeds limit')
                if channel == 'out': output.extend(data)
                # stderr is deliberately counted but never retained or exported.
            returncode = proc.wait(timeout=max(.01,timeout-time.monotonic()))
            return CommandOutput(returncode,output.decode('utf-8',errors='strict'))
        finally:
            stop.set()
            if proc.poll() is None: proc.kill()
            proc.wait(timeout=2)
            for thread in threads: thread.join(timeout=.2)
            proc.stdout.close();proc.stderr.close()

    def read_file(self, name):
        if name not in FILES: raise ValueError('Unregistered read-only file')
        if name not in IDENTITY_FILES: self._ready()
        return self._read(Path(name))

    def scap_results(self, request_id, engine_version):
        """Selected-rule evaluation of the pinned datastream; sanitized rule results only.

        Writes only the request's own result file under the approved scan directory, then removes it.
        Not yet run on the target VM: engine output format and timing are unvalidated there.
        """
        from .scap_results import (DATASTREAM, RESULT_LIMIT, RESULT_ROOT, SELECTED, TAILORING,
                                   engine_version as parse_version, result_path, sanitize_results, scan_argv)
        from .spec import SCAP_DATASTREAM_SHA256, SCAP_TAILORED_PROFILE, SCAP_TAILORING_SHA256
        self._ready()
        argv, result = scan_argv(request_id), Path(result_path(request_id))
        version = self.command('openscap_version')
        if version.returncode != 0 or parse_version(version.stdout) != engine_version:
            raise ValueError('OpenSCAP engine differs from the accepted version')
        if hashlib.sha256(self._bytes(Path(DATASTREAM), 64*1024*1024)).hexdigest() != SCAP_DATASTREAM_SHA256:
            raise ValueError('Installed SCAP datastream differs from the pinned content')
        if hashlib.sha256(self._bytes(Path(TAILORING), 1024*1024)).hexdigest() != SCAP_TAILORING_SHA256:
            raise ValueError('Installed SCAP tailoring differs from the pinned selection')
        root = Path(RESULT_ROOT)
        info = root.lstat()
        if root.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('Untrusted SCAP result directory')
        os.mkdir(result.parent, 0o700)  # Fails if the request directory already exists: no reuse.
        try:
            proc = self._run(argv, 300)
            if proc.returncode not in (0, 2):  # 0 all pass, 2 at least one failed rule; others are errors.
                raise ValueError('OpenSCAP evaluation failed')
            return sanitize_results(self._bytes(result, RESULT_LIMIT), rule_ids=SELECTED, profile_id=SCAP_TAILORED_PROFILE,
                                    expected_target=self._identity[1])
        finally:
            for leftover in result.parent.iterdir():
                leftover.unlink()
            result.parent.rmdir()

    def _read(self, path):
        return self._bytes(path, 4*1024*1024).decode('utf-8',errors='strict')

    def _bytes(self, path, limit):
        if time.monotonic() >= self.deadline: raise TimeoutError('Collection deadline exceeded')
        # Only os-release has an explicitly supported system symlink location.
        if path.is_symlink():
            if str(path) != '/etc/os-release' or str(path.resolve()) != '/usr/lib/os-release':
                raise ValueError('Unsupported configuration symlink')
        flags = os.O_RDONLY | getattr(os,'O_CLOEXEC',0)
        if str(path) != '/etc/os-release': flags |= getattr(os,'O_NOFOLLOW',0)
        fd = os.open(path,flags)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or not trusted_owner(before):
                raise ValueError('Untrusted configuration ownership/type')
            with os.fdopen(fd,'rb',closefd=False) as stream: data = read_bounded(stream, limit)
            after = os.fstat(fd)
            if len(data)>limit or (before.st_mtime_ns,before.st_size)!=(after.st_mtime_ns,after.st_size):
                raise ValueError('Configuration changed or exceeds limit')
            return data
        finally: os.close(fd)

    def files(self, group):
        if group not in GROUPS: raise ValueError('Unregistered configuration group')
        self._ready()
        directory, pattern = GROUPS[group]
        directory = Path(directory)
        if not directory.exists(): return ()
        info = directory.lstat()
        if directory.is_symlink() or not trusted_owner(info):
            raise ValueError('Untrusted configuration directory')
        paths = sorted(directory.glob(pattern),key=lambda p:p.name)
        if len(paths) > 256: raise ValueError('Too many configuration fragments')
        return tuple((p.name,self._read(p)) for p in paths)

    def privileged_paths(self):
        self._ready()
        from .inventory import eligible_mounts, discover_privileged
        output=self.command('mounts')
        if output.returncode != 0:raise ValueError('Mount discovery failed')
        mounts=eligible_mounts(output.stdout,self.read_file('/proc/filesystems'))
        return discover_privileged(mounts,deadline_seconds=min(120,self.deadline-time.monotonic()))


def preflight(io, request):
    if platform.system() != 'Linux' or not hasattr(os,'geteuid') or os.geteuid() != 0:
        raise ValueError('Collector requires approved root-owned Ubuntu helper execution')
    release = {}
    for line in io.read_file('/etc/os-release').splitlines():
        if not line or line.startswith('#'):continue
        if '=' not in line: raise ValueError('Malformed OS release data')
        key,value = line.split('=',1)
        parts = shlex.split(value)
        if key in release or len(parts) != 1: raise ValueError('Ambiguous OS release data')
        release[key] = parts[0]
    if release.get('ID') != 'ubuntu' or release.get('VERSION_ID') != '22.04':
        raise ValueError('Unsupported collector OS')
    if (io.read_file('/etc/machine-id').strip() != request['machine_id']
            or io.read_file('/proc/sys/kernel/hostname').strip().casefold() != request['hostname'].casefold()):
        raise ValueError('Collector target identity mismatch')
    io._identity = (request['machine_id'], request['hostname'].casefold())
    io._verified = True
