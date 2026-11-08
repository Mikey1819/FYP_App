"""Bounded metadata-only privileged-file discovery. Discovered files are never executed."""
import json
import os
from pathlib import PurePosixPath
import stat
import time


def eligible_mounts(raw, filesystems):
    if len(raw)>1024*1024 or len(filesystems)>65536:raise ValueError('Mount inventory exceeds limit')
    try:
        rows=json.loads(raw)['filesystems']
        if type(rows) is not list or len(rows)>4096:raise ValueError('Invalid mount inventory')
        local={line.strip() for line in filesystems.splitlines() if line.strip() and not line.lstrip().startswith('nodev')}
        mounts=[]
        for row in rows:
            if type(row) is not dict or set(row)!={'target','fstype','options'}:raise ValueError('Unsupported mount record')
            target,kind,options=row['target'],row['fstype'],row['options']
            if any(type(value) is not str for value in (target,kind,options)):raise ValueError('Invalid mount value')
            if not target.startswith('/') or '..' in target.split('/') or '\x00' in target:raise ValueError('Unsafe mount path')
            if kind in local and not {'nosuid','noexec'} & set(options.split(',')):mounts.append(target)
        if not mounts or len(set(mounts))>64:raise ValueError('Missing or excessive eligible mounts')
        return tuple(sorted(set(mounts)))
    except (KeyError,TypeError,json.JSONDecodeError):raise ValueError('Malformed mount inventory') from None


def discover_privileged(mounts, *, deadline_seconds=120, max_entries=2_000_000, max_paths=4096):
    # A stock Ubuntu root filesystem exceeded 20 s / 100,000 entries on the target (2026-11-06).
    if not 0<deadline_seconds<=120 or not 1<=len(mounts)<=64 or not 1<=max_entries<=2_000_000:
        raise ValueError('Invalid bounded inventory request')
    deadline=time.monotonic()+deadline_seconds
    count=0;found=set()
    flags=os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0)
    def walk(fd,directory,device,depth):
        nonlocal count
        if depth>128:raise ValueError('Inventory depth limit exceeded')
        with os.scandir(fd) as entries:
            for entry in entries:
                count+=1
                if count>max_entries or time.monotonic()>=deadline:raise ValueError('Inventory limit/deadline exceeded')
                info=entry.stat(follow_symlinks=False)
                if info.st_dev!=device:continue
                path=str(PurePosixPath(directory)/entry.name)
                if len(path)>1024 or any(c in path for c in ('\x00','\r','\n')):raise ValueError('Unsupported privileged inventory path')
                if stat.S_ISREG(info.st_mode) and info.st_mode & 0o6000:
                    found.add(path)
                    if len(found)>max_paths:raise ValueError('Privileged inventory path limit exceeded')
                elif stat.S_ISDIR(info.st_mode):
                    child=os.open(entry.name,flags,dir_fd=fd)
                    try:
                        current=os.fstat(child)
                        if current.st_dev!=device or current.st_ino!=info.st_ino:
                            raise ValueError('Filesystem changed during inventory')
                        walk(child,path,device,depth+1)
                    finally:os.close(child)
    try:
        for mount in mounts:
            if type(mount) is not str or not mount.startswith('/') or '..' in mount.split('/'):
                raise ValueError('Unsafe inventory root')
            fd=os.open(mount,flags)
            try:
                info=os.fstat(fd)
                if not stat.S_ISDIR(info.st_mode):raise ValueError('Inventory root is not a directory')
                walk(fd,mount,info.st_dev,0)
            finally:os.close(fd)
    except OSError:raise ValueError('Inventory incomplete due to filesystem access/change') from None
    return tuple(sorted(found))
