"""Consistent backup, verification and restore of the application's SQLite stores.

backup  - copies every *.sqlite3 under data/ with SQLite's online backup API (a consistent snapshot even while the app
          runs; uncommitted writes are not included) and writes manifest.json with each file's SHA-256 and
          `PRAGMA integrity_check` result. Other files under data/ (evaluation output) are not stores and are skipped.
verify  - re-checks a backup folder against its manifest: every file present, same hash, integrity ok.
restore - writes a verified backup into an EMPTY folder only. It never overwrites the live data/ folder; replacing
          it is a manual step with the app stopped (docs/OPERATIONS.md, "Back up and restore the stores").

Usage (from the app directory):
  ..\\.venv-integration\\Scripts\\python.exe -B -m tools.backup_stores backup [--to FOLDER]   (default ../store-backups)
  ..\\.venv-integration\\Scripts\\python.exe -B -m tools.backup_stores verify FOLDER
  ..\\.venv-integration\\Scripts\\python.exe -B -m tools.backup_stores restore FOLDER --into EMPTY_FOLDER
"""
from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing
import argparse
import hashlib
import json
import shutil
import sqlite3
import sys

APP = Path(__file__).resolve().parents[1]


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _integrity(path):
    try:
        with closing(sqlite3.connect('file:%s?mode=ro' % Path(path).as_posix(), uri=True)) as db:
            return db.execute('PRAGMA integrity_check').fetchone()[0]
    except sqlite3.DatabaseError as error:
        return 'error: %s' % error


def backup(data, destination):
    """A new timestamped folder under `destination` holding a consistent copy of every store and a manifest."""
    data, stamp = Path(data), datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    folder = Path(destination) / ('stores-' + stamp)
    folder.mkdir(parents=True)
    files = {}
    for source in sorted(data.rglob('*.sqlite3')):
        name = source.relative_to(data).as_posix()
        target = folder / name
        target.parent.mkdir(parents=True, exist_ok=True)
        # closing(): on Windows a connection's context manager only commits; an open handle blocks the file.
        with closing(sqlite3.connect('file:%s?mode=ro' % source.as_posix(), uri=True)) as src,                 closing(sqlite3.connect(target)) as dst:
            src.backup(dst)
        files[name] = {'sha256': _sha256(target), 'bytes': target.stat().st_size, 'integrity': _integrity(target)}
    (folder / 'manifest.json').write_text(json.dumps({'created_at': stamp, 'source': str(data), 'files': files},
                                                     indent=2, sort_keys=True), encoding='utf-8')
    return folder


def verify(folder):
    """Problems found ('name: reason'); an empty list means the backup is complete and intact."""
    folder = Path(folder)
    manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
    problems = []
    for name, expected in sorted(manifest['files'].items()):
        path = folder / name
        if not path.is_file():
            problems.append(name + ': missing')
        elif _sha256(path) != expected['sha256']:
            problems.append(name + ': hash differs from the manifest')
        elif _integrity(path) != 'ok':
            problems.append(name + ': integrity check failed')
    return problems


def restore(folder, into):
    """Copy a verified backup into an empty (or new) folder; refuses anything else."""
    folder, into = Path(folder), Path(into)
    problems = verify(folder)
    if problems:
        raise ValueError('Backup failed verification: ' + '; '.join(problems))
    if into.exists() and any(into.iterdir()):
        raise ValueError('Restore writes only into an empty folder; %s has content' % into)
    manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
    for name in manifest['files']:
        target = into / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(folder / name, target)
    return into


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='command', required=True)
    make = sub.add_parser('backup')
    make.add_argument('--to', default=str(APP.parent / 'store-backups'))
    check = sub.add_parser('verify')
    check.add_argument('folder')
    put = sub.add_parser('restore')
    put.add_argument('folder')
    put.add_argument('--into', required=True)
    args = parser.parse_args()
    if args.command == 'backup':
        folder = backup(APP / 'data', args.to)
        problems = verify(folder)
        print('Backup:', folder)
        print('Verified' if not problems else 'PROBLEMS: ' + '; '.join(problems))
        sys.exit(1 if problems else 0)
    if args.command == 'verify':
        problems = verify(args.folder)
        print('Verified' if not problems else 'PROBLEMS:\n' + '\n'.join(problems))
        sys.exit(1 if problems else 0)
    print('Restored into', restore(args.folder, args.into))


if __name__ == '__main__':
    main()
