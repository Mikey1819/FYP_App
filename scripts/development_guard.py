"""Cooperative development lock; no timeout-based lock stealing."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import sys
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / ".automation" / "development.lock"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("acquire", "status", "release"))
    parser.add_argument("--token")
    args = parser.parse_args()

    if args.action == "acquire":
        LOCK.parent.mkdir(exist_ok=True)
        record = {
            "token": secrets.token_hex(24),
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "project": str(ROOT),
            "note": "Held for an agent run, not the lifetime of this helper process.",
        }
        try:
            fd = os.open(LOCK, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            print("SKIP: another run holds the lock. Inspect status; do not steal it.")
            return 2
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        print(json.dumps({"status": "acquired", **record}, indent=2))
        return 0

    if not LOCK.exists():
        print("No active development lock.")
        return 0 if args.action == "status" else 2
    try:
        record = json.loads(LOCK.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"Lock unreadable; leave it intact and investigate: {error}")
        return 2
    if args.action == "status":
        # Do not disclose the ownership token to a competing run.
        print(json.dumps({k: v for k, v in record.items() if k != "token"}, indent=2))
        return 0
    if not args.token or not secrets.compare_digest(args.token, record.get("token", "")):
        print("Refusing release: ownership token does not match.")
        return 2
    LOCK.unlink()
    print("Development lock released.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
