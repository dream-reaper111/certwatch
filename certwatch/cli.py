from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .core import CertificateError, report


def main() -> None:
    parser = argparse.ArgumentParser(prog="certwatch")
    parser.add_argument("certificates", nargs="+", type=Path)
    parser.add_argument("--root", action="append", default=[], type=Path,
                        help="explicit trust root certificate; only used with --hostname")
    parser.add_argument("--hostname", help="expected DNS hostname for server chain verification")
    parser.add_argument("--renewal-days", type=int, default=30)
    args = parser.parse_args()
    if bool(args.root) != bool(args.hostname):
        parser.error("--root and --hostname must be supplied together")
    try:
        result = report(args.certificates, datetime.now(timezone.utc), args.renewal_days,
                        args.root if args.root else None, args.hostname)
    except (CertificateError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
