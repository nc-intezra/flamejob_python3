#!/usr/bin/env python3
"""M1 read-shadow diff CLI (P1-12).

Calls each M1 read endpoint on both the Rust and Python servers with the same
bearer token and reports any semantic difference (volatile fields normalised).
Exit 0 iff every endpoint matches — the gate for flipping Caddi to Python.

    python tools/diff_shadow.py \
        --rust https://rust.internal:8443 \
        --python https://python.internal:8443 \
        --token "$FJ_TOKEN" \
        --job-id <uuid> --hashlist-id <uuid>
"""

from __future__ import annotations

import argparse
import sys

import httpx

from flamejob_server.shadowdiff import READ_ENDPOINTS, compare


def _endpoints(args: argparse.Namespace) -> list[str]:
    eps = list(READ_ENDPOINTS)
    if args.job_id:
        eps += [f"/jobs/{args.job_id}", f"/jobs/{args.job_id}/tasks"]
    if args.hashlist_id:
        eps += [f"/hashlists/{args.hashlist_id}/cracked"]
    return eps


def main() -> int:
    ap = argparse.ArgumentParser(description="flamejob M1 read-shadow diff")
    ap.add_argument("--rust", required=True, help="Rust server base URL")
    ap.add_argument("--python", required=True, help="Python server base URL")
    ap.add_argument("--token", required=True, help="bearer token valid on both")
    ap.add_argument("--job-id")
    ap.add_argument("--hashlist-id")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    args = ap.parse_args()

    headers = {"Authorization": f"Bearer {args.token}"}
    verify = not args.insecure
    failures = 0
    with httpx.Client(headers=headers, verify=verify, timeout=30) as c:
        for path in _endpoints(args):
            try:
                r = c.get(args.rust + path)
                p = c.get(args.python + path)
            except httpx.HTTPError as e:
                print(f"FAIL {path}: request error {e}")
                failures += 1
                continue
            if r.status_code != p.status_code:
                print(f"FAIL {path}: status rust={r.status_code} python={p.status_code}")
                failures += 1
                continue
            diffs = compare(path, r.json(), p.json())
            if diffs:
                failures += 1
                print(f"FAIL {path}:")
                for d in diffs[:20]:
                    print(f"    {d}")
            else:
                print(f"OK   {path}")
    print(f"\n{'PASS' if failures == 0 else 'DIFFS'}: {failures} endpoint(s) differ")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
