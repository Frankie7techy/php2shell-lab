#!/usr/bin/env python3
"""detect.py — fingerprint a PHP server and give a patched/unpatched verdict
for PHP2Shell (CVE-2026-109618 / CVE-2026-109619).

Usage: python3 detect.py http://127.0.0.1:8080/
Intended for auditing servers you own or are authorized to test.
"""

from __future__ import annotations

import re
import sys

import common

# Fixed releases per the PHP security advisory of 2026-10-21.
FIXED = {"8.5": "8.5.12", "8.4": "8.4.27", "8.3": "8.3.36", "8.2": "8.2.35"}
EOL = ("8.1", "8.0", "7.4", "7.3", "7.2", "7.1", "7.0", "5.6", "5.5", "5.4")


def version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split(".")[:3])


def verdict(version: str) -> tuple[str, str]:
    """Returns (verdict, explanation)."""
    branch = ".".join(version.split(".")[:2])
    if branch in FIXED:
        return ("PATCHED" if version_tuple(version) >= version_tuple(FIXED[branch])
                else "VULNERABLE",
                f"branch {branch} fixed in {FIXED[branch]}")
    if branch in EOL:
        return "VULNERABLE (EOL, no fix ever)", \
            f"branch {branch} is end-of-life; only source backports exist"
    return "UNKNOWN", f"branch {branch} not in advisory table"


def scrape_version(base_url: str) -> str | None:
    """Read php_version from the lab target, or fall back to X-Powered-By."""
    status, body, _err = common.http("GET", base_url + "/?action=info")
    m = re.search(rb"php_version=([0-9.]+)", body) if status else None
    if m:
        return m.group(1).decode()
    status, body, _err = common.http("GET", base_url + "/")
    m = re.search(rb"X-Powered-By: .*?PHP/([0-9.]+)", body)
    if m:
        return m.group(1).decode()
    return None


def main() -> int:
    base = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8080"
    version = scrape_version(base)
    if not version:
        print(f"[!] could not fingerprint {base}")
        return 2
    v, why = verdict(version)
    print(f"target:    {base}")
    print(f"version:   {version}")
    print(f"verdict:   {v}  ({why})")
    return 0 if v.startswith("PATCHED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
