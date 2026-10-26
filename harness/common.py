#!/usr/bin/env python3
"""Shared helpers for the php2shell-lab harness."""

from __future__ import annotations

import http.client as _httpclient
import re
import socket
import sys
import time
import urllib.parse
import urllib.request

UA = "php2shell-lab-harness/1.0 (localhost lab; authorized)"


def http(method: str, url: str, body: bytes | None = None,
         headers: dict | None = None, timeout: float = 20.0,
         chunked: bool = False) -> tuple[int, bytes, str]:
    """Single request. Returns (status, body, error). status=0 on transport error."""
    p = urllib.parse.urlsplit(url)
    host, port = p.hostname, p.port or 80
    try:
        if chunked and body is not None:
            path = p.path or "/"
            if p.query:
                path += "?" + p.query
            return _chunked_request(host, port, path, body,
                                    headers or {}, timeout)
        req = urllib.request.Request(url, data=body, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        req.add_header("User-Agent", UA)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), ""
    except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
        return e.code, e.read(), ""
    except Exception as e:  # connection reset, timeout, ...
        return 0, b"", f"{type(e).__name__}: {e}"


def _chunked_request(host, port, path, body: bytes, headers: dict, timeout):
    """Send a POST with Transfer-Encoding: chunked (no Content-Length). This
    bypasses the pre-parse post_max_size Content-Length check, one of the OOM
    strategies named in GHSA-w8hw-w9fx-j79w."""
    try:
        conn = _httpclient.HTTPConnection(host, port, timeout=timeout)
        conn.putrequest("POST", path)
        conn.putheader("User-Agent", UA)
        conn.putheader("Transfer-Encoding", "chunked")
        conn.putheader("Content-Type",
                       headers.get("Content-Type", "application/x-www-form-urlencoded"))
        conn.endheaders()
        # send in 64 KiB chunks
        for i in range(0, len(body), 65536):
            part = body[i:i + 65536]
            conn.send(b"%X\r\n%s\r\n" % (len(part), part))
        conn.send(b"0\r\n\r\n")
        resp = conn.getresponse()
        data = resp.read()
        status = resp.status
        conn.close()
        return status, data, ""
    except Exception as e:
        return 0, b"", f"{type(e).__name__}: {e}"


def multipart(parts: list[tuple[str, str, bytes]], boundary: str) -> bytes:
    """Build a multipart/form-data body. parts = (name, filename, content)."""
    out = []
    for name, filename, content in parts:
        out.append(f"--{boundary}\r\n".encode())
        if filename is None:
            out.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        else:
            out.append(
                f'Content-Disposition: form-data; name="{name}"; '
                f'filename="{filename}"\r\n'.encode())
            out.append(b"Content-Type: application/octet-stream\r\n\r\n")
        out.append(content + b"\r\n")
    out.append(f"--{boundary}--\r\n".encode())
    return b"".join(out)


def tail_apache_errors(n: int = 10) -> str:
    """Last N lines of the lab vhost error log (run on the WSL host itself)."""
    try:
        with open("/var/log/apache2/php2shell-lab-error.log", errors="replace") as f:
            return "".join(f.readlines()[-n:])
    except OSError:
        return ""


CRASH_PATTERNS = [
    "exit signal Segmentation fault",
    "exit signal Bus error",
    "exit signal Illegal instruction",
    "free(): invalid pointer",
    "malloc(): corrupted",
    "munmap_chunk(): invalid pointer",
    "double free or corruption",
    "segfault",
    "caught SIGSEGV",
    " segfault at ",          # kernel log style
]


def looks_like_crash(line: str) -> bool:
    return any(p.lower() in line.lower() for p in CRASH_PATTERNS)


def baseline_error_log() -> list[str]:
    """Snapshot existing error-log lines so we can diff after a run."""
    try:
        with open("/var/log/apache2/php2shell-lab-error.log", errors="replace") as f:
            return f.readlines()
    except OSError:
        return []


def new_crash_lines(baseline: list[str]) -> list[str]:
    try:
        with open("/var/log/apache2/php2shell-lab-error.log", errors="replace") as f:
            now = f.readlines()
    except OSError:
        return []
    return [ln for ln in now[len(baseline):] if looks_like_crash(ln)]


def eprint(*a):
    print(*a, file=sys.stderr)


def opener_post(opener, url: str, body: bytes | None,
                 content_type: str | None) -> tuple[int, bytes, str]:
    """POST through a cookie-aware opener (session continuity matters here)."""
    req = urllib.request.Request(url, data=body if body is not None else b"",
                                 method="POST")
    if content_type:
        req.add_header("Content-Type", content_type)
    req.add_header("User-Agent", UA)
    try:
        with opener.open(req, timeout=20) as r:
            return r.status, r.read(), ""
    except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
        return e.code, e.read(), ""
    except Exception as e:
        return 0, b"", f"{type(e).__name__}: {e}"


def opener_get(opener, url: str) -> tuple[int, bytes, str]:
    """GET through a cookie-aware opener."""
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", UA)
    try:
        with opener.open(req, timeout=20) as r:
            return r.status, r.read(), ""
    except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
        return e.code, e.read(), ""
    except Exception as e:
        return 0, b"", f"{type(e).__name__}: {e}"


class Stopwatch:
    def __init__(self):
        self.t0 = time.time()

    def lapse(self) -> float:
        return time.time() - self.t0
