#!/usr/bin/env python3
"""Probe which PHP limit trips first: post_max_size vs memory_limit, with and
without Content-Length (chunked). Prints the server's verdict per request."""

import sys
import urllib.request

import common

BASE = "http://127.0.0.1:8080/"


def run(label: str, body: bytes, chunked: bool) -> None:
    status, out, err = common.http(
        "POST", BASE + "?action=upload", body=body,
        headers={"Content-Type": "multipart/form-data; boundary=probeX"},
        chunked=chunked, timeout=30)
    snip = out[:200].decode(errors="replace").replace("\n", " ")
    print(f"{label:28} status={status:3} err={err[:40]:40} body={snip}")


def tiny_parts_body(n_parts: int, seq: int) -> bytes:
    return common.multipart([(f"p{i}", None, b"x") for i in range(n_parts)],
                            boundary="probeX")


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 300000
    for label, chunked in (("with Content-Length", False),
                           ("chunked (no Content-Length)", True)):
        body = tiny_parts_body(n, 1)
        print(f"[probe] {label}: wire={len(body)/1e6:.1f}MB parts={n}")
        run(label, body, chunked)
