# FINDINGS — php2shell-lab verification run

Environment: WSL2 Ubuntu 26.04, PHP **8.5.11** built from source (`--with-apxs2`,
`--disable-cgi`, otherwise default configuration), served via Apache
**mod_php (apache2handler)** on `127.0.0.1:8080`, prefork pool of 2-8 workers,
stock `php.ini-production` values (memory_limit 128M, post_max_size 8M,
max_input_vars 1000, session.upload_progress enabled, fatal_error_backtraces on).

Run date: 2026-10-25/26. All traffic stayed on loopback.

## CVE-2026-109618 — RCE via OOM corruption

### Confirmed: deterministic in-parse OOM through the chunked Content-Length bypass

The primary trigger (`harness/oom_trigger.py --strategy chunked-long-names`)
sends 1020 multipart parts with 48-384 KB part names over
`Transfer-Encoding: chunked`. Two prerequisites were verified empirically:

1. **post_max_size bypass.** A 18.8 MB body with `Content-Length` is rejected
   pre-parse ("POST Content-Length of 18788902 bytes exceeds the limit of
   8388608"). The *same body sent chunked* is parsed: the rfc1867
   `max_multipart_body_parts` and `max_input_vars` warnings fire for it in the
   error log — i.e. parsing proceeded on a body that post_max_size would have
   refused. This matches the advisory's OOM strategy description ("a multipart
   request without a usable Content-Length ... bypasses the post_max_size check
   and continues parsing body data").
2. **memory_limit reached during parsing, before application code.** Every
   trigger request produced:

   ```
   PHP Fatal error: Allowed memory size of 134217728 bytes exhausted
   (tried to allocate 135168 bytes) in Unknown on line 0
   Stack trace: #0 {main}
   ```

   `Unknown on line 0` + `#0 {main}` = the fatal fires in the request-startup
   (RINIT) multipart parse, not in `index.php`. This is the exact pre-condition
   the advisory describes: `longjmp()` bailout while request memory is
   reachable but not fully initialized, followed by request shutdown over
   that state.

   ~60/60 (first campaign) and ~400/400 plus a 10-burst sanity set on the
   varied-size campaign — **471 in-parse OOM fatals in total, a ~100%
   trigger rate** across every chunked trigger request in
   `results/oom-campaign-400.log` (excerpt: `results/oom-fatal-excerpt.log`).
   The OOM failure point was moved across the parse by varying the part-name
   length per request (128-512 KB; sizes under ~128 KB never reach the limit
   because the parsed amplification is only ~1.2x wire size).

### Not observed: worker segfault / heap corruption

~470 in-parse OOM draws produced **zero** segfaults, `free()`/`malloc()`
corruption aborts, or worker deaths in this environment. Honest read: the
wrong-moment landing is a low-probability event per request (consistent with
CVSS `AC:H`) and full control-flow hijack additionally requires the heap
grooming demonstrated by the original researchers (not reimplemented here).
The lab gives you the deterministic trigger; the crash lottery requires many
more draws and/or specific allocator layouts (glibc version, worker count,
concurrent traffic shape).

## CVE-2026-109619 — RCE via stale global state

### Confirmed: both producer paths are live with default settings

- **session.upload_progress** tracking is active (default `enabled=1`,
  `freq=1%`) — multipart uploads with a `PHP_SESSION_UPLOAD_PROGRESS` field
  populate request-owned session state.
- **fatal-error backtraces** fire on every `?action=fatal` request (uncaught
  `Error: Call to undefined function` with full stack in the log) — the
  producer for the confirmed mod_php exploitation path on PHP 8.5.

### Not observed: consumer-side crash

200 producer→consumer pairs (both pairings) produced no crash correlation.
Same caveat as above: the confirmed UAF requires the consumer request to
reuse the exact freed chunk before RINIT — a heap-timing attack needing more
aggressive same-worker pinning and allocator grooming than this harness
implements.

## Detector result

```
target:    http://127.0.0.1:8080
version:   8.5.11
verdict:   VULNERABLE  (branch 8.5 fixed in 8.5.12)
```

## What this lab is for

- A **deterministic, authorized reproduction of the vulnerable trigger
  conditions** on the highest-risk SAPI with default settings.
- A base for iterating on the crash lottery (more draws, worker pinning,
  allocator notes) without touching anyone's production.
- A mitigation testbed: flip `memory_limit=-1` / `post_max_size` /
  `session.upload_progress.enabled=0` in `php-lab.ini` and re-run to watch the
  trigger paths change.

## Full RCE disclosure position

No exploit for arbitrary code execution is included or claimed. The PHP
project's advisories document that RCE was demonstrated by the reporters; the
public PoC ecosystem for these CVEs is largely non-functional (see Tenable /
watchTowr / Recorded Future summaries from 2026-10-21/22), and this lab does
not attempt to close that gap.
