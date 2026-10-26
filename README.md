# php2shell-lab

Local reproduction lab for the two critical PHP core RCE vulnerabilities disclosed on
**2026-10-21** ("PHP2Shell"):

| CVE | GHSA | Name | Root cause |
|---|---|---|---|
| CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | RCE via OOM corruption | `longjmp()` bailout on `memory_limit` exhaustion leaves request memory partially initialized; request shutdown later reads/branches on it |
| CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | RCE via stale global state | Request-owned global state (error backtraces, session upload progress) survives request shutdown; a later request on the same worker consumes freed memory (UAF) |

**CVSS 9.2 critical** (both), unauthenticated, pre-auth on `mod_php` with default settings.

> **Authorized lab only.** This repository targets `127.0.0.1` only. Scanning or
> exploiting PHP servers you do not own is illegal. The detector script exists so you
> can audit *your own* infrastructure.

## Why build from source?

Distro packages received the fix backported *before* disclosure (Ubuntu 26.04's
`8.5.4-0ubuntu1.5` already contains `CVE-2026-109618_109619.patch`), so any distro
PHP is already patched. To get the authentic pre-patch runtime the advisories were
written against, this lab compiles **PHP 8.5.11** (last vulnerable release) from
source as an **Apache `mod_php` module** with default settings — the highest-risk
setup per the PHP security team, where one unauthenticated request reaches the bug
before any application code runs.

## Layout

```
setup/
  setup-wsl.sh        one-shot lab builder (Ubuntu/Debian WSL or bare box): deps,
                      PHP 8.5.11 source build with apxs2, Apache vhost, php.ini
  apache-lab.conf     vhost: mod_php, prefork-tuned (small worker pool = easier
                      same-worker pinning, as real attack campaigns assume)
  php-lab.ini         stock php.ini-production values (memory_limit=128M etc.)
target/
  index.php           minimal upload app that exercises the vulnerable paths:
                      multipart parsing, session.upload_progress, a controlled
                      fatal-error producer for the stale-state bug
harness/
  common.py           HTTP helpers, worker crash detection, log tailing
  detect.py           version fingerprint + patched/unpatched verdict
  oom_trigger.py      CVE-2026-109618: four OOM strategies from the advisory
                      (deep input arrays, part-count amplification, oversized
                      part names, chunked no-Content-Length body), burst loop
  stale_state_probe.py CVE-2026-109619: producer/consumer pairs on one worker
                      (session.upload_progress + fatal-error backtrace state)
docs/FINDINGS.md      what we observed when running the harness against the lab
results/              raw logs from the verification run
```

## Quick start (WSL2 Ubuntu / Debian)

```bash
cd setup && sudo bash setup-wsl.sh
```

The script prints the lab URL (default `http://127.0.0.1:8080/`). From Windows the
WSL2 service is reachable on `localhost:8080`.

## Running the harness

```bash
cd harness
python3 detect.py http://127.0.0.1:8080/
python3 oom_trigger.py http://127.0.0.1:8080/ --strategy many-parts --bursts 200
python3 stale_state_probe.py http://127.0.0.1:8080/ --pairs 100
```

Success criteria we track (see `docs/FINDINGS.md`):

1. **worker death** — Apache `error.log` shows `child pid ... exit signal Segmentation fault`
   or heap corruption (`free(): invalid pointer`, `malloc(): corrupted top size`)
   correlated with a request,
2. **connection reset / 503** on the request that killed the worker,
3. **version verdict** from `detect.py` (8.5.11 = last vulnerable 8.5 release).

## Mitigations (for the report/audit use-case)

Patched releases: **8.5.12, 8.4.27, 8.3.36, 8.2.35**. PHP 8.1 and older never get an
official fix — treat EOL PHP as permanently vulnerable.

If you cannot patch:

- `CVE-2026-109618`: enforce `memory_limit=-1` via `php_admin_value` (FPM pool /
  Apache conf, not `.user.ini`), low `post_max_size`, proxy-level limits on decoded
  request size / part count / nesting. Incomplete: an underlying allocation failure
  can still reach the vulnerable path.
- `CVE-2026-109619`: `session.upload_progress.enabled=0` + restart every worker;
  on 8.5 `fatal_error_backtraces=0`. Blocks the *confirmed* paths only.
- Detect attempts: POST bodies containing `PHP_SESSION_UPLOAD_PROGRESS`, abnormal
  multipart part counts, chunked multipart bodies without `Content-Length`.
  Investigate logs from **2026-10-17** onward (pre-disclosure exploitation observed).

## References

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/
- https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- https://github.com/NCSC-NL/php2shell (third-party software embedding PHP)

## License

MIT — see `LICENSE`.
