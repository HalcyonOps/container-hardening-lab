# Known findings

Every CVE the scanner currently reports, why it hasn't been fixed, and what
would fix it.

**There are no `.trivyignore` files in this repo, and adding one is a policy
change rather than a maintenance decision.** Nothing is suppressed. Every
finding below appears in full in `make scan` output on every run. The gate
blocks a finding that is in CISA KEV, has EPSS above 0.1, has had a fix for at
least 30 days, or has not been reviewed in 90 days. Missing evidence blocks.

## Why a register instead of suppression

A suppression and a register look similar and behave in opposite ways.

A `.trivyignore` entry deletes the finding from the output. What's left is a
green tick, and the reasoning survives only in a comment nobody reads next to a
CVE nobody sees. It ages badly in a specific way: the justification was written
about one version of one image, and it keeps applying silently after the image,
the package, or the exploitability have all changed. The finding doesn't come
back when the reason stops being true.

A register does the opposite. The finding stays in the report and this file
records what's known about it. A finding can pass only while all four risk
conditions above remain clear. The noise is the reminder.

This also keeps the scanner honest as a **black box**. Trivy is imported
tooling; it decides what counts as a finding, and its verdicts change when its
database updates, without anything in this repo changing. Suppressing a CVE-ID
is an assertion about the scanner's output. Recording why the vulnerable code
isn't reachable is an assertion about the image, which is the thing actually
being defended. Only one of those survives a scanner swap. The same argument
applies to imported SAST and DAST gates and is worth writing up separately.

## Format

Each entry states the evidence, not a judgement. "Not exploitable here" with
nothing behind it is the thing this file exists to avoid. The machine-readable
comment under each heading records the last evidence review and the date a fix
first became available, or `none` when no fix exists:

```text
gate: cve=CVE-YYYY-NNNNN reviewed=YYYY-MM-DD fix-available=none
```

Wrap that line in an HTML comment for a real entry, as shown under each CVE
below. Only real CVE entries use the gate comment marker because the parser
treats every marked line as policy input.

---

## hardened-python

21 findings, 11 unique CVEs. None have a fix released by Debian.

`libpython3.13-minimal`/`-stdlib`/`python3.13-minimal`/`-venv` previously also
carried CVE-2026-11940 (`tarfile.extractall()` filter bypass), and
`libssl3t64` carried CVE-2026-14456 (shared with hardened-node, below). Both
were fixed upstream — Debian shipped `python3.13` 3.13.5-2+deb13u5 and
`openssl` 3.5.7-1~deb13u2 — and both findings disappeared the moment the
pinned distroless digest was bumped to pick them up
(`sha256:8ee214843129f43e2ebf5e0ca9f2e4e6d8292143d1b8a6787f169b5898578884`,
2026-09-15). Same for `libsqlite3-0`'s CVE-2026-11822/CVE-2026-11824: Debian
fixed both in `sqlite3` 3.46.1-7+deb13u2 (uploaded 2026-07-14, confirmed via
snapshot.debian.org), the same digest bump picked it up, and the finding is
gone. This is the register working as intended: a real, dated fix landing
removes the entry instead of it lingering as a stale exception. The bump was
diffed package-by-package against the previous digest first — only
`base-files`, `libc6`, `libc-bin`, `libcom-err2`, `tzdata`, `tzdata-legacy`,
and the three fixed packages moved; `libuuid1`, `libexpat1`,
`libncursesw6`/`libtinfo6` are byte-identical versions, so nothing below was
introduced by the bump.

### CVE-2026-15308 — `html.parser` CPU denial of service

<!-- gate: cve=CVE-2026-15308 reviewed=2026-08-23 fix-available=none -->

**Packages:** same four
**Fix:** none released

`html.parser.HTMLParser` can be driven into pathological CPU use by repeated
unterminated markup declarations.

**Why it isn't urgent here:** the reference application does not parse HTML. As
above, this is a property of the application, not the image.

**Resolved by:** a Debian fix, or an application that doesn't feed untrusted
HTML to the stdlib parser.

### CVE-2026-7210, CVE-2026-66046, CVE-2026-76956, CVE-2026-76957 — Expat hash flooding, quadratic-complexity DoS, and memory corruption

<!-- gate: cve=CVE-2026-7210 reviewed=2026-09-15 fix-available=none -->
<!-- gate: cve=CVE-2026-66046 reviewed=2026-09-15 fix-available=none -->
<!-- gate: cve=CVE-2026-76956 reviewed=2026-09-15 fix-available=none -->
<!-- gate: cve=CVE-2026-76957 reviewed=2026-09-15 fix-available=none -->

**Packages:** CVE-2026-7210 hits the same four CPython packages above (CPython
vendors its own copy of Expat for `pyexpat`); CVE-2026-66046, CVE-2026-76956,
and CVE-2026-76957 hit `libexpat1` itself, the separate shared library (1
finding each). Four CVEs, two independent copies of the vulnerable code.
**Fix:** none released for any of the four

CVE-2026-7210: `xml.parsers.expat` and `xml.etree.ElementTree` seed Expat's
hash-flooding protection with insufficient entropy, so a crafted document can
trigger collisions. CVE-2026-66046 is a separate DoS: `storeAtts()` does an
O(N^2) scan per non-normalized attribute, so a few-megabyte crafted document
burns excessive CPU. CVE-2026-76956 is the same entropy-seeding defect as
7210, in `libexpat1` proper. CVE-2026-76957 is a separate use-after-free:
Expat before 2.8.4 doesn't track handler call depth with custom encoding
callbacks.

**Why it isn't urgent here:** the reference application parses no XML, in
either the CPython-vendored copy or the shared library.

**EPSS as of 2026-09-15:** 7210 not separately scored by first.org (tracked
via the shared Debian advisory), 66046 0.00586, 76956 0.00287, 76957 0.00107.
None in CISA KEV.

**Resolved by:** libexpat 2.8.4 or later reaching both the CPython build and
the system package. Applications that must parse untrusted XML should use
`defusedxml` regardless of these CVEs.

### CVE-2026-82049 — `tarfile` hardlink-to-symlink extraction filter bypass

<!-- gate: cve=CVE-2026-82049 reviewed=2026-09-15 fix-available=none -->

**Packages:** same four CPython packages
**Fix:** none released

A crafted archive containing a hard link to a symbolic link can make
extraction modify permissions or mtimes outside the destination directory, or
expose that file's contents inside the extracted tree — a bypass of the
`data`/`tar` extraction filters distinct from CVE-2026-11940 (fixed above);
this is a new filter gap published 2026-09-14, one day before this review.

**Why it isn't urgent here:** the reference application (`app/main.py`) is an
HTTP server that never imports `tarfile`. Same application-not-image caveat as
every other stdlib-parser finding in this file: derive an application that
extracts untrusted archives from this image, and this applies to you at full
severity.

**Resolved by:** a Debian fix for `python3.13`, or a base image rebuild
carrying it.

### CVE-2026-76642, CVE-2026-78408, CVE-2026-78409, CVE-2026-78410 — util-linux privileged-mount and cgroup flaws

<!-- gate: cve=CVE-2026-76642 reviewed=2026-09-15 fix-available=none -->
<!-- gate: cve=CVE-2026-78408 reviewed=2026-09-15 fix-available=none -->
<!-- gate: cve=CVE-2026-78409 reviewed=2026-09-15 fix-available=none -->
<!-- gate: cve=CVE-2026-78410 reviewed=2026-09-15 fix-available=none -->

**Package:** `libuuid1` (1 finding each, 4 findings)
**Fix:** none released for any of the four

All four are privilege-escalation flaws in the `util-linux` *programs*:
CVE-2026-76642 lets a failed external mount helper's post-hooks still run
privileged; CVE-2026-78408 lets `nsenter --join-cgroup` leak root's cgroup
migration authority across an `execve()`; CVE-2026-78409 and CVE-2026-78410
are `/etc/fstab` `X-mount.*` option flaws that escape a restricted bind mount
via symlinks or an unpinned source. Every one of them requires the `mount`,
`nsenter`, or an fstab-driven mount helper to actually run.

**Why it isn't urgent here, with evidence:** this image ships none of the
util-linux CLI tools — only `libuuid1`, the shared library CPython's `uuid`
module links for `uuid.uuid1()`'s MAC-derived UUIDs:

```
$ tar tf <exported distroless-python filesystem> \
    | grep -iE 'bin/(mount|nsenter|findmnt|umount|lsblk|blkid|swapon)'
(no output)
```

Debian's `util-linux` source package builds the CLI tools and `libuuid1`
together and tracks CVEs at the source-package level, so Trivy attributes
these findings to the shared library even though none of the vulnerable code
ships in it. There is also no `/etc/fstab` in this image and the container
runs as non-root with no `CAP_SYS_ADMIN`, so the privileged-mount precondition
doesn't hold even where the binaries would.

**EPSS as of 2026-09-15:** 76642 0.00176, 78408 0.00113, 78409 0.00124, 78410
0.00096. None in CISA KEV.

**Resolved by:** a Debian fix landing in `libuuid1`, or dropping the
dependency (would require patching CPython's `uuid` module out, not realistic
for this image).

### CVE-2025-69720 — ncurses stack overflow in `infocmp`

<!-- gate: cve=CVE-2025-69720 reviewed=2026-08-23 fix-available=none -->

**Packages:** `libncursesw6`, `libtinfo6` (2 findings)
**Fix:** none released

**Why it isn't urgent here, with evidence:** the vulnerability is a stack-based
buffer overflow in `analyze_string` in `progs/infocmp.c` — that is, in the
`infocmp` *program*, not in the shared library that gets linked. This image
ships no such program:

```
$ docker run --rm --entrypoint /usr/bin/python3.13 hardened-python:latest \
    -c "import os; print([p for p in ['/usr/bin/infocmp','/usr/bin/tic','/usr/bin/tput'] if os.path.exists(p)])"
[]
```

The libraries are present because Python links them for `readline`. The code
containing the defect is not in the image at all. Trivy reports at package
granularity and cannot see that distinction, which is a good illustration of why
scanner output is evidence rather than a verdict.

This one previously *was* suppressed, with the weaker reasoning "this container
runs a headless HTTP server with no terminal interaction". That was a guess
about reachability. The binary being absent is a fact, and it's checkable.

**Resolved by:** a Debian fix for ncurses, or dropping the `readline` dependency.

---

## hardened-node

No findings at CRITICAL or HIGH. It previously shared CVE-2026-14456 (OpenSSL
QUIC listener memory exhaustion) with hardened-python — Debian shipped the fix
in `openssl` 3.5.7-1~deb13u2 via DSA-6465-1 (2026-08-25), and it disappeared
once the pinned `gcr.io/distroless/nodejs24-debian13:nonroot` digest was
bumped to `sha256:bb6b03d81066993293a10feda7250e8e1cc034035fe9b61cfceededa7c8bf04d`
(2026-09-15). Diffed against the previous digest first: only `base-files`,
`libc6`, `tzdata`, `tzdata-legacy`, and `libssl3t64` moved. The Node 24
migration separately removed CVE-2026-45447, whose fix had been available
since 2026-06-09 but never reached the Node 20 distroless image.

---

## hardened-nginx, hardened-go

No findings at CRITICAL or HIGH.
