# Container Hardening Lab

<!-- CI badge — update OWNER/REPO after pushing to GitHub -->
<!-- ![CI](https://github.com/OWNER/container-hardening-lab/actions/workflows/ci.yml/badge.svg) -->

A portfolio project demonstrating production-grade container hardening, vulnerability scanning, and policy-as-code enforcement — aligned with the [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) and [DoD Iron Bank](https://ironbank.dso.mil/) practices.

## What This Demonstrates

This lab addresses the most common container security failures in production:

- **Containers running as root** — every image in this repo uses a dedicated non-root user (UID 10001)
- **Bloated attack surface** — multi-stage builds strip build tooling; `wget`, `curl`, `perl`, SUID/SGID binaries are explicitly removed
- **Unpinned or untrusted base images** — an OPA allowlist enforces approved registries and warns on unpinned digests
- **No admission control** — Kyverno ClusterPolicies block privileged pods, host namespace sharing, and missing capability drops at deploy time
- **No evidence trail** — every image ships a CycloneDX + SPDX SBOM and a Trivy CVE report; findings gate the CI build

## Repository Structure

```
.
├── images/
│   ├── python/               # python:3.12-slim — reference hardened image
│   ├── node/                 # node:20-slim — Express API
│   └── nginx/                # nginx:1.27-alpine — static file server
│
├── policies/
│   ├── opa/                  # Rego policies evaluated by Conftest against Dockerfiles
│   │   ├── no-root.rego
│   │   ├── no-privileged.rego
│   │   └── image-source-allowlist.rego
│   └── kyverno/              # Kubernetes admission policies
│       ├── no-root.yaml
│       ├── no-privileged.yaml
│       └── image-source-allowlist.yaml
│
├── tests/
│   ├── opa/                  # OPA unit tests (opa test)
│   ├── kyverno/              # Kyverno CLI policy tests + fixture Pods
│   └── structure/            # Container structure tests (runtime assertions)
│
├── examples/
│   └── unhardened/           # Deliberately insecure Dockerfile — failure demo
│
├── .github/workflows/ci.yml  # Full CI pipeline
└── Makefile                  # Primary task interface
```

## Hardening Controls

All images apply the following controls, mapped to CIS Docker Benchmark sections:

| CIS Control | What It Does | Implementation |
|---|---|---|
| **4.1** Non-root user | Prevent privilege escalation if container is compromised | Dedicated `appuser`/`nginx` (UID 10001/101); `USER` set before `CMD` |
| **4.2** Trusted base images | Prevent supply-chain compromise via malicious base images | OPA allowlist policy; only official Docker Hub, GCR Distroless, Chainguard, Iron Bank, ECR permitted |
| **4.4** Multi-stage builds | Strip build tooling from the final image | Builder stage installs deps; final stage copies only artifacts |
| **4.7** Remove unnecessary packages | Reduce attack surface | `wget`, `curl`, `perl`, `gcc`, `binutils` removed; BusyBox applets removed by binary path |
| **4.8** No SUID/SGID bits | Prevent privilege escalation via setuid binaries | `find / -xdev -perm /4000 -o -perm /2000 -exec chmod ug-s` run at build time |
| **4.9** No secrets in image | Prevent credential leakage via image inspection | No `ENV` with credentials; runtime-injected secrets only |
| **5.2/5.3** No host namespaces | Prevent container escape via host PID/IPC/network | Kyverno policy blocks `hostPID`, `hostIPC`, `hostNetwork: true` |
| **5.4** No privileged containers | Prevent full host access | Kyverno policy blocks `privileged: true`, requires `allowPrivilegeEscalation: false`, requires `capabilities.drop: ALL` |
| **5.7** Unprivileged ports | Avoid requiring `CAP_NET_BIND_SERVICE` | All images expose ports ≥ 1024 (8000, 3000, 8080) |

## Test Layers

The test suite has three independent layers, each catching a different class of failure:

### 1. OPA Unit Tests — policy logic

Tests the Rego policy rules themselves using `opa test`, without needing Docker. Fast feedback on policy correctness.

```bash
make test-opa
```

46 tests across three policies:

| Policy | Tests | What It Verifies |
|---|---|---|
| `no-root.rego` | 13 | Detects missing `USER`, `USER root`, `USER 0`, `USER 0:group` |
| `no-privileged.rego` | 14 | Detects `RUN --privileged`, warns on ports < 1024 and `--chown=root` |
| `image-source-allowlist.rego` | 19 | Approves/denies registries, warns on unpinned digests, covers multi-stage |

### 2. Kyverno Policy Tests — admission control

Tests Kyverno `ClusterPolicy` rules against fixture Pod manifests using `kyverno test`. No cluster required.

```bash
make test-kyverno
```

13 tests covering pass and fail cases for each rule:

| Test | Fixture | Expected |
|---|---|---|
| Non-root user required | `pod-fail-runasroot.yaml` | Deny |
| `runAsNonRoot: false` blocked | `pod-fail-runasnonroot-false.yaml` | Deny |
| `allowPrivilegeEscalation` blocked | `pod-fail-privilege-escalation.yaml` | Deny |
| `privileged: true` blocked | `pod-fail-privileged.yaml` | Deny |
| `capabilities.drop: ALL` required | `pod-fail-no-caps-drop.yaml` | Deny |
| `hostPID/hostIPC/hostNetwork` blocked | 3 fixture files | Deny |
| Fully hardened pod | `pod-pass-hardened.yaml` | Pass |

### 3. Container Structure Tests — runtime assertions

Tests the actual built image at runtime using `container-structure-test`. These catch regressions that only manifest after the image is built — e.g., a package manager silently re-adding a SUID binary.

```bash
make test-structure IMAGE=python   # or node, nginx
```

41 tests across three images:

| Image | Tests | Checks |
|---|---|---|
| `hardened-python` | 14 | UID 10001, no SUID/SGID, no wget/curl/perl/gcc, `/app` workdir, nologin shell, OCI labels |
| `hardened-node` | 14 | UID 10001, no SUID/SGID, no wget/curl/perl, Express importable, `src/index.js` present, OCI labels |
| `hardened-nginx` | 13 | UID 101, no SUID/SGID, no wget/curl, `server_tokens off`, port 8080, security headers, OCI labels |

## Failure Demo

`examples/unhardened/Dockerfile` is deliberately insecure. The CI pipeline asserts that the OPA linter and Trivy scanner **must** flag it — a clean result would mean the tooling isn't working.

Violations the Conftest policies catch:

```
FAIL - examples/unhardened/Dockerfile - docker.security - CIS 4.1: No USER instruction found.
WARN - examples/unhardened/Dockerfile - docker.security - CIS 5.7: EXPOSE 80 uses a privileged port.
WARN - examples/unhardened/Dockerfile - docker.security - Files COPY'd with --chown=root will not be writable by the app user.
WARN - examples/unhardened/Dockerfile - docker.security - Image 'node:18' is not pinned to a digest.
```

Trivy separately flags `node:18` as carrying CRITICAL/HIGH CVEs (the image is intentionally pinned to an old, vulnerable release).

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Docker | ≥ 24 | [docs.docker.com](https://docs.docker.com/get-docker/) |
| Trivy | ≥ 0.69 | [aquasecurity.github.io/trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) |
| Syft | ≥ 1.0 | [github.com/anchore/syft](https://github.com/anchore/syft#installation) |
| Conftest | ≥ 0.57 | [conftest.dev](https://www.conftest.dev/install/) |
| OPA | ≥ 0.70 | [openpolicyagent.org](https://www.openpolicyagent.org/docs/latest/#1-download-opa) |
| Kyverno CLI | ≥ 1.17 | [kyverno.io/docs/kyverno-cli](https://kyverno.io/docs/kyverno-cli/) |
| container-structure-test | ≥ 1.19 | [github.com/GoogleContainerTools/container-structure-test](https://github.com/GoogleContainerTools/container-structure-test#installation) |

## Quick Start

```bash
# Run all policy and admission tests (no Docker required)
make test

# Build, scan, and generate SBOMs for all images
make all

# Run container structure tests (images must be built first)
make test-structure IMAGE=python
make test-structure IMAGE=node
make test-structure IMAGE=nginx

# Individual targets for a single image
make build IMAGE=python
make scan  IMAGE=python
make sbom  IMAGE=python
make lint  IMAGE=python
```

Scan reports and SBOMs are written to `reports/<image>/`:

```
reports/python/
├── trivy.json              # CVE scan results (JSON)
├── sbom.cyclonedx.json     # Software Bill of Materials (CycloneDX)
└── sbom.spdx.json          # Software Bill of Materials (SPDX)
```

## CI Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs three jobs on every push and pull request:

```mermaid
flowchart TD
    trigger([push / pull_request]):::event --> pt

    pt["**policy-tests**\nOPA unit tests — 46\nKyverno policy tests — 13"]:::job

    pt --> fd
    pt --> ip

    subgraph fd ["  failure-demo  "]
        direction TB
        f1["Conftest must reject\nunhardened Dockerfile"]:::check
        f2["Trivy must find CVEs\nin node:18"]:::check
    end

    subgraph ip ["  image-pipeline — python · node · nginx (parallel)  "]
        direction TB
        i1["Lint Dockerfile\nConftest / OPA"]:::step --> i2
        i2["Build image"]:::step --> i3
        i3["Trivy scan\ngate: CRITICAL / HIGH = fail"]:::gate --> i4
        i3 --> i5
        i4["SARIF → GitHub\nSecurity tab"]:::output
        i5["Generate SBOM\nSyft — CycloneDX + SPDX"]:::step --> i6
        i6["Container structure tests\n41 assertions"]:::step --> i7
        i7[("Reports artifact\n30-day retention")]:::output
    end

    classDef event  fill:#6366f1,stroke:#4f46e5,color:#fff
    classDef job    fill:#0ea5e9,stroke:#0284c7,color:#fff
    classDef step   fill:#10b981,stroke:#059669,color:#fff
    classDef gate   fill:#f59e0b,stroke:#d97706,color:#fff
    classDef check  fill:#ec4899,stroke:#db2777,color:#fff
    classDef output fill:#64748b,stroke:#475569,color:#fff
```

**`policy-tests`** runs first with no Docker dependency — fast feedback on every push.

**`failure-demo`** asserts that the unhardened Dockerfile and `node:18` base image are correctly flagged. A clean result here fails the job, proving the tooling is live.

**`image-pipeline`** runs in parallel across all three images. Trivy findings are uploaded to the GitHub Security tab as SARIF for triage. All reports are archived as build artifacts for 30 days.

## Deployment (Kubernetes)

To enforce the admission policies on a cluster:

```bash
# Apply Kyverno ClusterPolicies
kubectl apply -f policies/kyverno/

# Verify — this Pod should be blocked
kubectl apply -f tests/kyverno/resources/pod-fail-privileged.yaml
```

The policies are written in audit mode by default (`validationFailureAction: Audit`). Change to `Enforce` in production.
