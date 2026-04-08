# Contributing

## Prerequisites

Install these tools before working on the project locally. The versions listed are what CI uses — other versions may work but are untested.

| Tool | Version | Install |
|---|---|---|
| Docker | ≥ 24 | [docs.docker.com](https://docs.docker.com/get-docker/) |
| OPA | 0.70.0 | [openpolicyagent.org](https://www.openpolicyagent.org/docs/latest/#1-download-opa) |
| Conftest | 0.57.0 | [conftest.dev](https://www.conftest.dev/install/) |
| Kyverno CLI | 1.17.1 | [kyverno.io/docs/kyverno-cli](https://kyverno.io/docs/kyverno-cli/) |
| Trivy | 0.69.3 | [aquasecurity.github.io/trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) |
| Syft | ≥ 1.0 | [github.com/anchore/syft](https://github.com/anchore/syft#installation) |
| container-structure-test | 1.19.3 | [github.com/GoogleContainerTools/container-structure-test](https://github.com/GoogleContainerTools/container-structure-test#installation) |
| Cosign | ≥ 2.0 | [github.com/sigstore/cosign](https://github.com/sigstore/cosign#installation) |
| Docker Compose | ≥ 2.0 | bundled with Docker Desktop; `apt install docker-compose-plugin` on Linux |

---

## Running tests locally

### Policy tests — no Docker required

These run fast and should be your first check after any change to a Dockerfile or policy file.

```bash
# OPA unit tests (46 tests across 3 policies)
make test-opa

# Kyverno admission policy tests (13 tests)
make test-kyverno

# Both at once (fast, no Docker)
make test

# All tests including Falco rule validation (requires Docker)
make test-all
```

### Image pipeline — requires Docker

```bash
# Build, scan, and generate SBOMs for a single image
make build IMAGE=python
make scan  IMAGE=python
make sbom  IMAGE=python

# Lint a Dockerfile against OPA policies
make lint IMAGE=python

# Run container structure tests (image must be built first)
make test-structure IMAGE=python

# Full pipeline for all images
make all
```

### Checking what CI will do

The CI workflow runs three jobs. You can replicate each locally:

```bash
# Job 1: policy-tests
make test

# Job 2: failure-demo — these commands should exit non-zero (that's the pass condition)
conftest test examples/unhardened/Dockerfile \
  --policy policies/opa/ \
  --namespace docker.security
trivy image --severity CRITICAL,HIGH --exit-code 1 node:18

# Job 3: image-pipeline (repeat for node, nginx)
make lint IMAGE=python
make build IMAGE=python
make scan IMAGE=python
make sbom IMAGE=python
make test-structure IMAGE=python
```

---

### Runtime security demo — requires Docker Compose

```bash
cd falco/
docker compose up -d
docker logs -f falco

# In a second terminal — trigger a rule
docker exec lab-target apt-get update

# Stop when done
docker compose down
```

See [falco/README.md](../falco/README.md) for all five rule triggers.

---

## Project structure

```
images/<name>/
  Dockerfile          # Hardened image — follow the pattern in images/python/
  .trivyignore        # Accepted CVEs with justification (may be empty)
  .dockerignore       # Excludes local artifacts from build context
  README.md           # Per-image case study

policies/
  opa/<name>.rego     # Conftest policy + unit tests in tests/opa/
  kyverno/<name>.yaml # Kyverno ClusterPolicy + fixtures in tests/kyverno/

tests/
  opa/                # opa test unit tests — one file per policy
  kyverno/            # kyverno test fixtures — one Pod per violation
  structure/          # container-structure-test configs — one file per image

docs/
  adding-an-image.md  # Walkthrough for adding a new hardened image
  tool-decisions.md   # Rationale for tool choices
```

---

## Adding a new hardened image

See [docs/adding-an-image.md](docs/adding-an-image.md) for a full walkthrough. The short version:

1. Create `images/<name>/Dockerfile` following the hardening checklist
2. Verify `make lint IMAGE=<name>` passes
3. Verify `make scan IMAGE=<name>` exits 0 (no CRITICAL/HIGH CVEs)
4. Write `tests/structure/<name>.yaml` and verify `make test-structure IMAGE=<name>` passes
5. Add `<name>` to the matrix in `.github/workflows/container-security.yml`
6. Write `images/<name>/README.md` documenting the hardening decisions

---

## Adding or modifying a policy

### OPA/Rego policy

1. Edit or create `policies/opa/<name>.rego`
2. Write or update unit tests in `tests/opa/<name>_test.rego`
3. Run `make test-opa` — all tests must pass
4. Run `make lint IMAGE=python` (and other images) to confirm hardened images still pass

### Kyverno policy

1. Edit or create `policies/kyverno/<name>.yaml`
2. Add fixture Pods to `tests/kyverno/resources/` — one file per pass/fail case
3. Add result entries to `tests/kyverno/kyverno-test.yaml`
4. Run `make test-kyverno` — all tests must pass

---

## CI requirements

Every pull request must pass all CI jobs before merging:

| Job | What it checks |
|---|---|
| `policy-tests` | OPA unit tests (46) + Kyverno policy tests (13) + Falco rule validation (5 rules) |
| `failure-demo` | Conftest must reject `examples/unhardened/Dockerfile`; Trivy must find CVEs in `node:18` |
| `image-pipeline (python)` | Lint → Build → Trivy scan (0 CRITICAL/HIGH) → SBOM → Structure tests (14) |
| `image-pipeline (node)` | Lint → Build → Trivy scan (0 CRITICAL/HIGH) → SBOM → Structure tests (14) |
| `image-pipeline (nginx)` | Lint → Build → Trivy scan (0 CRITICAL/HIGH) → SBOM → Structure tests (13) |
| `image-pipeline (go)` | Lint → Build → Trivy scan (0 CRITICAL/HIGH) → SBOM → Structure tests (12) |

A Trivy scan that finds CRITICAL or HIGH CVEs will fail the pipeline. If a CVE has no fix available and the code path is not exploitable in this container, add it to the image's `.trivyignore` with a justification comment — do not suppress CVEs without documented reasoning.

---

## Commit style

Keep commits focused. Prefer one logical change per commit. Message format:

```
Short summary (≤ 72 chars)

Longer explanation of why the change was made, not just what it does.
Reference CIS controls or CVE IDs where relevant.
```
