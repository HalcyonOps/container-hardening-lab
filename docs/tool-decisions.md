# Tool decisions

Every tool in this project was chosen over at least one credible alternative. This document records those decisions — what was evaluated, what was chosen, and why.

---

## Vulnerability scanning — Trivy over Grype

**Chosen:** [Trivy](https://github.com/aquasecurity/trivy) (Aqua Security)
**Evaluated:** [Grype](https://github.com/anchore/grype) (Anchore)

Both are excellent open-source scanners with broad OS and language ecosystem coverage. The deciding factors:

| | Trivy | Grype |
|---|---|---|
| SARIF output | Native (`--format sarif`) | Native |
| GitHub Actions integration | Official action (`aquasecurity/trivy-action`) | Official action (`anchore/scan-action`) |
| Scan scope | Images, filesystems, repos, Kubernetes clusters, IaC | Images, filesystems, SBOMs |
| Secret scanning | Built-in (alongside CVE scan) | Separate tool |
| `.trivyignore` suppression | Structured ignore file with expiry date support | Separate file format |

Trivy's broader scan scope (IaC, Kubernetes cluster scanning) makes it the natural choice if this lab expands into infrastructure scanning. The single-binary, multi-mode design also keeps the CI pipeline simpler — one tool, multiple scan types.

Grype's advantage is its tight integration with Syft (same ecosystem) and arguably cleaner output formatting. It remains a strong choice and the decision could reasonably go either way.

---

## SBOM generation — Syft over Trivy SBOM

**Chosen:** [Syft](https://github.com/anchore/syft) (Anchore)
**Evaluated:** Trivy's built-in SBOM generation (`trivy image --format cyclonedx`)

Trivy can generate SBOMs directly, which would reduce the tool count. Syft was chosen separately because:

- **Richer SBOM output:** Syft produces more complete package metadata (licenses, CPEs, source locations) than Trivy's SBOM mode, which is optimised for vulnerability correlation rather than supply-chain audit
- **Both CycloneDX and SPDX:** Syft generates either format natively; Trivy's SBOM output is primarily CycloneDX
- **SBOM as a first-class artifact:** Keeping SBOM generation as an explicit step signals that SBOMs are a deliberate output, not a side effect of scanning
- **Grype compatibility:** Syft SBOMs can be fed directly to Grype for vulnerability scanning against an SBOM rather than a live image — useful for air-gapped environments

---

## Dockerfile policy enforcement — OPA/Conftest over Hadolint and Checkov

**Chosen:** [OPA](https://www.openpolicyagent.org/) + [Conftest](https://www.conftest.dev/)
**Evaluated:** [Hadolint](https://github.com/hadolint/hadolint), [Checkov](https://www.checkov.io/)

**Hadolint** is purpose-built for Dockerfile linting and is excellent at what it does — it catches common mistakes, enforces best practices, and integrates easily into CI. The reason it was not used here:

- Rules are fixed. Adding a custom policy (e.g. "only approved registries") requires patching Hadolint or combining it with a second tool
- The lab is explicitly about *policy-as-code* — policies should be readable, testable, version-controlled Rego, not configuration flags

**Checkov** supports Dockerfile checks via its built-in rules and can be extended with custom Python checks. It was not chosen because:

- Custom checks are Python, not a dedicated policy language — less expressive for complex conditions and harder to unit test in isolation
- Checkov's primary strength is IaC (Terraform, CloudFormation, Kubernetes manifests); Dockerfile coverage is secondary

**OPA/Conftest** was chosen because:

- **Rego is purpose-built for policy** — it handles set operations, comprehensions, and multi-stage reasoning naturally
- **`opa test` provides a proper unit test framework** — policies are tested with the same rigour as application code
- **The same policy language is used at both layers** — Rego for Dockerfile lint (via Conftest) and Rego is also the underlying language for OPA Gatekeeper (a Kubernetes admission controller), making the knowledge directly transferable
- **Conftest is format-agnostic** — the same workflow works for Dockerfiles, Kubernetes manifests, Terraform, and any other structured input

The tradeoff: Rego has a steeper learning curve than Hadolint configuration. For a team adopting Hadolint for the first time, it's the faster path to value. For a project where policies are a first-class artifact worth reading and testing, OPA is the right tool.

---

## Kubernetes admission control — Kyverno over OPA Gatekeeper

**Chosen:** [Kyverno](https://kyverno.io/)
**Evaluated:** [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)

Both are CNCF projects for Kubernetes admission control. The key differences:

| | Kyverno | OPA Gatekeeper |
|---|---|---|
| Policy language | YAML + JMESPath | Rego |
| Learning curve | Lower — YAML is familiar to Kubernetes users | Higher — requires learning Rego on top of Kubernetes concepts |
| Mutation support | Built-in (`mutate` rules) | Requires separate tooling |
| Test CLI | `kyverno test` (built-in) | `conftest` or custom tooling |
| Policy library | [kyverno.io/policies](https://kyverno.io/policies/) — large, maintained | [github.com/open-policy-agent/gatekeeper-library](https://github.com/open-policy-agent/gatekeeper-library) |
| Generate rules | Built-in (create resources from policy) | Not supported |

Kyverno was chosen primarily for the `kyverno test` CLI, which enables the same test-driven workflow used for OPA policies. Having `kyverno test tests/kyverno/` run 13 deterministic pass/fail assertions in CI provides a concrete verification signal that the policies work as intended.

OPA Gatekeeper is the choice for teams that already use Rego for other policies and want a unified language. In environments where both Dockerfile lint (OPA/Conftest) and admission control (Gatekeeper) use Rego, there is significant knowledge reuse and the policy taxonomy is consistent. That is a legitimate reason to prefer Gatekeeper.

---

## Container structure testing — container-structure-test over custom scripts

**Chosen:** [container-structure-test](https://github.com/GoogleContainerTools/container-structure-test) (Google)
**Evaluated:** Custom bash scripts using `docker run`

Custom scripts would work: `docker run --rm image sh -c "id | grep uid=10001"` is not complicated. The reasons for using container-structure-test instead:

- **Declarative test definitions** — YAML test configs are readable artifacts that document what the image is expected to contain, without mixing test logic and assertions
- **Multiple test types in one tool** — `commandTests`, `fileExistenceTests`, `fileContentTests`, `metadataTest` cover the full assertion surface without separate scripts for each
- **Structured output and exit codes** — clean pass/fail output with counts, compatible with CI without parsing
- **No shell required** — file existence and metadata tests run without invoking a shell inside the container, which matters for distroless images that have no shell

The tradeoff: one more tool to install. For a single assertion, a `docker run` one-liner is simpler. For 13–14 assertions per image, a declarative config file is significantly more maintainable.

---

## Base image selection — slim and alpine over full and distroless

**Python and Node:** `python:3.12-slim` and `node:20-slim` (Debian slim variants)
**nginx:** `nginx:1.27-alpine` (Alpine)
**Evaluated:** Full images, distroless (`gcr.io/distroless/*`), Chainguard Images (`cgr.dev/chainguard/*`)

**Full images** (e.g. `python:3.12`, `node:20`) include a complete Debian environment with package managers, compilers, and debugging tools. These are eliminated immediately — the goal is the opposite.

**Distroless** is the most hardened option: no shell, no package manager, no OS utilities. An attacker who achieves code execution in a distroless container has almost nothing to work with. The tradeoff:

- No shell means `docker exec` debugging doesn't work — you need a separate debug container or an ephemeral container
- Some applications require OS libraries that distroless doesn't include (e.g. `glibc` for native extensions)
- Structure tests that use `commandTests` with `sh -c "..."` cannot run inside distroless

Distroless is used in [docs/adding-an-image.md](adding-an-image.md) as the recommended final stage for a statically compiled Go binary, where it is the natural fit.

**slim variants** (Debian slim) were chosen for Python and Node because:

- Application dependencies frequently require OS packages that distroless doesn't provide
- The slim base allows `apt-get install` in the Dockerfile when genuinely needed
- Multi-stage builds achieve a result close to distroless by stripping everything added by the build stage — the final image contains only what was explicitly copied

**Alpine** was chosen for nginx because:

- The nginx Alpine image is maintained by the nginx project and is the standard production nginx image
- Alpine's musl libc and minimal package set result in a significantly smaller image (~50 MB vs ~190 MB for Debian nginx)
- nginx as a static file server has no native extension requirements that would make Alpine's libc a concern

**Chainguard Images** (`cgr.dev/chainguard/`) are on the approved registry allowlist and are a strong choice for new images — they are rebuilt daily, signed with Sigstore, and maintain near-zero CVE counts. They were not used as the primary base for the existing images because the Python and Node Chainguard images are minimalist by design and require more configuration to use as drop-in replacements.
