# policies/opa/image-source-allowlist.rego
#
# Enforce that all FROM bases in a Dockerfile come from approved registries,
# and warn when base images are not pinned to a digest.
#
# CIS Docker Benchmark: 4.2 — Ensure that containers use only trusted base images
#
# Evaluated by Conftest against each Dockerfile:
#   conftest test images/python/Dockerfile \
#     --policy policies/opa/ \
#     --namespace docker.security
#
# Unit tests: tests/opa/image-source-allowlist_test.rego
#   Run: opa test policies/opa/image-source-allowlist.rego \
#          tests/opa/image-source-allowlist_test.rego --verbose
#
# =============================================================================
# Why an allowlist rather than a denylist
# =============================================================================
#
# A denylist (block known-bad registries) fails open — anything not on the list
# is permitted. New or unknown registries slip through by default.
#
# An allowlist (permit known-good registries) fails closed — anything not
# explicitly approved is blocked. This is the correct posture for supply-chain
# security: unknown sources require a deliberate decision to add to the list,
# not a deliberate decision to block.
#
# =============================================================================
# Allowlist rationale
# =============================================================================
#
# Each entry is a prefix matched against the full image reference. The following
# sources are considered trusted for this project:
#
#   python, node, nginx,      — Docker Hub Official Images, maintained by Docker
#   golang, debian, ubuntu,     and the upstream projects; vetted and signed
#   alpine
#
#   gcr.io/distroless          — Google's minimal base images; no shell, no pkg mgr
#
#   cgr.dev/chainguard         — Chainguard Images; built with Wolfi, signed with
#                                Sigstore, daily rebuilds, near-zero CVEs
#
#   registry1.dso.mil          — DoD Iron Bank; government-hardened images used in
#                                classified and CMMC environments
#
#   public.ecr.aws             — AWS public ECR; home of Amazon Linux and official
#                                AWS service images
#
# To add a new registry, append its prefix to approved_registries and add a
# corresponding test case in tests/opa/image-source-allowlist_test.rego.

package docker.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# =============================================================================
# Configuration: approved image sources
# =============================================================================
#
# Stored as a set (curly braces) rather than an array for O(1) membership
# checks. Rego sets do not have duplicates or ordering — appropriate here
# since the values are used only for prefix matching, not iteration order.
approved_registries := {
    # Docker Hub Official Images (short names — no registry hostname prefix)
    "python",
    "node",
    "nginx",
    "golang",
    "debian",
    "ubuntu",
    "alpine",
    # External trusted registries (full hostname prefix)
    "gcr.io/distroless",
    "cgr.dev/chainguard",
    "registry1.dso.mil",
    "public.ecr.aws",
}

# =============================================================================
# DENY: FROM base not in allowlist
# =============================================================================
#
# Applies to every FROM instruction in every build stage. In a multi-stage
# Dockerfile, the builder stage is as dangerous as the final stage — a
# compromised builder can inject malicious artifacts into the final image.
#
# `image != "scratch"` is an explicit exemption: scratch is an empty image
# with no filesystem, used as the base for fully statically compiled binaries
# (Go, Rust). It carries no risk from a registry-trust perspective.
deny contains msg if {
    some cmd in input
    cmd.Cmd == "from"

    image := cmd.Value[0]

    # scratch is always allowed — it is not a registry image
    image != "scratch"

    # from_approved_registry is defined below; not(...) fires when no
    # approved prefix matches the image reference
    not from_approved_registry(image)

    msg := sprintf(
        "CIS 4.2: Base image '%v' does not match any approved registry. Approved sources: %v",
        [image, approved_registries],
    )
}

# =============================================================================
# WARN: FROM without a digest pin
# =============================================================================
#
# Image tags (`:latest`, `:3.12-slim`) are mutable — the content they point to
# can change between builds. A `docker pull python:3.12-slim` today may return
# a different image layer than it did yesterday if the upstream maintainer
# pushed a new version.
#
# Digest pinning (`@sha256:<hash>`) makes the reference immutable: the pull
# always returns the exact image that was tested. This is required for truly
# reproducible builds.
#
# This is a WARN rather than a DENY because:
# 1. Development workflows change tags frequently; blocking on this would be
#    too disruptive locally
# 2. CI can inject the digest at build time via --build-arg, so the Dockerfile
#    itself may intentionally use a tag
# 3. scratch has no digest and is handled by the exemption below
warn contains msg if {
    some cmd in input
    cmd.Cmd == "from"

    image := cmd.Value[0]
    image != "scratch"

    # @sha256: is the standard digest prefix for OCI image references
    not contains(image, "@sha256:")

    msg := sprintf(
        "Image '%v' is not pinned to a digest. Pin with @sha256:<digest> for reproducible builds.",
        [image],
    )
}

# =============================================================================
# Helper: from_approved_registry
# =============================================================================
#
# Returns true if `image` starts with any prefix in the approved set.
# `startswith` handles both short names ("python:3.12-slim") and full
# registry references ("gcr.io/distroless/python3-debian12").
#
# Multiple rule heads with the same name implement logical OR in Rego —
# the helper is true if any approved prefix matches. A single rule with
# `some approved in approved_registries` achieves the same result more
# concisely; both patterns are idiomatic Rego.
from_approved_registry(image) if {
    some approved in approved_registries
    startswith(image, approved)
}
