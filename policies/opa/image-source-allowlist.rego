# policies/opa/image-source-allowlist.rego
# Enforce that Dockerfiles only use FROM bases drawn from approved registries.
#
# CIS Docker Benchmark: 4.2 — Ensure that containers use only trusted base images
#
# Input format: conftest parses Dockerfiles as a flat array of command objects.
#   input[_] => { "Cmd": "from", "Value": ["python:3.12-slim"], "Flags": [], "Stage": 0 }

package docker.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Configuration: approved image sources
# ---------------------------------------------------------------------------
approved_registries := {
    "python",
    "node",
    "nginx",
    "debian",
    "ubuntu",
    "alpine",
    "gcr.io/distroless",
    "cgr.dev/chainguard",
    "registry1.dso.mil",
    "public.ecr.aws",
}

# ---------------------------------------------------------------------------
# Deny: FROM base not in allowlist
# ---------------------------------------------------------------------------
deny contains msg if {
    some cmd in input
    cmd.Cmd == "from"
    image := cmd.Value[0]
    image != "scratch"
    not from_approved_registry(image)
    msg := sprintf("CIS 4.2: Base image '%v' does not match any approved registry. Approved: %v", [image, approved_registries])
}

# ---------------------------------------------------------------------------
# Warn: FROM without a digest pin
# ---------------------------------------------------------------------------
warn contains msg if {
    some cmd in input
    cmd.Cmd == "from"
    image := cmd.Value[0]
    image != "scratch"
    not contains(image, "@sha256:")
    msg := sprintf("Image '%v' is not pinned to a digest. Pin with @sha256:<digest> in CI for reproducible builds.", [image])
}

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
from_approved_registry(image) if {
    some approved in approved_registries
    startswith(image, approved)
}
