# tests/opa/image-source-allowlist_test.rego
# Unit tests for policies/opa/image-source-allowlist.rego
#
# Run:
#   opa test policies/opa/image-source-allowlist.rego tests/opa/image-source-allowlist_test.rego -v

package docker.security

import future.keywords.if

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_from(image) := {"Cmd": "from", "Value": [image], "Flags": [], "Stage": 0}

_dockerfile(image) := [_from(image)]

_digest := "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# ---------------------------------------------------------------------------
# Pass: approved Docker Hub official short names
# ---------------------------------------------------------------------------

test_pass_python_slim if {
    count(deny) == 0 with input as _dockerfile("python:3.12-slim")
}

test_pass_node_slim if {
    count(deny) == 0 with input as _dockerfile("node:20-slim")
}

test_pass_nginx_alpine if {
    count(deny) == 0 with input as _dockerfile("nginx:1.27-alpine")
}

test_pass_golang if {
    count(deny) == 0 with input as _dockerfile("golang:1.24-bookworm")
}

test_pass_debian if {
    count(deny) == 0 with input as _dockerfile("debian:bookworm-slim")
}

test_pass_ubuntu if {
    count(deny) == 0 with input as _dockerfile("ubuntu:24.04")
}

test_pass_alpine if {
    count(deny) == 0 with input as _dockerfile("alpine:3.20")
}

# ---------------------------------------------------------------------------
# Pass: approved external registries
# ---------------------------------------------------------------------------

test_pass_distroless if {
    count(deny) == 0 with input as _dockerfile("gcr.io/distroless/python3-debian12")
}

test_pass_chainguard if {
    count(deny) == 0 with input as _dockerfile("cgr.dev/chainguard/python:latest")
}

test_pass_iron_bank if {
    count(deny) == 0 with input as _dockerfile("registry1.dso.mil/ironbank/opensource/python/python38")
}

test_pass_public_ecr if {
    count(deny) == 0 with input as _dockerfile("public.ecr.aws/amazonlinux/amazonlinux:2023")
}

# ---------------------------------------------------------------------------
# Pass: scratch is always allowed
# ---------------------------------------------------------------------------

test_pass_scratch if {
    count(deny) == 0 with input as _dockerfile("scratch")
}

# ---------------------------------------------------------------------------
# Deny: unapproved registries
# ---------------------------------------------------------------------------

test_deny_random_dockerhub_user if {
    count(deny) > 0 with input as _dockerfile("randomuser/malware:latest")
}

test_deny_unknown_registry if {
    count(deny) > 0 with input as _dockerfile("badregistry.example.com/image:tag")
}

test_deny_quay_io if {
    count(deny) > 0 with input as _dockerfile("quay.io/someorg/someimage:latest")
}

# ---------------------------------------------------------------------------
# Warn: no digest pin
# ---------------------------------------------------------------------------

test_warn_unpinned_approved_image if {
    count(warn) > 0 with input as _dockerfile("python:3.12-slim")
}

test_no_warn_pinned_approved_image if {
    pinned := concat("", ["python:3.12-slim", _digest])
    digest_warns := [w | w := warn[_] with input as _dockerfile(pinned); contains(w, "not pinned")]
    count(digest_warns) == 0 with input as _dockerfile(pinned)
}

test_no_warn_scratch_unpinned if {
    digest_warns := [w | w := warn[_] with input as _dockerfile("scratch"); contains(w, "not pinned")]
    count(digest_warns) == 0 with input as _dockerfile("scratch")
}

# ---------------------------------------------------------------------------
# Multi-stage: all FROM bases must be approved
# ---------------------------------------------------------------------------

test_deny_unapproved_base_in_builder_stage if {
    dockerfile := [
        {"Cmd": "from", "Value": ["badregistry.example.com/build-tools:latest"], "Flags": [], "Stage": 0},
        {"Cmd": "from", "Value": ["python:3.12-slim"],                           "Flags": [], "Stage": 1},
    ]
    count(deny) > 0 with input as dockerfile
}

test_pass_all_stages_approved if {
    dockerfile := [
        {"Cmd": "from", "Value": ["node:20-slim"],      "Flags": [], "Stage": 0},
        {"Cmd": "from", "Value": ["nginx:1.27-alpine"], "Flags": [], "Stage": 1},
    ]
    count(deny) == 0 with input as dockerfile
}
