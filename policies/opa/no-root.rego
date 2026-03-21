# policies/opa/no-root.rego
#
# Enforce that Dockerfiles declare a non-root USER.
#
# CIS Docker Benchmark: 4.1 — Ensure a user for the container has been created
#
# Evaluated by Conftest against each Dockerfile:
#   conftest test images/python/Dockerfile \
#     --policy policies/opa/ \
#     --namespace docker.security
#
# Unit tests: tests/opa/no-root_test.rego
#   Run: opa test policies/opa/no-root.rego tests/opa/no-root_test.rego --verbose
#
# =============================================================================
# How Conftest parses Dockerfiles
# =============================================================================
#
# Conftest converts a Dockerfile into a flat JSON array and binds it to `input`.
# Each instruction becomes one object:
#
#   [
#     { "Cmd": "from",  "Value": ["python:3.12-slim"], "Flags": [], "Stage": 0 },
#     { "Cmd": "run",   "Value": ["apt-get update"],   "Flags": [], "Stage": 0 },
#     { "Cmd": "user",  "Value": ["appuser"],           "Flags": [], "Stage": 0 },
#     ...
#   ]
#
# Key fields:
#   Cmd   — lowercase Dockerfile instruction name (from, run, copy, user, expose, ...)
#   Value — array of arguments to the instruction
#   Flags — BuildKit flags (e.g. --chown=, --mount=, --privileged)
#   Stage — integer index of the build stage (0 = first FROM, 1 = second FROM, ...)
#
# =============================================================================
# How OPA/Rego policy rules work
# =============================================================================
#
# Conftest evaluates policies in the `deny` and `warn` rule sets:
#   deny  — violations that fail the check (non-zero exit code)
#   warn  — advisory findings that print but do not fail
#
# Each rule uses the `contains` keyword to build a *set* of violation messages.
# A rule contributes a message to `deny` when all conditions in its body are true.
#
# `import future.keywords.*` opts into Rego v1 keyword syntax (contains, if, in)
# while remaining compatible with OPA 0.x. This will be the default in Rego v1.

package docker.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# =============================================================================
# DENY: No USER instruction present
# =============================================================================
#
# If a Dockerfile has no USER instruction at all, the container process runs
# as root (UID 0) — Docker's default. This rule detects that absence.
#
# Pattern: collect all "user" instructions into a list, then deny if empty.
# This is safer than checking for the *presence* of a non-root user, because
# an empty list unambiguously means no USER was set.
deny contains msg if {
    # Comprehension: build a list of every instruction whose Cmd is "user".
    # input[_] iterates over every element of the flat array.
    user_instructions := [cmd | cmd := input[_]; cmd.Cmd == "user"]

    # If the list is empty, no USER instruction exists anywhere in the file.
    count(user_instructions) == 0

    msg := "CIS 4.1: No USER instruction found. Containers must not run as root."
}

# =============================================================================
# DENY: USER is explicitly set to root
# =============================================================================
#
# Catches Dockerfiles that include a USER instruction but set it to root
# explicitly. Root can be expressed in several equivalent ways — all are caught.
#
# `some cmd in input` iterates over each instruction object.
# The rule body short-circuits: each condition must be true for the rule to fire.
deny contains msg if {
    some cmd in input
    cmd.Cmd == "user"

    # Normalise to lowercase before comparison so USER Root, USER ROOT, and
    # USER root are all caught. Dockerfile instructions are case-insensitive
    # but the parsed Value preserves the original casing.
    user_value := lower(cmd.Value[0])

    is_root_user(user_value)

    # The message uses the original (un-lowercased) value so the output matches
    # exactly what the developer wrote in the Dockerfile.
    msg := sprintf("CIS 4.1: USER is set to '%v'. Containers must not run as root.", [cmd.Value[0]])
}

# =============================================================================
# Helper: is_root_user
# =============================================================================
#
# A single helper with multiple heads — Rego evaluates each definition
# independently and the helper is true if *any* definition matches.
# This avoids a deeply nested OR expression and makes each case self-documenting.
#
# Cases covered:
#   "root"      — name-based, the most common form
#   "0"         — numeric UID, equivalent to root
#   "0:0"       — UID:GID pair, both root
#   "root:root" — name-based with explicit group
#   "0:*"       — UID 0 with any group — still root, regardless of group
is_root_user(value) if value == "root"
is_root_user(value) if value == "0"
is_root_user(value) if value == "0:0"
is_root_user(value) if value == "root:root"
is_root_user(value) if startswith(value, "0:")
