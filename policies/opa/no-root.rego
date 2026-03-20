# policies/opa/no-root.rego
# Enforce that Dockerfiles do not run as root.
#
# Evaluated with Conftest:
#   conftest test images/python/Dockerfile --policy policies/opa/
#
# CIS Docker Benchmark: 4.1 — Ensure a user for the container has been created
#
# Input format: conftest parses Dockerfiles as a flat array of command objects.
#   input[_] => { "Cmd": "user", "Value": ["appuser"], "Flags": [], "Stage": 0 }

package docker.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Deny: no USER instruction present in any stage
# ---------------------------------------------------------------------------
deny contains msg if {
    user_instructions := [cmd | cmd := input[_]; cmd.Cmd == "user"]
    count(user_instructions) == 0
    msg := "CIS 4.1: No USER instruction found. Containers must not run as root."
}

# ---------------------------------------------------------------------------
# Deny: USER is explicitly set to root (by name or UID 0)
# ---------------------------------------------------------------------------
deny contains msg if {
    some cmd in input
    cmd.Cmd == "user"
    user_value := lower(cmd.Value[0])
    is_root_user(user_value)
    msg := sprintf("CIS 4.1: USER is set to '%v'. Containers must not run as root.", [cmd.Value[0]])
}

# ---------------------------------------------------------------------------
# Helper: identify root user values
# ---------------------------------------------------------------------------
is_root_user(value) if value == "root"
is_root_user(value) if value == "0"
is_root_user(value) if value == "0:0"
is_root_user(value) if value == "root:root"
is_root_user(value) if startswith(value, "0:")
