# tests/opa/no-root_test.rego
# Unit tests for policies/opa/no-root.rego
#
# Run:
#   opa test policies/opa/no-root.rego tests/opa/no-root_test.rego -v
#
# conftest parses Dockerfiles as a flat array of command objects:
#   input => [{"Cmd": "from", "Value": [...], "Flags": [], "Stage": 0}, ...]
# Each test mocks `input` directly as this flat array.

package docker.security

import future.keywords.if

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_from(image) := {"Cmd": "from", "Value": [image], "Flags": [], "Stage": 0}

_user(u) := {"Cmd": "user", "Value": [u], "Flags": [], "Stage": 0}

_with_user(u)  := [_from("python:3.12-slim"), _user(u)]
_without_user  := [_from("python:3.12-slim")]

# ---------------------------------------------------------------------------
# Deny: no USER instruction at all
# ---------------------------------------------------------------------------

test_deny_missing_user_instruction if {
    count(deny) > 0 with input as _without_user
}

# ---------------------------------------------------------------------------
# Deny: USER root (by name)
# ---------------------------------------------------------------------------

test_deny_user_root_lowercase if {
    count(deny) > 0 with input as _with_user("root")
}

test_deny_user_root_uppercase if {
    count(deny) > 0 with input as _with_user("ROOT")
}

test_deny_user_root_root if {
    count(deny) > 0 with input as _with_user("root:root")
}

# ---------------------------------------------------------------------------
# Deny: USER by UID 0
# ---------------------------------------------------------------------------

test_deny_user_uid_zero if {
    count(deny) > 0 with input as _with_user("0")
}

test_deny_user_zero_zero if {
    count(deny) > 0 with input as _with_user("0:0")
}

test_deny_user_zero_colon_group if {
    count(deny) > 0 with input as _with_user("0:appgroup")
}

# ---------------------------------------------------------------------------
# Pass: non-root named user
# ---------------------------------------------------------------------------

test_pass_user_appuser if {
    count(deny) == 0 with input as _with_user("appuser")
}

test_pass_user_nginx if {
    count(deny) == 0 with input as _with_user("nginx")
}

# ---------------------------------------------------------------------------
# Pass: non-root by high UID
# ---------------------------------------------------------------------------

test_pass_user_high_uid if {
    count(deny) == 0 with input as _with_user("10001")
}

test_pass_user_high_uid_with_gid if {
    count(deny) == 0 with input as _with_user("10001:10001")
}

# ---------------------------------------------------------------------------
# Multi-stage: Stage field differentiates stages in the flat array
# ---------------------------------------------------------------------------

test_deny_user_root_in_second_stage if {
    dockerfile := [
        {"Cmd": "from",  "Value": ["python:3.12-slim"], "Flags": [], "Stage": 0},
        {"Cmd": "user",  "Value": ["appuser"],          "Flags": [], "Stage": 0},
        {"Cmd": "from",  "Value": ["python:3.12-slim"], "Flags": [], "Stage": 1},
        {"Cmd": "user",  "Value": ["root"],             "Flags": [], "Stage": 1},
    ]
    count(deny) > 0 with input as dockerfile
}

test_pass_nonroot_user_across_stages if {
    dockerfile := [
        {"Cmd": "from", "Value": ["python:3.12-slim"], "Flags": [], "Stage": 0},
        {"Cmd": "user", "Value": ["appuser"],          "Flags": [], "Stage": 0},
        {"Cmd": "from", "Value": ["python:3.12-slim"], "Flags": [], "Stage": 1},
        {"Cmd": "user", "Value": ["nginx"],            "Flags": [], "Stage": 1},
    ]
    count(deny) == 0 with input as dockerfile
}
