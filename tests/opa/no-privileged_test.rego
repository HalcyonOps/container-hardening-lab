# tests/opa/no-privileged_test.rego
# Unit tests for policies/opa/no-privileged.rego
#
# Run:
#   opa test policies/opa/no-privileged.rego tests/opa/no-privileged_test.rego -v

package docker.security

import future.keywords.if

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_run(flags)    := {"Cmd": "run",    "Value": ["echo hello"], "Flags": flags,  "Stage": 0}
_expose(port)  := {"Cmd": "expose", "Value": [port],         "Flags": [],     "Stage": 0}
_copy(flags)   := {"Cmd": "copy",   "Value": ["src", "dst"], "Flags": flags,  "Stage": 0}

_dockerfile(cmd) := [{"Cmd": "from", "Value": ["python:3.12-slim"], "Flags": [], "Stage": 0}, cmd]

# ---------------------------------------------------------------------------
# Deny: RUN --privileged
# ---------------------------------------------------------------------------

test_deny_run_privileged_flag if {
    count(deny) > 0 with input as _dockerfile(_run(["--privileged"]))
}

test_pass_run_without_privileged_flag if {
    count(deny) == 0 with input as _dockerfile(_run([]))
}

test_pass_run_with_unrelated_flag if {
    count(deny) == 0 with input as _dockerfile(_run(["--mount=type=cache,target=/var/cache"]))
}

# ---------------------------------------------------------------------------
# Warn: EXPOSE of a privileged port (< 1024)
# ---------------------------------------------------------------------------

test_warn_expose_port_80 if {
    count(warn) > 0 with input as _dockerfile(_expose("80"))
}

test_warn_expose_port_443 if {
    count(warn) > 0 with input as _dockerfile(_expose("443"))
}

test_warn_expose_port_1 if {
    count(warn) > 0 with input as _dockerfile(_expose("1"))
}

test_warn_expose_port_1023 if {
    count(warn) > 0 with input as _dockerfile(_expose("1023"))
}

test_no_warn_expose_port_1024 if {
    port_warns := [w | w := warn[_] with input as _dockerfile(_expose("1024")); contains(w, "privileged port")]
    count(port_warns) == 0 with input as _dockerfile(_expose("1024"))
}

test_no_warn_expose_port_8000 if {
    port_warns := [w | w := warn[_]; contains(w, "privileged port")]
    count(port_warns) == 0 with input as _dockerfile(_expose("8000"))
}

test_no_warn_expose_port_8080 if {
    port_warns := [w | w := warn[_]; contains(w, "privileged port")]
    count(port_warns) == 0 with input as _dockerfile(_expose("8080"))
}

# ---------------------------------------------------------------------------
# Warn: COPY --chown=root
# ---------------------------------------------------------------------------

test_warn_copy_chown_root if {
    count(warn) > 0 with input as _dockerfile(_copy(["--chown=root"]))
}

test_warn_copy_chown_root_root if {
    count(warn) > 0 with input as _dockerfile(_copy(["--chown=root:root"]))
}

test_no_warn_copy_chown_appuser if {
    chown_warns := [w | w := warn[_]; contains(w, "chown=root")]
    count(chown_warns) == 0 with input as _dockerfile(_copy(["--chown=appuser:appgroup"]))
}

test_no_warn_copy_no_chown if {
    chown_warns := [w | w := warn[_]; contains(w, "chown=root")]
    count(chown_warns) == 0 with input as _dockerfile(_copy([]))
}
