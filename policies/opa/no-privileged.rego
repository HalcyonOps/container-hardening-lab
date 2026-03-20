# policies/opa/no-privileged.rego
# Enforce that Dockerfiles do not contain instructions that imply privileged
# operation, and warn against patterns that require privilege at runtime.
#
# CIS Docker Benchmark: 5.4 — Ensure privileged containers are not used
#
# Input format: conftest parses Dockerfiles as a flat array of command objects.
#   input[_] => { "Cmd": "run", "Value": ["..."], "Flags": ["--privileged"], "Stage": 0 }

package docker.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Deny: --privileged flag in a RUN instruction (BuildKit syntax)
# ---------------------------------------------------------------------------
deny contains msg if {
    some cmd in input
    cmd.Cmd == "run"
    some flag in cmd.Flags
    contains(flag, "--privileged")
    msg := "CIS 5.4: RUN instruction uses --privileged. This is not permitted."
}

# ---------------------------------------------------------------------------
# Warn: EXPOSE of a privileged port (< 1024) requires CAP_NET_BIND_SERVICE
# ---------------------------------------------------------------------------
warn contains msg if {
    some cmd in input
    cmd.Cmd == "expose"
    port := to_number(split(cmd.Value[0], "/")[0])
    port < 1024
    msg := sprintf("CIS 5.7: EXPOSE %v uses a privileged port (< 1024). Use a port >= 1024 and drop CAP_NET_BIND_SERVICE.", [cmd.Value[0]])
}

# ---------------------------------------------------------------------------
# Warn: COPY --chown=root (files owned by root in non-root images)
# ---------------------------------------------------------------------------
warn contains msg if {
    some cmd in input
    cmd.Cmd == "copy"
    some flag in cmd.Flags
    contains(lower(flag), "chown=root")
    msg := "Files COPY'd with --chown=root will not be writable by a non-root USER. Consider --chown=appuser:appgroup."
}
