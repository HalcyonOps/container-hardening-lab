# policies/opa/no-privileged.rego
#
# Warn against Dockerfile patterns that require elevated privileges at runtime,
# and deny instructions that are unconditionally dangerous.
#
# CIS Docker Benchmark:
#   5.4 — Ensure privileged containers are not used
#   5.7 — Ensure privileged ports are not mapped within containers
#
# Evaluated by Conftest against each Dockerfile:
#   conftest test images/python/Dockerfile \
#     --policy policies/opa/ \
#     --namespace docker.security
#
# Unit tests: tests/opa/no-privileged_test.rego
#   Run: opa test policies/opa/no-privileged.rego tests/opa/no-privileged_test.rego --verbose
#
# =============================================================================
# deny vs warn — when to use each
# =============================================================================
#
# deny  → the pattern is unconditionally unsafe; no legitimate use case exists
#         in a production hardened image. Conftest exits non-zero.
#
# warn  → the pattern is a smell that frequently indicates a problem, but has
#         legitimate exceptions. The finding is printed but does not fail CI.
#         A reviewer must evaluate whether the exception is justified.
#
# This file uses:
#   deny  for RUN --privileged (no legitimate use in a production image)
#   warn  for privileged ports and --chown=root (sometimes intentional)

package docker.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# =============================================================================
# DENY: RUN --privileged (BuildKit mount syntax)
# =============================================================================
#
# BuildKit allows `RUN --privileged <command>` to run a build step with full
# root access to the host — mounting arbitrary filesystems, loading kernel
# modules, and more. This is occasionally used for cross-compilation or device
# access during builds, but has no place in a production hardened image.
#
# The check iterates over Flags (not Value) because --privileged is a BuildKit
# flag, not an argument to the shell command.
#
# Example Dockerfile line that triggers this:
#   RUN --privileged apt-get install -y some-package
deny contains msg if {
    some cmd in input
    cmd.Cmd == "run"

    # cmd.Flags contains BuildKit flags as strings, e.g. ["--privileged"]
    # or ["--mount=type=cache,target=/root/.cache"].
    some flag in cmd.Flags
    contains(flag, "--privileged")

    msg := "CIS 5.4: RUN instruction uses --privileged. This is not permitted."
}

# =============================================================================
# WARN: EXPOSE of a privileged port (< 1024)
# =============================================================================
#
# Linux restricts binding to ports below 1024 to processes with the
# CAP_NET_BIND_SERVICE capability. If a container EXPOSEs port 80, the runtime
# must grant that capability — preventing --cap-drop=ALL.
#
# The EXPOSE value may include a protocol suffix (e.g. "80/tcp").
# split(..., "/")[0] extracts just the port number before converting to integer.
#
# Approved alternatives: use a port >= 1024 (e.g. 8080) and handle 80→8080
# mapping at the ingress/load balancer layer.
warn contains msg if {
    some cmd in input
    cmd.Cmd == "expose"

    # split(...)[0] handles both "80" and "80/tcp"
    port := to_number(split(cmd.Value[0], "/")[0])
    port < 1024

    msg := sprintf(
        "CIS 5.7: EXPOSE %v uses a privileged port (< 1024). Use a port >= 1024 and handle port mapping at the ingress layer.",
        [cmd.Value[0]],
    )
}

# =============================================================================
# WARN: COPY --chown=root
# =============================================================================
#
# Files copied with --chown=root are owned by root and not writable by a
# non-root application user. In most cases this is a mistake — the developer
# forgot to set the correct owner. In some cases (read-only config files) it
# may be intentional.
#
# The check is case-insensitive (lower()) because --chown=Root and --chown=ROOT
# are semantically equivalent.
warn contains msg if {
    some cmd in input
    cmd.Cmd == "copy"

    some flag in cmd.Flags
    # lower() normalises casing: --chown=Root, --chown=root, --chown=ROOT
    contains(lower(flag), "chown=root")

    msg := "Files COPY'd with --chown=root will not be writable by a non-root USER. Consider --chown=appuser:appgroup."
}
