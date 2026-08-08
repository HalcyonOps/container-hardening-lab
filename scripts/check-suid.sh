#!/usr/bin/env bash
# Assert an image contains no SUID/SGID binaries (CIS 4.8), from outside it.
#
#     scripts/check-suid.sh hardened-python:latest
#
# Exit 1 if any are found, listing them.
#
# Why this isn't a container-structure-test commandTest: it used to be. The
# test ran `sh -c 'find / -xdev -perm /4000 | wc -l'` inside the image. That
# works on a Debian base and is impossible on distroless, which ships no shell,
# no find, and no coreutils. The options were to delete the test, or to keep
# the assertion and move it somewhere that doesn't need a shell.
#
# Deleting it would have left the repo claiming a CIS control it had stopped
# verifying, which is the failure this lab exists to demonstrate. So the check
# reads the image's filesystem from the host instead: `docker export` streams
# the flattened container as a tar, and tar records the permission bits, so the
# setuid and setgid flags are readable without executing anything in the image.
#
# A side benefit: this now works on any image, including ones that could never
# run the old test, and it can't be fooled by a tampered `find` binary.
set -uo pipefail

image="${1:?usage: check-suid.sh <image>}"

if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "ERROR: image not found locally: $image" >&2
    echo "       build it first (make build IMAGE=<name>)" >&2
    exit 1
fi

cid=$(docker create "$image" 2>/dev/null) || {
    echo "ERROR: could not create a container from $image" >&2
    exit 1
}
trap 'docker rm -f "$cid" >/dev/null 2>&1' EXIT

# tar's mode string is like -rwsr-xr-x: position 4 is the owner execute bit
# (s/S when setuid), position 7 the group execute bit (s/S when setgid).
# Only regular files can carry a meaningful setuid bit, hence the leading "-";
# directories commonly and legitimately carry setgid.
hits=$(docker export "$cid" 2>/dev/null | tar -tv 2>/dev/null | awk '
    {
        mode = $1
        if (substr(mode, 1, 1) != "-") next
        u = substr(mode, 4, 1)
        g = substr(mode, 7, 1)
        if (u == "s" || u == "S" || g == "s" || g == "S")
            print "  " mode "  " $NF
    }')

if [ -n "$hits" ]; then
    echo "FAIL: SUID/SGID binaries present in $image (CIS 4.8)"
    echo "$hits"
    exit 1
fi

echo "ok: no SUID/SGID binaries in $image"
