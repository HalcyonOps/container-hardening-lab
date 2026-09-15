#!/usr/bin/env bash
# Assert that none of the given paths exist in an image, from outside it.
#
#     scripts/check-absence.sh hardened-python:latest /usr/bin/infocmp /usr/bin/tic
#
# Exit 0 and print nothing if none of the paths are present. Exit 1 and list
# which paths ARE present otherwise.
#
# Generalizes the docker-export technique from check-suid.sh: distroless
# images ship no shell, so a VEX statement that claims "this binary is absent"
# has to be checked by reading the flattened filesystem from the host rather
# than execing into the image.
set -uo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: check-absence.sh <image> <path> [<path>...]" >&2
    exit 1
fi

image="$1"
shift

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

manifest=$(docker export "$cid" 2>/dev/null | tar -tv 2>/dev/null)

present=()
for path in "$@"; do
    # tar -tv fields are: perms owner/group size date time name[...]. The
    # name itself may contain spaces and, for symlinks/hardlinks, a trailing
    # " -> target" or " link to target" that isn't part of the path — strip
    # that before comparing. Entries are relative (no leading slash).
    relative="${path#/}"
    if printf '%s\n' "$manifest" | awk -v p="$relative" '
        {
            name = ""
            for (i = 6; i <= NF; i++) name = name (i > 6 ? " " : "") $i
            sub(/ -> .*$/, "", name)
            sub(/ link to .*$/, "", name)
            sub(/\/$/, "", name)
            if (name == p) found = 1
        }
        END { exit !found }'; then
        present+=("$path")
    fi
done

if [ "${#present[@]}" -gt 0 ]; then
    echo "FAIL: paths present in $image:" >&2
    for path in "${present[@]}"; do
        echo "  $path" >&2
    done
    exit 1
fi

echo "ok: none of the given paths are present in $image"
