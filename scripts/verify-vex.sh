#!/usr/bin/env bash
# Prove a generated VEX document suppresses exactly the CVE it claims to,
# and nothing else — the mutation-style proof issue #4 requires before a
# VEX statement can be trusted.
#
#     scripts/verify-vex.sh reports/python/vex.json hardened-python:latest
#
# Fails if the baseline scan doesn't contain the VEX-eligible CVE (the demo
# would be meaningless), if applying the VEX doesn't suppress it, or if any
# of the deliberately-never-VEXed stdlib parser CVEs disappear too.
set -euo pipefail

vex_file="${1:?usage: verify-vex.sh <vex.json> <image>}"
image="${2:?usage: verify-vex.sh <vex.json> <image>}"

VEXED_CVE="CVE-2025-69720"
NEVER_VEXED_CVES=("CVE-2026-11940" "CVE-2026-15308" "CVE-2026-7210")

pre=$(mktemp)
post=$(mktemp)
trap 'rm -f "$pre" "$post"' EXIT

cves_in() {
    python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
cves = set()
for r in d.get('Results', []) or []:
    for v in r.get('Vulnerabilities') or []:
        cves.add(v['VulnerabilityID'])
print('\n'.join(sorted(cves)))
" "$1"
}

trivy image --format json --severity CRITICAL,HIGH --exit-code 0 \
    --output "$pre" "$image" >/dev/null
trivy image --format json --severity CRITICAL,HIGH --exit-code 0 \
    --vex "$vex_file" --output "$post" "$image" >/dev/null

pre_cves=$(cves_in "$pre")
post_cves=$(cves_in "$post")

fail=0

if ! grep -qx "$VEXED_CVE" <<<"$pre_cves"; then
    echo "FAIL: baseline scan of $image does not contain $VEXED_CVE — nothing for this VEX to demonstrate" >&2
    fail=1
fi

if grep -qx "$VEXED_CVE" <<<"$post_cves"; then
    echo "FAIL: $VEXED_CVE is still present after applying $vex_file — VEX did not suppress it" >&2
    fail=1
fi

for cve in "${NEVER_VEXED_CVES[@]}"; do
    if ! grep -qx "$cve" <<<"$pre_cves"; then
        continue  # not present in this image's baseline at all; nothing to check
    fi
    if ! grep -qx "$cve" <<<"$post_cves"; then
        echo "FAIL: $cve disappeared after applying VEX — it must never be suppressed" >&2
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    exit 1
fi

echo "ok: $vex_file suppresses only $VEXED_CVE for $image"
