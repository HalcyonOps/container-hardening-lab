#!/usr/bin/env python3
"""Generate an OpenVEX document for image facts only.

Implements runbook decisions 0011/0016 and container-hardening-lab issue #4:
a finding is VEX-eligible only when "not affected" is true of the artifact
itself, for every consumer — never when it's merely true of this repo's
reference application. See docs/known-findings.md for the reasoning behind
each entry below.

    scripts/generate_vex.py \
        --register docs/known-findings.md \
        --trivy-report reports/python/trivy.json \
        --image hardened-python:latest \
        --output reports/python/vex.json

Fails closed: a CVE present in the scan but missing from the register, or
whose absence evidence can no longer be confirmed, aborts the whole run
rather than silently emitting a document without it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from vuln_evidence import GateError, parse_register, parse_report

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECK_ABSENCE_SCRIPT = REPO_ROOT / "scripts" / "check-absence.sh"

VEX_DOCUMENT_AUTHOR = "HalcyonOps/container-hardening-lab"
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"


@dataclass(frozen=True)
class VexEligible:
    justification: str
    statement: str
    absence_paths: tuple[str, ...]


# The only CVEs this generator will ever emit a statement for. Adding one
# here is a reviewable, deliberate diff — nothing outside this dict is
# reachable, by construction. See docs/known-findings.md for why each of
# these three stdlib parser CVEs must NEVER appear here: "not in the execute
# path" is true only of this reference app, not of anything built on this
# image that parses untrusted input.
NON_VEX_ELIGIBLE_CVES = ("CVE-2026-11940", "CVE-2026-15308", "CVE-2026-7210")

VEX_ELIGIBLE: dict[str, VexEligible] = {
    "CVE-2025-69720": VexEligible(
        justification="component_not_present",
        statement=(
            "The defect is in progs/infocmp.c (the infocmp program). "
            "infocmp, tic, and tput are not present in this image. "
            "See docs/known-findings.md."
        ),
        absence_paths=("/usr/bin/infocmp", "/usr/bin/tic", "/usr/bin/tput"),
    ),
}


def _purls_for_cve(report_payload: Any, cve: str) -> list[str]:
    """Exact package PURLs Trivy reported for this CVE.

    Trivy's --vex filtering matches a statement's products against the PURL
    it found during the scan, not a synthesized one — using anything less
    exact (e.g. a bare pkg:deb/<name> with no version/arch/distro) silently
    fails to suppress the finding.
    """
    purls: list[str] = []
    for result in report_payload.get("Results", []):
        for vulnerability in result.get("Vulnerabilities") or []:
            if vulnerability.get("VulnerabilityID") != cve:
                continue
            purl = (vulnerability.get("PkgIdentifier") or {}).get("PURL")
            if isinstance(purl, str) and purl not in purls:
                purls.append(purl)
    return purls


def generate(
    *,
    report_payload: Any,
    register_text: str,
    image: str,
    check_absence: Callable[[tuple[str, ...]], bool],
    timestamp: dt.datetime | None = None,
) -> dict[str, Any]:
    """Build an OpenVEX document for `image` from already-loaded evidence.

    `check_absence` takes a tuple of paths and returns True only if none of
    them are present in the image. Kept injectable so this stays testable
    without Docker.
    """
    findings = parse_report(report_payload)
    register = parse_register(register_text)

    statements: list[dict[str, Any]] = []
    for cve, eligible in VEX_ELIGIBLE.items():
        finding = findings.get(cve)
        if finding is None:
            continue  # this image doesn't have the finding; nothing to say

        if cve not in register:
            raise GateError(
                f"{cve}: VEX-eligible but missing from the known-findings register"
            )

        if not check_absence(eligible.absence_paths):
            raise GateError(
                f"{cve}: absence check failed for {image} — "
                "the paths this VEX statement depends on being absent "
                "were found, or could not be checked"
            )

        purls = _purls_for_cve(report_payload, cve)
        products = [{"@id": purl} for purl in purls] or [{"@id": image}]
        statements.append(
            {
                "vulnerability": {"name": cve},
                "products": products,
                "status": "not_affected",
                "justification": eligible.justification,
                "impact_statement": eligible.statement,
            }
        )

    ts = (timestamp or dt.datetime.now(dt.UTC)).isoformat()
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"https://github.com/{VEX_DOCUMENT_AUTHOR}/vex/{image}",
        "author": VEX_DOCUMENT_AUTHOR,
        "timestamp": ts,
        "version": 1,
        "statements": statements,
    }


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"could not load {path}: {exc}") from exc


def check_absence_via_docker(image: str, paths: tuple[str, ...]) -> bool:
    result = subprocess.run(
        [str(CHECK_ABSENCE_SCRIPT), image, *paths],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trivy-report", required=True, type=Path)
    parser.add_argument("--register", required=True, type=Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report_payload = load_json(args.trivy_report)
        register_text = args.register.read_text()
        doc = generate(
            report_payload=report_payload,
            register_text=register_text,
            image=args.image,
            check_absence=lambda paths: check_absence_via_docker(args.image, paths),
        )
    except (GateError, OSError) as exc:
        print(f"VEX generation failed closed: {exc}", file=sys.stderr)
        return 1

    args.output.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"Wrote {len(doc['statements'])} VEX statement(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
