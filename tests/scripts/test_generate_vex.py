from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from vuln_evidence import GateError  # noqa: E402
from generate_vex import (  # noqa: E402
    NON_VEX_ELIGIBLE_CVES,
    VEX_ELIGIBLE,
    generate,
)

ELIGIBLE_CVE = "CVE-2025-69720"


def report(cve: str, package: str = "libncursesw6", purl: str | None = None) -> dict:
    vulnerability = {"VulnerabilityID": cve, "PkgName": package}
    if purl:
        vulnerability["PkgIdentifier"] = {"PURL": purl}
    return {"Results": [{"Vulnerabilities": [vulnerability]}]}


def register(cve: str) -> str:
    return f"<!-- gate: cve={cve} reviewed=2026-08-23 fix-available=none -->\n"


class GenerateVexTests(unittest.TestCase):
    def test_eligible_cve_with_confirmed_absence_produces_one_statement(self):
        doc = generate(
            report_payload=report(ELIGIBLE_CVE),
            register_text=register(ELIGIBLE_CVE),
            image="hardened-python:latest",
            check_absence=lambda paths: True,
        )
        self.assertEqual(1, len(doc["statements"]))
        statement = doc["statements"][0]
        self.assertEqual(ELIGIBLE_CVE, statement["vulnerability"]["name"])
        self.assertEqual("not_affected", statement["status"])
        self.assertEqual(
            VEX_ELIGIBLE[ELIGIBLE_CVE].justification, statement["justification"]
        )

    def test_product_id_is_the_exact_reported_purl(self):
        purl = "pkg:deb/debian/libncursesw6@6.5%2B20250216-2?arch=amd64&distro=debian-13.6"
        doc = generate(
            report_payload=report(ELIGIBLE_CVE, purl=purl),
            register_text=register(ELIGIBLE_CVE),
            image="hardened-python:latest",
            check_absence=lambda paths: True,
        )
        products = doc["statements"][0]["products"]
        self.assertEqual([{"@id": purl}], products)

    def test_eligible_cve_missing_from_register_fails_closed(self):
        with self.assertRaisesRegex(GateError, "missing.*register"):
            generate(
                report_payload=report(ELIGIBLE_CVE),
                register_text="",
                image="hardened-python:latest",
                check_absence=lambda paths: True,
            )

    def test_absence_check_failure_fails_closed_and_emits_nothing(self):
        with self.assertRaisesRegex(GateError, "absence check failed"):
            generate(
                report_payload=report(ELIGIBLE_CVE),
                register_text=register(ELIGIBLE_CVE),
                image="hardened-python:latest",
                check_absence=lambda paths: False,
            )

    def test_cve_not_in_this_images_report_is_skipped(self):
        doc = generate(
            report_payload=report("CVE-2099-00001", package="unrelated"),
            register_text=register(ELIGIBLE_CVE),
            image="hardened-node:latest",
            check_absence=lambda paths: True,
        )
        self.assertEqual([], doc["statements"])

    def test_stdlib_parser_cves_are_never_eligible(self):
        for cve in NON_VEX_ELIGIBLE_CVES:
            self.assertNotIn(cve, VEX_ELIGIBLE)


if __name__ == "__main__":
    unittest.main()
