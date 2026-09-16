from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from vuln_evidence import (  # noqa: E402
    GateError,
    fetch_epss,
    fetch_json,
    parse_epss,
    parse_kev,
)


class ParseKevTests(unittest.TestCase):
    def test_valid_feed(self):
        kev = parse_kev({"vulnerabilities": [{"cveID": "CVE-2020-0001"}]})
        self.assertEqual({"CVE-2020-0001"}, kev)

    def test_missing_vulnerabilities_key_fails_closed(self):
        with self.assertRaisesRegex(GateError, "CISA KEV feed"):
            parse_kev({})

    def test_empty_vulnerabilities_list_fails_closed(self):
        with self.assertRaisesRegex(GateError, "CISA KEV feed is empty"):
            parse_kev({"vulnerabilities": []})

    def test_invalid_entry_fails_closed(self):
        with self.assertRaisesRegex(GateError, "invalid vulnerability"):
            parse_kev({"vulnerabilities": [{"cveID": 123}]})


class ParseEpssTests(unittest.TestCase):
    def test_valid_feed(self):
        scores = parse_epss(
            {"data": [{"cve": "CVE-2020-0001", "epss": "0.5"}]},
            {"CVE-2020-0001"},
        )
        self.assertEqual({"CVE-2020-0001": 0.5}, scores)

    def test_missing_data_key_fails_closed(self):
        with self.assertRaisesRegex(GateError, "EPSS feed is missing"):
            parse_epss({}, set())

    def test_missing_expected_cve_fails_closed(self):
        with self.assertRaisesRegex(GateError, "EPSS feed is missing"):
            parse_epss({"data": []}, {"CVE-2020-0001"})

    def test_out_of_range_score_fails_closed(self):
        with self.assertRaisesRegex(GateError, "outside 0..1"):
            parse_epss(
                {"data": [{"cve": "CVE-2020-0001", "epss": "1.5"}]},
                {"CVE-2020-0001"},
            )

    def test_invalid_score_fails_closed(self):
        with self.assertRaisesRegex(GateError, "missing or invalid"):
            parse_epss(
                {"data": [{"cve": "CVE-2020-0001", "epss": "not-a-number"}]},
                {"CVE-2020-0001"},
            )


class FetchJsonTests(unittest.TestCase):
    def test_network_failure_fails_closed(self):
        with patch("vuln_evidence.urlopen", side_effect=OSError("boom")):
            with self.assertRaisesRegex(GateError, "could not load required feed"):
                fetch_json("https://example.invalid/feed")


class FetchEpssTests(unittest.TestCase):
    def test_empty_cve_set_short_circuits(self):
        self.assertEqual({"data": []}, fetch_epss(set()))

    def test_batches_over_one_hundred_cves(self):
        cves = {f"CVE-2020-{i:04d}" for i in range(150)}
        calls: list[str] = []

        def fake_fetch(url: str):
            calls.append(url)
            return {"data": []}

        with patch("vuln_evidence.fetch_json", side_effect=fake_fetch):
            fetch_epss(cves)
        self.assertEqual(2, len(calls))


if __name__ == "__main__":
    unittest.main()
