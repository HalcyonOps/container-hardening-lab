#!/usr/bin/env python3
"""Shared KEV/EPSS/register evidence parsing for the vulnerability gate,
the VEX generator, and the visibility report.

Extracted from vulnerability_gate.py so the three scripts that all need the
same evidence (what did Trivy find, what does the register say, is a CVE in
KEV, what's its EPSS score) share one parser each instead of three that can
drift apart.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss"
REQUEST_TIMEOUT_SECONDS = 30
USER_AGENT = "container-hardening-lab-vulnerability-gate/1"

REGISTER_RE = re.compile(
    r"<!-- gate: cve=(CVE-\d{4}-\d{4,}) "
    r"reviewed=(\d{4}-\d{2}-\d{2}) "
    r"fix-available=(none|\d{4}-\d{2}-\d{2}) -->"
)


class GateError(Exception):
    """The gate could not obtain or validate required evidence."""


@dataclass
class Finding:
    cve: str
    packages: set[str] = field(default_factory=set)
    fixed_version_reported: bool = False


@dataclass(frozen=True)
class RegisterEntry:
    reviewed: dt.date
    fix_available: dt.date | None


def parse_date(value: str, field_name: str, cve: str) -> dt.date:
    try:
        return dt.date.fromisoformat(value)
    except ValueError as exc:
        raise GateError(f"{cve}: invalid {field_name} date {value!r}") from exc


def parse_report(payload: Any) -> dict[str, Finding]:
    if not isinstance(payload, dict) or not isinstance(payload.get("Results"), list):
        raise GateError("Trivy report is missing a Results list")

    findings: dict[str, Finding] = {}
    for result in payload["Results"]:
        if not isinstance(result, dict):
            raise GateError("Trivy report contains an invalid result")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise GateError("Trivy result contains an invalid Vulnerabilities value")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise GateError("Trivy report contains an invalid vulnerability")
            cve = vulnerability.get("VulnerabilityID")
            package = vulnerability.get("PkgName")
            if not isinstance(cve, str) or not cve.startswith("CVE-"):
                raise GateError("Trivy vulnerability is missing a CVE identifier")
            if not isinstance(package, str) or not package:
                raise GateError(f"{cve}: Trivy vulnerability is missing a package name")
            finding = findings.setdefault(cve, Finding(cve=cve))
            finding.packages.add(package)
            if vulnerability.get("FixedVersion"):
                finding.fixed_version_reported = True
    return findings


def parse_register(text: str) -> dict[str, RegisterEntry]:
    entries: dict[str, RegisterEntry] = {}
    for line in text.splitlines():
        if "<!-- gate:" not in line:
            continue
        match = REGISTER_RE.fullmatch(line.strip())
        if not match:
            raise GateError(f"invalid gate metadata: {line.strip()}")
        cve, reviewed_text, fix_text = match.groups()
        if cve in entries:
            raise GateError(f"{cve}: duplicate gate metadata")
        reviewed = parse_date(reviewed_text, "reviewed", cve)
        fix_available = (
            None if fix_text == "none" else parse_date(fix_text, "fix-available", cve)
        )
        entries[cve] = RegisterEntry(
            reviewed=reviewed,
            fix_available=fix_available,
        )
    return entries


def parse_kev(payload: Any) -> dict[str, dt.date]:
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise GateError("CISA KEV feed is missing a vulnerabilities list")
    if not payload["vulnerabilities"]:
        raise GateError("CISA KEV feed is empty")

    kev: dict[str, dt.date] = {}
    for item in payload["vulnerabilities"]:
        if not isinstance(item, dict) or not isinstance(item.get("cveID"), str):
            raise GateError("CISA KEV feed contains an invalid vulnerability")
        cve = item["cveID"]
        date_added = item.get("dateAdded")
        if not isinstance(date_added, str):
            raise GateError(f"CISA KEV feed entry for {cve} is missing dateAdded")
        kev[cve] = parse_date(date_added, "dateAdded", cve)
    return kev


def parse_epss(payload: Any, expected_cves: set[str]) -> dict[str, float]:
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise GateError("EPSS feed is missing a data list")

    scores: dict[str, float] = {}
    for item in payload["data"]:
        if not isinstance(item, dict):
            raise GateError("EPSS feed contains an invalid record")
        cve = item.get("cve")
        value = item.get("epss")
        if not isinstance(cve, str):
            raise GateError("EPSS record is missing a CVE identifier")
        try:
            score = float(value)
        except (TypeError, ValueError) as exc:
            raise GateError(f"{cve}: EPSS score is missing or invalid") from exc
        if not 0 <= score <= 1:
            raise GateError(f"{cve}: EPSS score is outside 0..1")
        scores[cve] = score

    missing = expected_cves - scores.keys()
    if missing:
        raise GateError(f"EPSS feed is missing: {', '.join(sorted(missing))}")
    return scores


def fetch_json(url: str) -> Any:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return json.load(response)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise GateError(f"could not load required feed {url}: {exc}") from exc


def fetch_epss(cves: set[str]) -> dict[str, Any]:
    if not cves:
        return {"data": []}

    records: list[Any] = []
    ordered = sorted(cves)
    for start in range(0, len(ordered), 100):
        query = urlencode({"cve": ",".join(ordered[start : start + 100])})
        payload = fetch_json(f"{EPSS_URL}?{query}")
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise GateError("EPSS feed is missing a data list")
        records.extend(payload["data"])
    return {"data": records}
