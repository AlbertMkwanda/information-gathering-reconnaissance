"""Report generation for a bounded, recorded public-metadata review."""

import json
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATH = ROOT / "data" / "public_review_evidence.json"
RISK_ORDER = {"high": 0, "medium": 1, "low": 2, "informational": 3}
EXPECTED_CATEGORIES = {
    "dns_record",
    "mail_policy",
    "https_header",
    "public_page",
    "http_reachability",
}


def load_evidence(path: Path = EVIDENCE_PATH) -> dict[str, Any]:
    """Load pre-recorded evidence for an approved coursework scope."""
    with path.open(encoding="utf-8") as evidence_file:
        evidence = json.load(evidence_file)
    return _validate_loaded_evidence(evidence)


def _findings(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    observations = evidence["observations"]
    findings: list[dict[str, Any]] = []
    dmarc_absent = any(
        item["category"] == "mail_policy"
        and item["value"].get("record_type") == "DMARC"
        and item["value"].get("present") is False
        for item in observations
    )
    if dmarc_absent:
        findings.append(
            {
                "id": "RECON-01",
                "title": "DMARC policy was not present in the supplied DNS evidence",
                "severity": "medium",
                "confidence": "medium",
                "evidence_ids": [
                    item["id"]
                    for item in observations
                    if item["category"] == "mail_policy"
                    and item["value"].get("record_type") == "DMARC"
                ],
                "observation": "The supplied evidence explicitly records a DMARC policy as absent.",
                "recommendation": (
                    "If the domain sends email, inventory legitimate senders and introduce "
                    "a monitored DMARC policy before considering a stricter enforcement mode."
                ),
                "scope_note": "This finding is limited to the evidence supplied for the review.",
            }
        )

    for observation in observations:
        value = observation["value"]
        if observation["category"] == "https_header":
            header = value.get("name", "").lower()
            if value.get("present") is False and header == "strict-transport-security":
                findings.append(
                    {
                        "id": "RECON-02",
                        "title": "HSTS was not present in the supplied HTTPS response snapshot",
                        "severity": "low",
                        "confidence": "medium",
                        "evidence_ids": [observation["id"]],
                        "observation": "The synthetic HTTPS header snapshot marks HSTS as absent.",
                        "recommendation": (
                            "After confirming HTTPS is correctly deployed for all relevant hosts, "
                            "consider a carefully staged Strict-Transport-Security policy."
                        ),
                        "scope_note": "A single simulated response snapshot cannot establish deployment-wide behavior.",
                    }
                )
            elif observation["category"] == "https_header" and header == "server":
                banner = str(value.get("value", ""))
                if banner:
                    findings.append(
                        {
                            "id": "RECON-03",
                            "title": "The response snapshot discloses a server banner",
                            "severity": "low",
                            "confidence": "high",
                            "evidence_ids": [observation["id"]],
                            "observation": f"The simulated response includes the banner {banner!r}.",
                            "recommendation": (
                                "Review whether the reverse proxy or web server can suppress "
                                "unnecessary product and version details."
                            ),
                            "scope_note": "Banner disclosure alone does not demonstrate a vulnerability.",
                        }
                    )

    findings.sort(key=lambda finding: (RISK_ORDER[finding["severity"]], finding["id"]))
    return findings


def build_report(evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build findings and counts from validated, locally stored observations."""
    evidence = evidence if evidence is not None else load_evidence()
    if evidence is not None:
        evidence = _validate_loaded_evidence(evidence)
    findings = _findings(evidence)
    if evidence["scope"]["collection_mode"] == "recorded_public_metadata_review":
        collection_statement = (
            "A bounded public-metadata review was authorized. A lookups through the system "
            "resolver, Cloudflare DNS (1.1.1.1), and Google Public DNS (8.8.8.8) returned "
            "8.209.69.209; AAAA lookups returned a negative SOA response with no AAAA answer. "
            "An HTTPS GET returned the homepage HTML, while a separate HEAD request timed out "
            "before returning headers. No linked app frame, other route, login, scan, or "
            "vulnerability test was accessed. Running this report does not contact the target."
        )
    else:
        collection_statement = (
            "This is a fictional, offline lab exercise. No live target was contacted; no domain resolution, HTTP request, "
            "port scan, account access, or interaction with a public target was performed."
        )
    return {
        "project": "Information Gathering and Reconnaissance",
        "scope": evidence["scope"],
        "collection_statement": collection_statement,
        "observation_count": len(evidence["observations"]),
        "finding_count": len(findings),
        "severity_summary": {
            severity: sum(finding["severity"] == severity for finding in findings)
            for severity in ("high", "medium", "low", "informational")
        },
        "observations": evidence["observations"],
        "findings": findings,
        "limitations": [
            "DNS answers describe the review date only; the address may change and does not establish who operates the service.",
            "Only the homepage HTML was retrieved. The embedded app frame was not followed, and the timed-out HEAD request yielded no response headers.",
            "MX/TXT records, application routes, authentication, and security controls were not assessed; no vulnerability conclusions are made.",
        ],
    }


def _validate_loaded_evidence(evidence: Any) -> dict[str, Any]:
    """Apply the same approved-scope and shape checks to caller-provided evidence."""
    if not isinstance(evidence, dict) or not isinstance(evidence.get("scope"), dict):
        raise ValueError("Evidence must declare its lab scope.")
    scope = evidence["scope"]
    domain = scope.get("domain")
    mode = scope.get("collection_mode")
    approved_scope = (
        domain == "kwachahelper.com" and mode == "recorded_public_metadata_review"
    ) or (
        isinstance(domain, str)
        and domain.endswith(".test")
        and mode == "offline_simulated_evidence"
    )
    if not approved_scope:
        raise ValueError("Evidence must match an approved coursework domain and collection mode.")
    observations = evidence.get("observations")
    if not isinstance(observations, list) or not observations:
        raise ValueError("Evidence must contain observations.")
    identifiers = set()
    for observation in observations:
        if not isinstance(observation, dict) or not {
            "id", "category", "source", "observed_at", "value"
        }.issubset(observation):
            raise ValueError("Each observation needs an id, category, source, date, and value.")
        if not isinstance(observation["id"], str) or not observation["id"]:
            raise ValueError("Observation ids must be non-empty strings.")
        if observation["category"] not in EXPECTED_CATEGORIES:
            raise ValueError(f"Unsupported evidence category: {observation['category']}.")
        if observation["id"] in identifiers:
            raise ValueError(f"Duplicate observation id: {observation['id']}.")
        identifiers.add(observation["id"])
        if not isinstance(observation["source"], str) or not observation["source"]:
            raise ValueError(f"Observation {observation['id']} needs a source description.")
        if not isinstance(observation["value"], dict):
            raise ValueError(f"Observation {observation['id']} value must be an object.")
        if not isinstance(observation["observed_at"], str):
            raise ValueError(f"Observation {observation['id']} needs an ISO date.")
        try:
            date.fromisoformat(observation["observed_at"])
        except ValueError as error:
            raise ValueError(f"Observation {observation['id']} needs an ISO date.") from error
    return evidence
