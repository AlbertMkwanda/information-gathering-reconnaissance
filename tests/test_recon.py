import json
import tempfile
import unittest
from pathlib import Path

from src.recon import build_report, load_evidence


class ReconnaissanceTests(unittest.TestCase):
    def test_report_records_bounded_homepage_observations_without_security_claims(self):
        report = build_report()
        self.assertEqual(report["scope"]["domain"], "kwachahelper.com")
        self.assertEqual(report["observation_count"], 4)
        self.assertEqual(report["finding_count"], 0)
        self.assertIn("8.209.69.209", report["collection_statement"])
        self.assertIn("timed out", report["collection_statement"])
        page = next(item for item in report["observations"] if item["id"] == "HTTP-01")
        self.assertEqual(page["value"]["title"], "KwachaHelper")
        self.assertTrue(page["value"]["embedded_app_frame"])
        head = next(item for item in report["observations"] if item["id"] == "HTTP-02")
        self.assertEqual(head["value"]["status"], "timeout")
        self.assertIn("may change", report["limitations"][0])

    def test_report_does_not_infer_unobserved_mail_or_web_controls(self):
        report = build_report()
        self.assertEqual(report["findings"], [])
        self.assertTrue(
            any("not assessed" in limitation for limitation in report["limitations"])
        )

    def test_loader_refuses_unapproved_domain_and_collection_mode(self):
        source = json.loads(
            Path(__file__).resolve().parents[1].joinpath("data", "public_review_evidence.json")
            .read_text(encoding="utf-8")
        )
        for mutate in (
            lambda data: data["scope"].update(domain="public.example.org"),
            lambda data: data["scope"].update(collection_mode="offline_simulated_evidence"),
        ):
            modified = json.loads(json.dumps(source))
            mutate(modified)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "evidence.json"
                path.write_text(json.dumps(modified), encoding="utf-8")
                with self.subTest(scope=modified["scope"]), self.assertRaises(ValueError):
                    load_evidence(path)

    def test_explicit_dmarc_observation_is_linked_to_finding(self):
        report = build_report()
        report["observations"].append(
            {
                "id": "MAIL-01",
                "category": "mail_policy",
                "source": "Authorized review fixture",
                "observed_at": "2026-11-23",
                "value": {"record_type": "DMARC", "present": False},
            }
        )
        updated = build_report(report)
        finding = next(item for item in updated["findings"] if item["id"] == "RECON-01")
        self.assertIn("MAIL-01", finding["evidence_ids"])

    def test_loader_rejects_malformed_observation_values(self):
        source = json.loads(
            Path(__file__).resolve().parents[1].joinpath("data", "public_review_evidence.json")
            .read_text(encoding="utf-8")
        )
        source["observations"][0]["value"] = "not an evidence object"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(source), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "value must be an object"):
                load_evidence(path)


if __name__ == "__main__":
    unittest.main()
