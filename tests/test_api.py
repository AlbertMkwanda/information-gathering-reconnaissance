import unittest

from src.web import create_app


class ReconnaissanceApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app({"TESTING": True}).test_client()

    def test_home_and_api_explain_bounded_homepage_review(self):
        home = self.client.get("/")
        self.assertEqual(home.status_code, 200)
        self.assertIn(b"kwachahelper.com", home.data)
        self.assertIn(b"8.209.69.209", home.data)
        report = self.client.get("/api/report")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.json["finding_count"], 0)

    def test_health_identifies_recorded_report_mode(self):
        self.assertEqual(
            self.client.get("/health").json,
            {"status": "ok", "mode": "recorded-metadata-report"},
        )

    def test_stylesheet_is_served_as_css(self):
        response = self.client.get("/static/site.css")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.content_type.startswith("text/css"))
        response.close()


if __name__ == "__main__":
    unittest.main()
