import json
import unittest
from main import XON


class BasicTestCase(unittest.TestCase):
    def setUp(self):
        self.app = XON.test_client()

    def tearDown(self):
        pass

    # Test case for the index route
    def test_index(self):
        response = self.app.get("/", follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    # Test case for the /v1/metrics route
    def test_metrics(self):
        response = self.app.get("/v1/metrics/", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        json_data = json.loads(response.data.decode("utf8"))
        self.assertIn("Breaches_Count", json_data)
        self.assertIn("Breaches_Records", json_data)
        self.assertIn("Pastes_Count", json_data)
        self.assertIn("Pastes_Records", json_data)

    # Test case for the /v1/check-email/<email> route
    def test_check_email(self):
        response = self.app.get(
            "/v1/check-email/test@example.com", follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        json_data = json.loads(response.data.decode("utf8"))
        self.assertIn("Exposed_Breaches", json_data)
        self.assertIn("domains", json_data)

    # Test case for the /v1/breach-analytics/<email> route
    def test_breach_analytics(self):
        response = self.app.get(
            "/v1/breach-analytics/test@example.com", follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        json_data = json.loads(response.data.decode("utf8"))
        self.assertIn("ExposedBreaches", json_data)
        self.assertIn("BreachesSummary", json_data)
        self.assertIn("BreachMetrics", json_data)
        self.assertIn("PastesSummary", json_data)
        self.assertIn("ExposedPastes", json_data)
        self.assertIn("PasteMetrics", json_data)


if __name__ == "__main__":
    unittest.main()
