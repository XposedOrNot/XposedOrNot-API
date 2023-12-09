import json
import unittest
from main import XON


class BasicTestCase(unittest.TestCase):
    """
    BasicTestCase contains unit tests for testing the routes in the XON application.
    """

    def setUp(self):
        """
        Set up the test client for XON application before each test case.
        """
        self.app = XON.test_client()

    def tearDown(self):
        """
        Tear down operations after each test case. Currently, it does nothing.
        """
        pass

    def test_index(self):
        """
        Test case for the index route.
        It verifies that the response status code is 200 (OK).
        """
        response = self.app.get("/", follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_metrics(self):
        """
        Test case for the /v1/metrics route.
        It checks the response status code and verifies specific keys in the JSON response.
        """
        response = self.app.get("/v1/metrics/", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        json_data = json.loads(response.data.decode("utf8"))
        self.assertIn("Breaches_Count", json_data)
        self.assertIn("Breaches_Records", json_data)
        self.assertIn("Pastes_Count", json_data)
        self.assertIn("Pastes_Records", json_data)

    def test_check_email(self):
        """
        Test case for the /v1/check-email/<email> route.
        It checks the response status code and verifies specific keys in the JSON response.
        """
        response = self.app.get(
            "/v1/check-email/test@example.com", follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        json_data = json.loads(response.data.decode("utf8"))
        self.assertIn("Exposed_Breaches", json_data)
        self.assertIn("domains", json_data)

    def test_breach_analytics(self):
        """
        Test case for the /v1/breach-analytics/<email> route.
        It checks the response status code and verifies specific keys in the JSON response.
        """
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
