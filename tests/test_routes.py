import unittest
from base_test import BaseTestCase
from flask_login import current_user

class TestPublic(BaseTestCase):
    def test_main_requires_login(self):
        response = self.client.get("/", follow_redirects=True)
        self.assertTrue(response.status_code == 200)
        self.assertIn(b"Please log in to access this page", response.data)

    def test_logout_route_requires_login(self):
        response = self.client.get("/logout", follow_redirects=True)
        self.assertIn(b"Please log in to access this page", response.data)

class TestLoggingInOut(BaseTestCase):
    def test_correct_login(self):
        with self.client:
            response = self.client.post("/login", data=dict(email="ad@min.com", password="admin_user"), follow_redirects=True,)
            self.assertTrue(current_user.email == "ad@min.com")
            self.assertTrue(current_user.is_active)
            self.assertTrue(response.status_code == 200)

    def test_logout_behaves_correctly(self):
        with self.client:
            self.client.post("/login", data=dict(email="ad@min.com", password="admin_user"), follow_redirects=True,)
            response = self.client.get("/logout", follow_redirects=True)
            self.assertIn(b"You were logged out", response.data)
            self.assertFalse(current_user.is_active)

if __name__ == "__main__":
    unittest.main()
