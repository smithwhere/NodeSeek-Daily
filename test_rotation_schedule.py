import unittest
from nodeseek_daily import password_refresh_due


class RotationScheduleTests(unittest.TestCase):
    def test_initial_login_due(self):
        self.assertTrue(password_refresh_due({}, "2026-11-05"))

    def test_cookie_used_on_ninth_day(self):
        state = {"last_password_login_date": "2026-11-05"}
        self.assertFalse(password_refresh_due(state, "2026-11-14"))

    def test_password_refresh_on_tenth_elapsed_day(self):
        state = {"last_password_login_date": "2026-11-05"}
        self.assertTrue(password_refresh_due(state, "2026-11-15"))

    def test_invalid_date_is_due(self):
        self.assertTrue(password_refresh_due({"last_password_login_date": "bad"}, "2026-11-15"))

    def test_year_boundary(self):
        self.assertTrue(password_refresh_due({"last_password_login_date": "2026-12-28"}, "2027-01-07"))


if __name__ == "__main__":
    unittest.main()
