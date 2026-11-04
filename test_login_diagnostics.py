import unittest
from unittest.mock import Mock, patch

import nodeseek_daily as daily


class CookiePreflightTests(unittest.TestCase):
    def test_authenticated_page_preflight_is_read_only(self):
        session = Mock()
        session.get.return_value = Mock(status_code=200)
        self.assertTrue(daily.preflight_session(session))
        session.get.assert_called_once_with(daily.BASE + "/board", timeout=30)
        session.post.assert_not_called()

    def test_unauthorized_preflight_does_not_login(self):
        session = Mock()
        session.get.return_value = Mock(status_code=401)
        self.assertFalse(daily.preflight_session(session))
        session.post.assert_not_called()

    def test_cloudflare_challenge_does_not_invalidate_cookie(self):
        session = Mock()
        session.get.return_value = Mock(
            status_code=403,
            headers={"cf-mitigated": "challenge"},
            text="Just a moment",
        )
        with self.assertRaises(daily.CloudflareChallengeError):
            daily.preflight_session(session)
        session.post.assert_not_called()

    def test_unknown_forbidden_does_not_invalidate_cookie(self):
        session = Mock()
        session.get.return_value = Mock(status_code=403, headers={}, text="Forbidden")
        with self.assertRaisesRegex(RuntimeError, "不能判定 Cookie 失效"):
            daily.preflight_session(session)

    def test_server_error_does_not_trigger_login(self):
        session = Mock()
        session.get.return_value = Mock(status_code=503)
        with self.assertRaisesRegex(RuntimeError, "未尝试重新登录"):
            daily.preflight_session(session)


class LoginDiagnosticsTests(unittest.TestCase):
    def _login_response(self, payload):
        session = Mock()
        session.get.return_value = Mock(status_code=200)
        session.post.return_value = Mock(status_code=200, json=Mock(return_value=payload))
        return session

    @patch.object(daily, "solve_turnstile", return_value="test-token")
    @patch.dict("os.environ", {"NS_USERNAME": "test-user", "NS_PASSWORD": "test-password"})
    def test_email_verification_requires_human(self, _solve):
        session = self._login_response({"success": True, "redirect": "/emailSignIn"})
        with self.assertRaises(daily.LoginVerificationRequired):
            daily.login(session)

    @patch.object(daily, "solve_turnstile", return_value="test-token")
    @patch.dict("os.environ", {"NS_USERNAME": "test-user", "NS_PASSWORD": "test-password"})
    def test_two_factor_requires_human(self, _solve):
        session = self._login_response({"success": False, "need2FA": True})
        with self.assertRaises(daily.LoginVerificationRequired):
            daily.login(session)

    @patch.object(daily, "solve_turnstile", return_value="test-token")
    @patch.dict("os.environ", {"NS_USERNAME": "test-user", "NS_PASSWORD": "test-password"})
    def test_invalid_password_is_not_device_verification(self, _solve):
        session = self._login_response({"success": False, "message": "bad password"})
        with self.assertRaisesRegex(RuntimeError, "拒绝账号密码登录"):
            daily.login(session)


if __name__ == "__main__":
    unittest.main()
