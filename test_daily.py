import base64
import json
import os
import unittest
from unittest.mock import patch, Mock
from cryptography.fernet import Fernet
import nodeseek_daily as app


class Tests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {
            "COOKIE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "GITHUB_TOKEN": "test-token", "GITHUB_REPOSITORY": "test/repo",
            "NS_COMMENT": "false", "NS_COOKIE": "",
        })
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_encrypted_write_and_read(self):
        store = app.StateStore()
        state = {"cookies": [{"name": "session", "value": "private-value"}]}
        put = Mock(status_code=201)
        put.json.return_value = {"content": {"sha": "new-sha"}}
        with patch.object(app.requests, "put", return_value=put) as request:
            store.save(state)
        data = request.call_args.kwargs["json"]
        encrypted = base64.b64decode(data["content"])
        self.assertNotIn(b"private-value", encrypted)
        get = Mock(status_code=200)
        get.json.return_value = {"sha": "new-sha", "content": data["content"]}
        with patch.object(app.requests, "get", return_value=get):
            self.assertEqual(store.load(), state)
        self.assertEqual(store.sha, "new-sha")

    def test_invalid_key_cannot_load(self):
        store = app.StateStore()
        get = Mock(status_code=200)
        get.json.return_value = {"sha": "x", "content": base64.b64encode(
            Fernet(Fernet.generate_key()).encrypt(b"{}")).decode()}
        with patch.object(app.requests, "get", return_value=get):
            with self.assertRaisesRegex(RuntimeError, "密文验证失败"):
                store.load()

    def test_saved_state_has_no_expiry(self):
        store = app.StateStore()
        state = {"cookies": [{"name": "session", "value": "saved"}]}
        encrypted = store.cipher.encrypt_at_time(json.dumps(state).encode(), 946684800)
        response = Mock(status_code=200)
        response.json.return_value = {"sha": "old", "content": base64.b64encode(encrypted).decode()}
        with patch.object(app.requests, "get", return_value=response):
            self.assertEqual(store.load(), state)

    def test_cookie_metadata_expiry_is_not_enforced(self):
        session = app.cookie_session([{"name": "session", "value": "saved", "domain": ".nodeseek.com", "path": "/", "expires": 1}])
        try:
            self.assertEqual(session.cookies.get("session"), "saved")
            self.assertNotIn("expires", app.dump_cookies(session)[0])
        finally:
            session.close()

    def test_failed_write_is_fatal(self):
        store = app.StateStore()
        with patch.object(app.requests, "put", return_value=Mock(status_code=403)):
            with self.assertRaisesRegex(RuntimeError, "写回失败"):
                store.save({"cookies": []})

    def test_valid_cookie_never_logs_in(self):
        store = Mock(sha="existing")
        store.load.return_value = {"cookies": [{"value": "saved-cookie"}]}
        with patch.object(app, "StateStore", return_value=store), \
             patch.object(app, "cookie_session", return_value=Mock()), \
             patch.object(app, "attendance", return_value=True), \
             patch.object(app, "login") as login:
            app.main()
        login.assert_not_called()
        store.save.assert_not_called()

    def test_expired_cookie_writes_then_reloads(self):
        events = []
        store = Mock(sha="existing")
        store.load.side_effect = [
            {"cookies": [{"value": "old"}]},
            {"cookies": [{"value": "new"}]},
        ]
        store.save.side_effect = lambda state: events.append("write")
        def session(cookies, headers=None):
            events.append("cookie:" + (cookies[0]["value"] if cookies else "empty"))
            return Mock(headers={})
        def login(_):
            events.append("login")
        with patch.object(app, "StateStore", return_value=store), \
             patch.object(app, "cookie_session", side_effect=session), \
             patch.object(app, "attendance", side_effect=[False, True]), \
             patch.object(app, "login", side_effect=login), \
             patch.object(app, "dump_cookies", return_value=[{"value": "new"}]):
            app.main()
        self.assertEqual(events, ["cookie:old", "cookie:empty", "login", "write", "cookie:new"])
        self.assertEqual(store.load.call_count, 2)

    def test_challenge_does_not_trigger_paid_login(self):
        response = Mock(status_code=403)
        with self.assertRaisesRegex(RuntimeError, "HTTP 状态"):
            app.attendance(Mock(post=Mock(return_value=response)))

    def test_captcha_poll_retains_task_id(self):
        created = Mock()
        created.json.return_value = {"errorId": 0, "taskId": "task-1"}
        processing = Mock()
        processing.json.return_value = {"errorId": 0, "status": "processing"}
        ready = Mock()
        ready.json.return_value = {"errorId": 0, "status": "ready", "solution": {"token": "ok"}}
        with patch.dict(os.environ, {"YESCAPTCHA_KEY": "test-key"}), \
             patch.object(app.requests, "post", side_effect=[created, processing, ready]) as request, \
             patch.object(app.time, "sleep"):
            self.assertEqual(app.solve_turnstile(), "ok")
        self.assertEqual(request.call_args_list[2].kwargs["json"]["taskId"], "task-1")

    def test_new_device_verification_is_not_login_success(self):
        response = Mock(status_code=200)
        response.json.return_value = {"success": True, "redirect": "/emailSignIn.html"}
        session = Mock()
        session.post.return_value = response
        with patch.dict(os.environ, {"NS_USERNAME": "test", "NS_PASSWORD": "test"}), \
             patch.object(app, "solve_turnstile", return_value="test-token"):
            with self.assertRaisesRegex(RuntimeError, "验证新设备"):
                app.login(session)

    def test_known_device_verification_never_retries_paid_login(self):
        store = Mock(sha="existing")
        store.load.return_value = {"needs_device_verification": True}
        with patch.object(app, "StateStore", return_value=store), \
             patch.object(app, "cookie_session", return_value=Mock()), \
             patch.object(app, "login") as login:
            with self.assertRaisesRegex(RuntimeError, "已跳过付费验证"):
                app.main()
        login.assert_not_called()

    def test_verification_requirement_is_persisted(self):
        store = Mock(sha=None)
        store.load.return_value = {}
        with patch.object(app, "StateStore", return_value=store), \
             patch.object(app, "cookie_session", return_value=Mock()), \
             patch.object(app, "login", side_effect=app.LoginVerificationRequired("verify")):
            with self.assertRaises(app.LoginVerificationRequired):
                app.main()
        self.assertTrue(store.save.call_args.args[0]["needs_device_verification"])

    def test_new_cookie_clears_block_and_is_saved(self):
        store = Mock(sha="existing")
        store.load.return_value = {"needs_device_verification": True}
        with patch.dict(os.environ, {"NS_COOKIE": "session=new-session"}), \
             patch.object(app, "StateStore", return_value=store), \
             patch.object(app, "cookie_session", return_value=Mock()), \
             patch.object(app, "attendance", return_value=True), \
             patch.object(app, "login") as login:
            app.main()
        saved = store.save.call_args.args[0]
        self.assertNotIn("needs_device_verification", saved)
        self.assertEqual(saved["cookies"][0]["value"], "new-session")
        login.assert_not_called()

    def test_already_signed_in_http_400_is_success(self):
        response = Mock(status_code=400)
        response.json.return_value = {"success": False, "message": "今天已签到，请勿重复操作"}
        self.assertTrue(app.attendance(Mock(post=Mock(return_value=response))))


if __name__ == "__main__":
    unittest.main()
