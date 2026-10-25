import base64
import copy
import hashlib
import io
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from nacl.public import PrivateKey, SealedBox

import nodeseek_daily as app


class MemoryStore:
    def __init__(self, state):
        self.state = copy.deepcopy(state)
        self.sha = "existing"

    def load(self):
        return copy.deepcopy(self.state)

    def save(self, state):
        self.state = copy.deepcopy(state)


class CookieSecretTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {
            "NS_COOKIE_WRITE_TOKEN": "secret-write-token",
            "GITHUB_REPOSITORY": "test/repo", "GITHUB_TOKEN": "contents-token",
            "NS_COOKIE": "", "NS_COMMENT": "false", "NS_FEED": "false",
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.private_key = PrivateKey.generate()
        self.public_key = Mock(status_code=200)
        self.public_key.json.return_value = {
            "key_id": "key-123",
            "key": base64.b64encode(bytes(self.private_key.public_key)).decode(),
        }
        self.store = MemoryStore({"cookies": [
            {"name": "session", "value": "old", "domain": ".nodeseek.com", "path": "/"}
        ]})

    def run_main(self, attendance=True, login=None, put_status=204):
        output = io.StringIO()
        with patch.object(app, "StateStore", return_value=self.store), \
             patch.object(app, "attendance_with_recovery", side_effect=attendance
                          if isinstance(attendance, list) else None,
                          return_value=attendance), \
             patch.object(app, "login", side_effect=login) as login_mock, \
             patch.object(app.requests, "get", return_value=self.public_key) as get, \
             patch.object(app.requests, "put", return_value=Mock(status_code=put_status)) as put, \
             redirect_stdout(output):
            app.main()
        return get, put, login_mock, output.getvalue()

    def decrypt_submission(self, put):
        put.assert_called_once()
        args = put.call_args.kwargs
        self.assertEqual(put.call_args.args[0],
                         "https://api.github.com/repos/test/repo/actions/secrets/NS_COOKIE")
        self.assertEqual(args["headers"]["Authorization"], "Bearer secret-write-token")
        self.assertEqual(args["json"]["key_id"], "key-123")
        self.assertNotIn("session=", args["json"]["encrypted_value"])
        return SealedBox(self.private_key).decrypt(
            base64.b64decode(args["json"]["encrypted_value"])).decode()

    def test_successful_login_encrypts_new_cookie_and_next_run_does_not_reseed(self):
        os.environ["NS_COOKIE"] = "session=old"
        self.store.state["seed_hash"] = hashlib.sha256(b"session=old").hexdigest()

        def login(session):
            session.cookies.set("session", "new=private", domain=".nodeseek.com", path="/")

        get, put, _, output = self.run_main([False, True], login)
        self.assertEqual(self.decrypt_submission(put), "session=new=private")
        self.assertNotIn("new=private", output)
        self.assertEqual(get.call_args.args[0],
                         "https://api.github.com/repos/test/repo/actions/secrets/public-key")
        self.assertEqual(self.store.state["seed_hash"],
                         hashlib.sha256(b"session=new=private").hexdigest())
        os.environ["NS_COOKIE"] = "session=new=private"
        _, put, login_mock, _ = self.run_main()
        self.assertEqual(self.store.state["cookies"][0]["value"], "new=private")
        put.assert_not_called()
        login_mock.assert_not_called()

    def test_existing_verified_session_can_sync_without_paid_login(self):
        _, put, login_mock, _ = self.run_main()
        self.assertEqual(self.decrypt_submission(put), "session=old")
        login_mock.assert_not_called()

    def test_no_write_token_keeps_existing_behavior_without_using_contents_token(self):
        os.environ["NS_COOKIE_WRITE_TOKEN"] = ""
        get, put, _, output = self.run_main()
        get.assert_not_called()
        put.assert_not_called()
        self.assertIn("NS_COOKIE_WRITE_TOKEN", output)
        self.assertNotIn("cookie_secret_hash", self.store.state)

    def test_device_verification_never_exports_unverified_cookie(self):
        with patch.object(app.requests, "put") as put:
            with self.assertRaises(app.LoginVerificationRequired):
                self.run_main([False], lambda _: (_ for _ in ()).throw(
                    app.LoginVerificationRequired("verify")))
        self.assertTrue(self.store.state["needs_device_verification"])
        put.assert_not_called()

    def test_rejected_secret_write_is_reported_and_retried_from_saved_session(self):
        with self.assertRaisesRegex(RuntimeError, "NS_COOKIE.*403"):
            self.run_main(put_status=403)
        self.assertNotIn("cookie_secret_hash", self.store.state)
        _, put, login_mock, _ = self.run_main()
        self.assertEqual(self.decrypt_submission(put), "session=old")
        login_mock.assert_not_called()

    def test_unconfirmed_login_cookie_does_not_replace_secret(self):
        def login(session):
            session.cookies.set("session", "invalid", domain=".nodeseek.com", path="/")
        with patch.object(app.requests, "put") as put:
            with self.assertRaisesRegex(RuntimeError, "Cookie 无效"):
                self.run_main([False, False], login)
        put.assert_not_called()
        self.assertNotIn("cookie_secret_hash", self.store.state)

    def test_serialization_excludes_other_domains_and_paths(self):
        self.store.state["cookies"] += [
            {"name": "private", "value": "elsewhere", "domain": "other.example", "path": "/"},
            {"name": "scoped", "value": "hidden", "domain": ".nodeseek.com", "path": "/settings"},
        ]
        _, put, _, _ = self.run_main(put_status=201)
        self.assertEqual(self.decrypt_submission(put), "session=old")

    def test_public_key_failure_never_submits_secret(self):
        self.public_key.status_code = 403
        with self.assertRaisesRegex(RuntimeError, "公钥.*403"):
            self.run_main()
        self.assertNotIn("cookie_secret_hash", self.store.state)

    def test_missing_secret_is_restored_even_when_cookie_was_previously_synced(self):
        self.run_main()
        _, put, _, _ = self.run_main()
        self.assertEqual(self.decrypt_submission(put), "session=old")

    def test_network_failure_does_not_leak_credentials_or_mark_synced(self):
        with patch.object(app.requests, "get", side_effect=app.requests.ConnectionError(
                "session=old secret-write-token")), \
             patch.object(app, "StateStore", return_value=self.store), \
             patch.object(app, "attendance_with_recovery", return_value=True):
            with self.assertRaises(RuntimeError) as raised:
                app.main()
        self.assertNotIn("session=old", str(raised.exception))
        self.assertNotIn("secret-write-token", str(raised.exception))
        self.assertNotIn("cookie_secret_hash", self.store.state)
