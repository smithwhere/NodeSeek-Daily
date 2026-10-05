import base64
import copy
import html
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
        for status in (400, 500):
            with self.subTest(status=status):
                response = Mock(status_code=status)
                response.json.return_value = {"success": False, "message": "今天已完成签到，请勿重复操作"}
                self.assertTrue(app.attendance(Mock(post=Mock(return_value=response))))

    def test_pending_comment_is_not_submitted_again(self):
        store = Mock(sha="existing")
        today = app.datetime.now(app.ZoneInfo("Asia/Shanghai")).date().isoformat()
        store.load.return_value = {"cookies": [{"value": "saved"}], "comment_pending_date": today}
        with patch.dict(os.environ, {"NS_COMMENT": "true"}), \
             patch.object(app, "StateStore", return_value=store), \
             patch.object(app, "cookie_session", return_value=Mock()), \
             patch.object(app, "attendance", return_value=True), \
             patch.object(app, "random_comment") as post:
            with self.assertRaisesRegex(RuntimeError, "避免重复发送"):
                app.main()
        post.assert_not_called()


class HomepageCommentsTests(unittest.TestCase):
    TODAY = "2026-10-05"
    TEXTS = ["第一条。", "第二条！", "第三条？", "第四条。", "第五条。"]

    def setUp(self):
        self.env = patch.dict(os.environ, {
            "NS_USERNAME": "tester", "NS_COMMENT_TEXTS": json.dumps(self.TEXTS),
        })
        self.env.start()
        self.shuffle = patch.object(app.random, "shuffle")
        self.shuffle_mock = self.shuffle.start()
        self.sleep = patch.object(app.time, "sleep")
        self.sleep_mock = self.sleep.start()
        self.snapshots = []
        self.store = Mock()
        self.store.save.side_effect = lambda state: self.snapshots.append(copy.deepcopy(state))

    def tearDown(self):
        self.sleep.stop()
        self.shuffle.stop()
        self.env.stop()

    def session(self, ids, unavailable=(), own=(), fail_at=None, unknown_at=None,
                unconfirmed_at=None, extra=""):
        session = Mock()
        posted = {}
        listing = extra + "".join(
            f'<li class="post-list-item"><div class="post-title">'
            f'<a href="/post-{post_id}-1">帖子 {post_id}</a></div></li>'
            for post_id in ids)

        def get(url, **kwargs):
            if url == app.BASE + "/":
                return Mock(status_code=200, text=listing)
            post_id = int(app.re.search(r"/post-(\d+)-", url).group(1))
            body = '<div id="editor"></div>' if post_id not in unavailable else ""
            if post_id in own:
                body += '<div class="content-item"><span class="author-name">tester</span></div>'
            if post_id in posted and post_id != unconfirmed_at:
                body += ('<div class="content-item"><span class="author-name">tester</span>'
                         f'<article>{html.escape(posted[post_id])}</article></div>')
            return Mock(status_code=200, text=body)

        def post(url, **kwargs):
            self.assertEqual(url, app.BASE + "/api/content/new-comment")
            post_id = kwargs["json"]["postId"]
            response = Mock(status_code=200)
            if post_id == fail_at:
                response.json.return_value = {"success": False}
                return response
            posted[post_id] = kwargs["json"]["content"]
            if post_id == unknown_at:
                response.json.side_effect = ValueError("invalid JSON")
            else:
                response.json.return_value = {"success": True, "redirect": f"/post-{post_id}-1"}
            return response

        session.get.side_effect = get
        session.post.side_effect = post
        return session

    def test_five_distinct_homepage_posts_choose_text_independently(self):
        session = self.session(range(1, 9))
        state = {}
        with patch.object(app.random, "choice", side_effect=self.TEXTS) as choice:
            self.assertTrue(app.random_comment(session, self.store, state, self.TODAY))
        self.assertEqual(session.post.call_count, 5)
        self.assertEqual(choice.call_count, 5)
        self.assertTrue(all(call.args[0] == self.TEXTS for call in choice.call_args_list))
        payloads = [call.kwargs["json"] for call in session.post.call_args_list]
        self.assertEqual([p["postId"] for p in payloads], [1, 2, 3, 4, 5])
        self.assertEqual([p["content"] for p in payloads], self.TEXTS)
        self.assertEqual(state["commented_post_ids"], [1, 2, 3, 4, 5])
        self.assertEqual(state["comment_date"], self.TODAY)
        self.assertNotIn("comment_pending_date", state)
        self.shuffle_mock.assert_called_once()
        self.assertEqual([c.args[0] for c in self.sleep_mock.call_args_list], [10, 10, 10, 10])
        self.assertEqual(session.get.call_args_list[0].args[0], app.BASE + "/")
        checkpoints = [s for s in self.snapshots if "comment_pending_date" not in s]
        self.assertEqual([len(s["commented_post_ids"]) for s in checkpoints], [1, 2, 3, 4, 5])

    def test_skip_duplicates_and_ineligible_posts_then_fill_five(self):
        extra = ('<li class="post-list-item"><i class="pined"></i>'
                 '<div class="post-title"><a href="/post-90-1">置顶</a></div></li>'
                 '<li class="post-list-item">只读<div class="post-title">'
                 '<a href="/post-91-1">只读帖</a></div></li>'
                 '<li class="post-list-item"><div class="post-title">'
                 '<a href="/post-92-1">已出</a></div></li>')
        session = self.session([1, 1, 2, 3, 4, 5, 6, 7], unavailable=[1], own=[2], extra=extra)
        state = {}
        app.random_comment(session, self.store, state, self.TODAY)
        self.assertEqual([c.kwargs["json"]["postId"] for c in session.post.call_args_list], [3, 4, 5, 6, 7])

    def test_partial_run_resumes_only_missing_posts_and_stops_at_five(self):
        state = {}
        with self.assertRaisesRegex(RuntimeError, "2/5"):
            app.random_comment(self.session([1, 2]), self.store, state, self.TODAY)
        self.assertNotIn("comment_date", state)
        self.assertEqual(self.snapshots[-1]["commented_post_ids"], [1, 2])
        state = copy.deepcopy(self.snapshots[-1])
        session = self.session([1, 2, 3, 4, 5, 6])
        self.sleep_mock.reset_mock()
        app.random_comment(session, self.store, state, self.TODAY)
        self.assertEqual([c.kwargs["json"]["postId"] for c in session.post.call_args_list], [3, 4, 5])
        self.assertEqual([c.args[0] for c in self.sleep_mock.call_args_list], [10, 10])
        session.reset_mock()
        app.random_comment(session, self.store, state, self.TODAY)
        session.get.assert_not_called()
        session.post.assert_not_called()

    def test_rejected_submission_keeps_confirmed_progress_for_retry(self):
        state = {}
        session = self.session(range(1, 7), fail_at=3)
        with self.assertRaisesRegex(RuntimeError, "评论提交失败"):
            app.random_comment(session, self.store, state, self.TODAY)
        self.assertEqual(state["commented_post_ids"], [1, 2])
        self.assertNotIn("comment_pending_date", state)
        session = self.session(range(1, 7))
        app.random_comment(session, self.store, state, self.TODAY)
        self.assertEqual([c.kwargs["json"]["postId"] for c in session.post.call_args_list], [3, 4, 5])

    def test_ambiguous_or_unconfirmed_submission_blocks_next_run(self):
        for option in ("unknown_at", "unconfirmed_at"):
            with self.subTest(option=option):
                state = {}
                session = self.session(range(1, 7), **{option: 3})
                with self.assertRaisesRegex(RuntimeError, "停止避免重复发送"):
                    app.random_comment(session, self.store, state, self.TODAY)
                self.assertEqual(state["commented_post_ids"], [1, 2])
                self.assertEqual(state["comment_pending_post_id"], 3)
                state = copy.deepcopy(self.snapshots[-1])
                session.reset_mock()
                with self.assertRaisesRegex(RuntimeError, "为避免重复发送已停止"):
                    app.random_comment(session, self.store, state, self.TODAY)
                session.post.assert_not_called()
                session.get.assert_not_called()

    def test_checkpoint_failure_prevents_sending_another_comment(self):
        session = self.session(range(1, 7))
        # Pending is persisted, but the confirmation checkpoint cannot be saved.
        self.store.save.side_effect = [None, RuntimeError("写回失败")]
        with self.assertRaisesRegex(RuntimeError, "写回失败"):
            app.random_comment(session, self.store, {}, self.TODAY)
        self.assertEqual(session.post.call_count, 1)

    def test_new_day_resets_count_and_legacy_completed_day_is_skipped(self):
        state = {"comment_date": self.TODAY}
        session = self.session(range(1, 7))
        app.random_comment(session, self.store, state, self.TODAY)
        session.get.assert_not_called()
        state.update(comment_progress_date=self.TODAY, commented_post_ids=[10, 11, 12, 13, 14])
        app.random_comment(session, self.store, state, "2026-10-06")
        self.assertEqual(state["commented_post_ids"], [1, 2, 3, 4, 5])
        self.assertEqual(state["comment_date"], "2026-10-06")


if __name__ == "__main__":
    unittest.main()

