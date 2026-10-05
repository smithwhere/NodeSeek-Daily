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
            "NS_FEED": "false",
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


class TradeCommentsTests(unittest.TestCase):
    TODAY = "2026-10-05"
    TEXTS = app.DEFAULT_COMMENTS[:3]

    def setUp(self):
        self.env = patch.dict(os.environ, {
            "NS_USERNAME": "tester", "NS_COMMENT_TEXTS": "",
        })
        self.env.start()
        self.shuffle = patch.object(app.random, "shuffle")
        self.shuffle_mock = self.shuffle.start()
        self.interval = patch.object(app.random, "uniform", return_value=10)
        self.interval.start()
        self.sleep = patch.object(app.time, "sleep")
        self.sleep_mock = self.sleep.start()
        self.cookies = patch.object(app, "dump_cookies", return_value=[])
        self.cookies.start()
        self.snapshots = []
        self.store = Mock()
        self.store.save.side_effect = lambda state: self.snapshots.append(copy.deepcopy(state))

    def tearDown(self):
        self.cookies.stop()
        self.interval.stop()
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
            if url == app.BASE + "/categories/trade":
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

    def test_three_distinct_trade_posts_choose_text_independently(self):
        session = self.session(range(1, 9))
        state = {}
        with patch.object(app.random, "choice", side_effect=self.TEXTS) as choice:
            self.assertTrue(app.random_comment(session, self.store, state, self.TODAY))
        self.assertEqual(session.post.call_count, 3)
        self.assertEqual(choice.call_count, 3)
        self.assertEqual(len(app.DEFAULT_COMMENTS), 3)
        self.assertTrue(all(call.args[0] == app.DEFAULT_COMMENTS for call in choice.call_args_list))
        payloads = [call.kwargs["json"] for call in session.post.call_args_list]
        self.assertEqual([p["postId"] for p in payloads], [1, 2, 3])
        self.assertEqual([p["content"] for p in payloads], self.TEXTS)
        self.assertEqual(state["commented_post_ids"], [1, 2, 3])
        self.assertEqual(state["comment_date"], self.TODAY)
        self.assertNotIn("comment_pending_date", state)
        self.shuffle_mock.assert_called_once()
        self.assertEqual([c.args[0] for c in self.sleep_mock.call_args_list], [10, 10])
        self.assertEqual(session.get.call_args_list[0].args[0], app.BASE + "/categories/trade")
        checkpoints = [s for s in self.snapshots if "comment_pending_date" not in s]
        self.assertEqual([len(s["commented_post_ids"]) for s in checkpoints], [1, 2, 3])

    def test_skip_duplicates_and_ineligible_posts_then_fill_three(self):
        extra = ('<li class="post-list-item"><i class="pined"></i>'
                 '<div class="post-title"><a href="/post-90-1">置顶</a></div></li>'
                 '<li class="post-list-item">只读<div class="post-title">'
                 '<a href="/post-91-1">只读帖</a></div></li>'
                 '<li class="post-list-item"><div class="post-title">'
                 '<a href="/post-92-1">已出</a></div></li>')
        session = self.session([1, 1, 2, 3, 4, 5, 6, 7], unavailable=[1], own=[2], extra=extra)
        state = {}
        app.random_comment(session, self.store, state, self.TODAY)
        self.assertEqual([c.kwargs["json"]["postId"] for c in session.post.call_args_list], [3, 4, 5])

    def test_comment_intervals_are_random_between_ten_and_fifteen_seconds(self):
        with patch.object(app.random, "uniform", side_effect=[10.25, 14.75]) as interval:
            app.random_comment(self.session([1, 2, 3]), self.store, {}, self.TODAY)
        self.assertEqual([c.args for c in interval.call_args_list], [(10, 15), (10, 15)])
        self.assertEqual([c.args[0] for c in self.sleep_mock.call_args_list], [10.25, 14.75])

    def test_partial_run_resumes_only_missing_posts_and_stops_at_three(self):
        state = {}
        with self.assertRaisesRegex(RuntimeError, "2/3"):
            app.random_comment(self.session([1, 2]), self.store, state, self.TODAY)
        self.assertNotIn("comment_date", state)
        self.assertEqual(self.snapshots[-1]["commented_post_ids"], [1, 2])
        state = copy.deepcopy(self.snapshots[-1])
        session = self.session([1, 2, 3, 4, 5, 6])
        self.sleep_mock.reset_mock()
        app.random_comment(session, self.store, state, self.TODAY)
        self.assertEqual([c.kwargs["json"]["postId"] for c in session.post.call_args_list], [3])
        self.assertEqual([c.args[0] for c in self.sleep_mock.call_args_list], [])
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
        self.assertEqual([c.kwargs["json"]["postId"] for c in session.post.call_args_list], [3])

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

    def test_legacy_one_comment_is_migrated_and_only_two_are_added(self):
        state = {"comment_date": self.TODAY}
        session = self.session(range(1, 7), own=[1])
        app.random_comment(session, self.store, state, self.TODAY)
        self.assertEqual([c.kwargs["json"]["postId"] for c in session.post.call_args_list], [2, 3])
        self.assertEqual(state["comment_legacy_count"], 1)
        self.assertEqual(self.snapshots[0]["comment_legacy_count"], 1)
        self.assertEqual(state["comment_date"], self.TODAY)
        session.reset_mock()
        app.random_comment(session, self.store, state, self.TODAY)
        session.get.assert_not_called()
        session.post.assert_not_called()

    def test_completion_date_cannot_skip_partial_three_post_progress(self):
        state = {"comment_date": self.TODAY, "comment_progress_date": self.TODAY,
                 "commented_post_ids": [1]}
        session = self.session(range(1, 7))
        app.random_comment(session, self.store, state, self.TODAY)
        self.assertEqual([c.kwargs["json"]["postId"] for c in session.post.call_args_list], [2, 3])
        self.assertEqual(state["commented_post_ids"], [1, 2, 3])

    def test_new_day_resets_legacy_and_recorded_counts(self):
        state = {"comment_date": self.TODAY, "comment_progress_date": self.TODAY,
                 "comment_legacy_count": 1, "commented_post_ids": [10, 11]}
        session = self.session(range(1, 7))
        app.random_comment(session, self.store, state, "2026-10-06")
        self.assertEqual(state["commented_post_ids"], [1, 2, 3])
        self.assertEqual(state["comment_legacy_count"], 0)
        self.assertEqual(state["comment_date"], "2026-10-06")


class FreeFeedTests(unittest.TestCase):
    TODAY = "2026-10-05"

    def setUp(self):
        self.patches = [
            patch.dict(os.environ, {"NS_USERNAME": "tester", "NS_FEED": "true"}),
            patch.object(app.random, "shuffle"),
            patch.object(app.time, "sleep"),
            patch.object(app, "dump_cookies", return_value=[]),
        ]
        self.handles = [p.start() for p in self.patches]
        self.snapshots = []
        self.store = Mock()
        self.store.save.side_effect = lambda state: self.snapshots.append(copy.deepcopy(state))

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()

    def session(self, ids=(1, 2, 3), maximum=2, used=0, overrides=None,
                reject_at=None, unknown_at=None, changed_coin=False,
                unchanged_quota=False, exhaust_on_recheck=False):
        session = Mock()
        quota = {"maxFreeLike": maximum, "freeLikeUsed": used}
        reads = 0
        listing = "".join(
            f'<li class="post-list-item"><div class="post-title">'
            f'<a href="/post-{i}-1">帖子 {i}</a></div></li>' for i in ids)

        def get(url, **kwargs):
            nonlocal reads
            if url == app.BASE + "/api/progress/today?scope=freelike":
                reads += 1
                if exhaust_on_recheck and reads == 2:
                    quota["freeLikeUsed"] = quota["maxFreeLike"]
                response = Mock(status_code=200)
                response.json.return_value = copy.deepcopy(quota)
                return response
            if url == app.BASE + "/categories/trade":
                return Mock(status_code=200, text=listing)
            post_id = int(app.re.search(r"/post-(\d+)-", url).group(1))
            root = {"floorIndex": 0, "commentId": 1000 + post_id, "liked": False,
                    "poster": {"name": "other", "uid": post_id, "isMe": False},
                    "time": {"createdDate": app.datetime.now(app.ZoneInfo("Asia/Shanghai")).isoformat()}}
            root.update((overrides or {}).get(post_id, {}))
            config = {"user": {"coin": 1000, "member_id": 999},
                      "postData": {"postId": post_id, "locked": False, "comments": [root]}}
            encoded = base64.b64encode(json.dumps(config).encode()).decode()
            return Mock(status_code=200, text=f'<script id="temp-script" type="application/json">{encoded}</script>')

        def post(url, **kwargs):
            self.assertEqual(url, app.BASE + "/api/statistics/like")
            self.assertEqual(kwargs["json"]["action"], "add")
            post_id = kwargs["json"]["commentId"] - 1000
            response = Mock(status_code=200)
            if post_id == reject_at:
                response.json.return_value = {"success": False}
                return response
            if not unchanged_quota:
                quota["freeLikeUsed"] += 1
            if post_id == unknown_at:
                response.json.side_effect = ValueError("invalid JSON")
            else:
                response.json.return_value = {"success": True, "current": 1,
                                              "coin": 999 if changed_coin else 1000}
            return response

        session.get.side_effect = get
        session.post.side_effect = post
        return session

    def test_uses_all_free_quota_on_distinct_trade_posts(self):
        state = {}
        session = self.session(ids=[1, 1, 2, 3, 4, 5, 6], maximum=5)
        app.random_free_feed(session, self.store, state, self.TODAY)
        self.assertEqual(session.post.call_count, 5)
        self.assertEqual([c.kwargs["json"]["commentId"] for c in session.post.call_args_list], [1001, 1002, 1003, 1004, 1005])
        self.assertEqual(state["fed_post_ids"], [1, 2, 3, 4, 5])
        self.assertNotIn("feed_pending_date", state)
        self.assertEqual([c.args[0] for c in self.handles[2].call_args_list], [10, 10, 10, 10])
        self.assertEqual([len(s["fed_post_ids"]) for s in self.snapshots], [0, 1, 1, 2, 2, 3, 3, 4, 4, 5])
        session.reset_mock()
        app.random_free_feed(session, self.store, state, self.TODAY)
        session.get.assert_called_once_with(app.BASE + "/api/progress/today?scope=freelike", timeout=30)
        session.post.assert_not_called()

    def test_legacy_completed_task_uses_server_remaining_quota(self):
        state = {"feed_date": self.TODAY, "feed_progress_date": self.TODAY,
                 "fed_post_ids": [1, 2]}
        session = self.session(ids=[1, 2, 3, 4, 5, 6], maximum=6, used=3)
        app.random_free_feed(session, self.store, state, self.TODAY)
        self.assertEqual(session.post.call_count, 3)
        self.assertEqual(state["fed_post_ids"], [1, 2, 3, 4, 5])
        self.assertNotIn("feed_date", state)

    def test_no_free_quota_never_posts(self):
        for maximum, used in [(0, 0), (2, 2), (3, 3), (3, 4)]:
            with self.subTest(maximum=maximum):
                session = self.session(maximum=maximum, used=used)
                app.random_free_feed(session, self.store, {}, self.TODAY)
                session.post.assert_not_called()

    def test_quota_is_rechecked_after_persistence_before_post(self):
        state = {}
        session = self.session(exhaust_on_recheck=True)
        app.random_free_feed(session, self.store, state, self.TODAY)
        session.post.assert_not_called()
        self.assertNotIn("feed_pending_date", state)
        self.assertNotIn("feed_pending_date", self.snapshots[-1])

    def test_partial_quota_or_candidates_resume_only_missing_leg(self):
        for initial in [self.session(maximum=1), self.session(ids=[1])]:
            state = {}
            try:
                app.random_free_feed(initial, self.store, state, self.TODAY)
            except RuntimeError as error:
                self.assertIn("剩余免费额度 1", str(error))
            self.assertEqual(state["fed_post_ids"], [1])
            self.assertNotIn("feed_date", state)
            state = copy.deepcopy(self.snapshots[-1])
            session = self.session(used=1)
            app.random_free_feed(session, self.store, state, self.TODAY)
            self.assertEqual(session.post.call_count, 1)
            self.assertEqual(session.post.call_args.kwargs["json"]["commentId"], 1002)
            self.assertEqual(state["fed_post_ids"], [1, 2])

    def test_already_fed_own_and_old_posts_are_skipped(self):
        session = self.session(ids=[1, 2, 3, 4, 5, 6], overrides={
            1: {"liked": True},
            2: {"poster": {"name": "tester", "uid": 999, "isMe": True}},
            3: {"time": {"createdDate": "2000-01-01T00:00:00Z"}},
            4: {"liked": None},
        })
        state = {}
        app.random_free_feed(session, self.store, state, self.TODAY)
        self.assertEqual(state["fed_post_ids"], [5, 6])

    def test_unknown_or_unverified_submission_blocks_retry(self):
        for options in [{"unknown_at": 1}, {"changed_coin": True}, {"unchanged_quota": True}]:
            with self.subTest(options=options):
                state = {}
                session = self.session(**options)
                with self.assertRaises(RuntimeError):
                    app.random_free_feed(session, self.store, state, self.TODAY)
                self.assertEqual(session.post.call_count, 1)
                self.assertEqual(state["feed_pending_date"], self.TODAY)
                state = copy.deepcopy(self.snapshots[-1])
                session.reset_mock()
                with self.assertRaisesRegex(RuntimeError, "提交待确认"):
                    app.random_free_feed(session, self.store, state, self.TODAY)
                session.post.assert_not_called()

    def test_invalid_quota_is_rejected_before_post(self):
        session = self.session(maximum="2")
        with self.assertRaisesRegex(RuntimeError, "格式异常"):
            app.random_free_feed(session, self.store, {}, self.TODAY)
        session.post.assert_not_called()

    def test_pending_checkpoint_failure_never_posts(self):
        session = self.session()
        self.store.save.side_effect = RuntimeError("写回失败")
        with self.assertRaisesRegex(RuntimeError, "写回失败"):
            app.random_free_feed(session, self.store, {}, self.TODAY)
        session.post.assert_not_called()

    def test_explicit_rejection_preserves_previous_success(self):
        state = {}
        session = self.session(reject_at=2)
        with self.assertRaisesRegex(RuntimeError, "被拒绝"):
            app.random_free_feed(session, self.store, state, self.TODAY)
        self.assertEqual(state["fed_post_ids"], [1])
        self.assertNotIn("feed_pending_date", state)
        session = self.session(used=1)
        app.random_free_feed(session, self.store, state, self.TODAY)
        self.assertEqual(session.post.call_count, 1)

    def test_new_day_resets_completed_feed_count(self):
        state = {"feed_date": self.TODAY, "feed_progress_date": self.TODAY,
                 "fed_post_ids": [10, 11]}
        session = self.session()
        app.random_free_feed(session, self.store, state, "2026-10-06")
        self.assertEqual(state["fed_post_ids"], [1, 2])
        self.assertNotIn("feed_date", state)

    def test_manual_main_runs_feeding_even_when_comments_are_done(self):
        today = app.datetime.now(app.ZoneInfo("Asia/Shanghai")).date().isoformat()
        state = {"cookies": [{"value": "saved"}], "comment_date": today,
                 "comment_progress_date": today, "commented_post_ids": [1, 2, 3]}
        store = Mock(sha="existing")
        store.load.return_value = state
        with patch.dict(os.environ, {"NS_COOKIE": "", "NS_COMMENT": "true", "GITHUB_EVENT_NAME": "workflow_dispatch"}), \
             patch.object(app, "StateStore", return_value=store), \
             patch.object(app, "cookie_session", return_value=Mock()), \
             patch.object(app, "attendance", return_value=True), \
             patch.object(app, "random_free_feed", return_value=True) as feed:
            app.main()
        feed.assert_called_once()

    def test_manual_main_migrates_legacy_comment_before_feeding(self):
        today = app.datetime.now(app.ZoneInfo("Asia/Shanghai")).date().isoformat()
        state = {"cookies": [{"value": "saved"}], "comment_date": today}
        store = Mock(sha="existing")
        store.load.return_value = state
        calls = []
        def comment(session, store, state, today):
            calls.append("comment")
        def feed(session, store, state, today):
            calls.append("feed")
            raise RuntimeError("投喂额度读取失败")
        with patch.dict(os.environ, {"NS_COOKIE": "", "NS_COMMENT": "true", "GITHUB_EVENT_NAME": "workflow_dispatch"}), \
             patch.object(app, "StateStore", return_value=store), \
             patch.object(app, "cookie_session", return_value=Mock()), \
             patch.object(app, "attendance", return_value=True), \
             patch.object(app, "random_comment", side_effect=comment), \
             patch.object(app, "random_free_feed", side_effect=feed):
            with self.assertRaisesRegex(RuntimeError, "投喂额度读取失败"):
                app.main()
        self.assertEqual(calls, ["comment", "feed"])

    def test_manual_main_preserves_partial_progress_for_both_tasks(self):
        today = app.datetime.now(app.ZoneInfo("Asia/Shanghai")).date().isoformat()
        state = {"cookies": [{"value": "saved"}], "feed_progress_date": today,
                 "fed_post_ids": [10], "comment_progress_date": today,
                 "commented_post_ids": [20, 21]}
        store = Mock(sha="existing")
        store.load.return_value = state
        with patch.dict(os.environ, {"NS_COOKIE": "", "NS_COMMENT": "true", "GITHUB_EVENT_NAME": "workflow_dispatch"}), \
             patch.object(app, "StateStore", return_value=store), \
             patch.object(app, "cookie_session", return_value=Mock()), \
             patch.object(app, "attendance", return_value=True), \
             patch.object(app, "random_free_feed", return_value=True) as feed, \
             patch.object(app, "random_comment", return_value=True) as comment:
            app.main()
        feed.assert_called_once()
        comment.assert_called_once()
        self.assertIs(feed.call_args.args[2], state)
        self.assertIs(comment.call_args.args[2], state)
        self.assertEqual(state["fed_post_ids"], [10])
        self.assertEqual(state["commented_post_ids"], [20, 21])

    def test_manual_main_does_not_repeat_completed_daily_tasks(self):
        today = app.datetime.now(app.ZoneInfo("Asia/Shanghai")).date().isoformat()
        state = {"cookies": [{"value": "saved"}], "feed_date": today,
                 "feed_progress_date": today, "fed_post_ids": [10, 11],
                 "comment_date": today, "comment_progress_date": today,
                 "commented_post_ids": [20, 21, 22]}
        store = Mock(sha="existing")
        store.load.return_value = state
        session = self.session(used=2)
        with patch.dict(os.environ, {"NS_COOKIE": "", "NS_COMMENT": "true", "GITHUB_EVENT_NAME": "workflow_dispatch"}), \
             patch.object(app, "StateStore", return_value=store), \
             patch.object(app, "cookie_session", return_value=session), \
             patch.object(app, "attendance", return_value=True):
            app.main()
        session.get.assert_called_once_with(app.BASE + "/api/progress/today?scope=freelike", timeout=30)
        session.post.assert_not_called()
        store.save.assert_not_called()


if __name__ == "__main__":
    unittest.main()

