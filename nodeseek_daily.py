# -*- coding: utf-8 -*-
"""NodeSeek daily attendance and one random trade comment.
Copyright (c) 2024 Hosea. Licensed under the MIT License.
"""
import base64
import hashlib
import json
from datetime import datetime
from zoneinfo import ZoneInfo
from cryptography.fernet import Fernet
import os
import random
import re
import sys
import time
import uuid

import requests
from curl_cffi import requests as browser_requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import secrets

BASE = "https://www.nodeseek.com"
LOGIN_URL = BASE + "/signIn.html"
SITEKEY = "0x4AAAAAAAaNy7leGjewpVyR"
DEFAULT_COMMENTS = ["帮顶一下，祝早日成交。", "支持一下，祝交易顺利。", "帮顶，祝早日找到合适的买家或卖家。"]



class LoginVerificationRequired(RuntimeError):
    pass


class StateStore:
    """Persist only authenticated ciphertext in the public repository."""
    def __init__(self):
        key = os.environ.get("COOKIE_ENCRYPTION_KEY", "")
        self.token = os.environ.get("GITHUB_TOKEN", "")
        self.repo = os.environ.get("GITHUB_REPOSITORY", "")
        if not key or not self.token or not self.repo:
            raise RuntimeError("缺少 Cookie 持久化配置")
        self.cipher = Fernet(key.encode())
        self.url = "https://api.github.com/repos/" + self.repo + "/contents/.state/nodeseek.enc"
        self.headers = {"Authorization": "Bearer " + self.token,
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"}
        self.sha = None

    def load(self):
        response = requests.get(self.url, headers=self.headers, timeout=30)
        if response.status_code == 404:
            self.sha = None
            return {}
        if response.status_code != 200:
            raise RuntimeError("读取持久化 Cookie 失败，HTTP " + str(response.status_code))
        data = response.json()
        self.sha = data["sha"]
        encrypted = base64.b64decode(data["content"])
        try:
            return json.loads(self.cipher.decrypt(encrypted))
        except Exception:
            raise RuntimeError("Cookie 密文验证失败，请检查 COOKIE_ENCRYPTION_KEY")

    def save(self, state):
        encrypted = self.cipher.encrypt(json.dumps(state, ensure_ascii=False).encode())
        data = {"message": "Persist encrypted NodeSeek session state",
                "content": base64.b64encode(encrypted).decode(), "branch": "main"}
        if self.sha:
            data["sha"] = self.sha
        response = requests.put(self.url, headers=self.headers, json=data, timeout=30)
        if response.status_code not in (200, 201):
            raise RuntimeError("Cookie 写回失败，HTTP " + str(response.status_code))
        self.sha = response.json()["content"]["sha"]


def dump_cookies(session):
    return [{"name": item.name, "value": item.value, "domain": item.domain,
             "path": item.path or "/", "secure": item.secure}
            for item in session.cookies.jar if item.domain.endswith("nodeseek.com")]


def cookie_session(cookies, headers=None):
    session = browser_requests.Session(impersonate="chrome")
    session.headers.update(headers or {})
    for item in cookies:
        session.cookies.set(item["name"], item["value"],
                            domain=item["domain"], path=item.get("path", "/"))
    return session


def env_bool(name, default=False):
    return os.getenv(name, str(default)).strip().lower() == "true"


def solve_turnstile():
    key = os.environ.get("YESCAPTCHA_KEY", "").strip()
    if not key:
        raise RuntimeError("未配置 YESCAPTCHA_KEY")
    api = "https://api.yescaptcha.com"
    result = requests.post(api + "/createTask", json={
        "clientKey": key,
        "task": {"type": "TurnstileTaskProxyless",
                 "websiteURL": LOGIN_URL, "websiteKey": SITEKEY}
    }, timeout=30).json()
    if result.get("errorId") or not result.get("taskId"):
        raise RuntimeError("YesCaptcha 创建任务失败：" + str(result.get("errorCode", "UNKNOWN")))
    task_id = result["taskId"]
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        time.sleep(5)
        result = requests.post(api + "/getTaskResult", json={
            "clientKey": key, "taskId": task_id
        }, timeout=30).json()
        if result.get("errorId"):
            raise RuntimeError("YesCaptcha 获取结果失败：" + str(result.get("errorCode", "UNKNOWN")))
        if result.get("status") == "ready":
            token = result.get("solution", {}).get("token")
            if not token:
                raise RuntimeError("YesCaptcha 未返回验证令牌")
            return token
    raise RuntimeError("YesCaptcha 验证超时")


def login(session):
    username = os.environ.get("NS_USERNAME", "").strip()
    password = os.environ.get("NS_PASSWORD", "")
    if not username or not password:
        raise RuntimeError("未配置 NS_USERNAME / NS_PASSWORD")
    session.headers.setdefault("x-integrity-token", uuid.uuid4().hex)
    session.get(LOGIN_URL, timeout=30)
    token = solve_turnstile()
    response = session.post(BASE + "/api/account/signIn", json={
        "username": username, "password": password
    }, headers={"Origin": BASE, "Referer": LOGIN_URL,
                "x-captcha-token": token, "x-captcha-source": "turnstile"}, timeout=30)
    if response.status_code != 200:
        raise RuntimeError("登录 HTTP 状态：" + str(response.status_code))
    result = response.json()
    if not result.get("success"):
        raise RuntimeError("NodeSeek 登录失败，请检查账号密码或验证服务")
    redirect = str(result.get("redirect", ""))
    if redirect.startswith(("/emailSignIn", "/smsSignIn")):
        raise LoginVerificationRequired("NodeSeek 要求邮箱或短信验证新设备，请先提供已登录的 NS_COOKIE")
    if result.get("need2FA"):
        raise RuntimeError("账号需要 2FA 验证，自动登录无法继续")
    for header in ("x-security-token", "x-csrf-token"):
        if response.headers.get(header):
            session.headers[header] = response.headers[header]
    if not dump_cookies(session):
        raise RuntimeError("登录响应未返回会话 Cookie，不能视为登录成功")
    print("NodeSeek 登录成功，已取得 Cookie")


def attendance(session):
    reward_random = str(env_bool("NS_RANDOM", False)).lower()
    response = session.post(BASE + "/api/attendance?random=" + reward_random,
                            json={}, headers={"Origin": BASE, "Referer": BASE + "/board"},
                            timeout=30)
    if response.status_code == 401:
        return False
    if response.status_code not in (200, 400, 500):
        raise RuntimeError("签到 HTTP 状态：" + str(response.status_code))
    try:
        data = response.json()
    except ValueError:
        raise RuntimeError("签到响应不是 JSON，HTTP " + str(response.status_code))
    message = str(data.get("message", ""))
    if (response.status_code == 200 and data.get("success")) or any(text in message for text in ("已完成签到", "已经签到", "今天已签到", "请勿重复操作")):
        print("签到成功或今天已签到：" + message)
        return True
    if data.get("status") in (401, 404) or "登录" in message or "登陆" in message:
        print("Cookie 已失效")
        return False
    raise RuntimeError("签到失败（响应状态：" + str(data.get("status", "unknown")) + "）")


def random_comment(session, store, state, today):
    raw = os.getenv("NS_COMMENT_TEXTS", "")
    texts = json.loads(raw) if raw else DEFAULT_COMMENTS
    if not isinstance(texts, list) or not texts or any(
            not isinstance(x, str) or not x.strip() for x in texts):
        raise RuntimeError("NS_COMMENT_TEXTS 必须是非空字符串的 JSON 数组")
    response = session.get(BASE + "/categories/trade", timeout=30)
    if response.status_code != 200:
        raise RuntimeError("交易列表读取失败，HTTP " + str(response.status_code))
    soup = BeautifulSoup(response.text, "html.parser")
    urls = []
    for post in soup.select(".post-list-item"):
        if post.select_one(".pined") or "只读" in post.get_text():
            continue
        link = post.select_one(".post-title a")
        if not link or any(word in link.get_text() for word in ["已出", "已收", "不出了", "没有了"]):
            continue
        url = urljoin(BASE, link.get("href", ""))
        if re.fullmatch(re.escape(BASE) + r"/post-\d+-\d+", url):
            urls.append(url)
    random.shuffle(urls)
    username = os.environ.get("NS_USERNAME", "")
    for url in urls[:5]:
        response = session.get(url, timeout=30)
        if response.status_code != 200:
            continue
        soup = BeautifulSoup(response.text, "html.parser")
        if not soup.select_one("#editor"):
            continue
        if username and any(a.get_text(strip=True) == username for a in
                            soup.select(".content-item .author-name")):
            continue
        # Use the same endpoint and fields as NodeSeek's own comment editor.
        post_id = int(re.search(r"/post-(\d+)-", url).group(1))
        comment = random.choice(texts)
        state["comment_pending_date"] = today
        store.save(state)
        response = session.post(BASE + "/api/content/new-comment",
            json={"content": comment, "mode": "new-comment", "postId": post_id},
            headers={"Origin": BASE, "Referer": url, "csrf-token": secrets.token_urlsafe(12)},
            timeout=30)
        try:
            data = response.json()
        except ValueError:
            raise RuntimeError("评论响应无法确认，已停止避免重复发送")
        if not data.get("success"):
            state.pop("comment_pending_date", None)
            store.save(state)
            raise RuntimeError("评论提交失败，HTTP " + str(response.status_code))
        redirect = urljoin(BASE, str(data.get("redirect", "")))
        if not re.fullmatch(re.escape(BASE) + rf"/post-{post_id}-\d+", redirect):
            raise RuntimeError("评论已提交，但返回地址异常，已停止避免重复发送")
        # Verify the published author and text before marking the day complete.
        for _ in range(3):
            response = session.get(redirect, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                for item in soup.select(".content-item"):
                    author = item.select_one(".author-name")
                    body = item.select_one("article")
                    if author and body and author.get_text(strip=True) == username and body.get_text(strip=True) == comment:
                        print("随机评论已确认：" + redirect + str(data.get("redirectHash", "")) + " 内容：" + comment)
                        return True
            time.sleep(2)
        raise RuntimeError("评论已提交但未能确认，已停止避免重复发送")
    raise RuntimeError("未找到可评论的交易帖")


def main():
    store = StateStore()
    state = store.load()
    # An optional manually supplied Cookie seeds the initial encrypted state.
    seed_cookie = os.getenv("NS_COOKIE", "").strip()
    seed_hash = hashlib.sha256(seed_cookie.encode()).hexdigest() if seed_cookie else None
    seed_changed = bool(seed_cookie and state.get("seed_hash") != seed_hash)
    if seed_changed:
        cookies = []
        for part in os.environ["NS_COOKIE"].split(";"):
            if "=" in part:
                name, value = part.strip().split("=", 1)
                cookies.append({"name": name, "value": value,
                                "domain": ".nodeseek.com", "path": "/"})
        state["cookies"] = cookies
        state["seed_hash"] = seed_hash
        state.pop("needs_device_verification", None)
    session = cookie_session(state.get("cookies", []), state.get("headers"))
    try:
        valid = bool(state.get("cookies")) and attendance(session)
        if not valid:
            if state.get("needs_device_verification"):
                raise RuntimeError("尚未完成新设备验证，请更新 NS_COOKIE；已跳过付费验证")
            print("没有有效 Cookie，使用账号密码和 YesCaptcha 登录")
            session.close()
            session = cookie_session([], state.get("headers"))
            try:
                login(session)
            except LoginVerificationRequired:
                state["needs_device_verification"] = True
                store.save(state)
                raise
            state.pop("needs_device_verification", None)
            state["cookies"] = dump_cookies(session)
            if not state["cookies"]:
                raise RuntimeError("登录未返回 Cookie")
            state["headers"] = {k: v for k, v in session.headers.items()
                                if k in ("x-security-token", "x-csrf-token", "x-integrity-token")}
            store.save(state)
            # Read back persisted state and create a fresh session using only its Cookie.
            state = store.load()
            session.close()
            session = cookie_session(state["cookies"], state.get("headers"))
            print("新 Cookie 已加密写回并重新读取，使用 Cookie 会话继续")
            if not attendance(session):
                raise RuntimeError("写回后的 Cookie 无效")
        elif not store.sha or seed_changed:
            store.save(state)
        today = datetime.now(ZoneInfo("Asia/Shanghai")).date().isoformat()
        if env_bool("NS_COMMENT", True):
            if state.get("comment_date") == today:
                print("今天的随机评论已完成，跳过重复发送")
            elif state.get("comment_pending_date") == today:
                raise RuntimeError("今天已有评论提交待确认，为避免重复发送已停止")
            else:
                random_comment(session, store, state, today)
                state["comment_date"] = today
                state.pop("comment_pending_date", None)
                state["cookies"] = dump_cookies(session)
                store.save(state)
        print("每日任务完成")
    finally:
        session.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Never dump requests, cookies, page sources or exception messages that may contain secrets.
        if isinstance(error, RuntimeError):
            print("任务失败：" + str(error))
        else:
            print("任务失败：" + type(error).__name__)
        sys.exit(1)
