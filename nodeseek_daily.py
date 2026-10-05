# -*- coding: utf-8 -*-
"""NodeSeek daily attendance and three random trade comments.
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
COMMENT_TARGET = 3
COMMENT_INTERVAL_SECONDS = 10
COMMENT_INTERVAL_RANGE = (10, 15)
DEFAULT_COMMENTS = [
    "楼主辛苦了，感谢无私分享！",
    "字字珠玑，看完受益匪浅，果断收藏！",
    "给楼主点赞，这篇内容含金量太高了。",
    "及时雨！刚好需要这方面的资料，感谢！",
    "Mark慢慢看，楼主好人一生平安。",
    "前排围观，搬个小板凳坐等更新。",
    "自古评论出人才，我是来看评论区的。",
    "虽然看不太懂，但感觉很厉害的样子，顶一下！",
    "先赞后看，养成习惯。",
    "火钳刘明，感觉这帖要火！",
    "这波分析很到位，逻辑严密，无法反驳。",
    "确实如此，现在的普遍现象就是这样。",
    "路过帮顶，顺便混个经验。",
    "打卡留名，每日一卡。",
    "围观，帮顶。",
    "内容极佳，特来支持。",
    "赞一个，拿积分走人。",
    "感谢分享，多一个思路。",
    "这个角度还挺有意思，之前没注意到。",
    "看完了，确实有值得参考的地方。",
    "我也遇到过类似情况，看看大家怎么处理。",
    "蹲一个后续，想知道最后的结果。",
    "感谢整理，步骤写得很清楚。",
    "正好有这个需求，收藏备用。",
    "这个细节很实用，能少走不少弯路。",
    "配置看着不错，蹲个实际使用反馈。",
    "想看看晚高峰的表现，白天测试只能参考。",
    "这个价格挺有吸引力，长期稳定性怎么样？",
    "方便补一下测试地区和运营商吗？",
    "跑分之外，我更关心线路和稳定性。",
    "可以补一下报错和操作步骤，方便大家判断。",
    "这个问题我也碰到过，目前还没找到稳定的解决办法。",
    "最后如果解决了，麻烦更新一下原因，后来的人也能参考。",
    "先确认一下最近有没有改过配置或更新版本？",
    "又学到一招。",
    "钱包：你先冷静一下。",
    "收藏了，希望下次用得上时还能找到。",
    "看着挺香，就差一个下单的理由了。",
    "楼主负责种草，评论区负责劝退。",
]



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


def free_like_progress(session):
    response = session.get(BASE + "/api/progress/today?scope=freelike", timeout=30)
    if response.status_code != 200:
        raise RuntimeError("免费投喂额度读取失败，HTTP " + str(response.status_code))
    try:
        data = response.json()
    except ValueError:
        raise RuntimeError("免费投喂额度响应无法确认，已停止")
    maximum = data.get("maxFreeLike") if isinstance(data, dict) else None
    used = data.get("freeLikeUsed") if isinstance(data, dict) else None
    if (type(maximum) is not int or type(used) is not int or
            maximum < 0 or used < 0):
        raise RuntimeError("免费投喂额度格式异常，已停止")
    return maximum, used


def post_page_config(page):
    tag = BeautifulSoup(page, "html.parser").select_one("script#temp-script")
    if not tag:
        raise RuntimeError("投喂帖子状态无法确认，已停止")
    try:
        data = json.loads(base64.b64decode(tag.get_text().strip(), validate=True))
    except (ValueError, UnicodeError):
        raise RuntimeError("投喂帖子状态格式异常，已停止")
    if not isinstance(data, dict) or not isinstance(data.get("postData"), dict):
        raise RuntimeError("投喂帖子状态格式异常，已停止")
    return data


def clear_feed_pending(state):
    state.pop("feed_pending_date", None)
    state.pop("feed_pending_post_id", None)


def random_free_feed(session, store, state, today):
    if state.get("feed_pending_date") == today:
        raise RuntimeError("今天已有投喂提交待确认，为避免重复或付费投喂已停止")
    # Always consult the server, including after the old two-leg task completed.
    state.pop("feed_date", None)
    if state.get("feed_progress_date") != today:
        state["feed_progress_date"] = today
        state["fed_post_ids"] = []
        clear_feed_pending(state)
    completed = state["fed_post_ids"]
    maximum, used = free_like_progress(session)
    if used >= maximum:
        print(f"免费投喂额度已用完（{used}/{maximum}），本脚本今天已投喂 {len(completed)} 个")
        return True
    response = session.get(BASE + "/categories/trade", timeout=30)
    if response.status_code != 200:
        raise RuntimeError("投喂交易列表读取失败，HTTP " + str(response.status_code))
    urls = []
    seen = set(completed)
    for post in BeautifulSoup(response.text, "html.parser").select(".post-list-item"):
        link = post.select_one(".post-title a")
        if (post.select_one(".pined, .pinned") or "只读" in post.get_text() or not link or
                any(word in link.get_text() for word in ["已出", "已收", "不出了", "没有了"])):
            continue
        url = urljoin(BASE, link.get("href", ""))
        match = re.fullmatch(re.escape(BASE) + r"/post-(\d+)-\d+", url)
        if match and int(match.group(1)) not in seen:
            seen.add(int(match.group(1)))
            urls.append((int(match.group(1)), BASE + "/post-" + match.group(1) + "-1"))
    random.shuffle(urls)
    sent_in_run = 0
    for post_id, url in urls:
        response = session.get(url, timeout=30)
        if response.status_code != 200:
            continue
        config = post_page_config(response.text)
        user = config.get("user")
        post = config["postData"]
        if not isinstance(user, dict) or type(user.get("coin")) is not int:
            raise RuntimeError("投喂登录状态或余额无法确认，已停止")
        if post.get("postId") != post_id or post.get("locked"):
            continue
        root = next((item for item in post.get("comments", [])
                     if item.get("floorIndex") == 0), None)
        if not root or root.get("liked") is not False or type(root.get("commentId")) is not int:
            continue
        poster = root.get("poster", {})
        if (poster.get("isMe") or poster.get("uid") == user.get("member_id") or
                poster.get("name") == os.getenv("NS_USERNAME", "")):
            continue
        try:
            created = datetime.fromisoformat(root["time"]["createdDate"].replace("Z", "+00:00"))
            age = (datetime.now(ZoneInfo("Asia/Shanghai")) - created).total_seconds()
        except (KeyError, TypeError, ValueError):
            continue
        if not 0 <= age < 7 * 24 * 60 * 60:
            continue
        if sent_in_run:
            time.sleep(COMMENT_INTERVAL_SECONDS)
        state["feed_pending_date"] = today
        state["feed_pending_post_id"] = post_id
        store.save(state)
        # Recheck after the persistence request, immediately before sending.
        try:
            maximum, used = free_like_progress(session)
        except Exception:
            clear_feed_pending(state)
            store.save(state)
            raise
        if used >= maximum:
            clear_feed_pending(state)
            store.save(state)
            print("免费额度已用完，跳过付费投喂")
            return True
        response = session.post(BASE + "/api/statistics/like",
            json={"commentId": root["commentId"], "action": "add"},
            headers={"Origin": BASE, "Referer": url}, timeout=30)
        try:
            result = response.json()
        except ValueError:
            raise RuntimeError("投喂响应无法确认，已停止避免重复发送")
        if not isinstance(result, dict) or type(result.get("success")) is not bool:
            raise RuntimeError("投喂响应无法确认，已停止避免重复发送")
        if result["success"] is False:
            clear_feed_pending(state)
            store.save(state)
            raise RuntimeError("免费投喂被拒绝，HTTP " + str(response.status_code))
        if response.status_code != 200:
            raise RuntimeError("投喂响应状态异常，已停止避免重复发送")
        if type(result.get("coin")) is not int or result["coin"] != user["coin"]:
            raise RuntimeError("投喂后余额无法确认或发生变化，已停止后续投喂")
        after_maximum, after_used = free_like_progress(session)
        if after_maximum != maximum or after_used != used + 1:
            raise RuntimeError("投喂已提交但免费额度变化无法确认，已停止避免重复发送")
        completed.append(post_id)
        sent_in_run += 1
        clear_feed_pending(state)
        state["cookies"] = dump_cookies(session)
        store.save(state)
        print(f"免费投喂已确认：{url}，本脚本今天已投喂 {len(completed)} 个，剩余免费额度 {max(0, after_maximum - after_used)}")
        if after_used >= after_maximum:
            print("免费额度已用完，停止投喂")
            return True
    maximum, used = free_like_progress(session)
    if used >= maximum:
        print("免费额度已用完，停止投喂")
        return True
    raise RuntimeError(f"可免费投喂的交易帖不足，本脚本今天已投喂 {len(completed)} 个，剩余免费额度 {maximum - used}；补跑将继续")


def random_comment(session, store, state, today):
    if state.get("comment_pending_date") == today:
        raise RuntimeError("今天已有评论提交待确认，为避免重复发送已停止")
    raw = os.getenv("NS_COMMENT_TEXTS", "")
    texts = json.loads(raw) if raw else DEFAULT_COMMENTS
    if not isinstance(texts, list) or not texts or any(
            not isinstance(x, str) or not x.strip() for x in texts):
        raise RuntimeError("NS_COMMENT_TEXTS 必须是非空字符串的 JSON 数组")
    if state.get("comment_progress_date") != today:
        # The original one-post task saved only its completion date.
        legacy_count = 1 if state.get("comment_date") == today else 0
        state["comment_progress_date"] = today
        state["commented_post_ids"] = []
        state["comment_legacy_count"] = legacy_count
        state.pop("comment_date", None)
        if legacy_count:
            print("旧版今天已完成 1 条交易区评论，继续补足至 3 条")
            store.save(state)
    completed = state["commented_post_ids"]
    legacy_count = state.get("comment_legacy_count", 0)
    if len(completed) + legacy_count >= COMMENT_TARGET:
        if state.get("comment_date") != today:
            state["comment_date"] = today
            store.save(state)
        print("今天已确认评论 3/3 个交易区帖子，跳过重复发送")
        return True
    response = session.get(BASE + "/categories/trade", timeout=30)
    if response.status_code != 200:
        raise RuntimeError("交易区列表读取失败，HTTP " + str(response.status_code))
    soup = BeautifulSoup(response.text, "html.parser")
    urls = []
    seen = set(completed)
    for post in soup.select(".post-list-item"):
        if post.select_one(".pined, .pinned") or "只读" in post.get_text():
            continue
        link = post.select_one(".post-title a")
        if not link or any(word in link.get_text() for word in ["已出", "已收", "不出了", "没有了"]):
            continue
        url = urljoin(BASE, link.get("href", ""))
        if re.fullmatch(re.escape(BASE) + r"/post-\d+-\d+", url):
            post_id = int(re.search(r"/post-(\d+)-", url).group(1))
            if post_id in seen:
                continue
            seen.add(post_id)
            urls.append(url)
    random.shuffle(urls)
    username = os.environ.get("NS_USERNAME", "")
    sent_in_run = 0
    for url in urls:
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
        if sent_in_run:
            time.sleep(random.uniform(*COMMENT_INTERVAL_RANGE))
        state["comment_pending_date"] = today
        state["comment_pending_post_id"] = post_id
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
            state.pop("comment_pending_post_id", None)
            store.save(state)
            raise RuntimeError("评论提交失败，HTTP " + str(response.status_code))
        redirect = urljoin(BASE, str(data.get("redirect", "")))
        if not re.fullmatch(re.escape(BASE) + rf"/post-{post_id}-\d+", redirect):
            raise RuntimeError("评论已提交，但返回地址异常，已停止避免重复发送")
        # Verify the published author and text before marking the day complete.
        confirmed = False
        for _ in range(3):
            response = session.get(redirect, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                for item in soup.select(".content-item"):
                    author = item.select_one(".author-name")
                    body = item.select_one("article")
                    if author and body and author.get_text(strip=True) == username and body.get_text(strip=True) == comment:
                        print("随机评论已确认：" + redirect + str(data.get("redirectHash", "")) + " 内容：" + comment)
                        confirmed = True
                        break
            if confirmed:
                break
            time.sleep(2)
        if not confirmed:
            raise RuntimeError("评论已提交但未能确认，已停止避免重复发送")
        completed.append(post_id)
        sent_in_run += 1
        state.pop("comment_pending_date", None)
        state.pop("comment_pending_post_id", None)
        if len(completed) + legacy_count >= COMMENT_TARGET:
            state["comment_date"] = today
        state["cookies"] = dump_cookies(session)
        store.save(state)
        print(f"今天已确认评论 {len(completed) + legacy_count}/{COMMENT_TARGET} 个交易区帖子")
        if len(completed) + legacy_count >= COMMENT_TARGET:
            return True
    raise RuntimeError(f"交易区可评论帖子不足，今天已完成 {len(completed) + legacy_count}/{COMMENT_TARGET}；补跑将继续剩余额度")


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
            if state.get("comment_pending_date") == today:
                raise RuntimeError("今天已有评论提交待确认，为避免重复发送已停止")
            random_comment(session, store, state, today)
        if env_bool("NS_FEED", True):
            random_free_feed(session, store, state, today)
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

