# -*- coding: utf-8 -*-
"""NodeSeek daily attendance and one random trade comment.
Copyright (c) 2024 Hosea. Licensed under the MIT License.
"""
import base64
import json
from datetime import datetime
from zoneinfo import ZoneInfo
from cryptography.fernet import Fernet
import os
import random
import re
import subprocess
import sys
import time
import uuid

import requests
from curl_cffi import requests as browser_requests
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

BASE = "https://www.nodeseek.com"
LOGIN_URL = BASE + "/signIn.html"
SITEKEY = "0x4AAAAAAAaNy7leGjewpVyR"
DEFAULT_COMMENTS = ["帮顶一下，祝早日成交。", "支持一下，祝交易顺利。", "帮顶，祝早日找到合适的买家或卖家。"]



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
             "path": item.path or "/", "secure": item.secure, "expires": item.expires}
            for item in session.cookies.jar if item.domain.endswith("nodeseek.com")]


def cookie_session(cookies, headers=None):
    session = browser_requests.Session(impersonate="chrome")
    session.headers.update(headers or {"x-integrity-token": uuid.uuid4().hex})
    for item in cookies:
        if item.get("expires") and item["expires"] <= time.time():
            continue
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
    if result.get("need2FA"):
        raise RuntimeError("账号需要 2FA 验证，自动登录无法继续")
    for header in ("x-security-token", "x-csrf-token"):
        if response.headers.get(header):
            session.headers[header] = response.headers[header]
    print("NodeSeek 登录成功")


def attendance(session):
    reward_random = str(env_bool("NS_RANDOM", False)).lower()
    response = session.post(BASE + "/api/attendance?random=" + reward_random,
                            json={}, headers={"Origin": BASE, "Referer": BASE + "/board"},
                            timeout=30)
    if response.status_code == 401:
        return False
    if response.status_code != 200:
        raise RuntimeError("签到 HTTP 状态：" + str(response.status_code))
    data = response.json()
    message = str(data.get("message", ""))
    if data.get("success") or "已完成签到" in message or "已经签到" in message:
        print("签到成功或今天已签到：" + message)
        return True
    if data.get("status") in (401, 404) or "登录" in message or "登陆" in message:
        print("Cookie 已失效")
        return False
    raise RuntimeError("签到失败（响应状态：" + str(data.get("status", "unknown")) + "）")


def setup_driver(session):
    options = uc.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")
    if env_bool("HEADLESS", True):
        options.add_argument("--headless=new")
    chrome = os.getenv("CHROME_BINARY", "/usr/bin/google-chrome")
    kwargs = {}
    if os.path.exists(chrome):
        options.binary_location = chrome
        version = subprocess.check_output([chrome, "--version"], text=True)
        match = re.search(r"(\d+)\.", version)
        if match:
            kwargs["version_main"] = int(match.group(1))
    driver = uc.Chrome(options=options, **kwargs)
    driver.set_page_load_timeout(60)
    try:
        driver.get(BASE)
        for item in session.cookies.jar:
            if item.domain.endswith("nodeseek.com"):
                driver.add_cookie({"name": item.name, "value": item.value,
                                   "domain": item.domain, "path": item.path or "/",
                                   "secure": item.secure})
        driver.get(BASE + "/categories/trade")
        return driver
    except Exception:
        driver.quit()
        raise


def random_comment(driver, store, state, today):
    raw = os.getenv("NS_COMMENT_TEXTS", "")
    texts = json.loads(raw) if raw else DEFAULT_COMMENTS
    if not isinstance(texts, list) or not texts or any(
            not isinstance(x, str) or not x.strip() for x in texts):
        raise RuntimeError("NS_COMMENT_TEXTS 必须是非空字符串的 JSON 数组")
    wait = WebDriverWait(driver, 30)
    posts = wait.until(EC.presence_of_all_elements_located((By.CSS_SELECTOR, ".post-list-item")))
    urls = []
    for post in posts:
        if post.find_elements(By.CSS_SELECTOR, ".pined") or "只读" in post.text:
            continue
        link = post.find_element(By.CSS_SELECTOR, ".post-title a")
        if any(word in link.text for word in ["已出", "已收", "不出了", "没有了"]):
            continue
        url = link.get_attribute("href")
        if url and url.startswith(BASE + "/post-"):
            urls.append(url)
    random.shuffle(urls)
    for url in urls[:5]:
        driver.get(url)
        # Skip posts without an editor, or threads already showing our comments.
        username = os.environ.get("NS_USERNAME", "")
        if username and any(el.text == username for el in
                            driver.find_elements(By.CSS_SELECTOR, ".content-item .author-name")):
            continue
        try:
            editor = WebDriverWait(driver, 8).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, ".CodeMirror textarea")))
        except Exception:
            continue
        text = random.choice(texts)
        # CodeMirror's textarea accepts native keystrokes.
        driver.find_element(By.CSS_SELECTOR, ".CodeMirror").click()
        editor.send_keys(Keys.CONTROL, "a")
        editor.send_keys(text)
        button = wait.until(EC.element_to_be_clickable(
            (By.XPATH, "//button[contains(., '发布评论')]")))
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", button)
        old_url = driver.current_url
        old_count = len(driver.find_elements(By.CSS_SELECTOR, ".content-item"))
        state["comment_pending_date"] = today
        store.save(state)
        button.click()
        # Do not submit again if delivery is uncertain.
        wait.until(lambda d: d.current_url != old_url or
                   len(d.find_elements(By.CSS_SELECTOR, ".content-item")) > old_count)
        def confirmed(d):
            for item in d.find_elements(By.CSS_SELECTOR, ".content-item"):
                authors = item.find_elements(By.CSS_SELECTOR, ".author-name")
                bodies = item.find_elements(By.CSS_SELECTOR, "article")
                if any(a.text == username for a in authors) and any(b.text.strip() == text for b in bodies):
                    return True
            return False
        wait.until(confirmed)
        print("随机评论已确认：" + driver.current_url + " 内容：" + text)
        return True
    raise RuntimeError("未找到可评论的交易帖")


def main():
    store = StateStore()
    state = store.load()
    # An optional manually supplied Cookie seeds the initial encrypted state.
    if not state.get("cookies") and os.getenv("NS_COOKIE", "").strip():
        cookies = []
        for part in os.environ["NS_COOKIE"].split(";"):
            if "=" in part:
                name, value = part.strip().split("=", 1)
                cookies.append({"name": name, "value": value,
                                "domain": ".nodeseek.com", "path": "/"})
        state["cookies"] = cookies
    session = cookie_session(state.get("cookies", []), state.get("headers"))
    driver = None
    try:
        valid = bool(state.get("cookies")) and attendance(session)
        if not valid:
            print("没有有效 Cookie，使用账号密码和 YesCaptcha 登录")
            session.close()
            session = cookie_session([])
            login(session)
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
        elif not store.sha:
            store.save(state)
        today = datetime.now(ZoneInfo("Asia/Shanghai")).date().isoformat()
        if env_bool("NS_COMMENT", True):
            if state.get("comment_date") == today:
                print("今天的随机评论已完成，跳过重复发送")
            elif state.get("comment_pending_date") == today:
                raise RuntimeError("今天已有评论提交待确认，为避免重复发送已停止")
            else:
                driver = setup_driver(session)
                random_comment(driver, store, state, today)
                state["comment_date"] = today
                state.pop("comment_pending_date", None)
                state["cookies"] = dump_cookies(session)
                store.save(state)
        print("每日任务完成")
    finally:
        if driver:
            driver.quit()
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
