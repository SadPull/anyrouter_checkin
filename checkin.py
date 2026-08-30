#!/usr/bin/env python3
"""Daily check-in for several relay sites with PushPlus notification.

Two kinds of sites are supported:

- AnyRouter: exposes `POST /api/user/sign_in`, so a saved session cookie is
  enough to claim the daily bonus.
- New-API v1 sites (Justwoker / Gorouter / Tabitoken): expose
  `POST /api/user/checkin`, authenticated with a personal access token
  (Bearer) or a refresh cookie; the POST may require a Cloudflare Turnstile
  token, minted inside a real Chrome driven over the DevTools protocol
  (playwright chromium fallback where Chrome is absent, e.g. CI).
"""

from __future__ import annotations

import gzip
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any
from zoneinfo import ZoneInfo


ANYROUTER_BASE_URL = "https://anyrouter.top"
PUSHPLUS_URL = "https://www.pushplus.plus/send"
# The site reports quota_per_unit = 500000 in /api/status.
QUOTA_PER_USD = Decimal("500000")
TIMEOUT_SECONDS = 15
MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 1
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/150.0.0.0 Safari/537.36"
)
# Aliyun WAF challenge served by the site.
ACW_POSITIONS = [
    15, 35, 29, 24, 33, 16, 1, 38, 10, 9, 19, 31, 40, 27, 22, 23, 25, 13,
    6, 11, 39, 18, 20, 8, 14, 21, 32, 26, 2, 30, 7, 4, 17, 5, 3, 28, 34,
    37, 12, 36,
]
ACW_XOR_KEY = "3000176000856006061501533003690027800375"
AUTH_FAILURE_HINTS = ("未登录", "无权", "登录已过期", "token 无效", "无效的 token")
# New-API check-in POST retries: a Turnstile token is single-use, so every
# attempt mints a fresh one.
CHECKIN_ATTEMPTS = 3
BROWSER_NAV_TIMEOUT_MS = 60_000
TURNSTILE_SCRIPT_TIMEOUT_MS = 20_000
TURNSTILE_TOKEN_TIMEOUT_MS = 45_000
# A Cloudflare interstitial usually clears by itself in a real browser.
CF_SETTLE_SECONDS = 45
# (显示名, 站点地址, 环境变量前缀)
NEW_API_SITES = (
    ("Justwoker", "https://api.justwoker.icu", "JUSTWOKER"),
    ("Gorouter", "https://gorouter.app", "GOROUTER"),
    ("Tabitoken", "https://tabitoken.com", "TABITOKEN"),
)


class CheckinError(RuntimeError):
    """A user-facing error that is safe to print in CI logs."""


class WafBlockedError(CheckinError):
    """The endpoint returned an HTML interstitial instead of its API JSON."""


class CookieExpiredError(CheckinError):
    """A configured cookie is no longer valid and must be re-copied."""


class TurnstileRequiredError(CheckinError):
    """The site demands a Turnstile token but the HTTP channel cannot mint one."""


def solve_acw_cookie(arg1: str) -> str:
    rearranged = [""] * len(ACW_POSITIONS)
    for index, char in enumerate(arg1):
        rearranged[ACW_POSITIONS.index(index + 1)] = char
    value = "".join(rearranged)
    return "".join(
        f"{int(value[i:i + 2], 16) ^ int(ACW_XOR_KEY[i:i + 2], 16):02x}"
        for i in range(0, len(value), 2)
    )


def merge_cookie(cookie: str, name: str, value: str) -> str:
    parts = [part.strip() for part in cookie.split(";") if part.strip()]
    parts = [part for part in parts if part.split("=", 1)[0].strip() != name]
    parts.append(f"{name}={value}")
    return "; ".join(parts)


def is_html(text: str, headers: Any = None) -> bool:
    """True when a body is markup rather than JSON.

    Checks the declared type first, then sniffs: WAF interstitials do not
    always start with a doctype (they can open with <script> or a comment).
    """
    if headers is not None and "text/html" in headers.get("Content-Type", "").lower():
        return True
    head = text.lstrip()[:400].lower()
    return head.startswith(("<!doctype", "<html", "<script", "<!--", "<meta", "<head"))


def expects_json(request_headers: dict[str, str]) -> bool:
    return "json" in request_headers.get("Accept", "").lower()


def looks_login_page(text: str) -> bool:
    """Identify an HTML login wall only when it contains clear login clues."""
    lowered = text.lower()
    markers = (
        "<form action=\"/login",
        "<form action='/login",
        "/login",
        "sign in",
        "log in",
        "unauthorized",
        "未登录",
    )
    return any(marker in lowered for marker in markers)


def looks_unauthenticated(text: str, message: str) -> bool:
    """True when a 200 response is really a login wall or an auth complaint."""
    if any(hint in message for hint in AUTH_FAILURE_HINTS):
        return True
    return is_html(text)



@dataclass
class Session:
    """Per-account HTTP state: cookies stay isolated between accounts."""

    base_cookie: str = ""
    # Names the env var this cookie came from, so expiry errors can point at it.
    cookie_env: str = ""
    extra_cookies: dict[str, str] = field(default_factory=dict)
    # Appended to expiry errors; sites using tokens need different advice
    # than sites using browser cookies.
    expiry_hint: str = ""

    def cookie_header(self) -> str:
        cookie = self.base_cookie
        for name, value in self.extra_cookies.items():
            cookie = merge_cookie(cookie, name, value)
        return cookie

    def _capture_set_cookie(self, headers: Any) -> None:
        for raw in headers.get_all("Set-Cookie") or []:
            pair = raw.split(";", 1)[0].strip()
            if "=" in pair:
                name, value = pair.split("=", 1)
                self.extra_cookies[name.strip()] = value.strip()

    def expired(self, detail: str) -> CookieExpiredError:
        target = self.cookie_env or "对应的凭证环境变量"
        hint = self.expiry_hint or "请从浏览器重新复制"
        return CookieExpiredError(f"{target} 已失效（{detail}），{hint}")

    def request_raw(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
        attempts: int = MAX_ATTEMPTS,
    ) -> tuple[int, Any, str]:
        body = None
        request_headers = dict(headers or {})
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json; charset=utf-8")

        opener = urllib.request.build_opener()
        challenge_retried = False
        attempt = 0
        while attempt < attempts:
            attempt += 1
            cookie = self.cookie_header()
            if cookie:
                request_headers["Cookie"] = cookie
            request = urllib.request.Request(
                url, data=body, headers=request_headers, method=method
            )
            try:
                with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                    self._capture_set_cookie(response.headers)
                    text = decode_body(response.read(), response.headers, method, url)

                    challenge = re.search(r"var arg1='([0-9A-Fa-f]{40})'", text)
                    if challenge and not challenge_retried:
                        self.extra_cookies["acw_sc__v2"] = solve_acw_cookie(
                            challenge.group(1)
                        )
                        challenge_retried = True
                        attempt -= 1  # Solving the challenge is not a failed try.
                        continue

                    # A WAF interstitial without an arg1 puzzle: the acw_tc
                    # cookie just handed to us is often enough on a retry.
                    # Datacenter IPs (GitHub runners) see this where a home IP
                    # gets clean JSON, so retry rather than fail outright.
                    if (
                        not challenge
                        and is_html(text, response.headers)
                        and expects_json(request_headers)
                    ):
                        if attempt < attempts:
                            time.sleep(RETRY_BACKOFF_SECONDS * attempt)
                            continue

                    return response.status, response.headers, text
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    self._capture_set_cookie(exc.headers)
                    error_text = decode_body(
                        exc.read(), exc.headers, method, url
                    )
                    if is_html(error_text, exc.headers) and expects_json(
                        request_headers
                    ):
                        if looks_login_page(error_text):
                            raise self.expired(
                                f"{method} {url} 返回了登录页（HTTP {exc.code}）"
                            ) from exc
                        if attempt < attempts:
                            time.sleep(RETRY_BACKOFF_SECONDS * attempt)
                            continue
                        raise WafBlockedError(
                            f"{method} {url} 返回了 HTML 而不是 JSON"
                            f"（HTTP {exc.code}）：请求很可能被 WAF 拦截；"
                            "可稍后重试或改用自建 runner"
                        ) from exc
                    raise self.expired(f"{method} {url} 返回 HTTP {exc.code}") from exc
                retryable = exc.code == 429 or 500 <= exc.code < 600
                if not retryable or attempt >= attempts:
                    raise CheckinError(
                        f"{method} {url} failed with HTTP {exc.code}"
                    ) from exc
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt >= attempts:
                    reason = getattr(exc, "reason", exc)
                    raise CheckinError(f"{method} {url} failed: {reason}") from exc

            time.sleep(2 ** (attempt - 1))

        raise CheckinError(f"{method} {url} failed after {attempts} attempts")

    def request_json(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
        attempts: int = MAX_ATTEMPTS,
    ) -> dict[str, Any]:
        status, response_headers, text = self.request_raw(
            url, method=method, headers=headers, payload=payload, attempts=attempts
        )
        try:
            result = json.loads(text)
        except json.JSONDecodeError as exc:
            content_type = response_headers.get("Content-Type", "unknown")
            if is_html(text, response_headers):
                if looks_login_page(text):
                    raise self.expired(
                        f"{method} {url} 返回了登录页而不是 JSON"
                    ) from exc
                # Distinguish a WAF interstitial from an actual login wall:
                # blaming the cookie for a WAF block sends the user chasing
                # the wrong fix.
                raise WafBlockedError(
                    f"{method} {url} 返回了 HTML 而不是 JSON（HTTP {status}）："
                    "请求很可能被阿里云 WAF 拦截。GitHub Actions 的机房 IP 比家用 IP "
                    "更容易触发，可稍后重试或改用自建 runner"
                ) from exc
            raise CheckinError(
                f"{method} {url} returned non-JSON content "
                f"(HTTP {status}, Content-Type: {content_type})"
            ) from exc
        if not isinstance(result, dict):
            raise CheckinError(f"{method} {url} returned a non-object JSON value")
        if result.get("success") is not True:
            message = str(result.get("message") or "")
            if looks_unauthenticated(text, message):
                raise self.expired(message or "接口拒绝了当前凭证")
        return result


def decode_body(raw: bytes, headers: Any, method: str, url: str) -> str:
    if headers.get("Content-Encoding", "").lower() == "gzip":
        try:
            raw = gzip.decompress(raw)
        except (OSError, EOFError) as exc:
            raise CheckinError(f"{method} {url} returned invalid gzip data") from exc
    charset = headers.get_content_charset() or "utf-8"
    try:
        return raw.decode(charset)
    except (LookupError, UnicodeDecodeError):
        return raw.decode("utf-8", errors="replace")


def quota_text(value: int, per_unit: Decimal = QUOTA_PER_USD) -> str:
    usd = Decimal(value) / per_unit
    return f"{value} (${usd.quantize(Decimal('0.01'))})"


def as_checkin_error(exc: Exception) -> CheckinError:
    if isinstance(exc, CheckinError):
        return exc
    return CheckinError(f"Unexpected {type(exc).__name__}: {exc}")


@dataclass
class Account:
    label: str
    suffix: str
    values: dict[str, str]


@dataclass
class AccountReport:
    label: str
    title: str = ""
    lines: list[str] = field(default_factory=list)
    # True: bonus granted. False: authenticated but no bonus (already claimed).
    # None: no check-in was attempted, quota was only read.
    checked_in: bool | None = None
    # Non-empty means the user must act (cookie expired, relay broke).
    warning: str = ""

    def text(self) -> str:
        return "\n".join([f"【{self.label}】{self.title}", *self.lines])


def discover_env_accounts(site: str, prefix: str, keys: tuple[str, ...]) -> list[Account]:
    """Collect numbered account groups from the environment.

    Detects the un-numbered `<PREFIX>_<KEY>` group plus every numbered
    `<PREFIX>_<KEY><n>` group. Which keys are mandatory is up to the provider,
    since the two sites need different combinations.
    """
    alternation = "|".join(re.escape(key) for key in sorted(keys, key=len, reverse=True))
    pattern = re.compile(rf"^{re.escape(prefix)}_({alternation})(\d*)$")
    suffixes: set[str] = set()
    for name, value in os.environ.items():
        match = pattern.match(name)
        if match and value.strip():
            suffixes.add(match.group(2))

    accounts: list[Account] = []
    for suffix in sorted(suffixes, key=lambda s: (s != "", int(s) if s else 0)):
        values = {
            key: os.environ.get(f"{prefix}_{key}{suffix}", "").strip() for key in keys
        }
        label = f"{site} 账号{suffix}" if suffix else f"{site} 账号"
        accounts.append(Account(label=label, suffix=suffix, values=values))
    return accounts


class Provider:
    name = ""
    env_prefix = ""
    env_keys: tuple[str, ...] = ()

    def accounts(self) -> list[Account]:
        return discover_env_accounts(self.name, self.env_prefix, self.env_keys)

    def run(self, account: Account) -> AccountReport:
        raise NotImplementedError


class AnyRouterProvider(Provider):
    """anyrouter.top: a real check-in endpoint, driven by a session cookie."""

    name = "AnyRouter"
    env_prefix = "ANYROUTER"
    env_keys = ("USER_ID", "COOKIE")

    def accounts(self) -> list[Account]:
        accounts = super().accounts()
        for account in accounts:
            for key in self.env_keys:
                if not account.values.get(key):
                    raise CheckinError(
                        f"账号配置不完整：缺少 {self.env_prefix}_{key}{account.suffix}"
                    )
        return accounts

    def headers(self, session: Session, user_id: str) -> dict[str, str]:
        return {
            "New-API-User": user_id,
            "Accept": "application/json",
            "Cache-Control": "no-store",
            "User-Agent": USER_AGENT,
        }

    def get_user(self, session: Session, user_id: str) -> dict[str, Any]:
        result = session.request_json(
            f"{ANYROUTER_BASE_URL}/api/user/self",
            headers=self.headers(session, user_id),
        )
        if result.get("success") is not True or not isinstance(result.get("data"), dict):
            message = str(result.get("message") or "unknown server response")
            raise CheckinError(f"读取 AnyRouter 用户信息失败：{message}")
        return result["data"]

    def check_in(self, session: Session, user_id: str) -> dict[str, Any]:
        result = session.request_json(
            f"{ANYROUTER_BASE_URL}/api/user/sign_in",
            method="POST",
            headers=self.headers(session, user_id),
        )
        if result.get("success") is not True:
            message = str(result.get("message") or "unknown server response")
            raise CheckinError(f"AnyRouter 签到失败：{message}")
        return result

    def run(self, account: Account) -> AccountReport:
        user_id = account.values["USER_ID"]
        session = Session(
            base_cookie=account.values["COOKIE"],
            cookie_env=f"{self.env_prefix}_COOKIE{account.suffix}",
        )

        before = self.get_user(session, user_id)
        checkin_result = self.check_in(session, user_id)
        after = self.get_user(session, user_id)

        before_quota = int(before.get("quota", 0))
        after_quota = int(after.get("quota", 0))
        username = str(after.get("display_name") or after.get("username") or "Unknown")
        message = str(checkin_result.get("message") or "签到接口返回成功")

        return AccountReport(
            label=account.label,
            title=username,
            lines=[
                f"签到结果：{message}",
                f"签到前额度：{quota_text(before_quota)}",
                f"当前额度：{quota_text(after_quota)}",
                f"额度变化：{quota_text(after_quota - before_quota)}",
            ],
            checked_in=True,
        )


class HttpApi:
    """Plain urllib transport for New-API sites.

    Auth is a Bearer personal access token (preferred) or a JWT minted from
    a refresh cookie. Raises WafBlockedError when Cloudflare interposes, so
    the caller can switch to BrowserApi.
    """

    transport_name = "http"

    def __init__(
        self,
        session: Session,
        base_url: str,
        token: str = "",
        user_id: str = "",
    ) -> None:
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.user_id = user_id

    def headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Cache-Control": "no-store",
            "User-Agent": USER_AGENT,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.user_id:
            headers["New-Api-User"] = self.user_id
        return headers

    def request(self, method: str, path: str, payload: dict | None = None) -> dict:
        return self.session.request_json(
            self.base_url + path,
            method=method,
            headers=self.headers(),
            payload=payload,
        )

    def refresh_token(self) -> None:
        result = self.request("POST", "/api/user/auth/refresh")
        token = str((result.get("data") or {}).get("access_token") or "")
        if result.get("success") is not True or not token:
            raise self.session.expired(
                str(result.get("message") or "刷新响应缺少 access_token")
            )
        self.token = token

    def mint_turnstile(self, sitekey: str) -> str:
        raise TurnstileRequiredError("站点要求 Turnstile 校验，HTTP 通道无法生成令牌")

    def close(self) -> None:
        pass


TURNSTILE_MINT_JS = """
async (sitekey) => {
  if (!window.turnstile) {
    await new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      script.onload = resolve;
      script.onerror = () => reject(new Error('Turnstile 脚本加载失败'));
      document.head.appendChild(script);
      setTimeout(() => reject(new Error('Turnstile 脚本加载超时')), 20000);
    });
  }
  const holder = document.createElement('div');
  document.body.appendChild(holder);
  try {
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('等待 Turnstile 令牌超时')), 45000);
      window.turnstile.render(holder, {
        sitekey: sitekey,
        callback: (value) => { clearTimeout(timer); resolve(value); },
        'error-callback': (code) => { clearTimeout(timer); reject(new Error('Turnstile 错误码: ' + code)); },
        'expired-callback': () => { clearTimeout(timer); reject(new Error('Turnstile 令牌已过期')); },
      });
    });
  } finally {
    holder.remove();
  }
}
"""

BROWSER_FETCH_JS = """
async ({path, method, token, userId, payload}) => {
  const headers = {Accept: 'application/json'};
  if (token) headers['Authorization'] = 'Bearer ' + token;
  if (userId) headers['New-Api-User'] = userId;
  let body;
  if (payload !== null && payload !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(payload);
  }
  const response = await fetch(path, {
    method: method, headers: headers, body: body, credentials: 'include',
  });
  const text = await response.text();
  return {status: response.status, text: text};
}
"""


class BrowserApi:
    """Real-Chrome-over-CDP transport (playwright chromium fallback).

    The browser is only started when needed (site blocked HTTP or the
    check-in POST requires Turnstile). API calls run as same-origin fetches
    inside the page, so Cloudflare cookies travel with them.

    A real Chrome binary launched as a plain subprocess (no automation
    flags, dedicated profile) and driven over the DevTools protocol keeps a
    clean fingerprint: Cloudflare serves its invisible managed challenge
    and Turnstile mints tokens non-interactively. Playwright-launched
    chromium gets an interactive challenge it can never pass, so it is only
    a fallback for environments without a Chrome install (CI).
    """

    transport_name = "browser"

    def __init__(
        self,
        session: Session,
        base_url: str,
        token: str = "",
        user_id: str = "",
        cookie: str = "",
    ) -> None:
        self._session = session
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.user_id = user_id
        self.cookie = cookie.strip()
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None
        self._chrome_proc: Any = None

    def request(self, method: str, path: str, payload: dict | None = None) -> dict:
        self._ensure_page()
        try:
            raw = self._page.evaluate(
                BROWSER_FETCH_JS,
                {
                    "path": path,
                    "method": method,
                    "token": self.token,
                    "userId": self.user_id,
                    "payload": payload,
                },
            )
        except Exception as exc:
            raise CheckinError(f"浏览器请求 {path} 失败：{exc}") from exc
        text = str(raw.get("text") or "")
        if is_html(text) and expects_json({"Accept": "application/json"}):
            if looks_login_page(text):
                raise self._session.expired(f"{method} {path} 返回了登录页")
            raise WafBlockedError(
                f"{method} {path} 返回了 HTML 而不是 JSON"
                f"（浏览器通道，HTTP {raw.get('status')}）"
            )
        try:
            result = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CheckinError(
                f"{method} {path} returned non-JSON content (HTTP {raw.get('status')})"
            ) from exc
        if not isinstance(result, dict):
            raise CheckinError(f"{method} {path} returned a non-object JSON value")
        if result.get("success") is not True and looks_unauthenticated(
            text, str(result.get("message") or "")
        ):
            raise self._session.expired(str(result.get("message") or "接口拒绝了当前凭证"))
        return result

    def refresh_token(self) -> None:
        self._ensure_page()
        result = self.request("POST", "/api/user/auth/refresh")
        token = str((result.get("data") or {}).get("access_token") or "")
        if result.get("success") is not True or not token:
            raise self._session.expired(
                str(result.get("message") or "刷新响应缺少 access_token")
            )
        self.token = token

    def mint_turnstile(self, sitekey: str) -> str:
        self._ensure_page()
        last_error: Exception = CheckinError("未尝试")
        for attempt in range(2):
            if attempt:
                self._reload_page()
            try:
                token = self._page.evaluate(TURNSTILE_MINT_JS, sitekey)
            except Exception as exc:
                last_error = exc
                continue
            if token:
                return str(token)
            last_error = CheckinError("Turnstile 未返回令牌")
        raise CheckinError(f"Turnstile 令牌获取失败：{last_error}")

    def close(self) -> None:
        for resource in (self._browser, self._playwright):
            try:
                if resource is not None:
                    resource.close()
            except Exception:
                pass
        try:
            if self._playwright is not None:
                self._playwright.stop()
        except Exception:
            pass
        if self._chrome_proc is not None:
            try:
                self._chrome_proc.terminate()
                self._chrome_proc.wait(timeout=10)
            except Exception:
                try:
                    self._chrome_proc.kill()
                except Exception:
                    pass
        self._page = self._context = self._browser = self._playwright = None
        self._chrome_proc = None

    def _ensure_page(self) -> None:
        if self._page is not None:
            return
        sync_playwright = _load_playwright()
        self._playwright = sync_playwright().start()
        chrome_exe = _find_chrome()
        if chrome_exe:
            try:
                self._launch_real_chrome(chrome_exe)
            except Exception:
                self._teardown_browser()
                self._launch_playwright_chromium()
        else:
            # No real Chrome (CI runner): headed chromium under xvfb.
            self._launch_playwright_chromium()
        if self.cookie:
            self._context.add_cookies(self._context_cookies())
        self._page = self._context.new_page()
        self._page.goto(
            self.base_url + "/",
            wait_until="domcontentloaded",
            timeout=BROWSER_NAV_TIMEOUT_MS,
        )
        self._wait_cloudflare_settled()

    def _launch_real_chrome(self, chrome_exe: str) -> None:
        profile = os.environ.get("CHECKIN_CHROME_PROFILE") or os.path.join(
            tempfile.gettempdir(), "checkin-chrome-profile"
        )
        os.makedirs(profile, exist_ok=True)
        port = _free_port()
        self._chrome_proc = subprocess.Popen(
            [
                chrome_exe,
                f"--remote-debugging-port={port}",
                f"--user-data-dir={profile}",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-session-crashed-bubble",
                "--window-size=1280,800",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        endpoint = f"http://127.0.0.1:{port}"
        deadline = time.time() + 30
        last_error: Exception = CheckinError("未尝试")
        while time.time() < deadline:
            if self._chrome_proc.poll() is not None:
                raise CheckinError("Chrome 进程提前退出")
            try:
                self._browser = self._playwright.chromium.connect_over_cdp(
                    endpoint, timeout=3000
                )
                break
            except Exception as exc:
                last_error = exc
                time.sleep(0.6)
        else:
            raise CheckinError(f"连接 Chrome DevTools 失败：{last_error}")
        if self._browser.contexts:
            self._context = self._browser.contexts[0]
        else:
            self._context = self._browser.new_context()

    def _launch_playwright_chromium(self) -> None:
        # Under xvfb (CI) DISPLAY exists and a headed browser passes
        # Cloudflare/Turnstile more reliably; headless elsewhere.
        headless = not os.environ.get("DISPLAY")
        launch_args = ["--disable-blink-features=AutomationControlled"]
        try:
            self._browser = self._playwright.chromium.launch(
                channel="chrome", headless=headless, args=launch_args
            )
        except Exception:
            self._browser = self._playwright.chromium.launch(
                headless=headless, args=launch_args
            )
        self._context = self._browser.new_context(
            user_agent=USER_AGENT,
            locale="zh-CN",
            timezone_id="Asia/Shanghai",
            viewport={"width": 1280, "height": 800},
        )

    def _teardown_browser(self) -> None:
        for resource in (self._browser, self._playwright):
            try:
                if resource is not None:
                    resource.close()
            except Exception:
                pass
        try:
            if self._playwright is not None:
                self._playwright.stop()
        except Exception:
            pass
        if self._chrome_proc is not None:
            try:
                self._chrome_proc.terminate()
            except Exception:
                pass
        self._page = self._context = self._browser = self._playwright = None
        self._chrome_proc = None

    def _reload_page(self) -> None:
        self._page.reload(
            wait_until="domcontentloaded", timeout=BROWSER_NAV_TIMEOUT_MS
        )
        self._wait_cloudflare_settled()

    def _wait_cloudflare_settled(self) -> None:
        deadline = time.time() + CF_SETTLE_SECONDS
        while time.time() < deadline:
            try:
                title = (self._page.title() or "").strip().lower()
            except Exception:
                title = "unknown"
            if title and not any(
                marker in title
                for marker in ("just a moment", "attention required", "请稍候")
            ):
                return
            self._page.wait_for_timeout(1500)

    def _context_cookies(self) -> list[dict[str, Any]]:
        host = urllib.parse.urlparse(self.base_url).hostname or ""
        if "=" in self.cookie:
            pairs = [pair.strip() for pair in self.cookie.split(";") if "=" in pair]
            return [
                {
                    "name": name.strip(),
                    "value": value.strip(),
                    "domain": host,
                    "path": "/",
                    "secure": True,
                }
                for name, value in (pair.split("=", 1) for pair in pairs)
            ]
        return [
            {
                "name": "new_api_refresh",
                "value": self.cookie,
                "domain": host,
                "path": "/",
                "secure": True,
            }
        ]


def _load_playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise CheckinError(
            "需要 playwright 浏览器通道：先 pip install playwright，"
            "再 python -m playwright install chromium"
        ) from exc
    return sync_playwright


def _find_chrome() -> str:
    """Locate a real Chrome install; empty string when none exists."""
    candidates = [
        os.environ.get("CHECKIN_CHROME_PATH", ""),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return ""


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class NewApiCheckinProvider(Provider):
    """New-API v1 sites: GET/POST /api/user/checkin with token or cookie auth.

    The POST accepts a Turnstile token as a query parameter when the site
    enables Turnstile; tokens are single-use, so each attempt mints a fresh
    one. HTTP is preferred; the browser is started only when Cloudflare
    blocks it or Turnstile must be minted.
    """

    def __init__(self, display_name: str, base_url: str, env_prefix: str) -> None:
        self.name = display_name
        self.base_url = base_url.rstrip("/")
        self.env_prefix = env_prefix
        self.env_keys = ("TOKEN", "COOKIE", "USER_ID")

    def accounts(self) -> list[Account]:
        accounts = discover_env_accounts(self.name, self.env_prefix, self.env_keys)
        for account in accounts:
            if not account.values.get("TOKEN") and not account.values.get("COOKIE"):
                raise CheckinError(
                    f"账号配置不完整：{account.label} 需要 "
                    f"{self.env_prefix}_TOKEN{account.suffix}"
                    f"（推荐，站点「个人设置 → 系统访问令牌」生成）"
                    f"或 {self.env_prefix}_COOKIE{account.suffix}，"
                    f"只配置 {self.env_prefix}_USER_ID{account.suffix} 无法登录"
                )
        return accounts

    def run(self, account: Account) -> AccountReport:
        token = account.values.get("TOKEN", "")
        cookie = account.values.get("COOKIE", "")
        user_id = account.values.get("USER_ID", "")
        suffix = account.suffix
        token_env = f"{self.env_prefix}_TOKEN{suffix}"

        session = Session(
            base_cookie=cookie,
            cookie_env=token_env if token else f"{self.env_prefix}_COOKIE{suffix}",
            expiry_hint=(
                f"请到站点「个人设置 → 系统访问令牌」重新生成 {token_env}"
                if token
                else ""
            ),
        )
        api: Any = HttpApi(session, self.base_url, token=token, user_id=user_id)
        try:
            try:
                config = self._site_config(api)
            except WafBlockedError:
                api = self._ensure_browser(api, session, token, user_id, cookie)
                config = self._site_config(api)

            if config["checkin_enabled"] is False:
                return AccountReport(
                    label=account.label,
                    title="签到功能未启用",
                    lines=["站点 checkin_enabled=false，跳过签到"],
                    checked_in=None,
                )

            if cookie and not token:
                api.refresh_token()

            checkin_data = self._get_checkin_data(api)
            if checkin_data is None:
                return AccountReport(
                    label=account.label,
                    title="签到功能未启用",
                    lines=["站点未开启签到（接口返回未启用）"],
                    checked_in=None,
                )
            stats = checkin_data.get("stats") or {}
            if stats.get("checked_in_today"):
                user = api.request("GET", "/api/user/self")
                return self._already_report(account, user, stats, config)

            before_user = api.request("GET", "/api/user/self")
            try:
                result = self._do_checkin(api, config)
            except TurnstileRequiredError:
                api = self._ensure_browser(api, session, token, user_id, cookie)
                result = self._do_checkin(api, config)

            if result.get("success") is not True:
                message = str(result.get("message") or "")
                if "已签到" in message:
                    return self._already_report(
                        account, before_user, stats, config, message
                    )
                raise CheckinError(f"{self.name} 签到失败：{message}")

            try:
                final_stats = (self._get_checkin_data(api) or {}).get("stats") or stats
            except CheckinError:
                final_stats = stats
            try:
                after_user = api.request("GET", "/api/user/self")
            except CheckinError:
                after_user = before_user
            return self._success_report(
                account, result, before_user, after_user, final_stats, config
            )
        finally:
            api.close()

    def _ensure_browser(
        self,
        api: Any,
        session: Session,
        token: str,
        user_id: str,
        cookie: str,
    ) -> Any:
        if api.transport_name == "browser":
            return api
        browser = BrowserApi(
            session,
            self.base_url,
            token=getattr(api, "token", "") or token,
            user_id=user_id,
            cookie=cookie,
        )
        api.close()
        if cookie and not browser.token:
            browser.refresh_token()
        return browser

    def _site_config(self, api: Any) -> dict[str, Any]:
        result = api.request("GET", "/api/status")
        if result.get("success") is not True:
            raise CheckinError(
                f"读取 {self.name} 站点配置失败：{result.get('message') or 'unknown response'}"
            )
        data = result.get("data") or {}
        enabled = data.get("checkin_enabled")
        try:
            per_unit = Decimal(str(data.get("quota_per_unit") or QUOTA_PER_USD))
        except Exception:
            per_unit = QUOTA_PER_USD
        return {
            "checkin_enabled": None if enabled is None else bool(enabled),
            "turnstile": bool(data.get("turnstile_check")),
            "sitekey": str(data.get("turnstile_site_key") or ""),
            "quota_per_unit": per_unit,
        }

    def _get_checkin_data(self, api: Any) -> dict[str, Any] | None:
        result = api.request("GET", "/api/user/checkin")
        if result.get("success") is not True:
            message = str(result.get("message") or "")
            if "未启用" in message:
                return None
            raise CheckinError(f"读取签到状态失败：{message}")
        return result.get("data") or {}

    def _do_checkin(self, api: Any, config: dict[str, Any]) -> dict[str, Any]:
        if config["turnstile"] and not config["sitekey"]:
            raise CheckinError(
                "站点开启了 Turnstile 但 /api/status 未返回 sitekey，无法自动签到"
            )
        last_message = ""
        for _ in range(CHECKIN_ATTEMPTS):
            path = "/api/user/checkin"
            if config["turnstile"]:
                turnstile_token = api.mint_turnstile(config["sitekey"])
                path += "?turnstile=" + urllib.parse.quote(turnstile_token)
            result = api.request("POST", path)
            if result.get("success") is True:
                return result
            message = str(result.get("message") or "")
            last_message = message
            if "已签到" in message:
                return result
            if "turnstile" in message.lower():
                continue
            raise CheckinError(f"{self.name} 签到失败：{message}")
        raise CheckinError(
            f"{self.name} 签到失败（重试 {CHECKIN_ATTEMPTS} 次后）：{last_message}"
        )

    def _already_report(
        self,
        account: Account,
        user: dict[str, Any],
        stats: dict[str, Any],
        config: dict[str, Any],
        message: str = "今日已签到",
    ) -> AccountReport:
        data = user.get("data") or {}
        per_unit = config["quota_per_unit"]
        quota = int(data.get("quota") or 0)
        lines = [
            f"签到结果：{message}",
            f"当前额度：{quota_text(quota, per_unit)}",
            f"本月已签 {stats.get('checkin_count', 0)} 天；"
            f"累计签到 {stats.get('total_checkins', 0)} 次，"
            f"累计获得 {quota_text(int(stats.get('total_quota') or 0), per_unit)}",
        ]
        return AccountReport(
            label=account.label,
            title=str(data.get("display_name") or data.get("username") or "Unknown"),
            lines=lines,
            checked_in=False,
        )

    def _success_report(
        self,
        account: Account,
        result: dict[str, Any],
        before_user: dict[str, Any],
        after_user: dict[str, Any],
        stats: dict[str, Any],
        config: dict[str, Any],
    ) -> AccountReport:
        per_unit = config["quota_per_unit"]
        data = result.get("data") or {}
        awarded = int(data.get("quota_awarded") or 0)
        before_quota = int((before_user.get("data") or {}).get("quota") or 0)
        after_quota = int((after_user.get("data") or {}).get("quota") or 0)
        after_data = after_user.get("data") or {}
        lines = [
            f"签到结果：{result.get('message') or '签到成功'}",
            f"获得额度：{quota_text(awarded, per_unit)}",
            f"额度变化：{quota_text(before_quota, per_unit)}"
            f" → {quota_text(after_quota, per_unit)}",
            f"累计签到 {stats.get('total_checkins', '?')} 次，"
            f"累计获得 {quota_text(int(stats.get('total_quota') or 0), per_unit)}",
        ]
        return AccountReport(
            label=account.label,
            title=str(
                after_data.get("display_name")
                or after_data.get("username")
                or "Unknown"
            ),
            lines=lines,
            checked_in=True,
        )


PROVIDERS: tuple[Provider, ...] = (AnyRouterProvider(),) + tuple(
    NewApiCheckinProvider(name, base_url, prefix)
    for name, base_url, prefix in NEW_API_SITES
)


def send_pushplus(token: str, title: str, content: str) -> None:
    result = Session().request_json(
        PUSHPLUS_URL,
        method="POST",
        payload={
            "token": token,
            "title": title,
            "content": content,
            "template": "txt",
        },
    )
    # PushPlus normally uses code=200 for success.
    if result.get("code") != 200:
        message = str(result.get("msg") or result.get("message") or "unknown response")
        raise CheckinError(f"PushPlus 推送失败：{message}")


def now_text() -> str:
    return datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")


def run() -> tuple[bool, str, str]:
    pending: list[tuple[Provider, Account]] = []
    for provider in PROVIDERS:
        for account in provider.accounts():
            pending.append((provider, account))

    if not pending:
        raise CheckinError(
            "未配置任何账号：请设置 ANYROUTER_USER_ID/ANYROUTER_COOKIE，"
            "或 JUSTWOKER_TOKEN / GOROUTER_TOKEN / TABITOKEN_TOKEN"
            "（也支持编号后缀，如 JUSTWOKER_TOKEN1）"
        )

    sections = [f"执行时间：{now_text()}（北京时间）"]
    warnings: list[str] = []
    failures = 0
    not_checked_in = 0

    for provider, account in pending:
        try:
            report = provider.run(account)
            sections.append(report.text())
            if report.checked_in is None:
                not_checked_in += 1
            if report.warning:
                warnings.append(report.warning)
        except Exception as exc:
            failures += 1
            safe_error = as_checkin_error(exc)
            print(f"ERROR [{account.label}]: {safe_error}", file=sys.stderr)
            sections.append(f"【{account.label}】签到失败\n失败原因：{safe_error}")

    total = len(pending)
    if failures:
        title = f"每日签到：{total - failures} 成功 / {failures} 失败"
    elif not_checked_in:
        title = f"每日签到完成，但 {not_checked_in} 个账号未签到"
    elif total == 1:
        title = "每日签到成功"
    else:
        title = f"每日签到成功（{total} 个账号）"

    if warnings:
        sections.append("需要处理：\n" + "\n".join(f"- {item}" for item in warnings))

    return failures == 0, title, "\n\n".join(sections)


def main() -> int:
    pushplus_token = os.environ.get("PUSHPLUS_TOKEN", "").strip()
    try:
        if not pushplus_token:
            raise CheckinError("缺少必需的环境变量：PUSHPLUS_TOKEN")
        all_ok, title, content = run()
        print(title)
        print(content)
        send_pushplus(pushplus_token, title, content)
        print("PushPlus notification sent successfully.")
        return 0 if all_ok else 1
    except Exception as exc:
        safe_error = as_checkin_error(exc)
        title = "每日签到失败"
        content = f"执行时间：{now_text()}（北京时间）\n失败原因：{safe_error}"
        print(f"ERROR: {safe_error}", file=sys.stderr)
        if pushplus_token:
            try:
                send_pushplus(pushplus_token, title, content)
                print("Failure notification sent through PushPlus.")
            except Exception as notify_error:
                print(f"ERROR: {as_checkin_error(notify_error)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
