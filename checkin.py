#!/usr/bin/env python3
"""Daily check-in for AnyRouter and AgentRouter with PushPlus notification.

The two sites are both New-API forks but grant the daily bonus differently:

* AnyRouter exposes `POST /api/user/sign_in`, so a saved session cookie is enough.
* AgentRouter has no check-in endpoint at all. The bonus is a side effect of
  authenticating (the server's `DailyCheckinQuota` option), reported back as
  `data.checked_in`. A session cookie therefore cannot trigger it -- it already
  means "logged in" -- so we replay an OAuth flow (LinuxDO `/api/oauth/linuxdo`
  or GitHub `/api/oauth/github`, the channel captured in the HAR) to
  re-authenticate.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import sys
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
AGENTROUTER_BASE_URL = "https://agentrouter.org"
AGENTROUTER_FALLBACK_BASE_URL = "https://ps.air-outer.com"
LINUXDO_AUTHORIZE_URL = "https://connect.linux.do/oauth2/authorize"
GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
# Login cookies to keep when replaying OAuth on github.com / connect.linux.do.
# GitHub's user_session is the auth cookie; _gh_sess is the CSRF-coupled
# session cookie. LinuxDO login is represented by auth.session-token.
LINUXDO_SESSION_COOKIE_NAMES = {"auth.session-token"}
GITHUB_SESSION_COOKIE_NAMES = {
    "user_session",
    "__Host-user_session_same_site",
    "_gh_sess",
    "logged_in",
}
PUSHPLUS_URL = "https://www.pushplus.plus/send"
# Both sites report quota_per_unit = 500000 in /api/status.
QUOTA_PER_USD = Decimal("500000")
TIMEOUT_SECONDS = 15
MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 1
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/150.0.0.0 Safari/537.36"
)
# Aliyun WAF challenge, served by both sites.
ACW_POSITIONS = [
    15, 35, 29, 24, 33, 16, 1, 38, 10, 9, 19, 31, 40, 27, 22, 23, 25, 13,
    6, 11, 39, 18, 20, 8, 14, 21, 32, 26, 2, 30, 7, 4, 17, 5, 3, 28, 34,
    37, 12, 36,
]
ACW_XOR_KEY = "3000176000856006061501533003690027800375"
AUTH_FAILURE_HINTS = ("未登录", "无权", "登录已过期", "token 无效", "无效的 token")

class CheckinError(RuntimeError):
    """A user-facing error that is safe to print in CI logs."""


class WafBlockedError(CheckinError):
    """The endpoint returned an HTML interstitial instead of its API JSON."""


class CookieExpiredError(CheckinError):
    """A configured cookie is no longer valid and must be re-copied."""


class RelayError(CheckinError):
    """The AgentRouter OAuth relay could not complete; caller may degrade."""


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


def select_cookie(cookie: str, allowed_names: set[str]) -> str:
    """Keep only stable cookies needed by a cross-network auth request."""
    selected: list[str] = []
    for part in cookie.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name = part.split("=", 1)[0].strip()
        if name in allowed_names:
            selected.append(part)
    return "; ".join(selected)


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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface 3xx responses instead of following them.

    The OAuth relay needs the `code` query parameter out of the Location
    header; letting urllib follow the hop would lose it.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class Session:
    """Per-account HTTP state: cookies stay isolated between accounts.

    The AgentRouter relay also depends on this: the `session` cookie handed
    out with the OAuth state token must be sent back on the callback, because
    the server validates the state against it.
    """

    base_cookie: str = ""
    # Names the env var this cookie came from, so expiry errors can point at it.
    cookie_env: str = ""
    extra_cookies: dict[str, str] = field(default_factory=dict)

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
        target = self.cookie_env or "对应的 Cookie 环境变量"
        return CookieExpiredError(f"{target} 已失效，请从浏览器重新复制（{detail}）")

    def request_raw(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
        attempts: int = MAX_ATTEMPTS,
        allow_redirects: bool = True,
    ) -> tuple[int, Any, str]:
        body = None
        request_headers = dict(headers or {})
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json; charset=utf-8")

        opener = urllib.request.build_opener(
            *([] if allow_redirects else [_NoRedirect])
        )
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
                if not allow_redirects and 300 <= exc.code < 400:
                    self._capture_set_cookie(exc.headers)
                    return exc.code, exc.headers, ""
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


def quota_text(value: int) -> str:
    usd = Decimal(value) / QUOTA_PER_USD
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


class AgentRouterProvider(Provider):
    """agentrouter.org: no check-in endpoint, the bonus rides on authentication.

    Preferred path replays an OAuth flow -- LinuxDO (/api/oauth/linuxdo) or
    GitHub (/api/oauth/github, the channel captured in the HAR) -- with the
    forum/GitHub login cookie to re-authenticate the account and grant the
    bonus. If that cannot complete (WAF, or an interactive consent screen), we
    fall back to reading the quota with the site cookie and say plainly that no
    check-in happened.
    """

    name = "AgentRouter"
    env_prefix = "AGENTROUTER"
    env_keys = ("USER_ID", "COOKIE", "LINUXDO_COOKIE", "GITHUB_COOKIE")

    def accounts(self) -> list[Account]:
        accounts = super().accounts()
        for account in accounts:
            configured = [
                key
                for key in ("COOKIE", "LINUXDO_COOKIE", "GITHUB_COOKIE")
                if account.values.get(key)
            ]
            if not configured:
                raise CheckinError(
                    f"账号配置不完整：{self.env_prefix}_COOKIE{account.suffix}、"
                    f"{self.env_prefix}_LINUXDO_COOKIE{account.suffix}、"
                    f"{self.env_prefix}_GITHUB_COOKIE{account.suffix} 至少要配一个"
                )
        return accounts

    def api_headers(
        self, user_id: str, base_url: str = AGENTROUTER_BASE_URL
    ) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Cache-Control": "no-store",
            "User-Agent": USER_AGENT,
            "Referer": f"{base_url}/console",
        }
        if user_id:
            headers["New-API-User"] = user_id
        return headers

    def request_json(
        self,
        session: Session,
        path: str,
        *,
        user_id: str = "",
    ) -> dict[str, Any]:
        """Use the official backup domain when the primary is WAF-blocked."""
        blocked: WafBlockedError | None = None
        for base_url in (AGENTROUTER_BASE_URL, AGENTROUTER_FALLBACK_BASE_URL):
            try:
                return session.request_json(
                    f"{base_url}{path}",
                    headers=self.api_headers(user_id, base_url),
                )
            except WafBlockedError as exc:
                blocked = exc
                continue
        assert blocked is not None
        raise blocked

    def get_user(self, session: Session, user_id: str) -> dict[str, Any]:
        result = self.request_json(session, "/api/user/self", user_id=user_id)
        if result.get("success") is not True or not isinstance(result.get("data"), dict):
            message = str(result.get("message") or "unknown server response")
            raise CheckinError(f"读取 AgentRouter 用户信息失败：{message}")
        return result["data"]

    def status_option(self, session: Session, key: str, label: str) -> str:
        result = self.request_json(session, "/api/status")
        data = result.get("data")
        value = ""
        if isinstance(data, dict):
            value = str(data.get(key) or "")
        if not value:
            raise RelayError(f"无法从 /api/status 读取 {label}")
        return value

    def linuxdo_client_id(self, session: Session) -> str:
        return self.status_option(session, "linuxdo_client_id", "linuxdo_client_id")

    def github_client_id(self, session: Session) -> str:
        return self.status_option(session, "github_client_id", "github_client_id")

    def oauth_state(self, session: Session) -> str:
        result = self.request_json(session, "/api/oauth/state?mode=login")
        state = str(result.get("data") or "")
        if result.get("success") is not True or not state:
            message = str(result.get("message") or "unknown server response")
            raise RelayError(f"获取 OAuth state 失败：{message}")
        return state

    def authorize_code(
        self, cookie: str, client_id: str, state: str, channel: str
    ) -> str:
        """Exchange a forum/GitHub login cookie for an authorization code.

        The authorize endpoint either redirects with ``code`` in the Location
        (the app is already approved) or shows a consent page. Both channels
        are replayed the same way; a non-redirect (consent page / WAF) raises
        RelayError so the caller can degrade gracefully.
        """
        if channel == "github":
            authorize_url = GITHUB_AUTHORIZE_URL
            query = urllib.parse.urlencode(
                {"client_id": client_id, "state": state, "scope": "user:email"}
            )
            stable_cookie = select_cookie(cookie, GITHUB_SESSION_COOKIE_NAMES)
            service = "GitHub"
            missing = "GitHub Cookie 中缺少登录会话（user_session/_gh_sess）"
        else:  # linuxdo
            authorize_url = LINUXDO_AUTHORIZE_URL
            query = urllib.parse.urlencode(
                {"response_type": "code", "client_id": client_id, "state": state}
            )
            stable_cookie = select_cookie(cookie, LINUXDO_SESSION_COOKIE_NAMES)
            service = "LinuxDO"
            missing = "LinuxDO Cookie 中缺少 auth.session-token"

        if not stable_cookie:
            raise RelayError(missing)

        # A dedicated session: the login cookie must never leak to AgentRouter.
        # Cloudflare clearance cookies are bound to the browser's IP and
        # fingerprint. GitHub Actions uses a different egress (WARP), so
        # replaying cf_clearance/_cfuvid there causes an immediate 403. The
        # LinuxDO login itself is represented by auth.session-token; GitHub by
        # its user_session cookie.
        forum = Session(base_cookie=stable_cookie, cookie_env=f"{service.upper()}_COOKIE")
        try:
            status, headers, _ = forum.request_raw(
                f"{authorize_url}?{query}",
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "cross-site",
                    "Upgrade-Insecure-Requests": "1",
                },
                attempts=1,
                allow_redirects=False,
            )
        except CookieExpiredError as exc:
            # 403 here is ambiguous: an expired cookie and a WAF/consent block
            # look identical from the outside. Say both.
            raise RelayError(
                f"{service} 授权被拒绝：{exc}。也可能是 WAF 拦截了脚本请求"
            ) from exc

        if not 300 <= status < 400:
            raise RelayError(
                f"{service} 授权未返回跳转（HTTP {status}）："
                "可能被 WAF 拦截，或需要在浏览器里手动授权一次"
            )
        location = headers.get("Location") or ""
        code = urllib.parse.parse_qs(
            urllib.parse.urlparse(location).query
        ).get("code", [""])[0]
        if not code:
            raise RelayError(f"{service} 跳转中没有 code 参数：{location or '(空 Location)'}")
        return code

    def relay_login(
        self, session: Session, cookie: str, channel: str
    ) -> dict[str, Any]:
        if channel == "github":
            client_id = self.github_client_id(session)
            oauth_path = "/api/oauth/github"
        else:  # linuxdo
            client_id = self.linuxdo_client_id(session)
            oauth_path = "/api/oauth/linuxdo"
        state = self.oauth_state(session)
        code = self.authorize_code(cookie, client_id, state, channel)
        query = urllib.parse.urlencode({"code": code, "state": state, "mode": "login"})
        result = self.request_json(session, f"{oauth_path}?{query}")
        if result.get("success") is not True:
            message = str(result.get("message") or "unknown server response")
            raise RelayError(f"OAuth 回调失败：{message}")
        data = result.get("data")
        return data if isinstance(data, dict) else {}

    def run(self, account: Account) -> AccountReport:
        user_id = account.values.get("USER_ID", "")
        site_cookie = account.values.get("COOKIE", "")
        channels: list[tuple[str, str, str]] = []
        if account.values.get("LINUXDO_COOKIE"):
            channels.append(("LinuxDO", "LINUXDO_COOKIE", "linuxdo"))
        if account.values.get("GITHUB_COOKIE"):
            channels.append(("GitHub", "GITHUB_COOKIE", "github"))

        relay_failures: list[str] = []
        if channels:
            for label, env_name, channel in channels:
                session = Session(
                    cookie_env=f"{self.env_prefix}_{env_name}{account.suffix}"
                )
                try:
                    logged_in = self.relay_login(
                        session, account.values[env_name], channel
                    )
                    checked_in = bool(logged_in.get("checked_in"))
                    # The relay session is authenticated; read quota through it.
                    user = self.get_user(session, user_id)
                    username = str(
                        user.get("display_name") or user.get("username") or "Unknown"
                    )
                    message = (
                        "签到成功，新增额度已到账" if checked_in else "登录成功，今日已签到过"
                    )
                    return AccountReport(
                        label=account.label,
                        title=username,
                        lines=[
                            f"签到结果：{message}",
                            f"当前额度：{quota_text(int(user.get('quota', 0)))}",
                        ],
                        checked_in=checked_in,
                    )
                except Exception as exc:
                    failure = f"{label}：{as_checkin_error(exc)}"
                    relay_failures.append(failure)
                    print(
                        f"WARNING [{account.label}]: {failure}",
                        file=sys.stderr,
                    )
            if not site_cookie:
                raise CheckinError(f"OAuth 签到中继失败：{'；'.join(relay_failures)}")

        # Degraded path: report quota only, and say so.
        session = Session(
            base_cookie=site_cookie,
            cookie_env=f"{self.env_prefix}_COOKIE{account.suffix}",
        )
        user = self.get_user(session, user_id)
        username = str(user.get("display_name") or user.get("username") or "Unknown")
        lines = ["签到结果：未签到（仅查询额度）"]
        if relay_failures:
            lines.append(f"中继失败原因：{'；'.join(relay_failures)}")
        else:
            lines.append(
                f"未配置 {self.env_prefix}_LINUXDO_COOKIE{account.suffix} 或 "
                f"{self.env_prefix}_GITHUB_COOKIE{account.suffix}，无法触发签到"
            )
        lines.append(f"当前额度：{quota_text(int(user.get('quota', 0)))}")

        return AccountReport(
            label=account.label,
            title=username,
            lines=lines,
            checked_in=None,
            warning=f"{account.label} 未完成签到",
        )


PROVIDERS: tuple[Provider, ...] = (AnyRouterProvider(), AgentRouterProvider())


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
            "未配置任何账号：请设置 ANYROUTER_USER_ID/ANYROUTER_COOKIE "
            "AGENTROUTER_LINUXDO_COOKIE 或 AGENTROUTER_GITHUB_COOKIE（也支持 ANYROUTER_USER_ID1 这类编号形式）"
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
