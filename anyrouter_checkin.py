#!/usr/bin/env python3
"""Daily AnyRouter check-in with PushPlus notification."""

from __future__ import annotations

import json
import gzip
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from decimal import Decimal
from typing import Any
from zoneinfo import ZoneInfo


ANYROUTER_BASE_URL = "https://anyrouter.top"
PUSHPLUS_URL = "https://www.pushplus.plus/send"
QUOTA_PER_USD = Decimal("500000")
TIMEOUT_SECONDS = 15
MAX_ATTEMPTS = 3
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/150.0.0.0 Safari/537.36"
)
ACW_POSITIONS = [
    15, 35, 29, 24, 33, 16, 1, 38, 10, 9, 19, 31, 40, 27, 22, 23, 25, 13,
    6, 11, 39, 18, 20, 8, 14, 21, 32, 26, 2, 30, 7, 4, 17, 5, 3, 28, 34,
    37, 12, 36,
]
ACW_XOR_KEY = "3000176000856006061501533003690027800375"
_acw_cookie = ""


class CheckinError(RuntimeError):
    """A user-facing error that is safe to print in CI logs."""


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise CheckinError(f"Missing required environment variable: {name}")
    return value


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
    attempts: int = MAX_ATTEMPTS,
) -> dict[str, Any]:
    body = None
    request_headers = dict(headers or {})
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json; charset=utf-8")

    challenge_retried = False
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            url, data=body, headers=request_headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                raw = response.read()
                if response.headers.get("Content-Encoding", "").lower() == "gzip":
                    try:
                        raw = gzip.decompress(raw)
                    except (OSError, EOFError) as exc:
                        raise CheckinError(f"{method} {url} returned invalid gzip data") from exc
                charset = response.headers.get_content_charset() or "utf-8"
                try:
                    text = raw.decode(charset)
                except (LookupError, UnicodeDecodeError):
                    text = raw.decode("utf-8", errors="replace")

                challenge = re.search(r"var arg1='([0-9A-Fa-f]{40})'", text)
                if challenge and not challenge_retried:
                    global _acw_cookie
                    _acw_cookie = solve_acw_cookie(challenge.group(1))
                    request_headers["Cookie"] = merge_cookie(
                        request_headers.get("Cookie", ""), "acw_sc__v2", _acw_cookie
                    )
                    challenge_retried = True
                    continue
                try:
                    result = json.loads(text)
                except json.JSONDecodeError as exc:
                    content_type = response.headers.get("Content-Type", "unknown")
                    raise CheckinError(
                        f"{method} {url} returned non-JSON content "
                        f"(HTTP {response.status}, Content-Type: {content_type})"
                    ) from exc
                if not isinstance(result, dict):
                    raise CheckinError(f"{method} {url} returned a non-object JSON value")
                return result
        except urllib.error.HTTPError as exc:
            retryable = exc.code == 429 or 500 <= exc.code < 600
            if not retryable or attempt == attempts:
                raise CheckinError(f"{method} {url} failed with HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == attempts:
                reason = getattr(exc, "reason", exc)
                raise CheckinError(f"{method} {url} failed: {reason}") from exc

        time.sleep(2 ** (attempt - 1))

    raise CheckinError(f"{method} {url} failed after {attempts} attempts")


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


def anyrouter_headers(user_id: str, login_cookie: str) -> dict[str, str]:
    headers = {
        "New-API-User": user_id,
        "Accept": "application/json",
        "Cache-Control": "no-store",
        "User-Agent": USER_AGENT,
    }
    if login_cookie:
        headers["Cookie"] = login_cookie
    if _acw_cookie:
        headers["Cookie"] = merge_cookie(
            headers.get("Cookie", ""), "acw_sc__v2", _acw_cookie
        )
    return headers


def get_user(user_id: str, login_cookie: str) -> dict[str, Any]:
    result = request_json(
        f"{ANYROUTER_BASE_URL}/api/user/self",
        headers=anyrouter_headers(user_id, login_cookie),
    )
    if result.get("success") is not True or not isinstance(result.get("data"), dict):
        message = str(result.get("message") or "unknown server response")
        raise CheckinError(f"Failed to read AnyRouter user information: {message}")
    return result["data"]


def check_in(user_id: str, login_cookie: str) -> dict[str, Any]:
    result = request_json(
        f"{ANYROUTER_BASE_URL}/api/user/sign_in",
        method="POST",
        headers=anyrouter_headers(user_id, login_cookie),
    )
    if result.get("success") is not True:
        message = str(result.get("message") or "unknown server response")
        raise CheckinError(f"AnyRouter check-in failed: {message}")
    return result


def quota_text(value: int) -> str:
    usd = Decimal(value) / QUOTA_PER_USD
    return f"{value} (${usd.quantize(Decimal('0.01'))})"


def send_pushplus(token: str, title: str, content: str) -> None:
    result = request_json(
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
        raise CheckinError(f"PushPlus notification failed: {message}")


def run() -> tuple[str, str]:
    user_id = required_env("ANYROUTER_USER_ID")
    login_cookie = required_env("ANYROUTER_COOKIE")
    before = get_user(user_id, login_cookie)
    checkin_result = check_in(user_id, login_cookie)
    after = get_user(user_id, login_cookie)

    before_quota = int(before.get("quota", 0))
    after_quota = int(after.get("quota", 0))
    delta = after_quota - before_quota
    username = str(after.get("display_name") or after.get("username") or "Unknown")
    message = str(checkin_result.get("message") or "签到接口返回成功")
    executed_at = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")

    title = "AnyRouter 每日签到成功"
    content = "\n".join(
        [
            f"执行时间：{executed_at}（北京时间）",
            f"账号：{username}",
            f"签到结果：{message}",
            f"签到前额度：{quota_text(before_quota)}",
            f"当前额度：{quota_text(after_quota)}",
            f"额度变化：{quota_text(delta)}",
        ]
    )
    return title, content


def main() -> int:
    pushplus_token = os.environ.get("PUSHPLUS_TOKEN", "").strip()
    try:
        if not pushplus_token:
            raise CheckinError("Missing required environment variable: PUSHPLUS_TOKEN")
        title, content = run()
        print(title)
        print(content)
        send_pushplus(pushplus_token, title, content)
        print("PushPlus notification sent successfully.")
        return 0
    except Exception as exc:
        safe_error = exc if isinstance(exc, CheckinError) else CheckinError(
            f"Unexpected {type(exc).__name__}: {exc}"
        )
        executed_at = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
        title = "AnyRouter 每日签到失败"
        content = f"执行时间：{executed_at}（北京时间）\n失败原因：{safe_error}"
        print(f"ERROR: {safe_error}", file=sys.stderr)
        if pushplus_token:
            try:
                send_pushplus(pushplus_token, title, content)
                print("Failure notification sent through PushPlus.")
            except Exception as notify_error:
                safe_notify_error = (
                    notify_error
                    if isinstance(notify_error, CheckinError)
                    else CheckinError(type(notify_error).__name__)
                )
                print(f"ERROR: {safe_notify_error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
