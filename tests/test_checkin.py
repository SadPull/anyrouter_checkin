import io
import unittest
import urllib.error
from email.message import Message
from unittest.mock import patch

import checkin


def response_headers(content_type="application/json; charset=utf-8", cookies=()):
    headers = Message()
    headers["Content-Type"] = content_type
    for cookie in cookies:
        headers["Set-Cookie"] = cookie
    return headers


class FakeResponse:
    def __init__(self, body, *, status=200, headers=None):
        self.status = status
        self.headers = headers or response_headers()
        self.body = body.encode("utf-8")

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class FakeOpener:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class SessionTests(unittest.TestCase):
    def run_with_opener(self, opener, callback):
        with patch("checkin.urllib.request.build_opener", return_value=opener), patch(
            "checkin.time.sleep"
        ):
            return callback()

    def test_html_response_retries_and_reuses_set_cookie(self):
        opener = FakeOpener(
            [
                FakeResponse(
                    "<html>interstitial</html>",
                    headers=response_headers(
                        "text/html; charset=utf-8", ("acw_tc=challenge; Path=/",)
                    ),
                ),
                FakeResponse('{"success": true, "data": {"id": 1}}'),
            ]
        )
        session = checkin.Session()

        result = self.run_with_opener(
            opener,
            lambda: session.request_json(
                "https://anyrouter.top/api/user/self",
                headers={"Accept": "application/json"},
            ),
        )

        self.assertTrue(result["success"])
        self.assertEqual(len(opener.requests), 2)
        self.assertIn("acw_tc=challenge", opener.requests[1].get_header("Cookie"))

    def test_repeated_html_raises_waf_error_after_all_attempts(self):
        opener = FakeOpener(
            [
                FakeResponse(
                    "<html>interstitial</html>",
                    headers=response_headers("text/html; charset=utf-8"),
                )
                for _ in range(checkin.MAX_ATTEMPTS)
            ]
        )

        with self.assertRaises(checkin.WafBlockedError) as raised:
            self.run_with_opener(
                opener,
                lambda: checkin.Session().request_json(
                    "https://anyrouter.top/api/user/self",
                    headers={"Accept": "application/json"},
                ),
            )

        self.assertEqual(len(opener.requests), checkin.MAX_ATTEMPTS)
        self.assertIn("HTML", str(raised.exception))
        self.assertIn("WAF", str(raised.exception))

    def test_non_html_non_json_raises_regular_checkin_error(self):
        opener = FakeOpener(
            [
                FakeResponse(
                    "upstream unavailable",
                    headers=response_headers("text/plain; charset=utf-8"),
                )
            ]
        )

        with self.assertRaises(checkin.CheckinError) as raised:
            self.run_with_opener(
                opener,
                lambda: checkin.Session().request_json(
                    "https://anyrouter.top/api/user/self",
                    headers={"Accept": "application/json"},
                    attempts=1,
                ),
            )

        self.assertNotIsInstance(raised.exception, checkin.WafBlockedError)
        self.assertIn("non-JSON", str(raised.exception))

    def test_html_login_page_is_cookie_expiry(self):
        opener = FakeOpener(
            [
                FakeResponse(
                    '<html><form action="/login">Sign in</form></html>',
                    headers=response_headers("text/html; charset=utf-8"),
                )
            ]
        )
        session = checkin.Session(cookie_env="ANYROUTER_COOKIE")

        with self.assertRaises(checkin.CookieExpiredError):
            self.run_with_opener(
                opener,
                lambda: session.request_json(
                    "https://anyrouter.top/api/user/self",
                    headers={"Accept": "application/json"},
                    attempts=1,
                ),
            )

    def test_http_401_is_cookie_expiry(self):
        headers = response_headers()
        error = urllib.error.HTTPError(
            "https://anyrouter.top/api/user/self",
            401,
            "Unauthorized",
            headers,
            io.BytesIO(b'{"success": false}'),
        )
        opener = FakeOpener([error])

        with self.assertRaises(checkin.CookieExpiredError):
            self.run_with_opener(
                opener,
                lambda: checkin.Session(cookie_env="ANYROUTER_COOKIE").request_json(
                    "https://anyrouter.top/api/user/self",
                    headers={"Accept": "application/json"},
                    attempts=1,
                ),
            )

    def test_http_403_html_is_waf_block(self):
        errors = []
        for _ in range(checkin.MAX_ATTEMPTS):
            errors.append(
                urllib.error.HTTPError(
                    "https://anyrouter.top/api/user/self",
                    403,
                    "Forbidden",
                    response_headers("text/html; charset=utf-8"),
                    io.BytesIO(b"<html>interstitial</html>"),
                )
            )
        opener = FakeOpener(errors)

        with self.assertRaises(checkin.WafBlockedError):
            self.run_with_opener(
                opener,
                lambda: checkin.Session(cookie_env="ANYROUTER_COOKIE").request_json(
                    "https://anyrouter.top/api/user/self",
                    headers={"Accept": "application/json"},
                ),
            )

        self.assertEqual(len(opener.requests), checkin.MAX_ATTEMPTS)

    def test_http_403_login_page_is_cookie_expiry(self):
        error = urllib.error.HTTPError(
            "https://anyrouter.top/api/user/self",
            403,
            "Forbidden",
            response_headers("text/html; charset=utf-8"),
            io.BytesIO(b'<html><form action="/login">Sign in</form></html>'),
        )
        opener = FakeOpener([error])

        with self.assertRaises(checkin.CookieExpiredError):
            self.run_with_opener(
                opener,
                lambda: checkin.Session(cookie_env="ANYROUTER_COOKIE").request_json(
                    "https://anyrouter.top/api/user/self",
                    headers={"Accept": "application/json"},
                ),
            )

        self.assertEqual(len(opener.requests), 1)

    def test_json_unauthenticated_message_is_cookie_expiry(self):
        opener = FakeOpener(
            [FakeResponse('{"success": false, "message": "无权进行此操作，未登录"}')]
        )

        with self.assertRaises(checkin.CookieExpiredError):
            self.run_with_opener(
                opener,
                lambda: checkin.Session(cookie_env="ANYROUTER_COOKIE").request_json(
                    "https://anyrouter.top/api/user/self",
                    headers={"Accept": "application/json"},
                    attempts=1,
                ),
            )


class JustWokerProviderTests(unittest.TestCase):
    def setUp(self):
        self.provider = checkin.JustWokerProvider()

    def account(self):
        return checkin.Account(
            label="JustWoker 账号",
            suffix="",
            values={"USER_ID": "12345", "TOKEN": "tok"},
        )

    def test_headers_carry_bearer_token_and_user_id(self):
        headers = self.provider.headers("12345", "tok")
        self.assertEqual(headers["Authorization"], "Bearer tok")
        self.assertEqual(headers["New-Api-User"], "12345")
        self.assertIn("json", headers["Accept"])

    def test_run_reports_bonus_and_quota_delta(self):
        state = {"quota": 1_000_000}

        def fake(self_, url, **kwargs):
            if url.endswith("/api/status"):
                return {"success": True, "data": {"quota_per_unit": 500000}}
            if url.endswith("/api/user/self"):
                return {
                    "success": True,
                    "data": {"quota": state["quota"], "username": "SadPull"},
                }
            if url.endswith("/api/user/checkin"):
                if kwargs.get("method") != "POST":
                    raise AssertionError("check-in must be a POST")
                state["quota"] += 500_000
                return {"success": True, "message": "签到成功"}
            raise AssertionError(f"unexpected url: {url}")

        with patch("checkin.Session.request_json", fake):
            report = self.provider.run(self.account())

        self.assertTrue(report.checked_in)
        self.assertEqual(report.title, "SadPull")
        self.assertIn("额度变化：500000 ($1.00)", report.lines)
        self.assertIn("当前额度：1500000 ($3.00)", report.lines)

    def test_run_treats_already_checked_in_as_not_claimed(self):
        def fake(self_, url, **kwargs):
            if url.endswith("/api/status"):
                return {"success": True, "data": {"quota_per_unit": 500000}}
            if url.endswith("/api/user/self"):
                return {"success": True, "data": {"quota": 100, "username": "u"}}
            if url.endswith("/api/user/checkin"):
                # Duplicate check-in: 200 + success=false + message.
                return {"success": False, "message": "今日已签到"}
            raise AssertionError(f"unexpected url: {url}")

        with patch("checkin.Session.request_json", fake):
            report = self.provider.run(self.account())

        self.assertFalse(report.checked_in)
        self.assertIn("今日已签到", report.text())

    def test_checkin_falls_back_to_legacy_path_on_404(self):
        calls = []

        def fake(self_, url, **kwargs):
            calls.append(url)
            if url.endswith("/api/user/checkin"):
                raise checkin.CheckinError(f"POST {url} failed with HTTP 404")
            if url.endswith("/api/user/sign_in"):
                return {"success": True, "message": "签到成功"}
            raise AssertionError(f"unexpected url: {url}")

        session = checkin.Session()
        with patch("checkin.Session.request_json", fake):
            message, claimed = self.provider.check_in(session, "12345", "tok")

        self.assertTrue(claimed)
        self.assertEqual(message, "签到成功")
        self.assertEqual(
            calls,
            [
                "https://api.justwoker.icu/api/user/checkin",
                "https://api.justwoker.icu/api/user/sign_in",
            ],
        )

    def test_quota_per_unit_falls_back_to_default_when_status_fails(self):
        def fake(self_, url, **kwargs):
            raise checkin.CheckinError("GET https://api.justwoker.icu/api/status failed")

        session = checkin.Session()
        with patch("checkin.Session.request_json", fake):
            per_unit = self.provider.quota_per_unit(session)

        self.assertEqual(per_unit, checkin.QUOTA_PER_USD)

    def test_accounts_requires_all_keys(self):
        with patch.dict(
            checkin.os.environ, {"JUSTWOKER_USER_ID": "12345"}, clear=True
        ):
            with self.assertRaises(checkin.CheckinError) as raised:
                self.provider.accounts()

        self.assertIn("JUSTWOKER_TOKEN", str(raised.exception))

    def test_numbered_env_accounts_are_discovered(self):
        env = {
            "JUSTWOKER_USER_ID": "1",
            "JUSTWOKER_TOKEN": "a",
            "JUSTWOKER_USER_ID2": "2",
            "JUSTWOKER_TOKEN2": "b",
        }
        with patch.dict(checkin.os.environ, env, clear=True):
            accounts = self.provider.accounts()

        self.assertEqual([account.suffix for account in accounts], ["", "2"])


if __name__ == "__main__":
    unittest.main()
