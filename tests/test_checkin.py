import io
import os
import unittest
import urllib.error
from decimal import Decimal
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


class FakeApi:
    """Duck-typed transport for NewApiCheckinProvider tests."""

    def __init__(self, responses=(), mint_tokens=(), transport_name="http"):
        self.responses = list(responses)
        self.mint_tokens = list(mint_tokens)
        self.transport_name = transport_name
        self.calls = []
        self.token = ""
        self.closed = False

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if not self.responses:
            raise AssertionError("no more scripted responses")
        outcome = self.responses.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def refresh_token(self):
        self.calls.append(("POST", "/api/user/auth/refresh", None))
        self.token = "refreshed-jwt"

    def mint_turnstile(self, sitekey):
        self.calls.append(("MINT", sitekey, None))
        if self.transport_name == "http":
            raise checkin.TurnstileRequiredError("http cannot mint")
        return self.mint_tokens.pop(0)

    def close(self):
        self.closed = True


def make_account(provider):
    return checkin.Account(
        label=f"{provider.name} 账号",
        suffix="",
        values={"TOKEN": "tok", "COOKIE": "", "USER_ID": ""},
    )


class QuotaTextTests(unittest.TestCase):
    def test_custom_per_unit(self):
        self.assertEqual(
            checkin.quota_text(500_000, Decimal("1000000")), "500000 ($0.50)"
        )


class NewApiProviderTests(unittest.TestCase):
    def make_provider(self):
        return checkin.NewApiCheckinProvider(
            "Justwoker", "https://api.justwoker.icu", "JUSTWOKER"
        )

    def test_accounts_require_token_or_cookie(self):
        provider = self.make_provider()
        with patch.dict(os.environ, {"JUSTWOKER_USER_ID": "1"}, clear=True):
            with self.assertRaises(checkin.CheckinError):
                provider.accounts()
        with patch.dict(os.environ, {"JUSTWOKER_TOKEN": "t"}, clear=True):
            accounts = provider.accounts()
            self.assertEqual(len(accounts), 1)
            self.assertEqual(accounts[0].values["TOKEN"], "t")
        with patch.dict(os.environ, {"JUSTWOKER_COOKIE": "c"}, clear=True):
            accounts = provider.accounts()
            self.assertEqual(accounts[0].values["COOKIE"], "c")

    def test_disabled_site_is_skipped_without_browser(self):
        provider = self.make_provider()
        http = FakeApi(
            responses=[
                {"success": True, "data": {"checkin_enabled": False}},
            ]
        )

        with patch.object(checkin, "HttpApi", lambda *a, **k: http), patch.object(
            checkin,
            "BrowserApi",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("browser started")),
        ):
            report = provider.run(make_account(provider))

        self.assertIsNone(report.checked_in)
        self.assertIn("未启用", report.text())
        self.assertEqual(len(http.calls), 1)

    def test_already_checked_in_report(self):
        provider = self.make_provider()
        http = FakeApi(
            responses=[
                {
                    "success": True,
                    "data": {
                        "checkin_enabled": True,
                        "turnstile_check": True,
                        "turnstile_site_key": "sk",
                        "quota_per_unit": 500000,
                    },
                },
                {
                    "success": True,
                    "data": {
                        "stats": {
                            "checked_in_today": True,
                            "checkin_count": 3,
                            "total_checkins": 9,
                            "total_quota": 123456,
                        }
                    },
                },
                {
                    "success": True,
                    "data": {"quota": 55318758, "display_name": "xD Pull"},
                },
            ]
        )

        with patch.object(checkin, "HttpApi", lambda *a, **k: http), patch.object(
            checkin,
            "BrowserApi",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("browser started")),
        ):
            report = provider.run(make_account(provider))

        self.assertFalse(report.checked_in)
        self.assertIn("今日已签到", report.text())
        self.assertIn("xD Pull", report.text())
        # Even with Turnstile enabled the site is skipped browser-free.
        self.assertNotIn(("MINT", "sk", None), http.calls)

    def test_successful_checkin_switches_to_browser_for_turnstile(self):
        provider = self.make_provider()
        status = {
            "success": True,
            "data": {
                "checkin_enabled": True,
                "turnstile_check": True,
                "turnstile_site_key": "sk",
                "quota_per_unit": 500000,
            },
        }
        http = FakeApi(
            responses=[
                status,
                {
                    "success": True,
                    "data": {
                        "stats": {"checked_in_today": False, "total_checkins": 5}
                    },
                },
                {"success": True, "data": {"quota": 1_000_000, "username": "SadPull"}},
            ]
        )
        browser = FakeApi(
            transport_name="browser",
            mint_tokens=["tok-1"],
            responses=[
                {
                    "success": True,
                    "message": "签到成功",
                    "data": {"quota_awarded": 50_000, "checkin_date": "2026-08-30"},
                },
                {
                    "success": True,
                    "data": {
                        "stats": {
                            "checked_in_today": True,
                            "total_checkins": 6,
                            "total_quota": 1_050_000,
                        }
                    },
                },
                {
                    "success": True,
                    "data": {"quota": 1_050_000, "display_name": "xD Pull"},
                },
            ],
        )

        def make_browser(*args, **kwargs):
            return browser

        with patch.object(checkin, "HttpApi", lambda *a, **k: http), patch.object(
            checkin, "BrowserApi", make_browser
        ):
            report = provider.run(make_account(provider))

        self.assertTrue(report.checked_in)
        self.assertIn("获得额度：50000 ($0.10)", report.text())
        post_paths = [
            path for method, path, _ in browser.calls if method == "POST"
        ]
        self.assertEqual(post_paths, ["/api/user/checkin?turnstile=tok-1"])
        self.assertIn(("MINT", "sk", None), http.calls)
        self.assertIn(("MINT", "sk", None), browser.calls)
        self.assertTrue(http.closed)
        self.assertTrue(browser.closed)

    def test_successful_checkin_without_turnstile_stays_on_http(self):
        provider = self.make_provider()
        http = FakeApi(
            responses=[
                {
                    "success": True,
                    "data": {
                        "checkin_enabled": True,
                        "turnstile_check": False,
                        "turnstile_site_key": "",
                        "quota_per_unit": 500000,
                    },
                },
                {
                    "success": True,
                    "data": {"stats": {"checked_in_today": False}},
                },
                {"success": True, "data": {"quota": 2_000_000, "username": "u"}},
                {
                    "success": True,
                    "message": "签到成功",
                    "data": {"quota_awarded": 10_000},
                },
                {
                    "success": True,
                    "data": {
                        "stats": {"checked_in_today": True, "total_checkins": 7}
                    },
                },
                {"success": True, "data": {"quota": 2_010_000}},
            ]
        )

        with patch.object(checkin, "HttpApi", lambda *a, **k: http), patch.object(
            checkin,
            "BrowserApi",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("browser started")),
        ):
            report = provider.run(make_account(provider))

        self.assertTrue(report.checked_in)
        post_paths = [path for method, path, _ in http.calls if method == "POST"]
        self.assertEqual(post_paths, ["/api/user/checkin"])

    def test_do_checkin_retries_with_fresh_turnstile_token(self):
        provider = self.make_provider()
        config = {"turnstile": True, "sitekey": "sk", "quota_per_unit": Decimal("500000")}
        api = FakeApi(
            transport_name="browser",
            mint_tokens=["tok-1", "tok-2"],
            responses=[
                {"success": False, "message": "Turnstile 校验失败，请刷新重试！"},
                {"success": True, "message": "签到成功", "data": {"quota_awarded": 1}},
            ],
        )

        result = provider._do_checkin(api, config)

        self.assertTrue(result["success"])
        mints = [call for call in api.calls if call[0] == "MINT"]
        self.assertEqual(len(mints), 2)
        post_paths = [path for method, path, _ in api.calls if method == "POST"]
        self.assertEqual(
            post_paths,
            [
                "/api/user/checkin?turnstile=tok-1",
                "/api/user/checkin?turnstile=tok-2",
            ],
        )

    def test_duplicate_checkin_message_is_not_an_error(self):
        provider = self.make_provider()
        http = FakeApi(
            responses=[
                {
                    "success": True,
                    "data": {
                        "checkin_enabled": True,
                        "turnstile_check": False,
                        "quota_per_unit": 500000,
                    },
                },
                {
                    "success": True,
                    "data": {"stats": {"checked_in_today": False}},
                },
                {"success": True, "data": {"quota": 5_000_000, "username": "u"}},
                {"success": False, "message": "今日已签到，请明天再来"},
            ]
        )

        with patch.object(checkin, "HttpApi", lambda *a, **k: http), patch.object(
            checkin,
            "BrowserApi",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("browser started")),
        ):
            report = provider.run(make_account(provider))

        self.assertFalse(report.checked_in)
        self.assertIn("今日已签到", report.text())


if __name__ == "__main__":
    unittest.main()
