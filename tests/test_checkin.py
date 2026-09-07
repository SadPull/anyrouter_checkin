import io
import json
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


class PushPlusTests(unittest.TestCase):
    def setUp(self):
        self.opener = FakeOpener([])
        self.stderr = io.StringIO()
        for patcher in (
            patch.dict(checkin.os.environ, {"PUSHPLUS_TOKEN": "test-token"}, clear=True),
            patch("checkin.urllib.request.build_opener", return_value=self.opener),
            patch("checkin.now_text", return_value="2026-09-07 09:00:00"),
            patch("checkin.sys.stdout", new=io.StringIO()),
            patch("checkin.sys.stderr", new=self.stderr),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def group_payloads(self):
        payloads = []
        for request in self.opener.requests:
            self.assertEqual(request.full_url, "https://www.pushplus.plus/send")
            self.assertEqual(request.get_method(), "POST")
            payload = json.loads(request.data)
            self.assertEqual(payload["token"], "test-token")
            self.assertEqual(payload["topic"], "PullxD")
            self.assertEqual(payload["template"], "txt")
            payloads.append(payload)
        return payloads

    def test_summary_is_sent_to_fixed_group(self):
        for all_ok, title in (
            (True, "每日签到成功"),
            (False, "每日签到：1 成功 / 1 失败"),
        ):
            with self.subTest(all_ok=all_ok):
                self.opener.requests.clear()
                self.opener.outcomes = [FakeResponse('{"code": 200}')]
                content = "【AnyRouter 账号】签到结果\n当前额度：500000 ($1.00)"
                with patch("checkin.run", return_value=(all_ok, title, content)):
                    exit_code = checkin.main()

                self.assertEqual(exit_code, 0 if all_ok else 1)
                payloads = self.group_payloads()
                self.assertEqual(len(payloads), 1)
                self.assertEqual(payloads[0]["title"], title)
                self.assertEqual(payloads[0]["content"], content)

    def test_exception_notification_is_sent_to_fixed_group(self):
        self.opener.outcomes = [FakeResponse('{"code": 200}')]
        with patch("checkin.run", side_effect=checkin.CheckinError("账号配置不完整")):
            exit_code = checkin.main()

        self.assertEqual(exit_code, 1)
        payloads = self.group_payloads()
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["title"], "每日签到失败")
        self.assertIn("失败原因：账号配置不完整", payloads[0]["content"])

    def test_pushplus_rejection_raises_checkin_error(self):
        self.opener.outcomes = [FakeResponse('{"code": 400, "msg": "群组不存在"}')]
        with self.assertRaisesRegex(checkin.CheckinError, "PushPlus 推送失败：群组不存在"):
            checkin.send_pushplus("test-token", "测试标题", "测试内容")

        self.assertEqual(len(self.group_payloads()), 1)

    def test_main_fails_when_pushplus_rejects_notifications(self):
        self.opener.outcomes = [
            FakeResponse('{"code": 400, "msg": "群组不存在"}') for _ in range(2)
        ]
        with patch("checkin.run", return_value=(True, "每日签到成功", "签到结果")):
            exit_code = checkin.main()

        self.assertEqual(exit_code, 1)
        self.assertIn("PushPlus 推送失败：群组不存在", self.stderr.getvalue())
        payloads = self.group_payloads()
        self.assertEqual(len(payloads), 2)
        self.assertEqual(payloads[0]["title"], "每日签到成功")
        self.assertEqual(payloads[1]["title"], "每日签到失败")


class AccountDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.provider = checkin.AnyRouterProvider()

    def test_accounts_requires_all_keys(self):
        with patch.dict(checkin.os.environ, {"ANYROUTER_USER_ID": "12345"}, clear=True):
            with self.assertRaises(checkin.CheckinError) as raised:
                self.provider.accounts()

        self.assertIn("ANYROUTER_COOKIE", str(raised.exception))

    def test_numbered_env_accounts_are_discovered(self):
        env = {
            "ANYROUTER_USER_ID": "1",
            "ANYROUTER_COOKIE": "a",
            "ANYROUTER_USER_ID2": "2",
            "ANYROUTER_COOKIE2": "b",
        }
        with patch.dict(checkin.os.environ, env, clear=True):
            accounts = self.provider.accounts()

        self.assertEqual([account.suffix for account in accounts], ["", "2"])


if __name__ == "__main__":
    unittest.main()
