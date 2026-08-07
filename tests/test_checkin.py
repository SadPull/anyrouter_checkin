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
                "https://agentrouter.org/api/user/self",
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
                    "https://agentrouter.org/api/user/self",
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
                    "https://agentrouter.org/api/user/self",
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
        session = checkin.Session(cookie_env="AGENTROUTER_COOKIE")

        with self.assertRaises(checkin.CookieExpiredError):
            self.run_with_opener(
                opener,
                lambda: session.request_json(
                    "https://agentrouter.org/api/user/self",
                    headers={"Accept": "application/json"},
                    attempts=1,
                ),
            )

    def test_http_401_is_cookie_expiry(self):
        headers = response_headers()
        error = urllib.error.HTTPError(
            "https://agentrouter.org/api/user/self",
            401,
            "Unauthorized",
            headers,
            io.BytesIO(b'{"success": false}'),
        )
        opener = FakeOpener([error])

        with self.assertRaises(checkin.CookieExpiredError):
            self.run_with_opener(
                opener,
                lambda: checkin.Session(cookie_env="AGENTROUTER_COOKIE").request_json(
                    "https://agentrouter.org/api/user/self",
                    headers={"Accept": "application/json"},
                    attempts=1,
                ),
            )

    def test_http_403_html_is_waf_block(self):
        errors = []
        for _ in range(checkin.MAX_ATTEMPTS):
            errors.append(
                urllib.error.HTTPError(
                    "https://agentrouter.org/api/user/self",
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
                lambda: checkin.Session(cookie_env="AGENTROUTER_COOKIE").request_json(
                    "https://agentrouter.org/api/user/self",
                    headers={"Accept": "application/json"},
                ),
            )

        self.assertEqual(len(opener.requests), checkin.MAX_ATTEMPTS)

    def test_http_403_login_page_is_cookie_expiry(self):
        error = urllib.error.HTTPError(
            "https://agentrouter.org/api/user/self",
            403,
            "Forbidden",
            response_headers("text/html; charset=utf-8"),
            io.BytesIO(b'<html><form action="/login">Sign in</form></html>'),
        )
        opener = FakeOpener([error])

        with self.assertRaises(checkin.CookieExpiredError):
            self.run_with_opener(
                opener,
                lambda: checkin.Session(cookie_env="AGENTROUTER_COOKIE").request_json(
                    "https://agentrouter.org/api/user/self",
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
                lambda: checkin.Session(cookie_env="AGENTROUTER_COOKIE").request_json(
                    "https://agentrouter.org/api/user/self",
                    headers={"Accept": "application/json"},
                    attempts=1,
                ),
            )


class CookieHelperTests(unittest.TestCase):
    def test_select_cookie_removes_ip_bound_clearance(self):
        cookie = (
            "auth.session-token=stable; cf_clearance=bound; "
            "_cfuvid=bound-too; analytics=value"
        )

        self.assertEqual(
            checkin.select_cookie(cookie, {"auth.session-token"}),
            "auth.session-token=stable",
        )


class AgentRouterTests(unittest.TestCase):
    def setUp(self):
        self.provider = checkin.AgentRouterProvider()

    def account(self, *, site_cookie="site-cookie", linuxdo_cookie="linuxdo-cookie"):
        return checkin.Account(
            label="AgentRouter 账号",
            suffix="",
            values={
                "USER_ID": "277969",
                "COOKIE": site_cookie,
                "LINUXDO_COOKIE": linuxdo_cookie,
            },
        )

    def test_api_headers_match_browser_json_request(self):
        headers = self.provider.api_headers("277969")

        self.assertEqual(headers["Accept"], "application/json, text/plain, */*")
        self.assertEqual(headers["Referer"], "https://agentrouter.org/console")
        self.assertEqual(headers["New-API-User"], "277969")
        self.assertNotIn("New-API-User", self.provider.api_headers(""))

    def test_waf_block_uses_official_backup_domain(self):
        session = checkin.Session()
        with patch.object(
            session,
            "request_json",
            side_effect=[
                checkin.WafBlockedError("primary blocked"),
                {"success": True, "data": {"id": 1}},
            ],
        ) as request_json:
            result = self.provider.request_json(
                session, "/api/user/self", user_id="277969"
            )

        self.assertTrue(result["success"])
        primary = request_json.call_args_list[0]
        fallback = request_json.call_args_list[1]
        self.assertEqual(
            primary.args[0], "https://agentrouter.org/api/user/self"
        )
        self.assertEqual(
            fallback.args[0], "https://ps.air-outer.com/api/user/self"
        )
        self.assertEqual(
            fallback.kwargs["headers"]["Referer"],
            "https://ps.air-outer.com/console",
        )

    def test_non_waf_error_does_not_switch_domain(self):
        session = checkin.Session()
        with patch.object(
            session,
            "request_json",
            side_effect=checkin.CookieExpiredError("expired"),
        ) as request_json:
            with self.assertRaises(checkin.CookieExpiredError):
                self.provider.request_json(session, "/api/user/self")

        request_json.assert_called_once()

    def test_oauth_checked_in_true_reports_success(self):
        with patch.object(
            self.provider, "relay_login", return_value={"checked_in": True}
        ), patch.object(
            self.provider,
            "get_user",
            return_value={"username": "agent-user", "quota": 500000},
        ):
            report = self.provider.run(self.account())

        self.assertIs(report.checked_in, True)
        self.assertIn("签到成功", "\n".join(report.lines))

    def test_oauth_checked_in_false_reports_already_checked_in(self):
        with patch.object(
            self.provider, "relay_login", return_value={"checked_in": False}
        ), patch.object(
            self.provider,
            "get_user",
            return_value={"username": "agent-user", "quota": 500000},
        ):
            report = self.provider.run(self.account())

        self.assertIs(report.checked_in, False)
        self.assertIn("今日已签到过", "\n".join(report.lines))

    def test_oauth_failure_falls_back_to_site_cookie(self):
        with patch.object(
            self.provider, "relay_login", side_effect=checkin.RelayError("relay failed")
        ), patch.object(
            self.provider,
            "get_user",
            return_value={"username": "agent-user", "quota": 500000},
        ) as get_user, patch("checkin.sys.stderr", new_callable=io.StringIO):
            report = self.provider.run(self.account())

        self.assertIsNone(report.checked_in)
        self.assertTrue(report.warning)
        self.assertIn("仅查询额度", "\n".join(report.lines))
        self.assertEqual(get_user.call_args.args[0].base_cookie, "site-cookie")

    def test_site_cookie_only_never_claims_checkin(self):
        with patch.object(
            self.provider,
            "get_user",
            return_value={"username": "agent-user", "quota": 500000},
        ):
            report = self.provider.run(self.account(linuxdo_cookie=""))

        self.assertIsNone(report.checked_in)
        self.assertIn("未签到", "\n".join(report.lines))

    def account_with_github(self, *, site_cookie="", github_cookie="github-cookie"):
        return checkin.Account(
            label="AgentRouter 账号",
            suffix="",
            values={
                "USER_ID": "277969",
                "COOKIE": site_cookie,
                "LINUXDO_COOKIE": "",
                "GITHUB_COOKIE": github_cookie,
            },
        )

    def test_github_checked_in_reports_success(self):
        with patch.object(
            self.provider, "relay_login", return_value={"checked_in": True}
        ) as relay_login, patch.object(
            self.provider,
            "get_user",
            return_value={"username": "github-user", "quota": 500000},
        ):
            report = self.provider.run(self.account_with_github())

        self.assertIs(report.checked_in, True)
        self.assertIn("签到成功", "\n".join(report.lines))
        self.assertEqual(relay_login.call_args.args[2], "github")

    def test_github_selects_session_cookies_not_clearance(self):
        stable = checkin.select_cookie(
            "user_session=abc; _gh_sess=def; cf_clearance=bound; _cfuvid=no",
            checkin.GITHUB_SESSION_COOKIE_NAMES,
        )
        self.assertIn("user_session=abc", stable)
        self.assertIn("_gh_sess=def", stable)
        self.assertNotIn("cf_clearance", stable)
        self.assertNotIn("_cfuvid", stable)

    def test_github_authorize_builds_github_url(self):
        with patch.object(
            checkin.Session,
            "request_raw",
            return_value=(
                302,
                {"Location": "https://agentrouter.org/oauth/github?code=abc&state=state"},
                "",
            ),
        ) as request_raw:
            code = self.provider.authorize_code(
                "user_session=abc",
                "Ov23lidtiR4LeVZvVRNL",
                "state",
                "github",
            )

        self.assertEqual(code, "abc")
        url = request_raw.call_args.args[0]
        self.assertIn("https://github.com/login/oauth/authorize", url)
        self.assertIn("client_id=Ov23lidtiR4LeVZvVRNL", url)
        self.assertIn("scope=user%3Aemail", url)
        self.assertIn("state=state", url)

    def test_github_client_id_reads_status(self):
        session = checkin.Session()
        with patch.object(
            session,
            "request_json",
            return_value={
                "success": True,
                "data": {"github_client_id": "Ov23lidtiR4LeVZvVRNL"},
            },
        ):
            self.assertEqual(
                self.provider.github_client_id(session), "Ov23lidtiR4LeVZvVRNL"
            )

    def test_github_relay_calls_github_callback(self):
        session = checkin.Session()
        with patch.object(
            self.provider, "github_client_id", return_value="client"
        ), patch.object(self.provider, "oauth_state", return_value="st"), patch.object(
            self.provider, "authorize_code", return_value="code"
        ), patch.object(
            session,
            "request_json",
            return_value={"success": True, "data": {"checked_in": True}},
        ) as request_json:
            data = self.provider.relay_login(session, "user_session=x", "github")

        self.assertTrue(data["checked_in"])
        url = request_json.call_args.args[0]
        self.assertIn("/api/oauth/github?", url)
        self.assertIn("code=code", url)
        self.assertIn("state=st", url)
        self.assertIn("mode=login", url)

    def test_github_only_relay_failure_without_site_cookie_raises(self):
        with patch.object(
            self.provider, "relay_login", side_effect=checkin.RelayError("blocked")
        ), patch("checkin.sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(checkin.CheckinError):
                self.provider.run(self.account_with_github(site_cookie=""))

if __name__ == "__main__":
    unittest.main()
