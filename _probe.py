"""Probe what agentrouter.org actually returns for /api/user/self. Temporary."""
import gzip
import urllib.error
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")
URL = "https://agentrouter.org/api/user/self"


def probe(label, headers):
    req = urllib.request.Request(URL, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            status, hdrs = r.status, r.headers
    except urllib.error.HTTPError as e:
        raw, status, hdrs = e.read(), e.code, e.headers
    except Exception as e:
        print(f"--- {label}: ERR {e}")
        return
    if hdrs.get("Content-Encoding", "").lower() == "gzip":
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    text = raw.decode("utf-8", errors="replace")
    print(f"--- {label}")
    print(f"    status={status} ct={hdrs.get('Content-Type')} len={len(text)}")
    print(f"    set-cookie={hdrs.get('Set-Cookie')}")
    print(f"    has arg1={'var arg1=' in text}")
    print(f"    first200={text[:200]!r}")
    print()


probe("no cookie, Accept json (what the script sends)", {
    "Accept": "application/json", "Cache-Control": "no-store",
    "User-Agent": UA, "Referer": "https://agentrouter.org/console",
})
probe("dummy session cookie, Accept json", {
    "Accept": "application/json", "Cache-Control": "no-store",
    "User-Agent": UA, "Referer": "https://agentrouter.org/console",
    "Cookie": "session=MTc4NTY0NzUzNHxEWDhFQVFMX2dBQUJFQUVRQUFELUFVWF9nQUFH",
})
probe("dummy cookie + New-API-User, browser Accept", {
    "Accept": "application/json, text/plain, */*", "Cache-Control": "no-store",
    "User-Agent": UA, "Referer": "https://agentrouter.org/console",
    "New-API-User": "277969",
    "Cookie": "session=MTc4NTY0NzUzNHxEWDhFQVFMX2dBQUJFQUVRQUFELUFVWF9nQUFH",
})
probe("no UA at all (default urllib)", {"Accept": "application/json"})
