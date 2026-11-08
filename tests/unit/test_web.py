"""
Web interface tests: snapshot names cannot escape the snapshot directory, and the
audit trigger rejects cross-site browser requests.
"""

import http.client
import json
import threading
import time
from http.server import ThreadingHTTPServer
from urllib.parse import quote

import pytest

from serveraudit.web import app as web_app
from serveraudit.web.app import AuditWebHandler


class _StubOrchestrator:
    """Stands in for AuditOrchestrator so no real audit runs."""

    calls = 0
    snapshot = None

    def __init__(self, *args, **kwargs):
        pass

    def run_audit(self):
        _StubOrchestrator.calls += 1
        return _StubOrchestrator.snapshot


@pytest.fixture
def web(tmp_path, monkeypatch):
    base = tmp_path / "audits"
    snap = base / "testnode-2026-09-24T100000"
    snap.mkdir(parents=True)
    (snap / "audit.json").write_text(
        json.dumps({"metadata": {"hostname": "testnode", "timestamp": "2026-09-24T10:00:00", "profile": "private"}}),
        encoding="utf-8",
    )
    (snap / "audit.md").write_text("# Test Report", encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"leaked": True}), encoding="utf-8")

    _StubOrchestrator.calls = 0
    _StubOrchestrator.snapshot = snap
    monkeypatch.setattr(web_app, "AuditOrchestrator", _StubOrchestrator)
    monkeypatch.setattr(AuditWebHandler, "base_dir", base)
    monkeypatch.setattr(AuditWebHandler, "is_auditing", False)
    monkeypatch.setattr(AuditWebHandler, "last_audit_message", "")

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), AuditWebHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    host, port = httpd.server_address[:2]
    try:
        yield {"host": host, "port": port, "snapshot": snap.name, "outside": outside}
    finally:
        httpd.shutdown()
        httpd.server_close()


def _request(web, method, path, headers=None):
    conn = http.client.HTTPConnection(web["host"], web["port"], timeout=5)
    conn.request(method, path, headers=headers or {})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, resp.getheader("Content-Type", ""), body


def _wait_idle(web):
    for _ in range(200):
        status, _, body = _request(web, "GET", "/api/status")
        data = json.loads(body)
        if status == 200 and not data["is_auditing"]:
            return data
        time.sleep(0.02)
    raise AssertionError("audit did not finish")


def test_snapshot_artifacts_are_served(web):
    status, ctype, body = _request(web, "GET", f"/api/snapshot/{web['snapshot']}")
    assert status == 200 and "json" in ctype
    assert json.loads(body)["metadata"]["hostname"] == "testnode"

    status, ctype, body = _request(web, "GET", f"/api/snapshot/{web['snapshot']}/md")
    assert status == 200 and ctype.startswith("text/markdown")
    assert body == b"# Test Report"

    status, _, _ = _request(web, "GET", f"/api/snapshot/{web['snapshot']}/html")
    assert status == 404  # no audit.html in the fixture

    status, _, _ = _request(web, "GET", "/api/snapshot/testnode-2026-01-01T000000")
    assert status == 404  # well-formed name, no such snapshot


@pytest.mark.parametrize(
    "path",
    [
        "/api/snapshot/../outside.json",
        "/api/snapshot/../../outside.json/md",
        "/api/snapshot/..%2Foutside.json",
        "/api/snapshot/.",
        "/api/diff?a=../outside.json&b=../outside.json",
    ],
)
def test_paths_outside_snapshot_dir_are_rejected(web, path):
    status, _, body = _request(web, "GET", path)
    assert status == 400
    assert b"leaked" not in body


def test_absolute_path_in_diff_is_rejected(web):
    outside = quote(str(web["outside"]), safe="")
    status, _, body = _request(web, "GET", f"/api/diff?a={outside}&b={outside}")
    assert status == 400
    assert b"leaked" not in body


def _origin(web):
    return f"http://{web['host']}:{web['port']}"


def test_audit_run_same_origin_is_accepted(web):
    headers = {"Origin": _origin(web), "Sec-Fetch-Site": "same-origin"}
    status, _, body = _request(web, "POST", "/api/audit/run", headers)
    assert status == 200
    assert json.loads(body)["status"] == "started"
    assert web["snapshot"] in _wait_idle(web)["message"]
    assert _StubOrchestrator.calls == 1


def test_audit_run_without_browser_headers_is_accepted(web):
    status, _, _ = _request(web, "POST", "/api/audit/run")
    assert status == 200
    _wait_idle(web)
    assert _StubOrchestrator.calls == 1


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "http://evil.example"},
        {"Origin": "null"},
        {"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Host": "evil.example:8080"},  # DNS rebinding against a loopback bind
    ],
)
def test_audit_run_cross_site_is_rejected(web, headers):
    status, _, body = _request(web, "POST", "/api/audit/run", headers)
    assert status == 403
    assert json.loads(body)["error"]
    assert _StubOrchestrator.calls == 0
    assert json.loads(_request(web, "GET", "/api/status")[2])["is_auditing"] is False


# --------------------------------------------------------------------------- #
# DNS rebinding: the Host check must hold on every request, with no exemption
# for headers a rebound (same-origin) page can set itself.
# --------------------------------------------------------------------------- #

EVIL = "evil.example:8080"
PROXY_HEADER_SETS = [
    {},
    {"X-Forwarded-For": "203.0.113.9"},
    {"X-Forwarded-Host": EVIL},
    {"Forwarded": f"for=203.0.113.9;host={EVIL}"},
]
# What a rebound page sends: same-origin from the browser's point of view.
REBOUND_BROWSER_HEADERS = [
    {"Sec-Fetch-Site": "same-origin"},
    {"Origin": f"http://{EVIL}"},
    {"Origin": f"http://{EVIL}", "Sec-Fetch-Site": "same-origin"},
]


@pytest.mark.parametrize("proxy", PROXY_HEADER_SETS, ids=lambda h: ",".join(h) or "no-proxy-headers")
@pytest.mark.parametrize("browser", REBOUND_BROWSER_HEADERS, ids=lambda h: "+".join(h))
def test_rebinding_post_rejected_even_with_proxy_headers(web, proxy, browser):
    headers = {"Host": EVIL, **browser, **proxy}
    status, _, body = _request(web, "POST", "/api/audit/run", headers)
    assert status == 403
    assert _StubOrchestrator.calls == 0
    assert json.loads(_request(web, "GET", "/api/status")[2])["is_auditing"] is False


@pytest.mark.parametrize("proxy", PROXY_HEADER_SETS, ids=lambda h: ",".join(h) or "no-proxy-headers")
@pytest.mark.parametrize("path", [
    "/", "/api/status", "/api/snapshots",
    "/api/snapshot/testnode-2026-09-24T100000",
    "/api/snapshot/testnode-2026-09-24T100000/md",
])
def test_rebinding_get_rejected_with_foreign_host(web, path, proxy):
    status, _, body = _request(web, "GET", path, {"Host": EVIL, **proxy})
    assert status == 403
    assert b"testnode" not in body  # nothing from the snapshots leaks


def test_rebinding_diff_rejected_with_foreign_host(web):
    n = web["snapshot"]
    status, _, _ = _request(web, "GET", f"/api/diff?a={n}&b={n}", {"Host": EVIL})
    assert status == 403


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "localhost:1234", "[::1]:8080"])
def test_loopback_host_headers_are_accepted_on_get_and_post(web, host):
    assert _request(web, "GET", "/api/status", {"Host": host})[0] == 200
    status, _, _ = _request(web, "POST", "/api/audit/run", {"Host": host})
    assert status == 200
    _wait_idle(web)


@pytest.mark.parametrize("host", ["localhost.evil.example", "127.0.0.1.evil.example", "evil.example", ""])
def test_lookalike_or_missing_host_is_rejected(web, host):
    assert _request(web, "GET", "/api/status", {"Host": host})[0] == 403


def test_allowed_host_opt_in_for_reverse_proxy(web, monkeypatch):
    """A proxy that forwards the original Host (Caddy default) works with --allowed-host."""
    monkeypatch.setattr(AuditWebHandler, "allowed_hosts", frozenset({"audit.example.com"}), raising=False)
    ok = {"Host": "audit.example.com"}
    assert _request(web, "GET", "/api/status", ok)[0] == 200
    same_origin = {**ok, "Origin": "https://audit.example.com".replace("https", "http"),
                   "Sec-Fetch-Site": "same-origin"}
    status, _, _ = _request(web, "POST", "/api/audit/run", same_origin)
    assert status == 200
    _wait_idle(web)
    # still rejected: other hosts, and forged forwarding headers do not widen the list
    assert _request(web, "GET", "/api/status", {"Host": EVIL})[0] == 403
    assert _request(web, "GET", "/api/status",
                    {"Host": EVIL, "X-Forwarded-Host": "audit.example.com"})[0] == 403


# --------------------------------------------------------------------------- #
# Path traversal confirmation (snapshot name regex + resolve() parent check)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("path", [
    "/api/snapshot/../outside.json",
    "/api/snapshot/%2e%2e/outside.json",
    "/api/snapshot/%2E%2E%2Foutside.json",
    "/api/snapshot/..%2foutside.json",
    "/api/snapshot/..%5coutside.json",
    "/api/snapshot/....//outside.json",
    "/api/snapshot//etc/passwd",
    "/api/snapshot/%2Fetc%2Fpasswd",
    "/api/snapshot/..",
    "/api/snapshot/%2e%2e",
    "/api/snapshot/%2e%2e/md",
    "/api/snapshot/../html",
])
def test_traversal_variants_are_rejected(web, path):
    status, _, body = _request(web, "GET", path)
    assert status == 400, path
    assert b"leaked" not in body


@pytest.mark.parametrize("param", ["../outside.json", "%2e%2e/outside.json", "/etc/passwd", "%2Fetc%2Fpasswd"])
def test_diff_rejects_traversal_and_absolute(web, param):
    status, _, body = _request(web, "GET", f"/api/diff?a={param}&b={web['snapshot']}")
    assert status == 400
    assert b"leaked" not in body


def test_symlinks_cannot_escape_snapshot_dir(web):
    base = web["outside"].parent / "audits"
    escape_dir = web["outside"].parent / "escape"
    escape_dir.mkdir()
    (escape_dir / "audit.json").write_text(json.dumps({"leaked": True}), encoding="utf-8")
    (escape_dir / "audit.md").write_text("leaked", encoding="utf-8")
    (base / "linkdir").symlink_to(escape_dir, target_is_directory=True)
    (base / "linkfile").symlink_to(web["outside"])
    for path in ["/api/snapshot/linkdir", "/api/snapshot/linkdir/md", "/api/snapshot/linkfile",
                 "/api/diff?a=linkdir&b=linkfile"]:
        status, _, body = _request(web, "GET", path)
        assert status == 400, path
        assert b"leaked" not in body
