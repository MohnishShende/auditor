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
