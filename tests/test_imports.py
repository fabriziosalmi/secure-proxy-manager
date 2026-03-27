"""
Unit tests for blacklist import endpoints.
Run with: pytest tests/test_imports.py -v

Uses pytest-mock to stub outbound HTTP calls — no live network needed.
"""
import ipaddress
import tempfile
import os
import sys
import socket
import pytest
from unittest.mock import patch, MagicMock

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# Stub docker SDK (not available in CI)
sys.modules.setdefault('docker', MagicMock())

os.environ.setdefault("BASIC_AUTH_USERNAME", "testuser")
os.environ.setdefault("BASIC_AUTH_PASSWORD", "testpass")

from app.main import app  # noqa: E402
from app.auth import authenticate  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _init_db():
    """Patch main.DATABASE_PATH to a temp file and initialise the schema."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    import app.config as cfg
    from app.database import init_db
    original = cfg.DATABASE_PATH
    cfg.DATABASE_PATH = db_path
    init_db()
    yield
    cfg.DATABASE_PATH = original
    os.unlink(db_path)


@pytest.fixture(scope="session")
def client(_init_db):
    """TestClient with auth bypassed — tests focus on import logic."""
    app.dependency_overrides[authenticate] = lambda: "testuser"
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resp(status_code=200, text=""):
    m = MagicMock()
    m.status_code = status_code
    m.text = text
    m.iter_content.return_value = [text.encode("utf-8")] if text else []
    return m


@pytest.fixture(autouse=True)
def _mock_public_dns(mocker):
    original_gethostbyname = socket.gethostbyname

    def resolve(hostname):
        if hostname == "example.com":
            return "93.184.216.34"
        return original_gethostbyname(hostname)

    mocker.patch("socket.gethostbyname", side_effect=resolve)


# ---------------------------------------------------------------------------
# /api/blacklists/import — URL mode
# ---------------------------------------------------------------------------

IP_LIST = "10.0.0.1\n192.168.1.0/24\n# comment\n\n1.2.3.4"
DOMAIN_LIST = "bad-domain.com\n# comment\nmalware.net\n"


class TestImportUrl:
    def test_ip_list_success(self, client):
        with patch("app.routers.blacklists.requests.get", return_value=_resp(200, IP_LIST)):
            r = client.post("/api/blacklists/import",
                            json={"type": "ip", "url": "https://example.com/list.txt"})
        assert r.status_code == 200
        assert r.json()["status"] == "success"
        assert r.json()["data"]["added"] >= 0

    def test_domain_list_success(self, client):
        with patch("app.routers.blacklists.requests.get", return_value=_resp(200, DOMAIN_LIST)):
            r = client.post("/api/blacklists/import",
                            json={"type": "domain", "url": "https://example.com/domains.txt"})
        assert r.status_code == 200

    def test_retries_on_transient_failure(self, client):
        """Succeeds on 3rd attempt; verifies retry loop."""
        import requests as reqs
        calls = []

        def flaky(url, **kw):
            calls.append(url)
            if len(calls) < 3:
                raise reqs.exceptions.ConnectionError("transient")
            return _resp(200, IP_LIST)

        with patch("app.routers.blacklists.requests.get", side_effect=flaky), patch("time.sleep"):
            r = client.post("/api/blacklists/import",
                            json={"type": "ip", "url": "https://example.com/list.txt"})
        assert r.status_code == 200
        assert len(calls) == 3

    def test_fails_after_3_attempts(self, client):
        import requests as reqs
        with patch("app.routers.blacklists.requests.get", side_effect=reqs.exceptions.ConnectionError("always")), patch("time.sleep"):
            r = client.post("/api/blacklists/import",
                            json={"type": "ip", "url": "https://example.com/list.txt"})
        assert r.status_code == 400
        assert "3 attempts" in r.json()["detail"]

    def test_non_200_returns_400_with_status(self, client):
        with patch("app.routers.blacklists.requests.get", return_value=_resp(404)), patch("time.sleep"):
            r = client.post("/api/blacklists/import",
                            json={"type": "ip", "url": "https://example.com/list.txt"})
        assert r.status_code == 400
        assert "404" in r.json()["detail"]

    def test_ssrf_private_ip_blocked(self, client):
        with patch("socket.gethostbyname", return_value="192.168.1.1"):
            r = client.post("/api/blacklists/import",
                            json={"type": "ip", "url": "http://internal/list.txt"})
        assert r.status_code == 403

    def test_ssrf_loopback_blocked(self, client):
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            r = client.post("/api/blacklists/import",
                            json={"type": "ip", "url": "http://localhost/list.txt"})
        assert r.status_code == 403

    def test_non_http_scheme_blocked(self, client):
        r = client.post("/api/blacklists/import",
                        json={"type": "ip", "url": "file:///etc/passwd"})
        assert r.status_code == 400

    def test_invalid_type_rejected(self, client):
        r = client.post("/api/blacklists/import",
                        json={"type": "bad", "url": "https://example.com/list.txt"})
        assert r.status_code == 400

    def test_no_url_no_content_rejected(self, client):
        r = client.post("/api/blacklists/import", json={"type": "ip"})
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# /api/blacklists/import — content (bulk paste) mode
# ---------------------------------------------------------------------------

class TestImportContent:
    def test_bulk_ip_import(self, client):
        r = client.post("/api/blacklists/import",
                        json={"type": "ip", "content": "10.1.0.1\n10.1.0.2\n# skip\n10.1.0.3"})
        assert r.status_code == 200
        assert r.json()["data"]["added"] >= 0

    def test_bulk_domain_import(self, client):
        r = client.post("/api/blacklists/import",
                        json={"type": "domain", "content": "evil.com\nbad.net\n"})
        assert r.status_code == 200

    def test_comments_and_blanks_skipped(self, client):
        r = client.post("/api/blacklists/import",
                        json={"type": "ip", "content": "# only comments\n\n"})
        assert r.status_code == 200
        assert r.json()["data"]["added"] == 0


# ---------------------------------------------------------------------------
# /api/blacklists/import-geo
# ---------------------------------------------------------------------------

CIDR_CONTENT = "1.2.3.0/24\n5.6.7.0/24\n# comment\n"


class TestImportGeo:
    def test_success(self, client):
        with patch("app.routers.blacklists.requests.get", return_value=_resp(200, CIDR_CONTENT)):
            r = client.post("/api/blacklists/import-geo", json={"countries": ["CN"]})
        assert r.status_code == 200
        assert r.json()["data"]["imported"] >= 0

    def test_fallback_to_github_when_ipdeny_fails(self, client):
        tried = []

        def selective(url, **kw):
            tried.append(url)
            if "ipdeny" in url:
                return _resp(404)
            return _resp(200, CIDR_CONTENT)

        with patch("app.routers.blacklists.requests.get", side_effect=selective):
            r = client.post("/api/blacklists/import-geo", json={"countries": ["CN"]})
        assert r.status_code == 200
        assert any("github" in u for u in tried)

    def test_all_sources_fail_returns_502(self, client):
        with patch("app.routers.blacklists.requests.get", return_value=_resp(503)):
            r = client.post("/api/blacklists/import-geo", json={"countries": ["XX"]})
        assert r.status_code == 502

    def test_empty_countries_rejected(self, client):
        r = client.post("/api/blacklists/import-geo", json={"countries": []})
        assert r.status_code == 400
