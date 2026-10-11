from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from app.main import app
from app.db.database import init_db
from app.security.rate_limiter import rate_limiter

init_db()

READ_ROUTES = [
    ("get", "/api/stats"),
    ("get", "/stats"),
    ("get", "/api/logs"),
    ("get", "/api/ip-rules"),
    ("get", "/api/rules"),
]
WRITE_ROUTES = [
    ("post", "/api/ip-rules", {"ip": "203.0.113.250", "rule_type": "BLACKLIST", "reason": "test"}),
    ("delete", "/api/ip-rules/203.0.113.250", None),
    ("post", "/api/rules", {"name": "test rule", "pattern": "secureshield-test-pattern"}),
    ("patch", "/api/rules/999999/toggle", None),
    ("delete", "/api/rules/999999", None),
]
SIMULATE = {"category": "XSS", "target_location": "query", "payload": "<script>alert(1)</script>"}


@pytest.fixture
def client():
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(autouse=True)
def reset_rate_limit():
    # These tests send many requests quickly; keep the rate limiter out of the way
    for ip in ("testclient", "127.0.0.1"):
        rate_limiter.reset_ip(ip)


def send(client, method, path, body=None, headers=None):
    kwargs = {"headers": headers or {}}
    if body is not None:
        kwargs["json"] = body
    return getattr(client, method)(path, **kwargs)


@pytest.mark.parametrize("method,path", READ_ROUTES)
def test_reads_require_sign_in(client, method, path):
    assert send(client, method, path).status_code == 401


@pytest.mark.parametrize("method,path,body", WRITE_ROUTES)
def test_writes_require_sign_in(client, method, path, body):
    assert send(client, method, path, body).status_code == 401


def test_sandbox_requires_sign_in(client, analyst_headers):
    assert client.post("/api/waf/simulate", json=SIMULATE).status_code == 401
    assert client.post("/api/waf/simulate", json=SIMULATE, headers=analyst_headers).status_code == 200


@pytest.mark.parametrize("method,path", READ_ROUTES)
def test_analyst_can_read(client, analyst_headers, method, path):
    assert send(client, method, path, headers=analyst_headers).status_code == 200


@pytest.mark.parametrize("method,path,body", WRITE_ROUTES)
def test_analyst_cannot_change_settings(client, analyst_headers, method, path, body):
    response = send(client, method, path, body, analyst_headers)
    assert response.status_code == 403
    assert "Admin role required" in response.json()["detail"]


def test_token_signed_with_other_key_is_rejected(client):
    forged = jwt.encode(
        {"sub": "x@example.com", "role": "admin", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        "not-the-real-key-" * 4,
        algorithm="HS256",
    )
    response = client.post(
        "/api/ip-rules",
        json={"ip": "203.0.113.251", "rule_type": "WHITELIST", "reason": "forged"},
        headers={"Authorization": f"Bearer {forged}"},
    )
    assert response.status_code == 401


def test_admin_manages_ip_rules(client, admin_headers):
    ip = "203.0.113.252"
    created = client.post(
        "/api/ip-rules", json={"ip": ip, "rule_type": "BLACKLIST", "reason": "test"}, headers=admin_headers
    )
    try:
        assert created.status_code == 200
        listed = client.get("/api/ip-rules", headers=admin_headers).json()
        assert any(rule["ip"] == ip for rule in listed)
    finally:
        assert client.delete(f"/api/ip-rules/{ip}", headers=admin_headers).status_code == 200


def test_admin_manages_custom_rules(client, admin_headers):
    created = client.post(
        "/api/rules",
        json={"name": "test rule", "pattern": "secureshield-test-pattern", "action": "LOG"},
        headers=admin_headers,
    )
    assert created.status_code == 200
    rule_id = created.json()["rule_id"]
    try:
        assert client.patch(f"/api/rules/{rule_id}/toggle", headers=admin_headers).status_code == 200
    finally:
        assert client.delete(f"/api/rules/{rule_id}", headers=admin_headers).status_code == 200


def test_live_test_target_stays_public(client):
    assert client.get("/api/waf/test-target?search=hello").status_code == 200
