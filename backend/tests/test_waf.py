import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.database import init_db

# Initialize database schema before tests
init_db()

@pytest.fixture
def client():
    # Use FastAPI TestClient (backed by httpx)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c

def test_home_status(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "PROTECTED & ENFORCING"
    assert response.headers.get("x-secureshield-status") == "ACTIVE"

def test_block_sql_injection_in_query(client):
    response = client.get("/api/waf/test-target?query=admin' OR 1=1 --")
    assert response.status_code == 403
    data = response.json()
    assert data["action"] == "BLOCKED"
    assert data["threat_type"] == "SQL_INJECTION"
    assert response.headers.get("x-secureshield-status") == "BLOCKED"

def test_block_sql_injection_in_body(client):
    response = client.post(
        "/api/waf/test-target",
        json={"username": "admin", "search": "UNION SELECT 1,2,3 from passwords"}
    )
    assert response.status_code == 403
    data = response.json()
    assert data["action"] == "BLOCKED"
    assert data["threat_type"] == "SQL_INJECTION"

def test_block_xss_in_body(client):
    response = client.post(
        "/api/waf/test-target",
        json={"comment": "<script>alert(document.cookie)</script>"}
    )
    assert response.status_code == 403
    data = response.json()
    assert data["action"] == "BLOCKED"
    assert data["threat_type"] == "XSS"

def test_block_path_traversal(client):
    response = client.get("/api/waf/test-target?file=../../../../etc/passwd")
    assert response.status_code == 403
    data = response.json()
    assert data["action"] == "BLOCKED"
    assert data["threat_type"] == "PATH_TRAVERSAL"

def test_block_command_injection(client):
    response = client.post(
        "/api/waf/test-target",
        json={"cmd": "echo test; cat /etc/passwd"}
    )
    assert response.status_code == 403
    data = response.json()
    assert data["action"] == "BLOCKED"
    assert data["threat_type"] == "COMMAND_INJECTION"

def test_block_malicious_scanner_user_agent(client):
    response = client.get(
        "/api/waf/test-target",
        headers={"User-Agent": "sqlmap/1.6#stable (https://sqlmap.org)"}
    )
    assert response.status_code == 403
    data = response.json()
    assert data["action"] == "BLOCKED"
    assert data["threat_type"] == "SCANNER_BOT"

def test_allow_legitimate_request(client):
    response = client.post(
        "/api/waf/test-target",
        json={"message": "Hello World", "email": "valid.user@example.com", "count": 42}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert response.headers.get("x-secureshield-status") == "ACTIVE"

def test_simulation_sandbox(client, analyst_headers):
    payload = {
        "category": "SQL_INJECTION",
        "target_location": "query",
        "payload": "' UNION SELECT null, username, password FROM users --"
    }
    response = client.post("/api/waf/simulate", json=payload, headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["is_threat"] is True
    assert data["action"] == "BLOCKED"
    assert data["threat_type"] == "SQL_INJECTION"
    assert data["threat_score"] >= 90

def test_auth_registration_and_jwt_flow(client):
    from app.security.rate_limiter import rate_limiter
    rate_limiter.reset_ip("testclient")
    rate_limiter.reset_ip("127.0.0.1")

    # Register user
    user_payload = {
        "username": "testanalyst",
        "email": "analyst@secureshield.io",
        "password": "SecurePassword123!"
    }
    reg_resp = client.post("/api/auth/register", json=user_payload)
    assert reg_resp.status_code in [200, 400] # 400 if already exists

    # Login
    login_resp = client.post("/api/auth/login", json={
        "email": "analyst@secureshield.io",
        "password": "SecurePassword123!"
    })
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert "access_token" in login_data
    token = login_data["access_token"]

    # Access Protected Route with Bearer token
    prot_resp = client.get(
        "/api/protected",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert prot_resp.status_code == 200
    prot_data = prot_resp.json()
    assert prot_data["status"] == "AUTHORIZED"
    assert prot_data["user"]["sub"] == "analyst@secureshield.io"


def test_waf_stats_endpoint(client, analyst_headers):
    response = client.get("/api/stats", headers=analyst_headers)
    assert response.status_code == 200
    stats = response.json()
    assert "firewall_status" in stats
    assert "blocked_attacks" in stats
    assert "threat_breakdown" in stats
