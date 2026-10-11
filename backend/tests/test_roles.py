import uuid

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from app.main import app
from app.db.database import get_db, init_db
from app.security.config import SECRET_KEY, ALGORITHM

TEST_ADMIN = "secureshield-test-admin@example.com"
PASSWORD = "Str0ng!Passw0rd"

init_db()


@pytest.fixture
def client():
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def created_emails():
    emails = []
    yield emails
    # Remove test users so they don't pile up in the real database
    conn = get_db()
    conn.executemany("DELETE FROM users WHERE email = ?", [(e,) for e in emails])
    conn.commit()
    conn.close()


def register_and_login(client, email, extra=None):
    body = {"username": f"user-{uuid.uuid4().hex[:10]}", "email": email, "password": PASSWORD}
    body.update(extra or {})
    assert client.post("/api/auth/register", json=body).status_code == 200
    response = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200
    data = response.json()
    claims = jwt.decode(data["access_token"], SECRET_KEY, algorithms=[ALGORITHM])
    return data["role"], claims["role"]


def test_admin_looking_email_is_not_admin(client, created_emails):
    email = f"admin-{uuid.uuid4().hex[:10]}@example.com"
    created_emails.append(email)
    assert register_and_login(client, email) == ("analyst", "analyst")


def test_role_in_request_body_is_ignored(client, created_emails):
    email = f"user-{uuid.uuid4().hex[:10]}@example.com"
    created_emails.append(email)
    assert register_and_login(client, email, {"role": "admin"}) == ("analyst", "analyst")


def test_configured_admin_email_gets_admin(client, created_emails):
    created_emails.append(TEST_ADMIN)
    conn = get_db()
    conn.execute("DELETE FROM users WHERE email = ?", (TEST_ADMIN,))
    conn.commit()
    conn.close()
    assert register_and_login(client, TEST_ADMIN) == ("admin", "admin")


def test_role_is_stored_in_database(client, created_emails):
    email = f"admin-{uuid.uuid4().hex[:10]}@example.com"
    created_emails.append(email)
    register_and_login(client, email)
    conn = get_db()
    role = conn.execute("SELECT role FROM users WHERE email = ?", (email,)).fetchone()[0]
    conn.close()
    assert role == "analyst"
