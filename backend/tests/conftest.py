import os
import secrets

# Tests use a throwaway signing key and a fixed test admin; set before the app is imported
os.environ.setdefault("SECURESHIELD_SECRET_KEY", secrets.token_urlsafe(64))
os.environ["SECURESHIELD_ADMIN_EMAILS"] = "secureshield-test-admin@example.com"

import pytest


def _bearer(role):
    from app.security.auth import create_token
    token = create_token({"sub": f"test-{role}@example.com", "username": f"test-{role}", "role": role})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers():
    return _bearer("analyst")


@pytest.fixture
def admin_headers():
    return _bearer("admin")
