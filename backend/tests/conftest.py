import os
import secrets

# Tests use a throwaway signing key and a fixed test admin; set before the app is imported
os.environ.setdefault("SECURESHIELD_SECRET_KEY", secrets.token_urlsafe(64))
os.environ["SECURESHIELD_ADMIN_EMAILS"] = "secureshield-test-admin@example.com"
