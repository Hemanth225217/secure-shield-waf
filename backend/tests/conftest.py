import os
import secrets

# Tests use a throwaway signing key; set before the app is imported
os.environ.setdefault("SECURESHIELD_SECRET_KEY", secrets.token_urlsafe(64))
