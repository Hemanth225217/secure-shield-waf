import os

from dotenv import find_dotenv, load_dotenv

# Load .env from the working directory or any parent (backend/ or repo root)
load_dotenv(find_dotenv(usecwd=True))

MIN_SECRET_LENGTH = 32

# Values that must never be used as a real signing key
KNOWN_INSECURE_SECRETS = {
    "secureshield-enterprise-supersecret-jwt-key-2026",
    "change-me-generate-a-random-secret",
}

GENERATE_HINT = (
    'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(64))" '
    "and set it in a .env file (see .env.example) or as an environment variable."
)


def load_secret_key() -> str:
    """Returns the JWT signing key, refusing to start without a strong one."""
    secret = os.getenv("SECURESHIELD_SECRET_KEY", "").strip()

    if not secret:
        raise RuntimeError(f"SECURESHIELD_SECRET_KEY is not set. {GENERATE_HINT}")
    if secret in KNOWN_INSECURE_SECRETS:
        raise RuntimeError(
            f"SECURESHIELD_SECRET_KEY is set to a publicly known value. {GENERATE_HINT}"
        )
    if len(secret) < MIN_SECRET_LENGTH:
        raise RuntimeError(
            f"SECURESHIELD_SECRET_KEY must be at least {MIN_SECRET_LENGTH} characters. {GENERATE_HINT}"
        )

    return secret


SECRET_KEY = load_secret_key()
ALGORITHM = "HS256"
