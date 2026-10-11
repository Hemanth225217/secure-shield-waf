from fastapi import APIRouter, HTTPException, Request, Depends
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta, timezone
import os

from app.models.user_model import User, LoginUser
from app.db.database import (
    get_user_by_email,
    get_user_by_username,
    create_user_record,
    add_ip_rule
)

router = APIRouter(tags=["Authentication"])

SECRET_KEY = os.getenv("SECURESHIELD_SECRET_KEY", "secureshield-enterprise-supersecret-jwt-key-2026")
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Failed login attempt tracker per IP
failed_attempts = {}

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=8)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

@router.post("/register")
@router.post("/api/auth/register")
def register(user: User):
    existing = get_user_by_email(user.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    existing_name = get_user_by_username(user.username)
    if existing_name:
        raise HTTPException(status_code=400, detail="Username already taken")

    hashed_pw = hash_password(user.password)
    create_user_record(user.username, user.email, hashed_pw)

    return {
        "status": "success",
        "message": f"User '{user.username}' successfully registered."
    }

@router.post("/login")
@router.post("/api/auth/login")
def login(user: LoginUser, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Track failed login attempts for brute-force protection
    if failed_attempts.get(client_ip, 0) >= 5:
        # Auto-ban IP after 5 consecutive failures
        add_ip_rule(client_ip, "BLACKLIST", "Brute-force credential stuffing attack detected")
        raise HTTPException(
            status_code=403,
            detail="Too many failed login attempts. IP has been blacklisted by SecureShield WAF."
        )

    db_user = get_user_by_email(user.email)
    if not db_user or not verify_password(user.password, db_user["hashed_password"]):
        failed_attempts[client_ip] = failed_attempts.get(client_ip, 0) + 1
        remaining = 5 - failed_attempts[client_ip]
        raise HTTPException(
            status_code=401,
            detail=f"Invalid credentials. ({remaining} attempts remaining before IP ban)"
        )

    # Successful login: reset failed attempts
    failed_attempts[client_ip] = 0

    token = create_token({
        "sub": db_user["email"],
        "username": db_user["username"],
        "role": "admin" if db_user["email"].startswith("admin") else "analyst"
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "username": db_user["username"],
        "email": db_user["email"],
        "role": "admin" if db_user["email"].startswith("admin") else "analyst"
    }