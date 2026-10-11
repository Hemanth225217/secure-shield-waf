from fastapi import APIRouter, Depends
from datetime import datetime, timezone
from app.security.jwt_handler import verify_token

router = APIRouter(tags=["Protected Resources"])

@router.get("/protected")
@router.get("/api/protected")
def protected_route(user=Depends(verify_token)):
    return {
        "status": "AUTHORIZED",
        "message": f"Welcome {user.get('username', 'User')}! You have accessed an authenticated WAF resource.",
        "user": user,
        "session": {
            "authorized_at": datetime.now(timezone.utc).isoformat(),
            "encryption": "AES-256-GCM / TLS 1.3",
            "clearance_level": "SOC-Tier-2"
        },
        "system_health": {
            "core_engine": "NOMINAL",
            "signatures_loaded": 48,
            "waf_mode": "ACTIVE-BLOCKING"
        }
    }