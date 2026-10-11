from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

from app.security.config import SECRET_KEY, ALGORITHM

# auto_error=False so a missing token gets a consistent 401 instead of the default 403
security = HTTPBearer(auto_error=False)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required: sign in to access this resource",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid, malformed, or expired security token"
        )

def require_admin(user=Depends(verify_token)):
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin role required to change firewall settings"
        )
    return user
