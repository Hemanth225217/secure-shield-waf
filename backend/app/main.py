from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.db.database import init_db, get_waf_stats
from app.security.auth import router as auth_router
from app.routes.protected import router as protected_router
from app.routes.waf_routes import router as waf_router
from app.middleware.security_middleware import SecurityMiddleware

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database and seed default rules/IPs
    init_db()
    yield

app = FastAPI(
    title="SecureShield WAF",
    description="Enterprise Web Application Firewall (WAF) & Real-Time Threat Prevention Gateway",
    version="2.0.0",
    lifespan=lifespan
)

# CORS Middleware (Must be before custom application middleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Core WAF Security Middleware
app.add_middleware(SecurityMiddleware)

# API Routers
app.include_router(waf_router)
app.include_router(auth_router)
app.include_router(protected_router)

@app.get("/")
def home():
    return {
        "system": "SecureShield WAF",
        "version": "2.0.0",
        "status": "PROTECTED & ENFORCING",
        "mode": "ACTIVE-BLOCKING",
        "documentation": "/docs"
    }

@app.get("/stats")
def get_stats():
    """Backward compatibility endpoint for root /stats"""
    return get_waf_stats()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)