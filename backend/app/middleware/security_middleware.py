import time
import json
from datetime import datetime, timezone
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import Message

from app.security.waf_engine import waf_engine
from app.security.rate_limiter import rate_limiter
from app.db.database import (
    log_security_event,
    get_ip_cache,
    get_all_custom_rules,
    add_ip_rule
)

class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        # Cache IP lists and custom rules with 5-second TTL to keep request processing sub-millisecond
        self._last_cache_time = 0
        self._ip_cache = {"blacklist": set(), "whitelist": set()}
        self._custom_rules_cache = []

    def _refresh_caches_if_needed(self):
        now = time.time()
        if now - self._last_cache_time > 5:
            try:
                self._ip_cache = get_ip_cache()
                self._custom_rules_cache = get_all_custom_rules()
                self._last_cache_time = now
            except Exception:
                pass

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        self._refresh_caches_if_needed()

        # Resolve Client IP
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "127.0.0.1"

        path = request.url.path
        method = request.method
        query_string = request.url.query
        user_agent = request.headers.get("user-agent", "")

        # Bypass internal docs/static if needed, but inspect all API routes and target paths
        is_simulation_endpoint = path == "/api/waf/simulate"

        # Whitelist Check (Fast Path)
        if client_ip in self._ip_cache["whitelist"]:
            response = await call_next(request)
            response.headers["X-SecureShield-Status"] = "WHITELISTED"
            return response

        # Blacklist Check (Block Immediately)
        if client_ip in self._ip_cache["blacklist"]:
            log_security_event(
                client_ip=client_ip,
                method=method,
                path=path,
                threat_type="BLACKLISTED_IP",
                threat_score=100,
                action="BLOCKED",
                reason=f"Client IP {client_ip} is in active WAF blacklist",
                payload_sample="",
                user_agent=user_agent
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Access Denied by SecureShield WAF",
                    "reason": "Your IP address is listed on the security blacklist.",
                    "client_ip": client_ip,
                    "threat_type": "BLACKLISTED_IP",
                    "action": "BLOCKED"
                },
                headers={"X-SecureShield-Status": "BLOCKED-BLACKLIST"}
            )

        # Rate Limiting Check (Skip for read-only polling stats/logs and simulation sandbox)
        is_dashboard_poll = path in ["/api/stats", "/api/logs", "/stats"]
        if not is_dashboard_poll and not is_simulation_endpoint:
            # Stricter for auth routes, standard for others
            req_limit = 15 if "/auth" in path else 60
            allowed, count, limit = rate_limiter.is_allowed(client_ip, limit=req_limit, window=10)
            if not allowed:
                strikes = rate_limiter.get_strikes(client_ip)
                # Auto-ban if persistent abusive flood
                if strikes >= 10:
                    add_ip_rule(client_ip, "BLACKLIST", "Automated ban: Persistent rate limit abuse / DDoS flooding")
                    self._ip_cache["blacklist"].add(client_ip)

                log_security_event(
                    client_ip=client_ip,
                    method=method,
                    path=path,
                    threat_type="RATE_LIMIT_EXCEEDED",
                    threat_score=80,
                    action="BLOCKED",
                    reason=f"Rate limit exceeded: {count} requests within 10s (limit: {limit})",
                    payload_sample=f"Rate limit strike #{strikes}",
                    user_agent=user_agent
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Too Many Requests",
                        "detail": f"Rate limit exceeded ({count}/{limit} req/10s). Request throttled by SecureShield.",
                        "client_ip": client_ip,
                        "retry_after_seconds": 10,
                        "action": "BLOCKED"
                    },
                    headers={"X-SecureShield-Status": "THROTTLED", "Retry-After": "10"}
                )

        # If this is the simulation endpoint, let it pass through to the handler where waf_engine analyzes the payload
        if is_simulation_endpoint:
            response = await call_next(request)
            response.headers["X-SecureShield-Status"] = "SIMULATION-MODE"
            return response


        # Safe Request Body Extraction (Preserve stream for downstream route handlers)
        body_text = ""
        if method in ["POST", "PUT", "PATCH"]:
            try:
                body_bytes = await request.body()
                body_text = body_bytes.decode("utf-8", errors="ignore")

                # Restore request._receive so downstream endpoints can read request.body()
                async def receive() -> Message:
                    return {"type": "http.request", "body": body_bytes, "more_body": False}
                request._receive = receive
            except Exception:
                body_text = ""

        # Extract headers dict for WAF inspection
        headers_dict = {k.lower(): v for k, v in request.headers.items()}

        # Deep WAF Threat Inspection
        inspection = waf_engine.inspect_request(
            method=method,
            path=path,
            query_params=query_string,
            headers=headers_dict,
            body=body_text,
            custom_rules=self._custom_rules_cache
        )

        # Handle WAF Verdict
        if inspection.action == "BLOCKED":
            log_security_event(
                client_ip=client_ip,
                method=method,
                path=path,
                threat_type=inspection.threat_type,
                threat_score=inspection.threat_score,
                action="BLOCKED",
                reason=inspection.reason,
                payload_sample=inspection.payload_sample,
                user_agent=user_agent
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Forbidden - Attack Blocked by SecureShield WAF",
                    "threat_type": inspection.threat_type,
                    "threat_score": inspection.threat_score,
                    "reason": inspection.reason,
                    "rules_triggered": inspection.matched_rules,
                    "client_ip": client_ip,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "action": "BLOCKED"
                },
                headers={
                    "X-SecureShield-Status": "BLOCKED",
                    "X-SecureShield-Score": str(inspection.threat_score),
                    "X-SecureShield-Latency": f"{inspection.latency_ms}ms"
                }
            )

        if inspection.action == "MONITORED":
            log_security_event(
                client_ip=client_ip,
                method=method,
                path=path,
                threat_type=inspection.threat_type,
                threat_score=inspection.threat_score,
                action="MONITORED",
                reason=inspection.reason,
                payload_sample=inspection.payload_sample,
                user_agent=user_agent
            )

        # For allowed requests, log sample or general audit if not frequent polling
        if not is_dashboard_poll and inspection.action == "ALLOWED":
            log_security_event(
                client_ip=client_ip,
                method=method,
                path=path,
                threat_type="NONE",
                threat_score=0,
                action="ALLOWED",
                reason="Clean request passed WAF inspection",
                payload_sample="",
                user_agent=user_agent
            )

        # Call downstream application
        response = await call_next(request)

        # Inject Hardened Security Headers
        latency_total = round((time.time() - start_time) * 1000, 2)
        response.headers["X-SecureShield-Status"] = "ACTIVE"
        response.headers["X-SecureShield-Score"] = str(inspection.threat_score)
        response.headers["X-SecureShield-Processing-Time"] = f"{latency_total}ms"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        return response