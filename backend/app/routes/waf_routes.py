from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from app.db.database import (
    get_waf_stats,
    get_recent_logs,
    get_ip_rules,
    add_ip_rule,
    delete_ip_rule,
    get_all_custom_rules,
    add_custom_rule,
    toggle_custom_rule,
    delete_custom_rule
)
from app.security.waf_engine import waf_engine

router = APIRouter(prefix="/api", tags=["WAF Management & Analytics"])

class IPRuleRequest(BaseModel):
    ip: str = Field(..., json_schema_extra={"example": "192.168.1.50"})
    rule_type: str = Field(..., json_schema_extra={"example": "BLACKLIST"}) # 'BLACKLIST' or 'WHITELIST'
    reason: str = Field(..., json_schema_extra={"example": "Malicious probe attempts"})

class CustomRuleRequest(BaseModel):
    name: str = Field(..., json_schema_extra={"example": "Block Spring4Shell"})
    pattern: str = Field(..., json_schema_extra={"example": "class\\.module\\.classLoader"})
    target_location: str = Field("any", json_schema_extra={"example": "body"})
    severity: str = Field("HIGH", json_schema_extra={"example": "HIGH"})
    threat_score: int = Field(85, json_schema_extra={"example": 85})
    action: str = Field("BLOCK", json_schema_extra={"example": "BLOCK"})

class AttackSimulationRequest(BaseModel):
    category: str = Field(..., json_schema_extra={"example": "SQL_INJECTION"})
    target_location: str = Field("query", json_schema_extra={"example": "query"})
    payload: str = Field(..., json_schema_extra={"example": "' OR 1=1 --"})


@router.get("/stats")
def get_stats():
    """Retrieve real-time firewall statistics, block rate, and threat breakdown."""
    return get_waf_stats()

@router.get("/logs")
def get_logs(
    limit: int = Query(50, ge=1, le=200),
    threat_type: Optional[str] = Query(None),
    action: Optional[str] = Query(None)
):
    """Retrieve real-time security logs with optional filtering."""
    return get_recent_logs(limit=limit, threat_type=threat_type, action=action)

@router.get("/ip-rules")
def list_ip_rules():
    """List all active IP Blacklist and Whitelist rules."""
    return get_ip_rules()

@router.post("/ip-rules")
def create_ip_rule(req: IPRuleRequest):
    """Add an IP to the blacklist or whitelist."""
    if req.rule_type.upper() not in ["BLACKLIST", "WHITELIST"]:
        raise HTTPException(status_code=400, detail="rule_type must be BLACKLIST or WHITELIST")
    success = add_ip_rule(req.ip, req.rule_type, req.reason)
    return {"message": f"IP {req.ip} added to {req.rule_type.upper()}", "success": success}

@router.delete("/ip-rules/{ip}")
def remove_ip_rule(ip: str):
    """Remove an IP rule from access control."""
    deleted = delete_ip_rule(ip)
    if not deleted:
        raise HTTPException(status_code=404, detail="IP rule not found")
    return {"message": f"IP {ip} removed from access control", "success": True}

@router.get("/rules")
def list_custom_rules():
    """List all custom WAF detection rules."""
    return get_all_custom_rules()

@router.post("/rules")
def create_custom_rule(req: CustomRuleRequest):
    """Add a new custom regex rule to the WAF engine."""
    rule_id = add_custom_rule(
        name=req.name,
        pattern=req.pattern,
        target_location=req.target_location,
        severity=req.severity,
        threat_score=req.threat_score,
        action=req.action
    )
    return {"message": "Custom rule created successfully", "rule_id": rule_id}

@router.patch("/rules/{rule_id}/toggle")
def toggle_rule(rule_id: int):
    """Toggle a custom rule enabled/disabled."""
    new_state = toggle_custom_rule(rule_id)
    if new_state is None:
        raise HTTPException(status_code=404, detail="Custom rule not found")
    return {"message": f"Rule status updated", "enabled": new_state}

@router.delete("/rules/{rule_id}")
def remove_custom_rule(rule_id: int):
    """Delete a custom rule."""
    deleted = delete_custom_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Custom rule not found")
    return {"message": "Custom rule deleted", "success": True}

@router.post("/waf/simulate")
def simulate_attack(sim: AttackSimulationRequest):
    """
    Simulation Sandbox: evaluates payload against WAF inspection engine without needing a full exploit environment.
    """
    path = "/test"
    query = ""
    body = ""
    headers = {"user-agent": "SecureShield-Simulator/1.0"}

    if sim.target_location == "path":
        path = f"/test/{sim.payload}"
    elif sim.target_location == "query":
        query = f"search={sim.payload}"
    elif sim.target_location == "body":
        body = sim.payload
    elif sim.target_location == "header":
        headers["user-agent"] = sim.payload

    custom_rules = get_all_custom_rules()
    result = waf_engine.inspect_request(
        method="POST" if sim.target_location == "body" else "GET",
        path=path,
        query_params=query,
        headers=headers,
        body=body,
        custom_rules=custom_rules
    )

    return {
        "simulation_category": sim.category,
        "payload": sim.payload,
        "is_threat": result.is_threat,
        "action": result.action,
        "threat_type": result.threat_type,
        "threat_score": result.threat_score,
        "matched_rules": result.matched_rules,
        "reason": result.reason,
        "latency_ms": result.latency_ms
    }

@router.post("/waf/test-target")
def test_target_endpoint(payload: Dict[str, Any] = None):
    """
    Live test endpoint protected by WAF middleware. 
    If a payload contains malicious SQLi/XSS/RCE, the middleware will block it before reaching this handler!
    """
    return {
        "status": "SUCCESS",
        "message": "Payload safely reached the application handler (WAF allowed the request)",
        "received_data": payload
    }
