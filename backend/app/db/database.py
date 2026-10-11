import sqlite3
import os
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "secureshield.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Security event logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        threat_type TEXT NOT NULL,
        threat_score INTEGER NOT NULL,
        action TEXT NOT NULL,
        reason TEXT NOT NULL,
        payload_sample TEXT,
        user_agent TEXT
    )
    """)

    # IP Access Control (Blacklist / Whitelist)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ip_access_control (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        rule_type TEXT NOT NULL, -- 'BLACKLIST' or 'WHITELIST'
        reason TEXT NOT NULL,
        added_at TEXT NOT NULL
    )
    """)

    # Custom WAF Rules
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS custom_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        pattern TEXT NOT NULL,
        target_location TEXT NOT NULL, -- 'path', 'query', 'header', 'body', 'any'
        severity TEXT NOT NULL, -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        threat_score INTEGER NOT NULL,
        action TEXT NOT NULL, -- 'BLOCK' or 'LOG'
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """)

    # Persistent Users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        created_at TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'analyst'
    )
    """)

    # Migrate databases created before roles were stored per user
    columns = [row[1] for row in cursor.execute("PRAGMA table_info(users)")]
    if "role" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'analyst'")

    # Seed default custom rules if empty
    cursor.execute("SELECT COUNT(*) FROM custom_rules")
    if cursor.fetchone()[0] == 0:
        default_rules = [
            ("Block WordPress Probing", r"wp-admin|wp-login\.php|xmlrpc\.php", "path", "HIGH", 85, "BLOCK", 1),
            ("Detect Sensitive Config Exposure", r"\.env|\.git|config\.json|web\.config", "path", "CRITICAL", 95, "BLOCK", 1),
            ("Block Apache Struts / Log4Shell Patterns", r"\$\{jndi:(?:ldap|rmi|dns)", "any", "CRITICAL", 100, "BLOCK", 1),
            ("Detect Suspicious Header Manipulation", r"X-Forwarded-Host|X-Host|X-Forwarded-Server", "header", "MEDIUM", 45, "LOG", 1),
        ]
        now = datetime.now(timezone.utc).isoformat()
        for name, pattern, loc, sev, score, act, en in default_rules:
            cursor.execute("""
            INSERT INTO custom_rules (name, pattern, target_location, severity, threat_score, action, enabled, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, pattern, loc, sev, score, act, en, now))

    # Seed default blocked IP if empty
    cursor.execute("SELECT COUNT(*) FROM ip_access_control")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO ip_access_control (ip, rule_type, reason, added_at)
        VALUES (?, ?, ?, ?)
        """, ("198.51.100.42", "BLACKLIST", "Known botnet scanner IP", datetime.now(timezone.utc).isoformat()))

    conn.commit()
    conn.close()

# ----------------- Log Operations -----------------

def log_security_event(
    client_ip: str,
    method: str,
    path: str,
    threat_type: str,
    threat_score: int,
    action: str,
    reason: str,
    payload_sample: str = "",
    user_agent: str = ""
):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO security_logs (timestamp, client_ip, method, path, threat_type, threat_score, action, reason, payload_sample, user_agent)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat(),
        client_ip,
        method,
        path,
        threat_type,
        threat_score,
        action,
        reason,
        payload_sample[:500] if payload_sample else "",
        user_agent[:255] if user_agent else ""
    ))
    conn.commit()
    conn.close()

def get_recent_logs(limit: int = 50, threat_type: Optional[str] = None, action: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    query = "SELECT * FROM security_logs"
    params = []
    clauses = []
    if threat_type and threat_type != "ALL":
        clauses.append("threat_type = ?")
        params.append(threat_type)
    if action and action != "ALL":
        clauses.append("action = ?")
        params.append(action)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    logs = [dict(r) for r in rows]
    conn.close()
    return logs

def get_waf_stats() -> Dict[str, Any]:
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM security_logs")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE action = 'BLOCKED'")
    total_blocked = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE action = 'MONITORED'")
    total_monitored = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE action = 'ALLOWED'")
    total_allowed = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM ip_access_control WHERE rule_type = 'BLACKLIST'")
    active_blacklisted_ips = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM custom_rules WHERE enabled = 1")
    active_rules_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users")
    registered_users = cursor.fetchone()[0]

    # Threat type distribution
    cursor.execute("""
    SELECT threat_type, COUNT(*) as count 
    FROM security_logs 
    WHERE threat_type != 'NONE' AND action = 'BLOCKED'
    GROUP BY threat_type
    ORDER BY count DESC
    LIMIT 6
    """)
    threat_breakdown = {r["threat_type"]: r["count"] for r in cursor.fetchall()}

    conn.close()

    block_rate = round((total_blocked / total_events * 100), 1) if total_events > 0 else 0.0

    return {
        "firewall_status": "ACTIVE & ENFORCING",
        "threat_detection": "MULTILAYER ENGINE",
        "rate_limiter": "SLIDING WINDOW ACTIVE",
        "total_requests_processed": total_events,
        "blocked_attacks": total_blocked,
        "monitored_requests": total_monitored,
        "allowed_requests": total_allowed,
        "block_rate_percentage": block_rate,
        "active_blacklisted_ips": active_blacklisted_ips,
        "active_rules_count": active_rules_count,
        "authenticated_users": registered_users,
        "threat_breakdown": threat_breakdown
    }

# ----------------- IP Control Operations -----------------

def get_ip_rules() -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ip_access_control ORDER BY id DESC")
    rows = cursor.fetchall()
    rules = [dict(r) for r in rows]
    conn.close()
    return rules

def add_ip_rule(ip: str, rule_type: str, reason: str) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
        INSERT INTO ip_access_control (ip, rule_type, reason, added_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET rule_type=excluded.rule_type, reason=excluded.reason, added_at=excluded.added_at
        """, (ip.strip(), rule_type.upper(), reason, datetime.now(timezone.utc).isoformat()))
        conn.commit()
        return True
    finally:
        conn.close()

def delete_ip_rule(ip: str) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ip_access_control WHERE ip = ?", (ip.strip(),))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def get_ip_cache() -> Dict[str, set]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT ip, rule_type FROM ip_access_control")
    rows = cursor.fetchall()
    blacklist = set()
    whitelist = set()
    for r in rows:
        if r["rule_type"] == "BLACKLIST":
            blacklist.add(r["ip"])
        elif r["rule_type"] == "WHITELIST":
            whitelist.add(r["ip"])
    conn.close()
    return {"blacklist": blacklist, "whitelist": whitelist}

# ----------------- Custom Rules Operations -----------------

def get_all_custom_rules() -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM custom_rules ORDER BY id DESC")
    rows = cursor.fetchall()
    rules = [dict(r) for r in rows]
    conn.close()
    return rules

def add_custom_rule(name: str, pattern: str, target_location: str, severity: str, threat_score: int, action: str) -> int:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO custom_rules (name, pattern, target_location, severity, threat_score, action, enabled, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    """, (name, pattern, target_location, severity.upper(), threat_score, action.upper(), datetime.now(timezone.utc).isoformat()))
    rule_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return rule_id

def toggle_custom_rule(rule_id: int) -> Optional[bool]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT enabled FROM custom_rules WHERE id = ?", (rule_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    new_state = 0 if row["enabled"] else 1
    cursor.execute("UPDATE custom_rules SET enabled = ? WHERE id = ?", (new_state, rule_id))
    conn.commit()
    conn.close()
    return bool(new_state)

def delete_custom_rule(rule_id: int) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

# ----------------- User Persistence Operations -----------------

def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username.strip(),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def create_user_record(username: str, email: str, hashed_password: str, role: str = "analyst") -> bool:
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
        INSERT INTO users (username, email, hashed_password, created_at, role)
        VALUES (?, ?, ?, ?, ?)
        """, (username.strip(), email.strip().lower(), hashed_password, datetime.now(timezone.utc).isoformat(), role))
        conn.commit()
        return True
    finally:
        conn.close()

