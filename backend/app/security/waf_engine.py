import re
import urllib.parse
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

@dataclass
class WAFInspectionResult:
    is_threat: bool
    action: str  # 'BLOCKED', 'MONITORED', 'ALLOWED'
    threat_type: str
    threat_score: int
    matched_rules: List[str]
    reason: str
    payload_sample: str
    latency_ms: float

class WAFEngine:
    def __init__(self):
        # SQL Injection Patterns
        self.sqli_patterns = [
            (r"(?i)\bunion\s+(?:all\s+)?select\b", "SQLi: Union Select Query", 95),
            (r"(?i)\b(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", "SQLi: Boolean Tautology (OR 1=1)", 90),
            (r"(?i)(?:;\s*)?\b(?:drop\s+table|delete\s+from|insert\s+into|truncate\s+table|alter\s+table)\b", "SQLi: Destructive DDL/DML Statement", 100),
            (r"(?i)\bselect\s+[\w\*\s,]+\s+from\s+\w+", "SQLi: Direct Database Select Query", 90),
            (r"(?i)\b(information_schema|sysdatabases|sysobjects|pg_catalog)\b", "SQLi: Database Metadata Reconnaissance", 85),
            (r"(?i)\b(?:waitfor\s+delay|sleep\s*\(\s*\d+\s*\)|pg_sleep\s*\(\s*\d+\s*\))", "SQLi: Time-based Blind Delay", 95),
            (r"(?i)(?:'|\"|%27|%22)\s*(?:--|\#|\/\*).*?(?:select|drop|insert|delete|from)", "SQLi: Comment Injected Directive", 85),
            (r"(?i)\bexec\s*(?:master\.\.xp_cmdshell|sp_executesql)\b", "SQLi: Command Shell Execution via SQL", 100),

        ]

        # Cross-Site Scripting (XSS) Patterns
        self.xss_patterns = [
            (r"(?i)<\s*script\b[^>]*>", "XSS: Script Tag Injection", 95),
            (r"(?i)<\s*(?:iframe|object|embed|svg|img|video|audio|body|input|link)\b[^>]*(?:onerror|onload|onclick|onmouseover|src\s*=\s*javascript:)[^>]*>", "XSS: Inline Event Handler Injection", 90),
            (r"(?i)javascript\s*:\s*[^\s'\"]+", "XSS: JavaScript URI Scheme", 85),
            (r"(?i)document\.(?:cookie|location|domain|write)\b", "XSS: DOM Manipulation / Cookie Stealer", 80),
            (r"(?i)\b(?:alert|confirm|prompt)\s*\([^\)]*\)", "XSS: Script Popup Invocation", 85),
            (r"(?i)<\s*\/\s*script\s*>", "XSS: Closing Script Tag", 75),
        ]

        # Path Traversal & Local File Inclusion (LFI) Patterns
        self.path_traversal_patterns = [
            (r"(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e%252f)", "Path Traversal: Directory Traversal Sequence", 90),
            (r"(?i)(?:/etc/(?:passwd|shadow|hosts|issue)|boot\.ini|win(?:dows)?(?:/|\\)system32|win\.ini)", "Path Traversal: Sensitive Operating System File Target", 100),
            (r"(?i)\x00|%00", "Path Traversal: Null Byte Injection", 95),
        ]

        # Remote Code Execution & Command Injection Patterns
        self.rce_patterns = [
            (r"(?i)(?:;|\||&&|\$\(|\`)\s*(?:cat\s+/|ls\s+-|whoami|id\b|uname\b|wget\s+|curl\s+|bash\s+-i|powershell\s+|cmd(?:\.exe)?|nc\s+-e)", "RCE: Shell Command Chaining", 100),
            (r"(?i)\$\{(?:jndi|env|lower|upper):[^\}]+\}", "RCE: Log4Shell / JNDI Lookup Expression", 100),
            (r"(?i)\b(?:system|passthru|exec|shell_exec|popen|proc_open)\s*\(", "RCE: Native System Execution Function", 95),
        ]

        # Malicious Automated Scanners & Bot Signatures
        self.scanner_patterns = [
            (r"(?i)\b(?:sqlmap|nikto|acunetix|nessus|nmap|gobuster|dirbuster|wpscan|masscan|burpcollaborator|zgrab)\b", "Scanner: Automated Security Scanner Signature", 90),
            (r"(?i)\b(?:python-requests|curl/\d|wget/\d|libwww-perl)\b", "Bot: Scripted HTTP Client Agent", 40),
        ]

        # Sensitive Dotfile & Server Exposure Probing
        self.sensitive_probing_patterns = [
            (r"(?i)\b(?:\.env|\.git(?:/|\b)|\.aws|\.ssh|\.htaccess|wp-config\.php|phpinfo\.php|web\.config)\b", "Probe: Sensitive Configuration & Secrets Targeting", 90),
        ]

    def _decode_safely(self, text: str) -> str:
        """Repeatedly URL-decode up to 3 times to unmask obfuscated payloads."""
        current = text
        for _ in range(3):
            try:
                decoded = urllib.parse.unquote_plus(current)
                if decoded == current:
                    break
                current = decoded
            except Exception:
                break
        return current

    def inspect_request(
        self,
        method: str,
        path: str,
        query_params: str = "",
        headers: Dict[str, str] = None,
        body: str = "",
        custom_rules: List[Dict[str, Any]] = None
    ) -> WAFInspectionResult:
        start_time = time.time()
        headers = headers or {}
        custom_rules = custom_rules or []

        user_agent = headers.get("user-agent", "")
        referer = headers.get("referer", "")
        
        decoded_path = self._decode_safely(path)
        decoded_query = self._decode_safely(query_params)
        decoded_body = self._decode_safely(body) if body else ""

        # Aggregate payload strings for multi-vector inspection
        targets = {
            "path": decoded_path,
            "query": decoded_query,
            "body": decoded_body,
            "user_agent": user_agent,
            "referer": referer
        }

        matched_rules = []
        highest_score = 0
        detected_threat_type = "NONE"
        primary_reason = ""
        payload_sample = ""

        def check_category(patterns, category_name, content, location_name):
            nonlocal highest_score, detected_threat_type, primary_reason, payload_sample
            if not content:
                return
            for pattern, rule_desc, score in patterns:
                match = re.search(pattern, content)
                if match:
                    matched_rules.append(f"[{category_name}] {rule_desc} in {location_name}")
                    if score > highest_score:
                        highest_score = score
                        detected_threat_type = category_name
                        primary_reason = f"{rule_desc} detected in {location_name}"
                        snippet = match.group(0)
                        payload_sample = snippet[:150]

        # 1. SQL Injection Inspection (Path, Query, Body)
        for loc in ["query", "body", "path"]:
            check_category(self.sqli_patterns, "SQL_INJECTION", targets[loc], loc)

        # 2. XSS Inspection (Path, Query, Body, Referer)
        for loc in ["query", "body", "path", "referer"]:
            check_category(self.xss_patterns, "XSS", targets[loc], loc)

        # 3. Path Traversal & LFI Inspection (Path, Query)
        for loc in ["path", "query"]:
            check_category(self.path_traversal_patterns, "PATH_TRAVERSAL", targets[loc], loc)

        # 4. Command Injection / RCE Inspection (Path, Query, Body)
        for loc in ["query", "body", "path"]:
            check_category(self.rce_patterns, "COMMAND_INJECTION", targets[loc], loc)

        # 5. Scanner / Bot Inspection (User-Agent)
        check_category(self.scanner_patterns, "SCANNER_BOT", targets["user_agent"], "User-Agent Header")

        # 6. Sensitive File Probing (Path, Query)
        for loc in ["path", "query"]:
            check_category(self.sensitive_probing_patterns, "SENSITIVE_PROBING", targets[loc], loc)

        # 7. Evaluate Custom Dynamic Rules from Database
        for rule in custom_rules:
            if not rule.get("enabled", 1):
                continue
            r_pattern = rule.get("pattern", "")
            r_loc = rule.get("target_location", "any")
            r_score = rule.get("threat_score", 80)
            r_name = rule.get("name", "Custom Rule")
            r_action = rule.get("action", "BLOCK")

            search_areas = []
            if r_loc == "path":
                search_areas = [("path", targets["path"])]
            elif r_loc == "query":
                search_areas = [("query", targets["query"])]
            elif r_loc == "header":
                search_areas = [("user_agent", targets["user_agent"]), ("referer", targets["referer"])]
            elif r_loc == "body":
                search_areas = [("body", targets["body"])]
            else: # 'any'
                search_areas = [(k, v) for k, v in targets.items()]

            for loc_name, content in search_areas:
                if not content:
                    continue
                try:
                    match = re.search(r_pattern, content, re.IGNORECASE)
                    if match:
                        matched_rules.append(f"[CUSTOM] {r_name} in {loc_name}")
                        if r_score > highest_score:
                            highest_score = r_score
                            detected_threat_type = "CUSTOM_RULE"
                            primary_reason = f"Custom rule '{r_name}' triggered in {loc_name}"
                            payload_sample = match.group(0)[:150]
                except Exception:
                    pass

        # Determine WAF Action
        # Threshold: Score >= 70 -> BLOCKED
        # Score between 30 and 69 -> MONITORED
        # Score < 30 -> ALLOWED
        if highest_score >= 70:
            action = "BLOCKED"
            is_threat = True
        elif highest_score >= 30:
            action = "MONITORED"
            is_threat = True
        else:
            action = "ALLOWED"
            is_threat = False
            detected_threat_type = "NONE"
            primary_reason = "Request passed all WAF inspection checks"

        latency_ms = round((time.time() - start_time) * 1000, 3)

        return WAFInspectionResult(
            is_threat=is_threat,
            action=action,
            threat_type=detected_threat_type,
            threat_score=highest_score,
            matched_rules=matched_rules,
            reason=primary_reason,
            payload_sample=payload_sample,
            latency_ms=latency_ms
        )

# Global Singleton Engine Instance
waf_engine = WAFEngine()
