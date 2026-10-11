import React, { useState, useEffect } from "react";
import axios from "axios";
import {
  ShieldCheck,
  Activity,
  Terminal,
  Ban,
  Sliders,
  UserCheck,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Flame,
  Zap,
  Play,
  Send,
  Eye,
  Trash2,
  PlusCircle,
  Lock,
  Unlock,
  Radio,
  ExternalLink
} from "lucide-react";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000";
const TOKEN_KEY = "secureshield_token";
const ROLE_KEY = "secureshield_role";

// Management API client: sends the signed-in user's token with every request
const api = axios.create({ baseURL: API_BASE });
api.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export default function App() {
  const [activeTab, setActiveTab] = useState(localStorage.getItem(TOKEN_KEY) ? "dashboard" : "auth");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [loading, setLoading] = useState(false);

  // Stats State
  const [stats, setStats] = useState({
    firewall_status: "ACTIVE & ENFORCING",
    threat_detection: "MULTILAYER ENGINE",
    rate_limiter: "SLIDING WINDOW ACTIVE",
    total_requests_processed: 0,
    blocked_attacks: 0,
    monitored_requests: 0,
    allowed_requests: 0,
    block_rate_percentage: 0,
    active_blacklisted_ips: 0,
    active_rules_count: 0,
    authenticated_users: 0,
    threat_breakdown: {}
  });

  // Logs State
  const [logs, setLogs] = useState([]);
  const [filterThreat, setFilterThreat] = useState("ALL");
  const [filterAction, setFilterAction] = useState("ALL");
  const [selectedLog, setSelectedLog] = useState(null);

  // IP Rules State
  const [ipRules, setIpRules] = useState([]);
  const [newIp, setNewIp] = useState("");
  const [newIpType, setNewIpType] = useState("BLACKLIST");
  const [newIpReason, setNewIpReason] = useState("");

  // Custom Rules State
  const [customRules, setCustomRules] = useState([]);
  const [newRuleName, setNewRuleName] = useState("");
  const [newRulePattern, setNewRulePattern] = useState("");
  const [newRuleLoc, setNewRuleLoc] = useState("any");
  const [newRuleScore, setNewRuleScore] = useState(85);
  const [newRuleAction, setNewRuleAction] = useState("BLOCK");

  // Attack Simulator State
  const [simCategory, setSimCategory] = useState("SQL_INJECTION");
  const [simLocation, setSimLocation] = useState("query");
  const [simPayload, setSimPayload] = useState("' OR 1=1 --");
  const [simResult, setSimResult] = useState(null);
  const [liveTestResult, setLiveTestResult] = useState(null);
  const [simulating, setSimulating] = useState(false);

  // Auth State
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState(localStorage.getItem(TOKEN_KEY) || "");
  const [role, setRole] = useState(localStorage.getItem(ROLE_KEY) || "");
  const isAdmin = role === "admin";
  const [authMessage, setAuthMessage] = useState("");
  const [protectedData, setProtectedData] = useState(null);

  // ---------------- API Fetchers ----------------

  const fetchStats = async () => {
    try {
      const res = await api.get("/api/stats");
      setStats(res.data);
    } catch (err) {
      console.error("Failed to fetch stats", err);
    }
  };

  const fetchLogs = async () => {
    try {
      const res = await api.get("/api/logs", {
        params: {
          limit: 50,
          threat_type: filterThreat !== "ALL" ? filterThreat : undefined,
          action: filterAction !== "ALL" ? filterAction : undefined
        }
      });
      setLogs(res.data);
    } catch (err) {
      console.error("Failed to fetch logs", err);
    }
  };

  const fetchIpRules = async () => {
    try {
      const res = await api.get("/api/ip-rules");
      setIpRules(res.data);
    } catch (err) {
      console.error("Failed to fetch IP rules", err);
    }
  };

  const fetchCustomRules = async () => {
    try {
      const res = await api.get("/api/rules");
      setCustomRules(res.data);
    } catch (err) {
      console.error("Failed to fetch custom rules", err);
    }
  };

  const clearSession = (message) => {
    setToken("");
    setRole("");
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(ROLE_KEY);
    setProtectedData(null);
    setAuthMessage(message);
  };

  useEffect(() => {
    const id = api.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          clearSession("🔒 Your session has expired or you are not signed in. Please sign in again.");
          setActiveTab("auth");
        }
        return Promise.reject(error);
      }
    );
    return () => api.interceptors.response.eject(id);
  }, []);

  const refreshAll = () => {
    if (!localStorage.getItem(TOKEN_KEY)) return;
    fetchStats();
    fetchLogs();
    fetchIpRules();
    fetchCustomRules();
  };

  useEffect(() => {
    if (!token) return;
    refreshAll();
    let timer = null;
    if (autoRefresh) {
      timer = setInterval(() => {
        fetchStats();
        if (activeTab === "monitor") fetchLogs();
      }, 3000);
    }
    return () => clearInterval(timer);
  }, [token, autoRefresh, activeTab, filterThreat, filterAction]);

  // ---------------- Handlers ----------------

  const handleAddIp = async (e) => {
    e.preventDefault();
    if (!newIp.trim()) return;
    try {
      await api.post("/api/ip-rules", {
        ip: newIp.trim(),
        rule_type: newIpType,
        reason: newIpReason || "Manual entry via WAF Dashboard"
      });
      setNewIp("");
      setNewIpReason("");
      fetchIpRules();
      fetchStats();
    } catch (err) {
      alert(err.response?.data?.detail || "Failed to add IP rule");
    }
  };

  const handleDeleteIp = async (ip) => {
    try {
      await api.delete(`/api/ip-rules/${ip}`);
      fetchIpRules();
      fetchStats();
    } catch (err) {
      alert(err.response?.data?.detail || "Failed to remove IP rule");
    }
  };

  const handleAddCustomRule = async (e) => {
    e.preventDefault();
    if (!newRuleName.trim() || !newRulePattern.trim()) return;
    try {
      await api.post("/api/rules", {
        name: newRuleName,
        pattern: newRulePattern,
        target_location: newRuleLoc,
        severity: "HIGH",
        threat_score: Number(newRuleScore),
        action: newRuleAction
      });
      setNewRuleName("");
      setNewRulePattern("");
      fetchCustomRules();
      fetchStats();
    } catch (err) {
      alert(err.response?.data?.detail || "Failed to create custom rule");
    }
  };

  const handleToggleRule = async (id) => {
    try {
      await api.patch(`/api/rules/${id}/toggle`);
      fetchCustomRules();
      fetchStats();
    } catch (err) {
      alert(err.response?.data?.detail || "Failed to toggle rule");
    }
  };

  const handleDeleteRule = async (id) => {
    try {
      await api.delete(`/api/rules/${id}`);
      fetchCustomRules();
      fetchStats();
    } catch (err) {
      alert(err.response?.data?.detail || "Failed to delete rule");
    }
  };

  // ---------------- Simulation Sandbox ----------------

  const runSimulation = async () => {
    setSimulating(true);
    setLiveTestResult(null);
    try {
      const res = await api.post("/api/waf/simulate", {
        category: simCategory,
        target_location: simLocation,
        payload: simPayload
      });
      setSimResult(res.data);
    } catch (err) {
      setSimResult({ error: err.response?.data?.detail || err.message });
    } finally {
      setSimulating(false);
    }
  };

  const fireLiveAttack = async () => {
    setSimulating(true);
    try {
      let res;
      if (simLocation === "query") {
        res = await axios.get(`${API_BASE}/api/waf/test-target?search=${encodeURIComponent(simPayload)}`);
      } else if (simLocation === "path") {
        res = await axios.get(`${API_BASE}/api/waf/test-target/${encodeURIComponent(simPayload)}`);
      } else if (simLocation === "header") {
        res = await axios.get(`${API_BASE}/api/waf/test-target`, {
          headers: { "User-Agent": simPayload }
        });
      } else {
        res = await axios.post(`${API_BASE}/api/waf/test-target`, {
          test_field: simPayload
        });
      }
      setLiveTestResult({
        status: res.status,
        allowed: true,
        data: res.data
      });
    } catch (err) {
      setLiveTestResult({
        status: err.response?.status || 403,
        allowed: false,
        data: err.response?.data || { error: "Network Error" }
      });
    } finally {
      setSimulating(false);
      fetchStats();
      fetchLogs();
    }
  };

  const applyPreset = (cat, loc, payload) => {
    setSimCategory(cat);
    setSimLocation(loc);
    setSimPayload(payload);
    setSimResult(null);
    setLiveTestResult(null);
  };

  // ---------------- Auth Handlers ----------------

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${API_BASE}/api/auth/register`, {
        username,
        email,
        password
      });
      setAuthMessage(`✅ Registration successful: ${res.data.message}`);
    } catch (err) {
      setAuthMessage(`❌ ${err.response?.data?.detail || "Registration failed"}`);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${API_BASE}/api/auth/login`, {
        email,
        password
      });
      const jwtToken = res.data.access_token;
      setToken(jwtToken);
      setRole(res.data.role);
      localStorage.setItem(TOKEN_KEY, jwtToken);
      localStorage.setItem(ROLE_KEY, res.data.role);
      setAuthMessage(`✅ Login successful! Authenticated as ${res.data.username} (${res.data.role})`);
    } catch (err) {
      setAuthMessage(`❌ ${err.response?.data?.detail || "Login failed"}`);
    }
  };

  const handleTestProtected = async () => {
    if (!token) {
      setAuthMessage("❌ No token found. Please login first.");
      return;
    }
    try {
      const res = await axios.get(`${API_BASE}/api/protected`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setProtectedData(res.data);
      setAuthMessage("✅ Successfully accessed protected resource!");
    } catch (err) {
      setProtectedData(null);
      setAuthMessage(`❌ ${err.response?.data?.detail || "Protected route access denied"}`);
    }
  };

  const handleLogout = () => {
    clearSession("ℹ️ Logged out successfully.");
  };

  return (
    <div className="app-container">
      {/* SIDEBAR */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={24} color="#030712" />
          </div>
          <div>
            <h2>SecureShield</h2>
            <div className="brand-badge">WAF GATEWAY v2.0</div>
          </div>
        </div>

        <nav className="nav-menu">
          <div
            className={`nav-item ${activeTab === "dashboard" ? "active" : ""}`}
            onClick={() => setActiveTab("dashboard")}
          >
            <Activity size={18} />
            <span>SOC Dashboard</span>
          </div>

          <div
            className={`nav-item ${activeTab === "monitor" ? "active" : ""}`}
            onClick={() => { setActiveTab("monitor"); fetchLogs(); }}
          >
            <Radio size={18} />
            <span>Threat Monitor & Logs</span>
          </div>

          <div
            className={`nav-item ${activeTab === "simulator" ? "active" : ""}`}
            onClick={() => setActiveTab("simulator")}
          >
            <Terminal size={18} />
            <span>Attack Simulator</span>
          </div>

          <div
            className={`nav-item ${activeTab === "ip_control" ? "active" : ""}`}
            onClick={() => { setActiveTab("ip_control"); fetchIpRules(); }}
          >
            <Ban size={18} />
            <span>IP Access Control</span>
          </div>

          <div
            className={`nav-item ${activeTab === "rules" ? "active" : ""}`}
            onClick={() => { setActiveTab("rules"); fetchCustomRules(); }}
          >
            <Sliders size={18} />
            <span>WAF Rules Engine</span>
          </div>

          <div
            className={`nav-item ${activeTab === "auth" ? "active" : ""}`}
            onClick={() => setActiveTab("auth")}
          >
            <UserCheck size={18} />
            <span>Enterprise Auth Portal</span>
          </div>
        </nav>

        <div className="sidebar-footer">
          <div className="status-pill">
            <div className="dot-pulse"></div>
            <span>WAF STATUS: ACTIVE</span>
          </div>
          <div>Real-time multi-vector threat prevention running on port 8000.</div>
        </div>
      </aside>

      {/* MAIN CONTENT AREA */}
      <main className="main-content">
        {/* HEADER */}
        <header className="header">
          <div>
            <h1>
              {activeTab === "dashboard" && "Security Operations Center (SOC)"}
              {activeTab === "monitor" && "Live Threat Monitor & Firewall Logs"}
              {activeTab === "simulator" && "WAF Attack Sandbox & Exploit Bench"}
              {activeTab === "ip_control" && "IP Access Control (Blacklist / Whitelist)"}
              {activeTab === "rules" && "Custom Detection & Inspection Rules"}
              {activeTab === "auth" && "Identity & Protected Gateway"}
            </h1>
            <p className="header-subtitle">
              Intelligent Layer-7 Web Application Firewall protecting upstream APIs and applications.
            </p>
          </div>

          <div className="header-actions">
            <button
              className={`btn btn-sm ${autoRefresh ? "btn-outline" : "btn-outline"}`}
              onClick={() => setAutoRefresh(!autoRefresh)}
              style={{ borderColor: autoRefresh ? "var(--accent-green)" : "var(--border)" }}
            >
              <Radio size={14} color={autoRefresh ? "var(--accent-green)" : "var(--text-muted)"} />
              <span>Auto-refresh: {autoRefresh ? "ON (3s)" : "OFF"}</span>
            </button>

            <button className="btn btn-sm btn-primary" onClick={refreshAll}>
              <RefreshCw size={14} />
              <span>Refresh Telemetry</span>
            </button>
          </div>
        </header>

        {!token && activeTab !== "auth" && (
          <div className="panel access-notice">
            <Lock size={18} color="var(--accent-cyan)" />
            <span>
              Sign in to view firewall data.{" "}
              <button className="btn btn-sm btn-primary" onClick={() => setActiveTab("auth")}>
                Go to sign in
              </button>
            </span>
          </div>
        )}

        {token && !isAdmin && (activeTab === "ip_control" || activeTab === "rules") && (
          <div className="panel access-notice">
            <Eye size={18} color="var(--accent-cyan)" />
            <span>Read-only view: you are signed in as an analyst. Only admins can change IP rules and detection rules.</span>
          </div>
        )}

        {/* ==================== TAB 1: SOC DASHBOARD ==================== */}
        {activeTab === "dashboard" && (
          <div>
            {/* KPI Cards */}
            <div className="kpi-grid">
              <div className="kpi-card">
                <div className="kpi-card-header">
                  <span className="kpi-title">Firewall Status</span>
                  <div className="kpi-icon" style={{ background: "rgba(16, 185, 129, 0.15)" }}>
                    <ShieldCheck size={20} color="var(--accent-green)" />
                  </div>
                </div>
                <div className="kpi-value" style={{ color: "var(--accent-green)", fontSize: "22px" }}>
                  {stats.firewall_status}
                </div>
                <div className="kpi-subtitle">Active deep-packet inspection</div>
              </div>

              <div className="kpi-card">
                <div className="kpi-card-header">
                  <span className="kpi-title">Requests Processed</span>
                  <div className="kpi-icon" style={{ background: "rgba(56, 189, 248, 0.15)" }}>
                    <Activity size={20} color="var(--accent-cyan)" />
                  </div>
                </div>
                <div className="kpi-value">{stats.total_requests_processed}</div>
                <div className="kpi-subtitle">Total HTTP transactions audited</div>
              </div>

              <div className="kpi-card">
                <div className="kpi-card-header">
                  <span className="kpi-title">Attacks Intercepted</span>
                  <div className="kpi-icon" style={{ background: "rgba(239, 68, 68, 0.15)" }}>
                    <Flame size={20} color="var(--accent-red)" />
                  </div>
                </div>
                <div className="kpi-value" style={{ color: "var(--accent-red)" }}>
                  {stats.blocked_attacks}
                </div>
                <div className="kpi-subtitle">Block Rate: {stats.block_rate_percentage}%</div>
              </div>

              <div className="kpi-card">
                <div className="kpi-card-header">
                  <span className="kpi-title">Rate Limiter</span>
                  <div className="kpi-icon" style={{ background: "rgba(245, 158, 11, 0.15)" }}>
                    <Zap size={20} color="var(--accent-yellow)" />
                  </div>
                </div>
                <div className="kpi-value" style={{ color: "var(--accent-yellow)", fontSize: "20px" }}>
                  SLIDING WINDOW
                </div>
                <div className="kpi-subtitle">Flood protection active</div>
              </div>

              <div className="kpi-card">
                <div className="kpi-card-header">
                  <span className="kpi-title">Blacklisted IPs</span>
                  <div className="kpi-icon" style={{ background: "rgba(168, 85, 247, 0.15)" }}>
                    <Ban size={20} color="var(--accent-purple)" />
                  </div>
                </div>
                <div className="kpi-value">{stats.active_blacklisted_ips}</div>
                <div className="kpi-subtitle">Enforced access restrictions</div>
              </div>

              <div className="kpi-card">
                <div className="kpi-card-header">
                  <span className="kpi-title">Active Rules</span>
                  <div className="kpi-icon" style={{ background: "rgba(59, 130, 246, 0.15)" }}>
                    <Sliders size={20} color="var(--accent-blue)" />
                  </div>
                </div>
                <div className="kpi-value">{stats.active_rules_count}</div>
                <div className="kpi-subtitle">Custom regex signatures</div>
              </div>
            </div>

            {/* Attack Vectors Distribution */}
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <Flame size={20} color="var(--accent-red)" />
                  <span>Threat Vector Distribution</span>
                </div>
                <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                  Real-time categorized telemetry
                </span>
              </div>

              <div className="threat-grid">
                {[
                  { name: "SQL Injection", key: "SQL_INJECTION", count: stats.threat_breakdown?.SQL_INJECTION || 0 },
                  { name: "Cross-Site Scripting (XSS)", key: "XSS", count: stats.threat_breakdown?.XSS || 0 },
                  { name: "Path Traversal / LFI", key: "PATH_TRAVERSAL", count: stats.threat_breakdown?.PATH_TRAVERSAL || 0 },
                  { name: "Command Injection (RCE)", key: "COMMAND_INJECTION", count: stats.threat_breakdown?.COMMAND_INJECTION || 0 },
                  { name: "Automated Scanners", key: "SCANNER_BOT", count: stats.threat_breakdown?.SCANNER_BOT || 0 },
                  { name: "Rate Limit / DDoS", key: "RATE_LIMIT_EXCEEDED", count: stats.threat_breakdown?.RATE_LIMIT_EXCEEDED || 0 },
                ].map((item) => (
                  <div key={item.key} className="threat-item">
                    <div className="threat-item-name">{item.name}</div>
                    <div className="threat-item-count">{item.count}</div>
                    <div className="threat-bar">
                      <div
                        className="threat-bar-fill"
                        style={{
                          width: `${stats.blocked_attacks > 0 ? (item.count / stats.blocked_attacks) * 100 : 0}%`
                        }}
                      ></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Quick Actions / Gateway Banner */}
            <div className="panel" style={{ background: "linear-gradient(135deg, #0f172a, #1e1b4b)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "16px" }}>
                <div>
                  <h3 style={{ fontSize: "18px", fontWeight: "700", marginBottom: "6px" }}>
                    🚀 Test Your WAF Against Live Exploits
                  </h3>
                  <p style={{ color: "var(--text-secondary)", fontSize: "14px" }}>
                    Use the interactive Attack Simulator to test real payloads (SQLi, XSS, RCE, scanners) and verify immediate firewall blocks.
                  </p>
                </div>
                <button className="btn btn-primary" onClick={() => setActiveTab("simulator")}>
                  <Terminal size={16} />
                  <span>Launch Attack Sandbox</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ==================== TAB 2: THREAT MONITOR & LOGS ==================== */}
        {activeTab === "monitor" && (
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <Radio size={20} color="var(--accent-cyan)" />
                <span>Firewall Transaction Logs</span>
              </div>

              {/* Filters */}
              <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
                <select
                  value={filterThreat}
                  onChange={(e) => setFilterThreat(e.target.value)}
                  style={{ width: "180px", padding: "8px 12px" }}
                >
                  <option value="ALL">All Threat Types</option>
                  <option value="SQL_INJECTION">SQL Injection</option>
                  <option value="XSS">Cross-Site Scripting</option>
                  <option value="PATH_TRAVERSAL">Path Traversal</option>
                  <option value="COMMAND_INJECTION">Command Injection</option>
                  <option value="SCANNER_BOT">Scanner Bots</option>
                  <option value="RATE_LIMIT_EXCEEDED">Rate Limit</option>
                  <option value="BLACKLISTED_IP">Blacklisted IP</option>
                </select>

                <select
                  value={filterAction}
                  onChange={(e) => setFilterAction(e.target.value)}
                  style={{ width: "140px", padding: "8px 12px" }}
                >
                  <option value="ALL">All Actions</option>
                  <option value="BLOCKED">BLOCKED</option>
                  <option value="MONITORED">MONITORED</option>
                  <option value="ALLOWED">ALLOWED</option>
                </select>
              </div>
            </div>

            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Client IP</th>
                    <th>Method & Path</th>
                    <th>Threat Category</th>
                    <th>Score</th>
                    <th>Action</th>
                    <th>Reason</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.length === 0 ? (
                    <tr>
                      <td colSpan="8" style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)" }}>
                        No security logs matching criteria. Try running an attack in the Simulator!
                      </td>
                    </tr>
                  ) : (
                    logs.map((log) => (
                      <tr key={log.id}>
                        <td className="mono" style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="mono" style={{ fontWeight: "600" }}>{log.client_ip}</td>
                        <td className="mono" style={{ fontSize: "12px" }}>
                          <span style={{ color: "var(--accent-cyan)", fontWeight: "700" }}>{log.method}</span> {log.path}
                        </td>
                        <td>
                          <span className={`badge ${log.threat_type !== "NONE" ? "badge-threat" : ""}`}>
                            {log.threat_type}
                          </span>
                        </td>
                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <span className="mono" style={{ fontWeight: "700" }}>{log.threat_score}</span>
                            <div style={{ width: "40px", height: "4px", background: "#1f2937", borderRadius: "2px" }}>
                              <div
                                style={{
                                  height: "100%",
                                  width: `${log.threat_score}%`,
                                  background: log.threat_score >= 70 ? "var(--accent-red)" : "var(--accent-yellow)",
                                  borderRadius: "2px"
                                }}
                              ></div>
                            </div>
                          </div>
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              log.action === "BLOCKED"
                                ? "badge-blocked"
                                : log.action === "MONITORED"
                                ? "badge-monitored"
                                : "badge-allowed"
                            }`}
                          >
                            {log.action === "BLOCKED" && <XCircle size={12} />}
                            {log.action === "ALLOWED" && <CheckCircle size={12} />}
                            {log.action === "MONITORED" && <AlertTriangle size={12} />}
                            {log.action}
                          </span>
                        </td>
                        <td style={{ maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {log.reason}
                        </td>
                        <td>
                          <button
                            className="btn btn-sm btn-outline"
                            onClick={() => setSelectedLog(log)}
                          >
                            <Eye size={12} />
                            <span>Inspect</span>
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Modal / Inspector for selected log */}
            {selectedLog && (
              <div
                style={{
                  position: "fixed",
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  background: "rgba(0,0,0,0.8)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  zIndex: 999
                }}
              >
                <div
                  className="panel"
                  style={{
                    width: "600px",
                    maxWidth: "90%",
                    background: "var(--bg-secondary)",
                    borderColor: "var(--accent-cyan)"
                  }}
                >
                  <div className="panel-header">
                    <div className="panel-title">
                      <ShieldCheck size={20} color="var(--accent-cyan)" />
                      <span>Security Incident Analysis #{selectedLog.id}</span>
                    </div>
                    <button className="btn btn-sm btn-outline" onClick={() => setSelectedLog(null)}>
                      Close
                    </button>
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize: "14px" }}>
                    <div><strong>Timestamp:</strong> {selectedLog.timestamp}</div>
                    <div><strong>Client IP:</strong> <span className="mono">{selectedLog.client_ip}</span></div>
                    <div><strong>Target:</strong> <span className="mono">{selectedLog.method} {selectedLog.path}</span></div>
                    <div><strong>Verdict:</strong> <span className="badge badge-blocked">{selectedLog.action} (Threat Score: {selectedLog.threat_score}/100)</span></div>
                    <div><strong>Detection Reason:</strong> {selectedLog.reason}</div>
                    {selectedLog.payload_sample && (
                      <div>
                        <strong>Payload Snippet:</strong>
                        <pre style={{ background: "#030712", padding: "12px", borderRadius: "8px", marginTop: "6px", color: "var(--accent-red)", overflowX: "auto" }}>
                          {selectedLog.payload_sample}
                        </pre>
                      </div>
                    )}
                    {selectedLog.user_agent && (
                      <div><strong>User Agent:</strong> <span className="mono" style={{ fontSize: "12px", color: "var(--text-muted)" }}>{selectedLog.user_agent}</span></div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ==================== TAB 3: ATTACK SIMULATOR (SANDBOX) ==================== */}
        {activeTab === "simulator" && (
          <div>
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <Terminal size={20} color="var(--accent-cyan)" />
                  <span>Interactive Exploit Presets (1-Click Test)</span>
                </div>
                <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                  Click any preset to auto-populate payload test bench
                </span>
              </div>

              <div className="presets-grid">
                <button
                  className="preset-btn"
                  onClick={() => applyPreset("SQL_INJECTION", "query", "' UNION SELECT 1, username, password FROM users --")}
                >
                  <div className="preset-title" style={{ color: "var(--accent-red)" }}>💉 SQLi: Union Select</div>
                  <div className="preset-desc">Attempts database data exfiltration</div>
                </button>

                <button
                  className="preset-btn"
                  onClick={() => applyPreset("SQL_INJECTION", "query", "admin' OR 1=1 --")}
                >
                  <div className="preset-title" style={{ color: "var(--accent-red)" }}>💉 SQLi: Auth Tautology</div>
                  <div className="preset-desc">Attempts boolean logic bypass</div>
                </button>

                <button
                  className="preset-btn"
                  onClick={() => applyPreset("XSS", "body", "<script>alert(document.cookie)</script>")}
                >
                  <div className="preset-title" style={{ color: "var(--accent-yellow)" }}>☣️ XSS: Script Injection</div>
                  <div className="preset-desc">Injects inline JavaScript tag</div>
                </button>

                <button
                  className="preset-btn"
                  onClick={() => applyPreset("PATH_TRAVERSAL", "query", "../../../../etc/passwd")}
                >
                  <div className="preset-title" style={{ color: "var(--accent-purple)" }}>📁 Path Traversal / LFI</div>
                  <div className="preset-desc">Attempts access to host OS files</div>
                </button>

                <button
                  className="preset-btn"
                  onClick={() => applyPreset("COMMAND_INJECTION", "body", "; cat /etc/passwd && whoami")}
                >
                  <div className="preset-title" style={{ color: "var(--accent-red)" }}>💻 Command Injection (RCE)</div>
                  <div className="preset-desc">Attempts remote shell execution</div>
                </button>

                <button
                  className="preset-btn"
                  onClick={() => applyPreset("SCANNER_BOT", "header", "sqlmap/1.6#stable (https://sqlmap.org)")}
                >
                  <div className="preset-title" style={{ color: "var(--accent-blue)" }}>🤖 Scanner: sqlmap Bot</div>
                  <div className="preset-desc">Simulates automated scanner User-Agent</div>
                </button>
              </div>
            </div>

            {/* Custom Payload Bench */}
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <Flame size={20} color="var(--accent-yellow)" />
                  <span>Exploit Payload Configuration</span>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
                <div className="form-group">
                  <label>Threat Category</label>
                  <select value={simCategory} onChange={(e) => setSimCategory(e.target.value)}>
                    <option value="SQL_INJECTION">SQL Injection</option>
                    <option value="XSS">Cross-Site Scripting (XSS)</option>
                    <option value="PATH_TRAVERSAL">Path Traversal / LFI</option>
                    <option value="COMMAND_INJECTION">Command Injection (RCE)</option>
                    <option value="SCANNER_BOT">Automated Scanner User-Agent</option>
                  </select>
                </div>

                <div className="form-group">
                  <label>Injection Location</label>
                  <select value={simLocation} onChange={(e) => setSimLocation(e.target.value)}>
                    <option value="query">URL Query Parameter (?search=...)</option>
                    <option value="body">Request Body (JSON / Form Data)</option>
                    <option value="path">URL Path (/api/...)</option>
                    <option value="header">Request Header (User-Agent)</option>
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label>Payload String</label>
                <textarea
                  rows="3"
                  className="mono"
                  value={simPayload}
                  onChange={(e) => setSimPayload(e.target.value)}
                  placeholder="Enter custom attack string..."
                ></textarea>
              </div>

              <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
                <button
                  className="btn btn-primary"
                  onClick={runSimulation}
                  disabled={simulating}
                >
                  <Play size={16} />
                  <span>Analyze in Sandbox Engine</span>
                </button>

                <button
                  className="btn btn-danger"
                  onClick={fireLiveAttack}
                  disabled={simulating}
                >
                  <Send size={16} />
                  <span>Fire Live Attack against WAF API</span>
                </button>
              </div>

              {/* Simulation Result Box */}
              {simResult && (
                <div
                  className={`verdict-box ${simResult.action === "BLOCKED" ? "verdict-blocked" : "verdict-allowed"}`}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "10px", fontSize: "18px", fontWeight: "800" }}>
                      {simResult.action === "BLOCKED" ? (
                        <>
                          <XCircle size={24} color="var(--accent-red)" />
                          <span style={{ color: "var(--accent-red)" }}>ATTACK BLOCKED BY WAF</span>
                        </>
                      ) : (
                        <>
                          <CheckCircle size={24} color="var(--accent-green)" />
                          <span style={{ color: "var(--accent-green)" }}>REQUEST ALLOWED</span>
                        </>
                      )}
                    </div>
                    <span className="mono" style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                      Inspection Latency: {simResult.latency_ms} ms
                    </span>
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "12px", marginBottom: "12px" }}>
                    <div>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>THREAT SCORE</div>
                      <div style={{ fontSize: "20px", fontWeight: "800", color: simResult.threat_score >= 70 ? "var(--accent-red)" : "var(--accent-yellow)" }}>
                        {simResult.threat_score} / 100
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>CLASSIFICATION</div>
                      <div style={{ fontSize: "16px", fontWeight: "700" }}>{simResult.threat_type}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>VERDICT</div>
                      <div style={{ fontSize: "16px", fontWeight: "700" }}>{simResult.action}</div>
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: "12px", fontWeight: "600", marginBottom: "4px" }}>Detection Details:</div>
                    <p style={{ fontSize: "14px", color: "var(--text-secondary)" }}>{simResult.reason}</p>
                  </div>

                  {simResult.matched_rules?.length > 0 && (
                    <div style={{ marginTop: "10px" }}>
                      <div style={{ fontSize: "12px", fontWeight: "600", marginBottom: "4px" }}>Triggered Signatures:</div>
                      <ul style={{ paddingLeft: "20px", fontSize: "13px", color: "var(--text-muted)" }}>
                        {simResult.matched_rules.map((rule, idx) => (
                          <li key={idx} className="mono">{rule}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* Live Test Result */}
              {liveTestResult && (
                <div
                  className={`verdict-box ${!liveTestResult.allowed ? "verdict-blocked" : "verdict-allowed"}`}
                  style={{ marginTop: "16px" }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px", fontWeight: "700" }}>
                    {!liveTestResult.allowed ? (
                      <>
                        <XCircle size={20} color="var(--accent-red)" />
                        <span style={{ color: "var(--accent-red)" }}>
                          HTTP {liveTestResult.status} Forbidden - Blocked by WAF Middleware
                        </span>
                      </>
                    ) : (
                      <>
                        <CheckCircle size={20} color="var(--accent-green)" />
                        <span style={{ color: "var(--accent-green)" }}>
                          HTTP {liveTestResult.status} OK - Payload Passed WAF
                        </span>
                      </>
                    )}
                  </div>
                  <pre style={{ background: "#030712", padding: "12px", borderRadius: "8px", fontSize: "12px", overflowX: "auto" }}>
                    {JSON.stringify(liveTestResult.data, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ==================== TAB 4: IP ACCESS CONTROL ==================== */}
        {activeTab === "ip_control" && (
          <div>
            {/* Add IP Form */}
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <PlusCircle size={20} color="var(--accent-cyan)" />
                  <span>Add IP Access Rule</span>
                </div>
              </div>

              <form onSubmit={handleAddIp} style={{ display: "grid", gridTemplateColumns: "1fr 160px 1.5fr auto", gap: "12px", alignItems: "end" }}>
                <div>
                  <label>IP Address</label>
                  <input
                    type="text"
                    placeholder="e.g. 198.51.100.42"
                    className="mono"
                    value={newIp}
                    onChange={(e) => setNewIp(e.target.value)}
                    required
                  />
                </div>

                <div>
                  <label>Rule Action</label>
                  <select value={newIpType} onChange={(e) => setNewIpType(e.target.value)}>
                    <option value="BLACKLIST">BLACKLIST (Block)</option>
                    <option value="WHITELIST">WHITELIST (Bypass)</option>
                  </select>
                </div>

                <div>
                  <label>Reason / Threat Intel</label>
                  <input
                    type="text"
                    placeholder="e.g. Port scanner or trusted IP"
                    value={newIpReason}
                    onChange={(e) => setNewIpReason(e.target.value)}
                  />
                </div>

                <button type="submit" className="btn btn-primary" style={{ height: "46px" }}>
                  <PlusCircle size={16} />
                  <span>Enforce Rule</span>
                </button>
              </form>
            </div>

            {/* IP Rules Table */}
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <Ban size={20} color="var(--accent-purple)" />
                  <span>Active IP Access List ({ipRules.length})</span>
                </div>
              </div>

              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>IP Address</th>
                      <th>Policy</th>
                      <th>Reason</th>
                      <th>Added Timestamp</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ipRules.length === 0 ? (
                      <tr>
                        <td colSpan="5" style={{ textAlign: "center", padding: "20px", color: "var(--text-muted)" }}>
                          No active IP rules configured.
                        </td>
                      </tr>
                    ) : (
                      ipRules.map((r) => (
                        <tr key={r.id}>
                          <td className="mono" style={{ fontWeight: "700" }}>{r.ip}</td>
                          <td>
                            <span className={`badge ${r.rule_type === "BLACKLIST" ? "badge-blocked" : "badge-allowed"}`}>
                              {r.rule_type}
                            </span>
                          </td>
                          <td>{r.reason}</td>
                          <td className="mono" style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                            {new Date(r.added_at).toLocaleString()}
                          </td>
                          <td>
                            <button
                              className="btn btn-sm btn-danger"
                              onClick={() => handleDeleteIp(r.ip)}
                            >
                              <Trash2 size={12} />
                              <span>Remove</span>
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ==================== TAB 5: CUSTOM RULES ENGINE ==================== */}
        {activeTab === "rules" && (
          <div>
            {/* Create Custom Rule Form */}
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <PlusCircle size={20} color="var(--accent-cyan)" />
                  <span>Create Custom Regex Detection Rule</span>
                </div>
              </div>

              <form onSubmit={handleAddCustomRule} style={{ display: "grid", gridTemplateColumns: "1.2fr 1.5fr 120px 100px 120px auto", gap: "12px", alignItems: "end" }}>
                <div>
                  <label>Rule Name</label>
                  <input
                    type="text"
                    placeholder="e.g. Block Spring4Shell"
                    value={newRuleName}
                    onChange={(e) => setNewRuleName(e.target.value)}
                    required
                  />
                </div>

                <div>
                  <label>Regex Pattern</label>
                  <input
                    type="text"
                    placeholder="e.g. class\.module\.classLoader"
                    className="mono"
                    value={newRulePattern}
                    onChange={(e) => setNewRulePattern(e.target.value)}
                    required
                  />
                </div>

                <div>
                  <label>Target</label>
                  <select value={newRuleLoc} onChange={(e) => setNewRuleLoc(e.target.value)}>
                    <option value="any">Any</option>
                    <option value="path">Path</option>
                    <option value="query">Query</option>
                    <option value="body">Body</option>
                    <option value="header">Header</option>
                  </select>
                </div>

                <div>
                  <label>Score</label>
                  <input
                    type="number"
                    min="1"
                    max="100"
                    value={newRuleScore}
                    onChange={(e) => setNewRuleScore(e.target.value)}
                  />
                </div>

                <div>
                  <label>Action</label>
                  <select value={newRuleAction} onChange={(e) => setNewRuleAction(e.target.value)}>
                    <option value="BLOCK">BLOCK</option>
                    <option value="LOG">LOG</option>
                  </select>
                </div>

                <button type="submit" className="btn btn-primary" style={{ height: "46px" }}>
                  <PlusCircle size={16} />
                  <span>Add Rule</span>
                </button>
              </form>
            </div>

            {/* Custom Rules Table */}
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <Sliders size={20} color="var(--accent-blue)" />
                  <span>Active Custom Rules ({customRules.length})</span>
                </div>
              </div>

              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Rule Name</th>
                      <th>Regex Pattern</th>
                      <th>Location</th>
                      <th>Threat Score</th>
                      <th>Action</th>
                      <th>Manage</th>
                    </tr>
                  </thead>
                  <tbody>
                    {customRules.map((rule) => (
                      <tr key={rule.id}>
                        <td>
                          <button
                            className={`btn btn-sm ${rule.enabled ? "btn-outline" : "btn-outline"}`}
                            style={{ borderColor: rule.enabled ? "var(--accent-green)" : "var(--accent-red)" }}
                            onClick={() => handleToggleRule(rule.id)}
                          >
                            {rule.enabled ? (
                              <span style={{ color: "var(--accent-green)" }}>ENABLED</span>
                            ) : (
                              <span style={{ color: "var(--accent-red)" }}>DISABLED</span>
                            )}
                          </button>
                        </td>
                        <td style={{ fontWeight: "700" }}>{rule.name}</td>
                        <td className="mono" style={{ color: "var(--accent-cyan)", fontSize: "12px" }}>{rule.pattern}</td>
                        <td><span className="badge badge-threat">{rule.target_location}</span></td>
                        <td className="mono" style={{ fontWeight: "700" }}>{rule.threat_score}</td>
                        <td>
                          <span className={`badge ${rule.action === "BLOCK" ? "badge-blocked" : "badge-monitored"}`}>
                            {rule.action}
                          </span>
                        </td>
                        <td>
                          <button
                            className="btn btn-sm btn-danger"
                            onClick={() => handleDeleteRule(rule.id)}
                          >
                            <Trash2 size={12} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ==================== TAB 6: AUTHENTICATION & ENTERPRISE PORTAL ==================== */}
        {activeTab === "auth" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px" }}>
            {/* Registration & Login Panel */}
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <UserCheck size={20} color="var(--accent-cyan)" />
                  <span>Enterprise User Authentication</span>
                </div>
              </div>

              <div className="form-group">
                <label>Username</label>
                <input
                  type="text"
                  placeholder="analyst_hemanth"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label>Email Address</label>
                <input
                  type="email"
                  placeholder="analyst@secureshield.io"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label>Password</label>
                <input
                  type="password"
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>

              <div style={{ display: "flex", gap: "10px", marginTop: "10px", flexWrap: "wrap" }}>
                <button className="btn btn-outline" onClick={handleRegister}>
                  <UserCheck size={16} />
                  <span>Register Account</span>
                </button>

                <button className="btn btn-primary" onClick={handleLogin}>
                  <Lock size={16} />
                  <span>Login & Generate JWT</span>
                </button>

                {token && (
                  <button className="btn btn-danger" onClick={handleLogout}>
                    <Unlock size={16} />
                    <span>Logout</span>
                  </button>
                )}
              </div>

              {authMessage && (
                <div style={{ marginTop: "18px", padding: "12px", background: "#030712", borderRadius: "10px", fontSize: "14px" }}>
                  {authMessage}
                </div>
              )}
            </div>

            {/* Protected Resource & Token Inspector */}
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <Lock size={20} color="var(--accent-green)" />
                  <span>Protected Enterprise API Gateway</span>
                </div>
              </div>

              <p style={{ fontSize: "14px", color: "var(--text-secondary)", marginBottom: "16px" }}>
                Tests authorization against protected endpoint requiring valid Bearer JWT header.
              </p>

              <button className="btn btn-primary" onClick={handleTestProtected} style={{ marginBottom: "16px" }}>
                <ExternalLink size={16} />
                <span>Fetch /api/protected</span>
              </button>

              {token && (
                <div style={{ marginBottom: "16px" }}>
                  <label>Current Bearer Token (JWT):</label>
                  <pre
                    className="mono"
                    style={{
                      background: "#030712",
                      padding: "10px",
                      borderRadius: "8px",
                      fontSize: "11px",
                      wordBreak: "break-all",
                      maxHeight: "80px",
                      overflowY: "auto",
                      color: "var(--accent-cyan)"
                    }}
                  >
                    {token}
                  </pre>
                </div>
              )}

              {protectedData && (
                <div>
                  <label>Protected Response Data:</label>
                  <pre
                    style={{
                      background: "#030712",
                      padding: "14px",
                      borderRadius: "8px",
                      fontSize: "12px",
                      color: "var(--accent-green)",
                      maxHeight: "220px",
                      overflowY: "auto"
                    }}
                  >
                    {JSON.stringify(protectedData, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}