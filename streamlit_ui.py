import streamlit as st
import requests
import pandas as pd
import time
import json

# ============================================================
# CONFIG
# ============================================================
API_BASE = "http://localhost:8010"

st.set_page_config(
    page_title="ZombieNet — AI API Gateway",
    page_icon="🧟",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# CUSTOM CSS
# ============================================================
st.markdown("""
<style>
    .block-container { padding-top: 1.5rem; }
    div[data-testid="stMetric"] {
        background: #131a2b; border: 1px solid #1e2a42;
        border-radius: 12px; padding: 1rem 1.2rem;
    }
    div[data-testid="stMetric"] label { color: #7b8ba3; }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px; padding: 8px 20px;
        background: #131a2b; border: 1px solid #1e2a42;
    }
    .stTabs [aria-selected="true"] { background: #2563eb; border-color: #2563eb; }
</style>
""", unsafe_allow_html=True)


# ============================================================
# HELPERS
# ============================================================
def api_get(endpoint):
    try:
        r = requests.get(f"{API_BASE}{endpoint}", timeout=5)
        return r.json()
    except requests.ConnectionError:
        return None


def api_post(endpoint, payload):
    try:
        r = requests.post(f"{API_BASE}{endpoint}", json=payload, timeout=5)
        return r.status_code, r.json()
    except requests.ConnectionError:
        return None, None


def api_put(endpoint, payload):
    try:
        r = requests.put(f"{API_BASE}{endpoint}", json=payload, timeout=5)
        return r.status_code, r.json()
    except requests.ConnectionError:
        return None, None


def api_delete(endpoint):
    try:
        r = requests.delete(f"{API_BASE}{endpoint}", timeout=5)
        return r.status_code, r.json()
    except requests.ConnectionError:
        return None, None


def check_server():
    return api_get("/") is not None


# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown("# 🧟 ZombieNet")
    st.caption("Zombie API Discovery & Defence Platform")
    st.divider()

    server_up = check_server()
    if server_up:
        st.success("Backend: Online", icon="🟢")
        _dash = api_get("/api/dashboard/summary")
        if _dash:
            _reg = _dash.get("registry", {})
            st.metric("Total APIs", _reg.get("total_apis", 0))
            st.metric("🧟 Zombies", _dash.get("zombie_count", 0))
            st.metric("🔔 Unack Alerts", _dash.get("alerts", {}).get("unacknowledged", 0))
    else:
        st.error("Backend: Offline", icon="🔴")
        st.info("Start the server:\n```\npython agent.py\n```")

    st.divider()
    auto_refresh = st.toggle("Auto-refresh (5s)", value=False)
    if st.button("🔄 Refresh Now", use_container_width=True):
        st.rerun()

    st.divider()
    st.markdown("**Honeypot Traps:**")
    honeypot_routes = [
        "/api/v1/internal/customer-dump",
        "/api/v1/admin/export-users",
        "/api/v2/debug/db-query",
        "/internal/kyc/bulk-download",
        "/api/v1/legacy/account-details",
    ]
    for route in honeypot_routes:
        st.code(route, language=None)


# ============================================================
# MAIN TABS
# ============================================================
tab_dash, tab_discovery, tab_inventory, tab_security, tab_decommission, tab_monitor, tab_compliance, tab_honeypot, tab_simulate, tab_logs, tab_features = st.tabs(
    ["📊 Dashboard", "🔍 Discovery", "📋 Inventory", "🔒 Security", "⚡ Decommission", "📡 Monitoring", "✅ Compliance", "🍯 Honeypot", "🎮 Simulate", "📝 Log Analysis", "🛡️ Features"]
)

# ============================================================
# TAB 1: DASHBOARD
# ============================================================
with tab_dash:
    st.header("Gateway Dashboard")

    if not server_up:
        st.warning("Backend server is not running. Start it with: `python agent.py`")
    else:
        stats = api_get("/stats")
        blocked = api_get("/blocked")
        hp_stats = api_get("/honeypot/stats")

        # ── Metric cards ──
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total IPs Tracked", stats["total_ips"])
        c2.metric("Blocked IPs", stats["blocked_ips"])
        c3.metric("Avg Reputation", f"{stats['avg_reputation']:.2f}")
        c4.metric("Honeypot Catches", hp_stats["total_attackers_caught"])
        c5.metric("Honeypot Hits", hp_stats["total_honeypot_hits"])

        st.divider()

        # ── Blocked IPs ──
        col_left, col_right = st.columns([3, 2])

        with col_left:
            st.subheader("🚫 Blocked IPs")
            blocked_ips = blocked.get("blocked_ips", [])
            if blocked_ips:
                for ip in blocked_ips:
                    bcol1, bcol2 = st.columns([3, 1])
                    bcol1.code(ip)
                    if bcol2.button("Unblock", key=f"unblock_{ip}"):
                        api_post("/unblock", {"ip": ip})
                        st.rerun()
            else:
                st.info("No blocked IPs — all clear ✅")

        with col_right:
            st.subheader("⚙️ System Info")
            root_info = api_get("/")
            if root_info:
                for feat in root_info.get("features", []):
                    st.markdown(f"- ✅ {feat}")

        # ── Zombie API Summary ──
        st.divider()
        st.subheader("🧟 Zombie API Intelligence")
        dash_data = api_get("/api/dashboard/summary")
        if dash_data:
            zc1, zc2, zc3, zc4 = st.columns(4)
            _reg = dash_data.get("registry", {})
            _bs = _reg.get("by_status", {})
            zc1.metric("Total APIs", _reg.get("total_apis", 0))
            zc2.metric("🧟 Zombies", _bs.get("zombie", 0))
            zc3.metric("👻 Orphaned", _bs.get("orphaned", 0))
            zc4.metric("⚠️ Deprecated", _bs.get("deprecated", 0))
            st.markdown("**Top Risk APIs:**")
            for _ar in dash_data.get("highest_risk_apis", [])[:5]:
                st.markdown(f"- **{_ar['method']} {_ar['url']}** — {_ar['risk_level']} ({_ar['risk_score']:.0f})")


# ============================================================
# TAB 2: API DISCOVERY
# ============================================================
with tab_discovery:
    st.header("🔍 API Discovery")
    if not server_up:
        st.warning("Backend not running.")
    else:
        st.markdown("Scan infrastructure to discover APIs — including shadow and undocumented endpoints.")
        dc1, dc2 = st.columns([1, 1])
        with dc1:
            scan_type = st.selectbox("Scan Type", ["network", "gateway", "repo", "deployment", "shadow"])
            if st.button("🚀 Run Discovery Scan", type="primary", use_container_width=True):
                _st, _res = api_post("/api/discovery/scan", {"scan_type": scan_type})
                st.session_state["disc_result"] = _res
        with dc2:
            st.markdown("**Scan Types:**")
            st.markdown("- **Network** — Scans IP ranges for HTTP services")
            st.markdown("- **Gateway** — Parses API gateway configurations")
            st.markdown("- **Repo** — Scans code for route definitions")
            st.markdown("- **Deployment** — Scans K8s/Docker manifests")
            st.markdown("- **Shadow** — Finds undocumented APIs in traffic")

        if "disc_result" in st.session_state and st.session_state["disc_result"]:
            _r = st.session_state["disc_result"]
            st.divider()
            st.subheader("Scan Results")
            _cnt = _r.get("apis_discovered", _r.get("shadow_apis_found", 0))
            st.metric("APIs Discovered", _cnt)
            _apis = _r.get("new_apis", _r.get("apis", []))
            if _apis:
                _df = pd.DataFrame([{
                    "URL": a["url"], "Method": a["method"],
                    "Risk": a.get("risk_level", "?"), "Status": a.get("status", "?"),
                    "Auth": a.get("auth_type", "none"), "Source": a.get("source", "?")
                } for a in _apis])
                st.dataframe(_df, use_container_width=True, hide_index=True)
            else:
                st.info("No new APIs discovered (already in registry)")

        st.divider()
        st.subheader("📜 Scan History")
        _hist = api_get("/api/discovery/history")
        if _hist and _hist.get("scans"):
            for _s in _hist["scans"][:10]:
                st.markdown(f"**{_s['scan_type']}** — {_s['timestamp'][:19]} — {_s['apis_discovered']} found")
        else:
            st.info("No scans performed yet. Run a discovery scan above.")


# ============================================================
# TAB 3: API INVENTORY
# ============================================================
with tab_inventory:
    st.header("📋 API Inventory")
    if not server_up:
        st.warning("Backend not running.")
    else:
        fc1, fc2, fc3 = st.columns(3)
        with fc1:
            filter_status = st.selectbox("Status", ["All", "active", "deprecated", "orphaned", "zombie"], key="inv_st")
        with fc2:
            filter_risk = st.selectbox("Risk Level", ["All", "critical", "high", "medium", "low", "info"], key="inv_rl")
        with fc3:
            filter_source = st.selectbox("Source", ["All", "gateway_scan", "network_scan", "repo_scan", "deployment_scan", "shadow", "manual"], key="inv_src")

        _params = []
        if filter_status != "All":
            _params.append(f"status={filter_status}")
        if filter_risk != "All":
            _params.append(f"risk_level={filter_risk}")
        if filter_source != "All":
            _params.append(f"source={filter_source}")
        _q = "?" + "&".join(_params) if _params else ""

        _registry = api_get(f"/api/registry{_q}")
        if _registry:
            _summary = api_get("/api/registry/summary")
            if _summary:
                mc1, mc2, mc3, mc4, mc5 = st.columns(5)
                mc1.metric("Total", _summary["total_apis"])
                _bs2 = _summary.get("by_status", {})
                mc2.metric("Active", _bs2.get("active", 0))
                mc3.metric("Deprecated", _bs2.get("deprecated", 0))
                mc4.metric("Orphaned", _bs2.get("orphaned", 0))
                mc5.metric("🧟 Zombie", _bs2.get("zombie", 0))

            st.divider()
            _apis2 = _registry.get("apis", [])
            if _apis2:
                _df2 = pd.DataFrame([{
                    "Method": a["method"], "URL": a["url"], "Version": a["version"],
                    "Status": a["status"], "Risk": a["risk_level"],
                    "Security": f"{a['security_score']}/100", "Auth": a["auth_type"],
                    "Owner": a["owner"], "Requests(30d)": a["request_count_30d"], "Source": a["source"],
                } for a in _apis2])
                st.dataframe(_df2, use_container_width=True, hide_index=True)

                st.divider()
                st.subheader("🔎 API Details")
                _urls = [f"{a['method']} {a['url']}" for a in _apis2]
                _sel = st.selectbox("Select API", _urls, key="inv_sel")
                if _sel:
                    _idx = _urls.index(_sel)
                    _api = _apis2[_idx]
                    dc1, dc2, dc3, dc4 = st.columns(4)
                    dc1.metric("Security", f"{_api['security_score']}/100")
                    dc2.metric("Risk", f"{_api['risk_score']:.0f}")
                    dc3.metric("Compliance", f"{_api['compliance_score']}%")
                    dc4.metric("Error Rate", f"{_api['error_rate']*100:.1f}%")
                    with st.expander("Security Findings"):
                        for _f in _api.get("security_findings", []):
                            st.markdown(f"- **[{_f['severity'].upper()}]** {_f['finding']}")
                    with st.expander("Recommendations"):
                        _recs = api_get(f"/api/recommendations/{_api['id']}")
                        if _recs:
                            for _r2 in _recs.get("recommendations", []):
                                st.markdown(f"- **P{_r2['priority']}** [{_r2.get('impact','?')}] {_r2['action']}")
                    with st.expander("Compliance Findings"):
                        for _f2 in _api.get("compliance_findings", []):
                            st.markdown(f"- **{_f2['framework']}** {_f2['code']}: {_f2['name']}")
            else:
                st.info("No APIs match the filters")

        st.divider()
        with st.expander("➕ Register API Manually"):
            rc1, rc2 = st.columns(2)
            with rc1:
                reg_url = st.text_input("URL", "/api/v1/example", key="reg_url")
                reg_method = st.selectbox("Method", ["GET", "POST", "PUT", "DELETE"], key="reg_m")
                reg_desc = st.text_input("Description", key="reg_d")
                reg_owner = st.text_input("Owner", key="reg_o")
            with rc2:
                reg_auth = st.selectbox("Auth", ["none", "api_key", "basic", "jwt", "oauth2"], key="reg_a")
                reg_enc = st.selectbox("Encryption", ["none", "http", "https_tls12", "https_tls13"], key="reg_e")
                reg_rate = st.checkbox("Rate Limiting", key="reg_r")
                reg_input = st.checkbox("Input Validation", key="reg_i")
            if st.button("Register API", type="primary"):
                _sc, _rsp = api_post("/api/registry", {
                    "url": reg_url, "method": reg_method, "description": reg_desc,
                    "owner": reg_owner, "auth_type": reg_auth, "encryption": reg_enc,
                    "rate_limiting": reg_rate, "input_validation": reg_input
                })
                if _sc == 200:
                    st.success("API registered!")
                    st.rerun()


# ============================================================
# TAB 4: SECURITY POSTURE
# ============================================================
with tab_security:
    st.header("🔒 Security Posture Assessment")
    if not server_up:
        st.warning("Backend not running.")
    else:
        _reg3 = api_get("/api/registry")
        if _reg3:
            _apis3 = _reg3.get("apis", [])
            if _apis3:
                _avg_sec = sum(a["security_score"] for a in _apis3) / len(_apis3)
                _crit = sum(1 for a in _apis3 for f in a.get("security_findings", []) if f.get("severity") == "critical")
                _high = sum(1 for a in _apis3 for f in a.get("security_findings", []) if f.get("severity") == "high")
                _low_sc = sum(1 for a in _apis3 if a["security_score"] < 40)

                sc1, sc2, sc3, sc4 = st.columns(4)
                sc1.metric("Avg Security Score", f"{_avg_sec:.0f}/100")
                sc2.metric("Critical Findings", _crit)
                sc3.metric("High Findings", _high)
                sc4.metric("APIs Below 40%", _low_sc)
                st.divider()

                sl, sr = st.columns(2)
                with sl:
                    st.subheader("Security Scores")
                    _sdf = pd.DataFrame([{
                        "API": f"{a['method']} {a['url']}", "Score": a["security_score"],
                        "Risk": a["risk_level"], "Auth": a["auth_type"], "Encryption": a["encryption"],
                        "Rate Limit": "✅" if a["rate_limiting"] else "❌",
                        "Input Val": "✅" if a["input_validation"] else "❌",
                    } for a in sorted(_apis3, key=lambda x: x["security_score"])])
                    st.dataframe(_sdf, use_container_width=True, hide_index=True)
                with sr:
                    st.subheader("Top Issues")
                    _fc = {}
                    for a in _apis3:
                        for f in a.get("security_findings", []):
                            k = f["finding"]
                            _fc[k] = _fc.get(k, 0) + 1
                    for _fn, _cnt2 in sorted(_fc.items(), key=lambda x: -x[1])[:10]:
                        st.markdown(f"- **{_cnt2}x** {_fn}")

                st.divider()
                if st.button("🔄 Re-assess All APIs", use_container_width=True):
                    api_post("/api/security/assess-all", {})
                    st.success("Re-assessed!")
                    st.rerun()


# ============================================================
# TAB 5: DECOMMISSIONING
# ============================================================
with tab_decommission:
    st.header("⚡ Decommissioning Workflows")
    if not server_up:
        st.warning("Backend not running.")
    else:
        _zombies = api_get("/api/registry?status=zombie")
        _wfs = api_get("/api/decommission/workflows")
        _wf_ids = set()
        if _wfs:
            _wf_ids = {w["api_id"] for w in _wfs.get("workflows", [])}

        dl, dr = st.columns(2)
        with dl:
            st.subheader("🧟 Zombie APIs")
            if _zombies and _zombies.get("apis"):
                for _za in _zombies["apis"]:
                    with st.container():
                        st.markdown(f"**{_za['method']} {_za['url']}**")
                        st.caption(f"Risk: {_za['risk_level']} | Auth: {_za['auth_type']} | Enc: {_za['encryption']}")
                        if _za["id"] not in _wf_ids:
                            if st.button("Start Decommission", key=f"dec_{_za['id']}"):
                                api_post(f"/api/decommission/start/{_za['id']}", {})
                                st.rerun()
                        else:
                            st.info("Workflow started ✓")
                        st.divider()
            else:
                st.success("No zombie APIs! 🎉")

        with dr:
            st.subheader("📋 Active Workflows")
            if _wfs and _wfs.get("workflows"):
                _all_st = ["identified", "reviewed", "approved", "traffic_redirected", "disabled", "decommissioned"]
                for _wf in _wfs["workflows"]:
                    _state = _wf["current_state"]
                    _prog = (_all_st.index(_state) + 1) / len(_all_st)
                    with st.container():
                        st.markdown(f"**{_wf['api_method']} {_wf['api_url']}**")
                        st.progress(_prog, text=f"State: {_state}")
                        if _state != "decommissioned":
                            wc1, wc2 = st.columns(2)
                            with wc1:
                                if st.button("Advance ▶", key=f"adv_{_wf['id']}"):
                                    api_post(f"/api/decommission/advance/{_wf['id']}", {"actor": "admin"})
                                    st.rerun()
                            with wc2:
                                _hp = st.checkbox("Honeypot", value=_wf.get("convert_to_honeypot", False), key=f"hp_{_wf['id']}")
                                if _hp != _wf.get("convert_to_honeypot", False):
                                    api_post(f"/api/decommission/honeypot/{_wf['id']}", {"enabled": _hp})
                                    st.rerun()
                        else:
                            st.success("✅ Decommissioned")
                            if _wf.get("convert_to_honeypot"):
                                st.info("🍯 Converted to honeypot")
                        st.divider()
            else:
                st.info("No active workflows")


# ============================================================
# TAB 6: MONITORING & ALERTS
# ============================================================
with tab_monitor:
    st.header("📡 Monitoring & Alerts")
    if not server_up:
        st.warning("Backend not running.")
    else:
        _mon = api_get("/api/monitoring/status")
        _asum = api_get("/api/alerts/summary")

        mm1, mm2, mm3, mm4 = st.columns(4)
        mm1.metric("Monitor", "🟢 Running" if _mon and _mon.get("running") else "🔴 Stopped")
        mm2.metric("Scans Done", _mon.get("total_scans", 0) if _mon else 0)
        if _asum:
            mm3.metric("Total Alerts", _asum.get("total", 0))
            mm4.metric("Unacknowledged", _asum.get("unacknowledged", 0))

        st.divider()
        ct1, ct2 = st.columns(2)
        with ct1:
            _interval = st.number_input("Interval (sec)", 10, 3600, 60, key="mon_int")
            if st.button("▶ Start Monitoring", type="primary", use_container_width=True):
                api_post("/api/monitoring/start", {"interval": _interval})
                st.rerun()
        with ct2:
            st.markdown("")
            st.markdown("")
            if st.button("⏹ Stop Monitoring", use_container_width=True):
                api_post("/api/monitoring/stop", {})
                st.rerun()

        st.divider()
        st.subheader("🔔 Alerts")
        _afilt = st.selectbox("Severity", ["All", "critical", "high", "medium", "low"], key="a_sev")
        _aq = f"?severity={_afilt}" if _afilt != "All" else ""
        _alerts = api_get(f"/api/alerts{_aq}")
        if _alerts and _alerts.get("alerts"):
            _sicons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
            for _al in _alerts["alerts"][:25]:
                _ic = _sicons.get(_al["severity"], "⚪")
                with st.container():
                    al1, al2, al3 = st.columns([0.5, 4, 1])
                    al1.markdown(f"### {_ic}")
                    al2.markdown(f"**{_al['title']}**")
                    al2.caption(f"{_al['severity'].upper()} | {_al['created_at'][:19]} | {'✅' if _al['acknowledged'] else '⚠️'}")
                    if not _al["acknowledged"]:
                        if al3.button("Ack", key=f"ack_{_al['id']}"):
                            api_post(f"/api/alerts/{_al['id']}/acknowledge", {})
                            st.rerun()
                    st.divider()
        else:
            st.info("No alerts matching filter")


# ============================================================
# TAB 7: COMPLIANCE & REPORTS
# ============================================================
with tab_compliance:
    st.header("✅ Compliance & Reports")
    if not server_up:
        st.warning("Backend not running.")
    else:
        _reg4 = api_get("/api/registry")
        if _reg4:
            _apis4 = _reg4.get("apis", [])
            if _apis4:
                _avgc = sum(a["compliance_score"] for a in _apis4) / len(_apis4)
                _full = sum(1 for a in _apis4 if a["compliance_score"] >= 100)
                _nonc = sum(1 for a in _apis4 if a["compliance_score"] < 50)

                co1, co2, co3 = st.columns(3)
                co1.metric("Avg Compliance", f"{_avgc:.0f}%")
                co2.metric("Fully Compliant", _full)
                co3.metric("Non-Compliant (<50%)", _nonc)
                st.divider()

                _cdf = pd.DataFrame([{
                    "API": f"{a['method']} {a['url']}", "Status": a["status"],
                    "Compliance": f"{a['compliance_score']}%",
                    "Failures": len(a.get("compliance_findings", [])),
                    "OWASP": sum(1 for f in a.get("compliance_findings", []) if f["framework"] == "OWASP API Top 10"),
                    "PCI-DSS": sum(1 for f in a.get("compliance_findings", []) if f["framework"] == "PCI-DSS"),
                } for a in sorted(_apis4, key=lambda x: x["compliance_score"])])
                st.dataframe(_cdf, use_container_width=True, hide_index=True)

                st.divider()
                st.subheader("📤 Export Reports")
                ex1, ex2 = st.columns(2)
                with ex1:
                    if st.button("📥 Full Report (JSON)", use_container_width=True):
                        _rpt = api_get("/api/reports/export")
                        if _rpt:
                            st.download_button("Download JSON", json.dumps(_rpt, indent=2), "zombie_api_report.json", "application/json")
                with ex2:
                    if st.button("📥 API Inventory (CSV)", use_container_width=True):
                        _csv = pd.DataFrame([{
                            "URL": a["url"], "Method": a["method"], "Status": a["status"],
                            "Risk": a["risk_level"], "Security": a["security_score"],
                            "Compliance": a["compliance_score"], "Auth": a["auth_type"],
                            "Encryption": a["encryption"], "Owner": a["owner"],
                        } for a in _apis4]).to_csv(index=False)
                        st.download_button("Download CSV", _csv, "api_inventory.csv", "text/csv")

                st.divider()
                st.subheader("📜 Audit Log")
                _audit = api_get("/api/audit-log?limit=25")
                if _audit and _audit.get("entries"):
                    _adf = pd.DataFrame([{
                        "Time": e["timestamp"][:19], "Action": e["action"],
                        "Target": e["target_id"][:12], "Details": e["details"], "Actor": e["actor"],
                    } for e in _audit["entries"]])
                    st.dataframe(_adf, use_container_width=True, hide_index=True)


# ============================================================
# TAB 8: HONEYPOT
# ============================================================
with tab_honeypot:
    st.header("🍯 Honeypot Intelligence")

    if not server_up:
        st.warning("Backend server is not running.")
    else:
        hp_stats = api_get("/honeypot/stats")
        profiles = api_get("/honeypot/profiles")

        # ── Stats ──
        h1, h2, h3 = st.columns(3)
        h1.metric("Attackers Caught", hp_stats["total_attackers_caught"])
        h2.metric("Total Honeypot Hits", hp_stats["total_honeypot_hits"])
        h3.metric("Active Traps", len(hp_stats.get("honeypot_routes", [])))

        st.divider()

        # ── Trap Routes ──
        st.subheader("🪤 Active Trap Routes")
        trap_cols = st.columns(3)
        for i, route in enumerate(hp_stats.get("honeypot_routes", [])):
            trap_cols[i % 3].code(route)

        st.divider()

        # ── Attacker Profiles ──
        st.subheader("🕵️ Attacker Profiles")

        if profiles:
            for ip, profile in profiles.items():
                with st.expander(f"🔴 **{ip}** — {profile['total_hits']} hits", expanded=False):
                    pc1, pc2 = st.columns(2)
                    pc1.metric("Total Hits", profile["total_hits"])
                    pc2.metric("Routes Tried", len(profile.get("routes_tried", [])))

                    st.markdown("**Routes targeted:**")
                    for r in profile.get("routes_tried", []):
                        st.code(r, language=None)

                    st.markdown("**Recent activity (last 10):**")
                    hits = profile.get("hits", [])[-10:]
                    if hits:
                        df = pd.DataFrame(hits)
                        st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No attackers caught yet. The traps are waiting... 🕸️")


# ============================================================
# TAB 3: SIMULATE
# ============================================================
with tab_simulate:
    st.header("🎮 Attack Simulator")

    if not server_up:
        st.warning("Backend server is not running.")
    else:
        st.markdown("Send requests to the gateway and see how it responds.")

        sim_left, sim_right = st.columns([1, 1])

        with sim_left:
            st.subheader("Custom Request")
            sim_path = st.text_input("Path", value="/api/v1/data", key="sim_path")
            sim_body = st.text_area("Body", value="", key="sim_body", height=100)
            sim_session = st.text_input("Session ID (optional)", value="", key="sim_session")

            if st.button("🚀 Send to /analyze", use_container_width=True, type="primary"):
                payload = {"path": sim_path, "body": sim_body}
                if sim_session:
                    payload["session_id"] = sim_session
                status, resp = api_post("/analyze", payload)
                st.session_state["sim_result"] = resp
                st.session_state["sim_status"] = status

        with sim_right:
            st.subheader("Quick Attacks")

            attack_presets = {
                "💉 SQL Injection": {"path": "/api/v1/users", "body": "' OR 1=1 --"},
                "🔥 XSS Attack": {"path": "/search", "body": "<script>alert('xss')</script>"},
                "📂 Path Traversal": {"path": "/files/../../../etc/passwd", "body": ""},
                "💻 Command Injection": {"path": "/run", "body": "; ls -la && cat /etc/shadow"},
            }

            for label, preset in attack_presets.items():
                if st.button(label, use_container_width=True, key=f"atk_{label}"):
                    payload = {"path": preset["path"], "body": preset["body"]}
                    status, resp = api_post("/analyze", payload)
                    st.session_state["sim_result"] = resp
                    st.session_state["sim_status"] = status

            st.divider()
            st.subheader("🍯 Honeypot Test")

            honeypot_targets = [
                "/api/v1/internal/customer-dump",
                "/api/v1/admin/export-users",
                "/api/v2/debug/db-query",
            ]
            selected_hp = st.selectbox("Pick a trap route:", honeypot_targets)
            if st.button("🪤 Hit Honeypot", use_container_width=True):
                try:
                    r = requests.get(f"{API_BASE}{selected_hp}", timeout=5)
                    st.session_state["sim_result"] = r.json()
                    st.session_state["sim_status"] = r.status_code
                    st.session_state["sim_honeypot"] = True
                except requests.ConnectionError:
                    st.session_state["sim_result"] = {"error": "Connection failed"}
                    st.session_state["sim_status"] = 0

        # ── Result ──
        st.divider()
        st.subheader("Response")

        if "sim_result" in st.session_state and st.session_state["sim_result"]:
            result = st.session_state["sim_result"]
            status = st.session_state.get("sim_status", 0)
            is_hp = st.session_state.get("sim_honeypot", False)

            if is_hp:
                st.warning("🍯 **HONEYPOT RESPONSE** — This is what the attacker sees (all fake data):")
                st.session_state["sim_honeypot"] = False
            elif status == 403:
                st.error(f"🚨 **BLOCKED** (HTTP {status})")
            else:
                st.success(f"✅ **ALLOWED** (HTTP {status})")

            st.json(result)
        else:
            st.info("Send a request to see the response here.")


# ============================================================
# TAB 10: LOG ANALYSIS
# ============================================================
with tab_logs:
    st.header("📝 Attack Log Analysis")
    if not server_up:
        st.warning("Backend not running.")
    else:
        _log_summary = api_get("/api/logs/summary")
        if _log_summary:
            # ── Summary Metrics ──
            lm1, lm2, lm3, lm4, lm5 = st.columns(5)
            lm1.metric("Total Requests", _log_summary.get("total_requests", 0))
            lm2.metric("Blocked", _log_summary.get("blocked", 0))
            lm3.metric("Allowed", _log_summary.get("allowed", 0))
            lm4.metric("Block Rate", f"{_log_summary.get('block_rate', 0)}%")
            lm5.metric("Unique Attackers", _log_summary.get("unique_attacker_ips", 0))

            lm6, lm7 = st.columns(2)
            lm6.metric("Avg Threat Score", _log_summary.get("avg_threat_score", 0))
            lm7.metric("Max Threat Score", _log_summary.get("max_threat_score", 0))

            st.divider()

            # ── Attack Type Distribution & Top Attackers ──
            col_types, col_attackers = st.columns(2)

            with col_types:
                st.subheader("💣 Attack Type Distribution")
                _atk_types = _log_summary.get("top_attack_types", [])
                if _atk_types:
                    _atk_df = pd.DataFrame(_atk_types)
                    _atk_df.columns = ["Attack Type", "Count"]
                    st.dataframe(_atk_df, use_container_width=True, hide_index=True)
                    st.bar_chart(_atk_df.set_index("Attack Type"))
                else:
                    st.info("No attacks recorded yet.")

            with col_attackers:
                st.subheader("🕵️ Top Attacker IPs")
                _top_ips = _log_summary.get("top_attackers", [])
                if _top_ips:
                    _ip_df = pd.DataFrame(_top_ips)
                    _ip_df.columns = ["IP Address", "Blocked Requests"]
                    st.dataframe(_ip_df, use_container_width=True, hide_index=True)
                    st.bar_chart(_ip_df.set_index("IP Address"))
                else:
                    st.info("No attackers detected yet.")

            st.divider()

            # ── Most Targeted Paths ──
            st.subheader("🎯 Most Targeted Paths")
            _top_paths = _log_summary.get("top_targeted_paths", [])
            if _top_paths:
                _path_df = pd.DataFrame(_top_paths)
                _path_df.columns = ["Path", "Hits"]
                st.dataframe(_path_df, use_container_width=True, hide_index=True)
            else:
                st.info("No paths targeted yet.")

            st.divider()

            # ── Attack Timeline ──
            st.subheader("📈 Attack Timeline")
            _timeline = _log_summary.get("timeline", [])
            if _timeline:
                _tl_df = pd.DataFrame(_timeline)
                _tl_df.columns = ["Hour", "Requests"]
                _tl_df = _tl_df.set_index("Hour")
                st.line_chart(_tl_df)
            else:
                st.info("No timeline data yet. Send some requests first.")

        else:
            st.info("No log data available yet. Use the Simulator tab to generate some traffic.")

        st.divider()

        # ── Detailed Attack Logs ──
        st.subheader("📋 Detailed Attack Logs")
        log_c1, log_c2, log_c3 = st.columns(3)
        with log_c1:
            log_filter_type = st.selectbox("Attack Type", ["All", "SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION", "EDOS", "WORKFLOW_CONFUSION", "SEMANTIC_DRIFT", "SLOWLORIS", "ML_ANOMALY", "HONEYPOT_TRAP", "BENIGN"], key="log_type")
        with log_c2:
            log_filter_ip = st.text_input("Filter by IP", value="", key="log_ip")
        with log_c3:
            log_blocked_only = st.checkbox("Blocked Only", value=False, key="log_blocked")

        _log_params = []
        if log_filter_type != "All":
            _log_params.append(f"attack_type={log_filter_type}")
        if log_filter_ip:
            _log_params.append(f"ip={log_filter_ip}")
        if log_blocked_only:
            _log_params.append("blocked_only=true")
        _log_q = "?" + "&".join(_log_params) if _log_params else ""

        _attack_logs = api_get(f"/api/logs/attacks{_log_q}")
        if _attack_logs and _attack_logs.get("logs"):
            _log_df = pd.DataFrame([{
                "Time": l["timestamp"][:19],
                "IP": l["ip"],
                "Attack Type": l["attack_type"],
                "Path": l["path"],
                "Threat Score": f"{l['threat_score']:.0f}",
                "Blocked": "🚫" if l["blocked"] else "✅",
            } for l in _attack_logs["logs"]])
            st.dataframe(_log_df, use_container_width=True, hide_index=True)
        else:
            st.info("No logs match the current filters.")

        st.divider()

        # ── IP Deep Dive ──
        st.subheader("🔎 IP Deep Dive")
        dive_ip = st.text_input("Enter IP to investigate", value="127.0.0.1", key="dive_ip")
        if st.button("Investigate IP", type="primary"):
            _ip_report = api_get(f"/api/logs/ip/{dive_ip}")
            if _ip_report and "error" not in _ip_report:
                ir1, ir2, ir3 = st.columns(3)
                ir1.metric("Total Requests", _ip_report["total_requests"])
                ir2.metric("Blocked", _ip_report["blocked"])
                ir3.metric("Avg Threat Score", _ip_report["avg_threat_score"])

                st.markdown(f"**First Seen:** {_ip_report['first_seen'][:19]}")
                st.markdown(f"**Last Seen:** {_ip_report['last_seen'][:19]}")

                with st.expander("Attack Types Used"):
                    for atype, cnt in _ip_report.get("attack_types", {}).items():
                        st.markdown(f"- **{atype}**: {cnt} times")

                with st.expander("Paths Targeted"):
                    for p in _ip_report.get("paths_targeted", []):
                        st.code(p, language=None)

                with st.expander("Recent Activity (last 20)"):
                    _rl = _ip_report.get("recent_logs", [])
                    if _rl:
                        _rl_df = pd.DataFrame([{
                            "Time": l["timestamp"][:19],
                            "Attack": l["attack_type"],
                            "Path": l["path"],
                            "Threat": f"{l['threat_score']:.0f}",
                            "Blocked": "🚫" if l["blocked"] else "✅",
                        } for l in _rl])
                        st.dataframe(_rl_df, use_container_width=True, hide_index=True)
            else:
                st.warning(f"No logs found for IP: {dive_ip}")


# ============================================================
# TAB 4: FEATURES
# ============================================================
with tab_features:
    st.header("🛡️ Detection Features")
    st.markdown("All security layers active in this gateway:")

    features = [
        ("🛡️", "SQL Injection", "Detects UNION, SELECT, DROP, OR 1=1 patterns in request paths and bodies."),
        ("🔥", "XSS Detection", "Catches script tags, event handlers, and javascript: URI schemes."),
        ("📂", "Path Traversal", "Blocks ../ sequences and /etc/passwd access attempts."),
        ("💉", "Command Injection", "Detects shell command chaining with ; && || operators."),
        ("🐌", "Slowloris Detection", "Identifies low-rate DoS attacks via suspiciously slow request patterns."),
        ("💸", "EDoS Detection", "Tracks cumulative cost of requests to detect economic denial of service."),
        ("🔀", "Workflow Confusion", "Detects skipped steps in multi-stage workflows (checkout, password reset)."),
        ("🌊", "Semantic Drift", "Novel: detects behavioral drift using exponential moving average on feature vectors."),
        ("🤖", "ML Anomaly Detection", "Isolation Forest + LightGBM ensemble for unsupervised anomaly scoring."),
        ("⭐", "IP Reputation", "Decaying reputation scores with automatic blocking and time-based recovery."),
        ("🍯", "ZombieNet Honeypot", "Decommissioned APIs turned into intelligent traps that serve fake data and profile attackers."),
        ("🕵️", "Attacker Profiling", "Builds detailed profiles: IPs, user agents, paths tried, timestamps of every honeypot interaction."),
        ("🔍", "API Discovery", "Scans network, API gateways, code repos, and deployments to discover all APIs including shadow APIs."),
        ("📋", "API Registry", "Central inventory of all discovered APIs with metadata, status tracking, and filtering."),
        ("🏷️", "API Classification", "Auto-classifies APIs as Active, Deprecated, Orphaned, or Zombie based on traffic and maintenance."),
        ("🔒", "Security Posture", "Per-API scoring: authentication, encryption, rate limiting, CORS, data exposure, input validation."),
        ("📊", "Risk Scoring", "Composite risk scores from status, security posture, traffic patterns, and code staleness."),
        ("⚡", "Decommissioning", "Full workflow: identify → review → approve → redirect → disable → decommission. Convert to honeypot."),
        ("💡", "Remediation", "Priority-ranked actionable fix suggestions with effort and impact estimates per API."),
        ("📡", "Continuous Monitor", "Background scanning with configurable intervals. Auto-detects new zombies and posture changes."),
        ("👻", "Shadow API Detection", "Discovers undocumented APIs in traffic not in any registry or documentation."),
        ("🔔", "Alert Management", "Real-time alerts for zombie detection, security degradation, and overdue decommissions."),
        ("📈", "Traffic Analysis", "Per-API request counts, error rates, response times, and usage trend detection."),
        ("✅", "Compliance", "OWASP API Security Top 10 and PCI-DSS compliance checks with per-API scoring."),
        ("📜", "Audit Logging", "Immutable audit trail for all status changes, scans, and decommission actions."),
        ("📤", "Report Export", "Export full reports in JSON and CSV for offline analysis and regulatory compliance."),
        ("📝", "Attack Log Analysis", "Full attack log with analytics: attack type distribution, top attackers, timeline, IP deep dive, and filtering."),
    ]

    cols = st.columns(3)
    for i, (icon, name, desc) in enumerate(features):
        with cols[i % 3]:
            st.markdown(
                f"""
                <div style="background:#131a2b; border:1px solid #1e2a42; border-radius:12px;
                            padding:1.2rem; margin-bottom:1rem; min-height:160px;">
                    <div style="font-size:2rem; margin-bottom:0.4rem;">{icon}</div>
                    <div style="font-weight:700; margin-bottom:0.3rem;">{name}</div>
                    <div style="color:#7b8ba3; font-size:0.85rem;">{desc}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


# ============================================================
# AUTO-REFRESH
# ============================================================
if auto_refresh and server_up:
    time.sleep(5)
    st.rerun()
