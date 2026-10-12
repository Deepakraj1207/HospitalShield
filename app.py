"""
app.py - Level 1 — Network Exposure Dashboard
HospitalShield: Defensive Cybersecurity Education Project
Supports:
  1. Demo / Synthetic Scenario (Fictional Community Hospital)
  2. Live Authorized Scan (Controlled TCP Service Discovery)
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
from datetime import datetime
import sys

# Ensure current directory is in sys.path
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from utils.data_loader import (
    load_demo_data,
    calculate_risk_metrics,
    filter_and_sort_data
)
from scanner.validator import validate_target, validate_custom_ports
from scanner.scanner import (
    scan_target,
    QUICK_SCAN_PORTS,
    LEVEL1_PORTS
)
from scanner.service_map import PORT_SERVICE_MAP

# -----------------------------------------------------------------------------
# PAGE CONFIGURATION
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Level 1 — Network Exposure Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# PROFESSIONAL CYBERSECURITY CSS STYLING
# -----------------------------------------------------------------------------
CUSTOM_CSS = """
<style>
    /* Cybersecurity theme colors */
    :root {
        --bg-color: #0b1120;
        --card-bg: #1e293b;
        --card-border: #334155;
        --accent-blue: #38bdf8;
        --accent-red: #ef4444;
        --accent-amber: #f59e0b;
        --accent-green: #10b981;
        --text-primary: #f8fafc;
        --text-secondary: #94a3b8;
    }
    
    /* Notice Banners */
    .sim-banner {
        background: linear-gradient(90deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #38bdf8;
        border-left: 5px solid #38bdf8;
        border-radius: 6px;
        padding: 10px 16px;
        margin-bottom: 20px;
        color: #f1f5f9;
        font-size: 0.9rem;
    }
    .auth-banner {
        background: linear-gradient(90deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #10b981;
        border-left: 5px solid #10b981;
        border-radius: 6px;
        padding: 10px 16px;
        margin-bottom: 20px;
        color: #f1f5f9;
        font-size: 0.9rem;
    }
    .mode-tag {
        background-color: #0284c7;
        color: #ffffff;
        font-weight: 700;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        margin-right: 8px;
        letter-spacing: 0.5px;
    }
    .auth-tag {
        background-color: #059669;
        color: #ffffff;
        font-weight: 700;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        margin-right: 8px;
        letter-spacing: 0.5px;
    }
    
    /* Summary / Metric Cards */
    .metric-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 14px 18px;
        text-align: center;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    .metric-card.total { border-top: 4px solid #38bdf8; }
    .metric-card.open { border-top: 4px solid #10b981; }
    .metric-card.closed { border-top: 4px solid #64748b; }
    .metric-card.filtered { border-top: 4px solid #f59e0b; }
    .metric-card.unfiltered { border-top: 4px solid #818cf8; }
    .metric-card.high { border-top: 4px solid #ef4444; }
    .metric-card.medium { border-top: 4px solid #f59e0b; }
    .metric-card.low { border-top: 4px solid #10b981; }
    
    .metric-label {
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #94a3b8;
        margin-bottom: 4px;
    }
    .metric-value {
        font-size: 2.0rem;
        font-weight: 700;
        color: #f8fafc;
        line-height: 1.1;
    }
    .metric-subtext {
        font-size: 0.78rem;
        color: #cbd5e1;
        margin-top: 4px;
    }
    
    /* Port State Badges */
    .badge-open {
        background-color: rgba(16, 185, 129, 0.2);
        color: #6ee7b7;
        border: 1px solid #10b981;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.8rem;
    }
    .badge-closed {
        background-color: rgba(100, 116, 139, 0.2);
        color: #cbd5e1;
        border: 1px solid #64748b;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-filtered {
        background-color: rgba(245, 158, 11, 0.2);
        color: #fcd34d;
        border: 1px solid #f59e0b;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-unfiltered {
        background-color: rgba(129, 140, 248, 0.2);
        color: #c7d2fe;
        border: 1px solid #818cf8;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    
    /* Risk Badges */
    .badge-high {
        background-color: rgba(239, 68, 68, 0.2);
        color: #fca5a5;
        border: 1px solid #ef4444;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-medium {
        background-color: rgba(245, 158, 11, 0.2);
        color: #fcd34d;
        border: 1px solid #f59e0b;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-low {
        background-color: rgba(16, 185, 129, 0.2);
        color: #6ee7b7;
        border: 1px solid #10b981;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    
    /* Info Card */
    .info-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 16px 20px;
        margin: 10px 0;
    }
    
    /* Conceptual Flow Diagram */
    .flow-container {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        justify-content: center;
        gap: 8px;
        background-color: #111827;
        padding: 16px;
        border-radius: 8px;
        border: 1px solid #1f2937;
        margin: 14px 0;
    }
    .flow-step {
        background-color: #1f2937;
        border: 1px solid #374151;
        color: #e5e7eb;
        padding: 8px 14px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
        text-align: center;
    }
    .flow-arrow {
        color: #38bdf8;
        font-weight: bold;
        font-size: 1.1rem;
    }
    
    /* Segmentation Zones */
    .seg-zone {
        background-color: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
        padding: 14px;
        margin-bottom: 12px;
    }
    .seg-zone-header {
        font-weight: 700;
        font-size: 0.95rem;
        color: #38bdf8;
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 6px;
        border-bottom: 1px solid #374151;
        padding-bottom: 4px;
    }
    .seg-path {
        background-color: #1f2937;
        border-left: 3px solid #38bdf8;
        padding: 8px 12px;
        margin: 6px 0;
        font-family: monospace;
        font-size: 0.88rem;
        color: #e2e8f0;
        border-radius: 0 4px 4px 0;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# SESSION STATE INITIALIZATION
# -----------------------------------------------------------------------------
if "scan_history" not in st.session_state:
    st.session_state["scan_history"] = []

if "scan_results" not in st.session_state:
    st.session_state["scan_results"] = None

if "scan_target_meta" not in st.session_state:
    st.session_state["scan_target_meta"] = None

if "data_source" not in st.session_state:
    st.session_state["data_source"] = "Demo / Synthetic Scenario"


# -----------------------------------------------------------------------------
# TOP HEADER & NOTICE BANNER
# -----------------------------------------------------------------------------
def render_header(data_source: str):
    """Render title and appropriate data-source banner."""
    st.title("Level 1 — Network Exposure Dashboard")
    st.caption("Defensive Cybersecurity Assessment — What Was Exposed")
    
    if data_source == "Demo / Synthetic Scenario":
        st.markdown(
            """
            <div class="sim-banner">
                <span class="mode-tag">DEMO MODE</span>
                <strong>SIMULATION MODE — This dashboard uses synthetic scenario data. No live network scanning is performed.</strong><br>
                <span style="color: #94a3b8; font-size: 0.82rem;">
                    Educational defensive scenario — fictional Community Hospital. All asset, port, and exposure records are synthetic.
                </span>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        target_info = ""
        if st.session_state["scan_target_meta"]:
            m = st.session_state["scan_target_meta"]
            raw_disp = f" ({m['raw']})" if m.get("is_url") and m.get("raw") != m["host"] else ""
            target_info = f" | Active Target: <code>{m['host']}</code>{raw_disp} [{m.get('resolved_ip', '')}]"
        st.markdown(
            f"""
            <div class="auth-banner">
                <span class="auth-tag">LIVE AUTHORIZED SCAN</span>
                <strong>Live TCP Service Discovery — Authorized Assessment Mode.</strong>{target_info}<br>
                <span style="color: #94a3b8; font-size: 0.82rem;">
                    Educational defensive discovery only — conservative TCP connect checks. No offensive or exploitation features.
                </span>
            </div>
            """,
            unsafe_allow_html=True
        )


# -----------------------------------------------------------------------------
# PAGE 0 — NETWORK SCANNER (SERVICE DISCOVERY)
# -----------------------------------------------------------------------------
def render_network_scanner():
    """Render the Network Scanner page with authorization, profiles, filtering, sorting, charts, history, and CSV export."""
    st.subheader("🌐 Network Scanner — Authorized Service Discovery")
    st.markdown(
        "Execute conservative TCP connect-based service discovery against an authorized target. "
        "Discovers port states (**OPEN**, **CLOSED**, **FILTERED**, **UNFILTERED**) and maps services without exploitation."
    )
    
    # Notice
    st.info("⚠️ **Only scan systems you own or have explicit permission to assess.**")
    
    # Scanner Form
    col_input, col_config = st.columns([3, 2])
    
    with col_input:
        target_input = st.text_input(
            "Target:",
            value="127.0.0.1",
            placeholder="Enter IP / hostname / URL (e.g. 192.168.1.10, localhost, https://example.com)",
            help="Accepts IPv4, IPv6, hostname, or URL."
        )
        
        auth_confirmed = st.checkbox(
            "I confirm that I am authorized to scan this target.",
            value=False,
            help="You must confirm explicit authorization before initiating a scan."
        )
        
    with col_config:
        scan_profile = st.selectbox(
            "Scan profile:",
            options=["Quick Scan", "Level 1 Scan", "Custom Scan"],
            index=0,
            help="Select a predefined scan profile or define custom TCP ports."
        )
        
        custom_ports_list = []
        if scan_profile == "Custom Scan":
            custom_port_str = st.text_input(
                "Custom Ports (comma-separated):",
                value="22, 80, 443, 8080",
                help="Enter up to 50 comma-separated port numbers (1-65535)."
            )
        else:
            if scan_profile == "Quick Scan":
                st.caption(f"Ports to scan: `{', '.join(str(p) for p in QUICK_SCAN_PORTS)}`")
            else:
                st.caption(f"HospitalShield Level 1 Ports: `{', '.join(str(p) for p in LEVEL1_PORTS)}`")
                
    col_btn, col_btn_clear = st.columns([2, 4])
    with col_btn:
        scan_clicked = st.button("Scan Target", disabled=not auth_confirmed, type="primary")

    # Scan Execution Logic
    if scan_clicked:
        if not target_input.strip():
            st.error("❌ Target cannot be empty. Please enter an IP, hostname, or URL.")
            return

        # Validate target
        is_valid, target_meta, val_msg = validate_target(target_input)
        if not is_valid:
            st.error(f"❌ Target Validation Failed: {val_msg}")
            return

        # Determine ports
        if scan_profile == "Quick Scan":
            ports_to_scan = QUICK_SCAN_PORTS
        elif scan_profile == "Level 1 Scan":
            ports_to_scan = LEVEL1_PORTS
        else:
            is_valid_ports, custom_ports_list, port_err = validate_custom_ports(custom_port_str, max_ports=50)
            if not is_valid_ports:
                st.error(f"❌ Custom Port Error: {port_err}")
                return
            ports_to_scan = custom_ports_list

        target_host = target_meta["host"]
        target_ip = target_meta["resolved_ip"]
        ip_version = target_meta.get("ip_version", "IPv4")

        # Progress bar
        progress_text = f"Scanning {target_host} ({target_ip}) on {len(ports_to_scan)} port(s)..."
        progress_bar = st.progress(0, text=progress_text)

        def on_progress(done, total):
            pct = int(done / total * 100)
            progress_bar.progress(pct, text=f"Scanning port {done}/{total} on {target_host}...")

        # Run Scan
        with st.spinner("Executing conservative TCP connect discovery..."):
            scan_df = scan_target(
                target_ip=target_ip,
                ports=ports_to_scan,
                timeout=0.7,
                ip_version=ip_version,
                max_workers=8,
                progress_callback=on_progress
            )

        progress_bar.progress(100, text="Scan completed.")
        st.success(f"✓ Scan completed for **{target_host}** ({target_ip}).")

        # Save to Session State
        st.session_state["scan_results"] = scan_df
        scan_time_str = datetime.now().strftime("%H:%M:%S")
        target_meta["timestamp"] = scan_time_str
        target_meta["ports_scanned"] = ports_to_scan
        st.session_state["scan_target_meta"] = target_meta
        st.session_state["data_source"] = "Live Authorized Scan"

        # Calculate counts
        metrics = calculate_risk_metrics(scan_df)

        # Append to scan history
        target_display = target_meta["raw"] if target_meta.get("is_url") else f"{target_host} ({target_ip})"
        st.session_state["scan_history"].append({
            "Time": scan_time_str,
            "Target": target_display,
            "Ports Scanned": len(ports_to_scan),
            "Open": metrics["open_count"],
            "Closed": metrics["closed_count"],
            "Filtered": metrics["filtered_count"],
            "Unfiltered": metrics["unfiltered_count"]
        })

        st.rerun()

    # If Scan Results Exist
    if st.session_state["scan_results"] is not None and st.session_state["scan_target_meta"] is not None:
        results_df = st.session_state["scan_results"]
        meta = st.session_state["scan_target_meta"]
        metrics = calculate_risk_metrics(results_df)

        st.markdown("---")
        
        # Target metadata display
        raw_url_notice = f" | **Source URL:** `{meta['raw']}`" if meta.get("is_url") and meta.get("raw") != meta["host"] else ""
        st.markdown(
            f"### 📋 Scan Results: `{meta['host']}` ({meta.get('resolved_ip', '')}){raw_url_notice}"
        )
        st.caption(f"Scan Time: **{meta.get('timestamp', '')}** | Discovery Protocol: **Conservative TCP Connect**")

        # 7. SUMMARY CARDS
        sc1, sc2, sc3, sc4, sc5 = st.columns(5)
        with sc1:
            st.markdown(
                f"""
                <div class="metric-card total">
                    <div class="metric-label">Total Scanned</div>
                    <div class="metric-value">{metrics['total_scanned']}</div>
                    <div class="metric-subtext">Ports Probed</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with sc2:
            st.markdown(
                f"""
                <div class="metric-card open">
                    <div class="metric-label">Open</div>
                    <div class="metric-value" style="color: #6ee7b7;">{metrics['open_count']}</div>
                    <div class="metric-subtext">Reachable Services</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with sc3:
            st.markdown(
                f"""
                <div class="metric-card closed">
                    <div class="metric-label">Closed</div>
                    <div class="metric-value" style="color: #cbd5e1;">{metrics['closed_count']}</div>
                    <div class="metric-subtext">RST Received</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with sc4:
            st.markdown(
                f"""
                <div class="metric-card filtered">
                    <div class="metric-label">Filtered</div>
                    <div class="metric-value" style="color: #fcd34d;">{metrics['filtered_count']}</div>
                    <div class="metric-subtext">Packets Dropped</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with sc5:
            st.markdown(
                f"""
                <div class="metric-card unfiltered">
                    <div class="metric-label">Unfiltered</div>
                    <div class="metric-value" style="color: #c7d2fe;">{metrics['unfiltered_count']}</div>
                    <div class="metric-subtext">Ambiguous Response</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("---")

        # 8. FILTER & 9. SORT CONTROLS
        st.markdown("### 🔍 Filter & Sort Results")
        col_state, col_svc, col_search, col_sort, col_asc = st.columns([2, 2, 2, 2, 1])

        with col_state:
            state_filter = st.selectbox(
                "Port State:",
                options=["All", "Open", "Closed", "Filtered", "Unfiltered"],
                index=0,
                help="Filter table to show only ports matching selected state."
            )

        with col_svc:
            # Dynamically gather services in results
            all_services = sorted(results_df["service"].unique().tolist())
            service_options = ["All"] + all_services
            service_filter = st.selectbox(
                "Service Filter:",
                options=service_options,
                index=0,
                help="Filter by identified service name."
            )

        with col_search:
            port_search = st.text_input(
                "Port search:",
                placeholder="Search port...",
                help="Search by port number."
            )

        with col_sort:
            sort_by = st.selectbox(
                "Sort by:",
                options=["Port", "State", "Service", "Response Time"],
                index=0,
                help="Sort records by Port, State, Service, or Response Time."
            )

        with col_asc:
            ascending = st.checkbox("Ascending", value=True)

        # Apply filtering & sorting dynamically
        filtered_results = filter_and_sort_data(
            df=results_df,
            state_filter=state_filter,
            service_filter=service_filter,
            port_search=port_search,
            sort_by=sort_by,
            ascending=ascending
        )

        st.markdown(f"**Displaying {len(filtered_results)} of {len(results_df)} ports**")

        # Display Discovered Ports Table
        display_table = filtered_results[["port", "protocol", "state", "service", "response_time"]].copy()
        display_table.columns = ["Port", "Protocol", "State", "Service", "Response Time"]

        st.dataframe(display_table, use_container_width=True, hide_index=True)

        # 10. VISUALIZATION
        st.markdown("---")
        st.markdown("### 📊 Visualizations")
        vc1, vc2 = st.columns(2)

        with vc1:
            st.markdown("##### Chart 1: Port State Distribution")
            # Count distribution from the current filtered results or total results
            state_counts_df = pd.DataFrame({
                "State": ["OPEN", "CLOSED", "FILTERED", "UNFILTERED"],
                "Count": [
                    (results_df["state"] == "OPEN").sum(),
                    (results_df["state"] == "CLOSED").sum(),
                    (results_df["state"] == "FILTERED").sum(),
                    (results_df["state"] == "UNFILTERED").sum()
                ]
            })
            # Filter zero count states for pie or keep all for bar
            fig_state = px.bar(
                state_counts_df,
                x="State",
                y="Count",
                text="Count",
                color="State",
                color_discrete_map={
                    "OPEN": "#10b981",
                    "CLOSED": "#64748b",
                    "FILTERED": "#f59e0b",
                    "UNFILTERED": "#818cf8"
                }
            )
            fig_state.update_traces(
                textposition="outside",
                textfont=dict(size=13, color="#f8fafc"),
                marker=dict(line=dict(width=1, color="#334155"))
            )
            fig_state.update_layout(
                paper_bgcolor="#1e293b",
                plot_bgcolor="#0f172a",
                font=dict(color="#f8fafc"),
                showlegend=False,
                yaxis=dict(
                    title="Number of Ports",
                    dtick=1,
                    range=[0, max(state_counts_df["Count"]) + 2 if max(state_counts_df["Count"]) > 0 else 3],
                    gridcolor="#334155"
                ),
                xaxis=dict(title="Port State", gridcolor="#1e293b"),
                margin=dict(l=30, r=20, t=20, b=30)
            )
            st.plotly_chart(fig_state, use_container_width=True)

        with vc2:
            st.markdown("##### Chart 2: Open Services")
            open_df = results_df[results_df["state"] == "OPEN"]
            if not open_df.empty:
                open_svc_counts = open_df["service"].value_counts().reset_index()
                open_svc_counts.columns = ["Service", "Count"]

                fig_open = px.bar(
                    open_svc_counts,
                    x="Service",
                    y="Count",
                    text="Count",
                    color="Service",
                    color_discrete_sequence=["#10b981", "#38bdf8", "#f59e0b", "#a855f7", "#ec4899"]
                )
                fig_open.update_traces(
                    textposition="outside",
                    textfont=dict(size=13, color="#f8fafc"),
                    marker=dict(line=dict(width=1, color="#334155"))
                )
                fig_open.update_layout(
                    paper_bgcolor="#1e293b",
                    plot_bgcolor="#0f172a",
                    font=dict(color="#f8fafc"),
                    showlegend=False,
                    yaxis=dict(
                        title="Count",
                        dtick=1,
                        range=[0, max(open_svc_counts["Count"]) + 1],
                        gridcolor="#334155"
                    ),
                    xaxis=dict(title="Open Service", gridcolor="#1e293b"),
                    margin=dict(l=30, r=20, t=20, b=30)
                )
                st.plotly_chart(fig_open, use_container_width=True)
            else:
                st.info("No OPEN services discovered on target.")

        # 11. LEVEL 1 RISK CLASSIFICATION VIEW
        st.markdown("---")
        st.markdown("### 🛡️ Level 1 Risk Classification")
        st.caption(
            "Evaluation based on the Level 1 risk model. "
            "**Important:** Only OPEN services are treated as reachable/exposed. "
            "An open port is not automatically a vulnerability."
        )

        open_services_list = results_df[results_df["state"] == "OPEN"]
        if not open_services_list.empty:
            for _, row in open_services_list.iterrows():
                port = row["port"]
                svc = row["service"]
                risk = row["risk"]
                exp = row["exposure"]

                badge_class = f"badge-{risk.lower()}" if risk.lower() in ["high", "medium", "low"] else "badge-low"
                
                st.markdown(
                    f"""
                    <div class="info-card">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <strong>Port {port} — {svc} (TCP)</strong>
                            <span class="{badge_class}">{risk} Risk</span>
                        </div>
                        <p style="margin: 6px 0 2px 0; color: #cbd5e1; font-size: 0.9rem;">
                            <strong>Exposure:</strong> {exp}
                        </p>
                        <p style="margin: 0; color: #94a3b8; font-size: 0.82rem;">
                            <em>Reachable service — requires configuration and access-control review.</em>
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        else:
            st.info("No active open services requiring Level 1 risk review.")

        # 15. EXPORT CSV
        st.markdown("---")
        st.markdown("### 📥 Export Scan Data")
        
        # CSV Schema: target, timestamp, port, protocol, state, service, response_time, risk
        export_df = results_df[["port", "protocol", "state", "service", "response_time", "risk"]].copy()
        export_df.insert(0, "target", meta["host"])
        export_df.insert(1, "timestamp", meta.get("timestamp", ""))

        csv_bytes = export_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download Scan Results (CSV)",
            data=csv_bytes,
            file_name=f"scan_{meta['host']}_{meta.get('timestamp', '').replace(':', '')}.csv",
            mime="text/csv",
            help="Export the current authorized scan data as CSV."
        )

    # 14. SCAN HISTORY
    if st.session_state["scan_history"]:
        st.markdown("---")
        st.markdown("### 🕒 Session Scan History")
        
        hist_df = pd.DataFrame(st.session_state["scan_history"])
        st.dataframe(hist_df, use_container_width=True, hide_index=True)
        
        if st.button("Clear History"):
            st.session_state["scan_history"] = []
            st.rerun()

    # 26. EDUCATIONAL INFORMATION
    st.markdown("---")
    with st.expander("ℹ️ How to interpret scan results"):
        st.markdown(
            """
            #### Port States in Service Discovery:
            - **OPEN**: A service accepted the TCP connection (SYN-ACK completed). Indicates an active listening service reachable across the network.
            - **CLOSED**: The target host responded, but no service accepted the connection (TCP RST packet received). The host is online, but the port is not listening.
            - **FILTERED**: A filtering device (firewall, network ACL) or network condition prevented a clear determination because packets were dropped or blocked (timeout or unreachable).
            - **UNFILTERED**: The port is reachable, but its open/closed state cannot be determined reliably from the available response.

            #### Defensive Security Notice:
            > **"An open port is not automatically a vulnerability."**  
            > An open port simply indicates that a service is listening and reachable. Risk assessment is a separate analytical layer that evaluates whether that reachability is necessary, appropriately segmented, and securely configured.
            """
        )


# -----------------------------------------------------------------------------
# PAGE 1 — EXECUTIVE OVERVIEW
# -----------------------------------------------------------------------------
def render_overview(df: pd.DataFrame, metrics: dict, data_source: str):
    """Render Executive Overview page with dynamic metric cards and defensive focus."""
    st.subheader("Executive Overview")
    
    if data_source == "Demo / Synthetic Scenario":
        st.markdown(
            "Level 1 identifies representative network services and evaluates their exposure and associated risk."
        )
    else:
        target_str = st.session_state["scan_target_meta"]["host"] if st.session_state["scan_target_meta"] else "Authorized Target"
        st.markdown(
            f"Authorized exposure assessment results for **{target_str}**. "
            "Metrics reflect active reachable services observed during live TCP service discovery."
        )
    
    # Dynamic Metric Cards
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(
            f"""
            <div class="metric-card total">
                <div class="metric-label">Reachable Services</div>
                <div class="metric-value">{metrics['total']}</div>
                <div class="metric-subtext">Identified in Level 1</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with col2:
        st.markdown(
            f"""
            <div class="metric-card high">
                <div class="metric-label">High Risk Services</div>
                <div class="metric-value">{metrics['high_count']}</div>
                <div class="metric-subtext">{metrics['high_pct']:.0f}% of active inventory</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with col3:
        st.markdown(
            f"""
            <div class="metric-card medium">
                <div class="metric-label">Medium Risk Services</div>
                <div class="metric-value">{metrics['medium_count']}</div>
                <div class="metric-subtext">{metrics['medium_pct']:.0f}% of active inventory</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with col4:
        st.markdown(
            f"""
            <div class="metric-card low">
                <div class="metric-label">Low Risk Services</div>
                <div class="metric-value">{metrics['low_count']}</div>
                <div class="metric-subtext">{metrics['low_pct']:.0f}% of active inventory</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        
    st.markdown("---")
    
    # Why This Matters Section
    st.markdown("### ⚠️ Why This Matters")
    st.info(
        "**\"A service that is reachable from the wrong network segment gives an intruder "
        "more opportunities to test identities, software, and configuration.\"**"
    )
    
    st.markdown(
        """
        The exposed path is important because it connects **directly or indirectly to patient records and clinical scheduling**.
        
        Evaluating network reachability and exposure is a foundational defensive priority: reachability determines 
        the boundary conditions under which services interact and whether access is confined to intended segments.
        """
    )
    
    # Conceptual Flow
    st.markdown("##### Conceptual Relationship:")
    st.markdown(
        """
        <div class="flow-container">
            <div class="flow-step">Network Exposure</div>
            <div class="flow-arrow">→</div>
            <div class="flow-step">Network Reachability</div>
            <div class="flow-arrow">→</div>
            <div class="flow-step">Access Opportunities</div>
            <div class="flow-arrow">→</div>
            <div class="flow-step">Sensitive Systems<br><small style="color:#cbd5e1;">(Patient Records & Scheduling)</small></div>
            <div class="flow-arrow">→</div>
            <div class="flow-step" style="border-color:#ef4444; color:#fca5a5;">Potential Business Impact</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    # Defensive Focus Areas
    st.markdown("### 🛡️ Defensive Focus")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(
            """
            - **Accurate Asset Inventory**: Cataloging active services and listening network endpoints.
            - **Narrow Network Permissions**: Limiting traffic between network segments to authorized paths only.
            - **Continuous Monitoring**: Maintaining operational visibility over reachable services.
            """
        )
    with c2:
        st.markdown(
            """
            - **Network Segmentation**: Separating services into distinct, controlled network segments.
            - **Appropriate Access Control**: Ensuring administrative and sensitive services require strict authentication and authorization.
            """
        )


# -----------------------------------------------------------------------------
# PAGE 2 — EXPOSED SERVICES TABLE
# -----------------------------------------------------------------------------
def render_exposed_services(df: pd.DataFrame, data_source: str):
    """Render interactive exposed services table with functional filters, sorting, and live results support."""
    st.subheader("Exposed Services")
    st.markdown(
        "Interactive record of network services. "
        "Use the controls below to filter by port state, service, or risk tier, and sort by port, risk, or state."
    )
    
    # Filter and Sorting Controls
    col_f1, col_f2, col_f3, col_s1, col_s2 = st.columns([2, 2, 2, 2, 1])
    
    all_risks = sorted(df["risk"].unique().tolist()) if "risk" in df.columns else []
    all_services = sorted(df["service"].unique().tolist()) if "service" in df.columns else []
    all_states = sorted(df["state"].unique().tolist()) if "state" in df.columns else ["OPEN"]
    
    with col_f1:
        selected_states = st.multiselect(
            "State",
            options=all_states,
            default=all_states,
            help="Filter by port state (OPEN, CLOSED, FILTERED, UNFILTERED)."
        )
        
    with col_f2:
        selected_services = st.multiselect(
            "Service",
            options=all_services,
            default=all_services,
            help="Filter by Service name."
        )
        
    with col_f3:
        selected_risks = st.multiselect(
            "Risk",
            options=all_risks,
            default=all_risks,
            help="Filter by Risk tier."
        )
        
    with col_s1:
        sort_by = st.selectbox(
            "Sort by",
            options=["Port", "Risk", "State", "Response Time"],
            index=0,
            help="Sort records by Port number, Risk priority, State, or Response Time."
        )
        
    with col_s2:
        ascending = st.checkbox("Ascending", value=True)
        
    # Process Filter and Sort dynamically
    filtered_df = df.copy()
    if selected_states:
        filtered_df = filtered_df[filtered_df["state"].isin(selected_states)]
    if selected_services:
        filtered_df = filtered_df[filtered_df["service"].isin(selected_services)]
    if selected_risks:
        filtered_df = filtered_df[filtered_df["risk"].isin(selected_risks)]

    # Sorting
    filtered_df = filter_and_sort_data(
        df=filtered_df,
        sort_by=sort_by,
        ascending=ascending
    )
    
    st.markdown(f"**Showing {len(filtered_df)} of {len(df)} services**")
    
    # Columns: Port | Protocol | Service | State | Exposure | Risk | Response Time
    expected_cols = ["port", "protocol", "service", "state", "exposure", "risk", "response_time"]
    actual_cols = [c for c in expected_cols if c in filtered_df.columns]
    
    # Toggle for structured visualization fields
    show_visual_fields = st.toggle(
        "Show Segment & Target (Conceptual scenario fields)",
        value=True,
        help="Segment and Target are structured representations for architectural visualization."
    )
    if show_visual_fields and "segment" in filtered_df.columns and "target" in filtered_df.columns:
        actual_cols = actual_cols + ["segment", "target"]
        
    formatted_df = filtered_df[actual_cols].copy()
    formatted_df.columns = [c.replace("_", " ").title() for c in actual_cols]
    
    st.dataframe(
        formatted_df,
        use_container_width=True,
        hide_index=True
    )
    
    st.caption(
        "💡 *Note: Only OPEN services represent active reachable exposure. "
        "Closed, Filtered, and Unfiltered states represent non-reachable or protected ports.*"
    )


# -----------------------------------------------------------------------------
# PAGE 3 — RISK ANALYSIS
# -----------------------------------------------------------------------------
def render_risk_analysis(df: pd.DataFrame, metrics: dict, data_source: str):
    """Render Plotly bar chart and percentage breakdown dynamically calculated from active dataset."""
    st.subheader("Risk Analysis")
    st.markdown(
        "Dynamic risk evaluation calculated directly from the active dataset. "
        "No arbitrary vulnerability scores or external CVE weights are introduced."
    )
    
    # Prepare risk counts dataframe for plotting
    risk_data = pd.DataFrame({
        "Risk": ["High", "Medium", "Low"],
        "Count": [metrics["high_count"], metrics["medium_count"], metrics["low_count"]],
        "Percentage": [f"{metrics['high_pct']:.0f}%", f"{metrics['medium_pct']:.0f}%", f"{metrics['low_pct']:.0f}%"]
    })
    
    col_chart1, col_chart2 = st.columns([3, 2])
    
    color_map = {
        "High": "#ef4444",
        "Medium": "#f59e0b",
        "Low": "#10b981"
    }
    
    with col_chart1:
        st.markdown("##### Service Count by Risk")
        fig_bar = px.bar(
            risk_data,
            x="Risk",
            y="Count",
            text="Count",
            color="Risk",
            color_discrete_map=color_map,
            category_orders={"Risk": ["High", "Medium", "Low"]}
        )
        fig_bar.update_traces(
            textposition="outside",
            textfont=dict(size=14, color="#f8fafc"),
            marker=dict(line=dict(width=1, color="#334155"))
        )
        fig_bar.update_layout(
            paper_bgcolor="#1e293b",
            plot_bgcolor="#0f172a",
            font=dict(color="#f8fafc"),
            showlegend=False,
            yaxis=dict(
                title="Number of Reachable Services",
                dtick=1,
                range=[0, max(risk_data["Count"]) + 1 if max(risk_data["Count"]) > 0 else 2],
                gridcolor="#334155"
            ),
            xaxis=dict(title="Risk Level", gridcolor="#1e293b"),
            margin=dict(l=40, r=20, t=20, b=40)
        )
        st.plotly_chart(fig_bar, use_container_width=True)
        
    with col_chart2:
        st.markdown("##### Percentage Distribution")
        # Filter 0 count items for clean donut presentation
        donut_data = risk_data[risk_data["Count"] > 0]
        if not donut_data.empty:
            fig_pie = px.pie(
                donut_data,
                names="Risk",
                values="Count",
                color="Risk",
                color_discrete_map=color_map,
                hole=0.55
            )
            fig_pie.update_traces(
                textinfo="percent+label",
                textfont=dict(size=13, color="#f8fafc"),
                marker=dict(line=dict(color="#1e293b", width=2))
            )
            fig_pie.update_layout(
                paper_bgcolor="#1e293b",
                font=dict(color="#f8fafc"),
                legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
                margin=dict(l=20, r=20, t=20, b=20)
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No reachable exposed services currently identified.")
        
    st.markdown("##### Summary Distribution:")
    st.markdown(
        f"""
        - **High**: `{metrics['high_count']}` services (**{metrics['high_pct']:.0f}%**) — Administrative services requiring controlled access.
        - **Medium**: `{metrics['medium_count']}` services (**{metrics['medium_pct']:.0f}%**) — Public application TLS endpoint and internal resolver with broad reachability.
        - **Low**: `{metrics['low_count']}` services (**{metrics['low_pct']:.0f}%**) — Services requiring standard exposure checks.
        """
    )


# -----------------------------------------------------------------------------
# PAGE 4 — SERVICE DETAILS
# -----------------------------------------------------------------------------
def render_service_details(df: pd.DataFrame):
    """Render expandable explanation cards for each service and a concise Level 1 glossary."""
    st.subheader("Service Details")
    st.markdown(
        "Detailed examination of each representative service based on the Level 1 scenario. "
        "Explanations focus on appropriate configuration, exposure, network reachability, and access control."
    )
    
    # HTTPS Expander
    with st.expander("🌐 HTTPS — Port 443 (TLS endpoint for the public application)", expanded=True):
        st.markdown(
            """
            - **Port**: `443` | **Service**: `HTTPS`
            - **Scenario Detail**: *TLS endpoint for the public application*
            - **Risk Level**: <span class="badge-medium">Medium</span>
            
            **Exposure Analysis:**  
            Port 443 serves as the TLS endpoint for the hospital's public application. **Being publicly reachable is not automatically a vulnerability**, as public applications are intended to be accessible to users. The primary focus is whether the service is appropriately configured and exposed, ensuring that only the intended application interface is accessible.
            
            ---
            **🎓 Viva Quick Answer:**  
            * **Purpose**: TLS endpoint for the public hospital application.  
            * **Why does it require attention?** Because public reachability requires verifying that exposure is intentional and appropriately configured.  
            * **What is the Level 1 concern?** Verifying that only the intended public application is exposed.
            """,
            unsafe_allow_html=True
        )
        
    # SSH Expander
    with st.expander("🔑 SSH — Port 22 (Administrative access restricted by policy)", expanded=True):
        st.markdown(
            """
            - **Port**: `22` | **Service**: `SSH`
            - **Scenario Detail**: *Administrative access restricted by policy*
            - **Risk Level**: <span class="badge-high">High</span>
            
            **Exposure Analysis:**  
            SSH represents administrative access. Administrative services require controlled access because they provide system-level administrative capabilities. Network permissions and access control are essential to ensure administrative access remains restricted by policy.
            
            *(Note: The scenario specifies that SSH is restricted by policy, without designating a specific management subnet.)*
            
            ---
            **🎓 Viva Quick Answer:**  
            * **Purpose**: Remote administrative access.  
            * **Why does it require protection?** Administrative services require strictly controlled access and appropriate permissions.  
            * **What is the Level 1 concern?** Network exposure and access control.
            """,
            unsafe_allow_html=True
        )
        
    # DNS Expander
    with st.expander("📡 DNS — Port 53 (Internal resolver reachable from a broad segment)", expanded=True):
        st.markdown(
            """
            - **Port**: `53` | **Service**: `DNS`
            - **Scenario Detail**: *Internal resolver reachable from a broad segment*
            - **Risk Level**: <span class="badge-medium">Medium</span>
            
            **Exposure Analysis:**  
            This service is an internal resolver. The relevant exposure concern is reachability from a broad network segment. When an internal resolver is reachable across broad segments, network segmentation and narrowing network permissions are relevant defensive considerations.
            
            ---
            **🎓 Viva Quick Answer:**  
            * **Purpose**: Internal resolver for domain name resolution.  
            * **Why does it require protection?** Reachability across a broad network segment represents an unnecessary exposure surface.  
            * **What is the Level 1 concern?** Broad network reachability and network segmentation.
            """,
            unsafe_allow_html=True
        )
        
    # RDP Expander
    with st.expander("🖥️ RDP — Port 3389 (Remote desktop service exposed to a management subnet)", expanded=True):
        st.markdown(
            """
            - **Port**: `3389` | **Service**: `RDP`
            - **Scenario Detail**: *Remote desktop service exposed to a management subnet*
            - **Risk Level**: <span class="badge-high">High</span>
            
            **Exposure Analysis:**  
            RDP provides remote desktop access for administration. In this scenario, it is exposed to a management subnet. Remote administrative access should be restricted to appropriate management networks to maintain appropriate access boundaries.
            
            ---
            **🎓 Viva Quick Answer:**  
            * **Purpose**: Remote desktop service for management access.  
            * **Why does it require protection?** Administrative remote desktop access should be restricted to approved management networks.  
            * **What is the Level 1 concern?** Restricting remote administrative access to the appropriate management subnet.
            """,
            unsafe_allow_html=True
        )
        
    st.markdown("---")
    
    # Concise Level 1 Concepts Glossary
    st.markdown("### 📚 Level 1 Concepts Glossary")
    st.markdown("Core networking and defensive cybersecurity fundamentals relevant to Level 1:")
    
    with st.expander("🔍 Click to Expand: Glossary of Concepts"):
        glossary = [
            ("IP Address", "A numerical address identifying a device on a network to route communications."),
            ("Port", "A 16-bit numerical endpoint (0–65535) used to direct network traffic to a specific software service on a host."),
            ("Service", "A program running on a host that listens on a port and responds to network requests."),
            ("Protocol", "A standardized set of rules governing data communication across a network."),
            ("TCP vs UDP", "TCP is connection-oriented and provides reliable data transmission; UDP is connectionless and prioritizes lightweight, fast delivery."),
            ("HTTPS", "Hypertext Transfer Protocol Secure, provides encrypted web application traffic over TLS (Port 443)."),
            ("SSH", "Secure Shell, provides remote administrative command-line access (Port 22)."),
            ("DNS", "Domain Name System, resolves human-readable names to IP addresses (Port 53)."),
            ("RDP", "Remote Desktop Protocol, provides interactive remote desktop access (Port 3389)."),
            ("Network Exposure", "The reachability of a network service or port from a specific network location or segment."),
            ("Network Segmentation", "The practice of dividing a network into distinct subnets or zones to restrict traffic flow and access."),
            ("Access Control", "Rules and mechanisms that regulate which users or systems are permitted to connect to specific resources."),
            ("Least Privilege", "Granting only the minimum necessary access and network reachability required for legitimate operations."),
            ("Risk vs Vulnerability", "A vulnerability is a flaw in software or configuration; risk is the potential impact and likelihood resulting from exposure and reachability.")
        ]
        
        for term, definition in glossary:
            st.markdown(f"**{term}**: {definition}")


# -----------------------------------------------------------------------------
# PAGE 5 — NETWORK SEGMENTATION VIEW
# -----------------------------------------------------------------------------
def render_network_segmentation():
    """Render network segmentation view demonstrating zone-based reachability."""
    st.subheader("Network Segmentation View")
    
    # Prominent conceptual model notice (Requirement 23)
    st.warning(
        "ℹ️ **Conceptual Model Notice**: Conceptual segmentation based on the training scenario — "
        "not discovered from the scan. A network scanner only observes port reachability on a specific target."
    )
    
    st.markdown(
        """
        The purpose is to demonstrate that **different services should be reachable only from appropriate network segments**.
        Proper segmentation ensures that services are exposed only to their intended audiences.
        """
    )
    
    # Structured Architectural Representation
    st.markdown(
        """
        <div class="seg-zone" style="border-left: 5px solid #38bdf8;">
            <div class="seg-zone-header">
                <span>🌐 Internet</span>
            </div>
            <div class="seg-path">
                Internet ──────[ HTTPS : 443 ]──────> <strong>Public Application</strong>
            </div>
            <p style="font-size: 0.82rem; color: #94a3b8; margin: 4px 0 0 0;">
                <em>TLS endpoint for the public application.</em>
            </p>
        </div>
        
        <div class="seg-zone" style="border-left: 5px solid #f59e0b;">
            <div class="seg-zone-header" style="color: #f59e0b;">
                <span>🏢 Broad / Internal Segment</span>
            </div>
            <div class="seg-path">
                Broad/Internal Segment ──────[ DNS : 53 ]──────> <strong>Internal Resolver</strong>
            </div>
            <p style="font-size: 0.82rem; color: #94a3b8; margin: 4px 0 0 0;">
                <em>Internal resolver reachable from a broad segment.</em>
            </p>
        </div>
        
        <div class="seg-zone" style="border-left: 5px solid #ef4444;">
            <div class="seg-zone-header" style="color: #ef4444;">
                <span>🔒 Management Subnet</span>
            </div>
            <div class="seg-path">
                Management Subnet ──────[ RDP : 3389 ]──────> <strong>Remote Desktop Service</strong>
            </div>
            <p style="font-size: 0.82rem; color: #94a3b8; margin: 4px 0 0 0;">
                <em>Remote desktop service exposed to a management subnet.</em>
            </p>
        </div>
        
        <div class="seg-zone" style="border-left: 5px solid #a855f7;">
            <div class="seg-zone-header" style="color: #c084fc;">
                <span>🔑 Policy-Restricted Administrative Access (SSH)</span>
            </div>
            <div class="seg-path">
                SSH : 22 ──────> <strong>Administrative Access</strong> (<em>Restricted by policy</em>)
            </div>
            <p style="font-size: 0.82rem; color: #94a3b8; margin: 4px 0 0 0;">
                <em>Note: The scenario specifies that SSH is restricted by policy, without assigning it to a specific management subnet.</em>
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    st.markdown("##### Conceptual Segmentation Structure:")
    st.code(
        """
Internet
  |
  +-- HTTPS : 443 --> Public Application

Broad/Internal Segment
  |
  +-- DNS : 53 --> Internal Resolver

Management Subnet
  |
  +-- RDP : 3389 --> Remote Desktop Service

SSH (Restricted by Policy):
  SSH : 22 --> Administrative Access ("Restricted by policy")
        """,
        language="text"
    )


# -----------------------------------------------------------------------------
# PAGE 6 — DEFENSIVE RECOMMENDATIONS
# -----------------------------------------------------------------------------
def render_recommendations():
    """Render defensive recommendations focused on Level 1 principles."""
    st.subheader("Security Recommendations")
    st.markdown(
        "Defensive principles based on the Level 1 exposure analysis. "
        "These measures focus on minimizing unnecessary exposure and establishing clear network boundaries."
    )
    
    recommendations = [
        (
            "1. Accurate Asset Inventory",
            "Maintain an accurate inventory of internet-facing and internal network services to ensure all reachable listeners are identified.",
            "🛡️"
        ),
        (
            "2. Narrow Network Permissions",
            "Narrow network permissions so that services receive traffic only from required sources and designated network segments.",
            "🔒"
        ),
        (
            "3. Network Segmentation",
            "Implement network segmentation to separate public, internal, and management services into appropriate zones.",
            "🧱"
        ),
        (
            "4. Appropriate Access Control",
            "Apply appropriate access control and strong authentication for administrative services, restricting them to approved networks.",
            "🔑"
        ),
        (
            "5. Continuous Monitoring",
            "Continuously monitor relevant services, listening ports, and network activity to detect unintended exposure changes.",
            "📡"
        )
    ]
    
    for title, desc, icon in recommendations:
        st.markdown(
            f"""
            <div class="info-card">
                <h4 style="margin: 0 0 6px 0; color: #38bdf8;">{icon} {title}</h4>
                <p style="margin: 0; color: #cbd5e1; font-size: 0.92rem; line-height: 1.5;">{desc}</p>
            </div>
            """,
            unsafe_allow_html=True
        )
        
    st.markdown("---")
    st.markdown(
        """
        <div style="font-size: 0.85rem; color: #94a3b8;">
            <em>Note: The recommendations above represent general defensive principles derived from the Level 1 focus on 
            accurate asset inventory, narrow network permissions, continuous monitoring, network segmentation, and appropriate access control.</em>
        </div>
        """,
        unsafe_allow_html=True
    )


# -----------------------------------------------------------------------------
# MAIN APPLICATION CONTROLLER
# -----------------------------------------------------------------------------
def main():
    # Sidebar setup
    with st.sidebar:
        st.markdown("### 🛡️ LEVEL 1")
        st.markdown("**Network Exposure Dashboard**")
        st.caption("Defensive Cybersecurity Assessment")
        
        st.markdown("---")
        
        # DATA SOURCE INDICATOR / SELECTOR (Requirement 12)
        st.markdown("##### DATA SOURCE:")
        data_source = st.radio(
            "Select Data Source",
            options=["Demo / Synthetic Scenario", "Live Authorized Scan"],
            index=0 if st.session_state["data_source"] == "Demo / Synthetic Scenario" else 1,
            label_visibility="collapsed",
            help="Switch between the fixed synthetic hospital scenario (Demo) and the live authorized target scanner."
        )
        st.session_state["data_source"] = data_source
        
        st.markdown("---")
        
        # NAVIGATION ITEMS (Requirement 1: 'Network Scanner' included)
        nav_options = [
            "Network Scanner",
            "Overview",
            "Exposed Services",
            "Risk Analysis",
            "Service Details",
            "Network Segmentation",
            "Recommendations"
        ]
        
        nav_selection = st.radio(
            "Navigation",
            options=nav_options,
            index=0 if data_source == "Live Authorized Scan" and st.session_state["scan_results"] is None else 1
        )
        
        st.markdown("---")
        st.markdown(
            f"""
            <div style="font-size: 0.78rem; color: #94a3b8;">
                <strong>Active Data Source:</strong><br>
                {data_source}<br><br>
                <em>Defensive educational assessment — no exploitation</em>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Render persistent header
    render_header(data_source)

    # If user selects Network Scanner page:
    if nav_selection == "Network Scanner":
        render_network_scanner()
        return

    # Data Routing for Dashboard Pages
    if data_source == "Demo / Synthetic Scenario":
        # Load synthetic CSV data
        try:
            active_df = load_demo_data()
            metrics = calculate_risk_metrics(active_df)
        except Exception as e:
            st.error(f"❌ Failed to load Level 1 dataset: {str(e)}")
            st.info("Please verify that `data/level1_exposure.csv` exists and contains valid records.")
            return
    else:
        # Live Authorized Scan Mode: Use scan results if available
        if st.session_state["scan_results"] is not None:
            active_df = st.session_state["scan_results"]
            metrics = calculate_risk_metrics(active_df)
        else:
            st.warning("⚠️ No live scan results available yet for this session.")
            st.markdown(
                "Please navigate to **Network Scanner** in the sidebar to configure and initiate a scan "
                "against an authorized target."
            )
            if st.button("Go to Network Scanner", type="primary"):
                st.rerun()
            return

    # Render standard dashboard views (fed by either Demo or Live Scan)
    if nav_selection == "Overview":
        render_overview(active_df, metrics, data_source)
    elif nav_selection == "Exposed Services":
        render_exposed_services(active_df, data_source)
    elif nav_selection == "Risk Analysis":
        render_risk_analysis(active_df, metrics, data_source)
    elif nav_selection == "Service Details":
        render_service_details(active_df)
    elif nav_selection == "Network Segmentation":
        render_network_segmentation()
    elif nav_selection == "Recommendations":
        render_recommendations()


if __name__ == "__main__":
    main()
