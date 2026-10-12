# Level 1 — Network Exposure Dashboard
**HospitalShield: Defensive Cybersecurity Education Project**

> **EDUCATIONAL NOTICE**: This dashboard is built for defensive cybersecurity education, authorized lab assessments, and college project demonstrations.  
> **OPERATING MODES**:
> 1. **Demo / Synthetic Scenario**: Fictional Community Hospital synthetic dataset (4 scenario records from CSV).
> 2. **Live Authorized Scan**: Controlled, conservative TCP service discovery against authorized targets (e.g. `localhost`, lab hosts, URLs).

---

## 1. Project Purpose & Scope

The **HospitalShield** educational project demonstrates defensive cybersecurity principles within a healthcare infrastructure context.

This project implements **LEVEL 1**:
> **"LEVEL 1 — NETWORKING — What Was Exposed"**

Level 1 focuses strictly on answering: **"WHAT WAS EXPOSED?"**
- It identifies representative network services and evaluates their exposure, reachability, and risk.
- It highlights why reachability from improper network segments expands the attack surface, potentially exposing paths leading directly or indirectly to patient records and clinical scheduling systems.
- **Strict Scope Boundaries**: Omits offensive functionality, exploitation, brute-force attacks, payload crafting, stealth evasion, credential testing, IDS/firewall bypass, persistence, and destructive actions. This is a network and service discovery tool only.

---

## 2. Architecture & Project Structure

```
level1_dashboard/
│
├── app.py                     # Main Streamlit application supporting dual data sources & scanner
├── requirements.txt           # Python dependency specifications (streamlit, pandas, plotly)
├── README.md                  # Complete documentation, setup guide, and viva defense guide
│
├── scanner/
│   ├── __init__.py            # Scanner package initialization & exports
│   ├── scanner.py             # Conservative TCP service discovery (OPEN/CLOSED/FILTERED/UNFILTERED)
│   ├── validator.py           # Target validation (IPv4, IPv6, hostnames, URLs) & custom ports
│   └── service_map.py         # Port-to-service mapping and Level 1 defensive risk metadata
│
├── data/
│   └── level1_exposure.csv    # Source-of-truth synthetic exposure dataset for Demo Mode
│
├── utils/
│   ├── __init__.py            # Utilities package initialization
│   └── data_loader.py         # Data loading, dynamic filtering, sorting, and metric calculations
│
└── tests/
    └── test_scanner.py        # Automated test suite covering all 17 verification requirements
```

---

## 3. Supported Scan States & Port State Logic

The scanner implements conservative TCP connect-based service discovery using standard operating system socket calls. It clearly distinguishes four fundamental port states:

| Port State | Discovery Logic | Interpretation |
| :--- | :--- | :--- |
| **`OPEN`** | TCP connection succeeds (`SYN-ACK` received, handshake complete) | An active service accepted the connection. Indicates a reachable listener. |
| **`CLOSED`** | Target is reachable but TCP port rejects connection (`RST` received) | The host is online, but no application is listening on that port. |
| **`FILTERED`** | Packets/connections appeared blocked or dropped (timeout or unreachable) | A firewall, filter, or network condition dropped packets; state cannot be determined. |
| **`UNFILTERED`** | Port is reachable, but state cannot be determined from available response | Host responded, but ambiguous network stack responses occurred. |

> **IMPORTANT DEFENSIVE RULE**:  
> **An open port is NOT automatically a vulnerability.**  
> An open port indicates a reachable service. Risk assessment is an independent analytical layer that evaluates whether that reachability is necessary, appropriately segmented, and securely configured.

---

## 4. Supported Scan Profiles & Ports

1. **Quick Scan**:
   - Small predefined set of common TCP ports: `21, 22, 23, 25, 53, 80, 110, 143, 443, 3389, 8080`.
2. **Level 1 Scan**:
   - Ports relevant to the HospitalShield scenario: `22 (SSH), 53 (DNS), 80 (HTTP), 443 (HTTPS), 3389 (RDP)`.
3. **Custom Scan**:
   - Allows users to enter a limited comma-separated list of TCP ports (e.g. `22, 80, 443, 8501`).
   - Validates integers (1–65535) and enforces a safety cap (maximum 50 ports) to prevent unrestricted high-speed internet scanning.

---

## 5. Mandatory Authorization Requirement

This tool is intended strictly for authorized defensive security testing and college/lab environments.

- **Mandatory Checkbox**:
  `[ ] I confirm that I am authorized to scan this target.`
- The **Scan Target** button remains **strictly disabled** until the user confirms authorization.
- Scans are accompanied by the safety notice:
  > *"Only scan systems you own or have explicit permission to assess."*

---

## 6. Target Normalization & Handling

The scanner accepts:
- **IPv4 addresses** (e.g. `127.0.0.1`, `192.168.1.10`)
- **IPv6 addresses** (e.g. `::1`)
- **Hostnames** (e.g. `localhost`, `example.local`)
- **URLs** (e.g. `https://example.com`, `http://192.168.1.10:8080/path`)

**Normalization Behavior**:
- Extracts the host/domain name from URLs.
- Strips URL schemes (`http://`, `https://`), paths, query strings, and port numbers.
- Preserves the original input URL separately for display in the dashboard.
- Validates syntax and performs DNS resolution, displaying clear error messages on failure.

---

## 7. Installation & Execution

### Prerequisites
- Python 3.10+ (Tested on Python 3.11–3.14)

### Step 1: Install Dependencies
```bash
cd level1_dashboard
pip install -r requirements.txt
```

### Step 2: Run the Dashboard
```bash
streamlit run app.py
```
Or from the project root:
```bash
streamlit run level1_dashboard/app.py
```
Open your browser at `http://localhost:8501`.

---

## 8. How to Test Using Localhost & Lab Targets

### 1. Test Demo Mode
- In the sidebar, select **DATA SOURCE: Demo / Synthetic Scenario**.
- Verify that the 4 synthetic hospital scenario records (443, 22, 53, 3389) are displayed across Overview, Exposed Services, Risk Analysis, and Service Details.

### 2. Test Localhost Scanning
- Navigate to **Network Scanner** in the sidebar.
- Enter Target: `127.0.0.1` or `localhost` or `http://localhost:8501`.
- Check `[x] I confirm that I am authorized to scan this target.`
- Select **Scan profile: Level 1 Scan** or **Custom Scan** with `22, 80, 443, 8501`.
- Click **Scan Target**.
- Observe:
  - Port `8501` is detected as **`OPEN`** (active Streamlit listener).
  - Other ports are detected as **`CLOSED`** or **`FILTERED`**.
  - Response time is measured in milliseconds.
  - Results feed dynamically into the Overview, Exposed Services, and Risk Analysis pages under **Live Authorized Scan**.

### 3. Test Dynamic Filtering & Sorting
- In the results view, use the **Port State** dropdown (`All`, `Open`, `Closed`, `Filtered`, `Unfiltered`) to filter records instantly without rescanning.
- Use **Service Filter** and **Port search**.
- Sort by **Port**, **State**, **Service**, or **Response Time**.

### 4. Test Export & History
- Click **Download Scan Results (CSV)** to export `target, timestamp, port, protocol, state, service, response_time, risk`.
- Observe session scan history at the bottom of the page; click **Clear History** to reset session records.

### 5. Automated Verification Suite
Run the automated test suite verifying all 17 requirements:
```bash
python tests/test_scanner.py
```

---

## 9. Scanner Limitations & Responsible Design

- **Discovery Only**: The scanner only attempts standard TCP 3-way handshakes (`connect()`).
- **No Exploitation**: Does not inject payloads, test credentials, or attempt vulnerability exploitation.
- **No Stealth / Evasion**: Does not use SYN stealth, fragmented packets, decoys, or firewall evasion.
- **Rate-Limited**: Employs controlled thread pool concurrency (max 8 workers) and conservative timeouts to avoid overwhelming targets.
- **Session-Only Storage**: Scan history is stored in memory for the current session only and is never persisted to disk or shared between users.

---

## 10. Viva Defense & Examination Guide

- **Q: What is the primary focus of Level 1 in HospitalShield?**  
  *Answer*: Level 1 focuses on network exposure and reachability ("What was exposed?"). It catalogs listening services, evaluates their exposure across network segments, and reinforces that exposure creates attack surface.
- **Q: Why does the scanner distinguish between OPEN, CLOSED, FILTERED, and UNFILTERED?**  
  *Answer*: These states convey the network reality: OPEN means a service responded to the handshake; CLOSED means the host sent an RST; FILTERED means packets were dropped by a firewall or network boundary; UNFILTERED means the host is reachable but state is ambiguous.
- **Q: Why is an open port not automatically labeled a vulnerability?**  
  *Answer*: A port being open merely indicates reachability. Legitimate services (e.g. HTTPS on port 443) must be open to function. Vulnerabilities require flaws in software or configuration; exposure and vulnerability are distinct concepts.
