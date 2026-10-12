"""
service_map.py - Port to Service Mapping & Defensive Level 1 Risk Classifications
HospitalShield Level 1 — Network Exposure Dashboard
"""

from typing import Dict, Any

# Standard TCP Port to Service mapping
PORT_SERVICE_MAP: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8501: "Streamlit",
    8888: "HTTP-Alt",
    9090: "Prometheus",
    27017: "MongoDB"
}

# Level 1 Scenario & Defensive Guidance Metadata
LEVEL1_SERVICE_GUIDANCE: Dict[int, Dict[str, str]] = {
    22: {
        "service": "SSH",
        "exposure": "Administrative service reachable — review network restrictions and administrative access policy",
        "risk": "High",
        "segment": "Policy-Restricted",
        "target": "Administrative Access",
        "review": "Review network restrictions and administrative access policy"
    },
    53: {
        "service": "DNS",
        "exposure": "DNS service reachable — review whether access is appropriately limited to intended network segments",
        "risk": "Medium",
        "segment": "Broad/Internal Segment",
        "target": "Internal Resolver",
        "review": "Review whether access is appropriately limited to intended network segments"
    },
    80: {
        "service": "HTTP",
        "exposure": "Standard web service reachable — review exposure and secure configuration",
        "risk": "Medium",
        "segment": "Web Perimeter",
        "target": "Web Application",
        "review": "Review exposure and ensure encrypted redirection (HTTPS)"
    },
    443: {
        "service": "HTTPS",
        "exposure": "HTTPS endpoint reachable — review exposure and secure configuration",
        "risk": "Medium",
        "segment": "Internet / Perimeter",
        "target": "Public Application",
        "review": "Review exposure and secure configuration"
    },
    3389: {
        "service": "RDP",
        "exposure": "Remote desktop service reachable — review management-network restriction and access policy",
        "risk": "High",
        "segment": "Management Subnet",
        "target": "Remote Desktop Service",
        "review": "Review management-network restriction and access policy"
    }
}


def get_service_name(port: int) -> str:
    """
    Identify service name from port number.
    Returns 'Unknown' if the service cannot be confidently identified.
    """
    return PORT_SERVICE_MAP.get(port, "Unknown")


def get_service_exposure_metadata(port: int, state: str) -> Dict[str, str]:
    """
    Retrieve defensive Level 1 exposure and risk guidance based on port and state.
    
    IMPORTANT:
    - Only OPEN services are treated as reachable/exposed.
    - CLOSED, FILTERED, and UNFILTERED ports receive risk='None' (no active exposure observed).
    - An OPEN port is NOT automatically a vulnerability; it indicates a reachable service.
    """
    svc_name = get_service_name(port)
    state_upper = state.upper()

    if state_upper != "OPEN":
        if state_upper == "CLOSED":
            exposure_desc = "Port is closed — host responded but no service is accepting connections"
        elif state_upper == "FILTERED":
            exposure_desc = "Port appears filtered — packets dropped/blocked by firewall or network filter"
        elif state_upper == "UNFILTERED":
            exposure_desc = "Port is reachable, but state is ambiguous from available response"
        else:
            exposure_desc = f"Port is in {state_upper} state"

        return {
            "service": svc_name,
            "exposure": exposure_desc,
            "risk": "None",
            "segment": "Non-Reachable",
            "target": f"Port {port} ({svc_name})",
            "review": "No active exposure observed — no immediate configuration review required"
        }

    # If state is OPEN:
    if port in LEVEL1_SERVICE_GUIDANCE:
        guidance = LEVEL1_SERVICE_GUIDANCE[port].copy()
        return guidance

    # Other open ports:
    return {
        "service": svc_name,
        "exposure": f"Reachable {svc_name} service — requires configuration and access-control review",
        "risk": "Low" if port in [8501, 8080, 8000] else "Medium",
        "segment": "Unassigned Segment",
        "target": f"Port {port} Listener",
        "review": "Reachable service — review network permissions and access control policy"
    }
