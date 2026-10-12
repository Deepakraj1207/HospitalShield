"""
validator.py - Target input validation, URL normalization, and port range validation
HospitalShield Level 1 — Network Exposure Dashboard
"""

import socket
import ipaddress
import urllib.parse
import re
from typing import Tuple, List, Optional, Dict, Any


def normalize_target_input(raw_input: str) -> Dict[str, str]:
    """
    Extract and normalize the host portion from an IP, hostname, or URL.
    Preserves the original input for separate display.

    Returns:
        dict containing:
            - 'raw': original user input
            - 'host': extracted and normalized host (lowercase, no port/path)
            - 'is_url': whether input had a URL scheme or format
    """
    cleaned = raw_input.strip()
    if not cleaned:
        return {"raw": "", "host": "", "is_url": False}

    is_url = False

    # Check if a URL scheme is present (e.g. http://, https://) or protocol-relative (//)
    if "://" in cleaned or cleaned.startswith("//"):
        is_url = True
        try:
            url_to_parse = cleaned if "://" in cleaned else f"http:{cleaned}"
            parsed = urllib.parse.urlparse(url_to_parse)
            hostname = parsed.hostname
            if hostname:
                return {
                    "raw": cleaned,
                    "host": hostname.strip().lower(),
                    "is_url": True
                }
        except Exception:
            pass

    # If it contains slashes like example.com/path, treat as URL without scheme
    if "/" in cleaned:
        is_url = True
        cleaned_no_path = cleaned.split("/")[0]
    else:
        cleaned_no_path = cleaned

    # Check for host:port format (avoiding IPv6 colons)
    if ":" in cleaned_no_path:
        # IPv6 enclosed in brackets [::1]:80 or raw ::1
        if cleaned_no_path.startswith("[") and "]" in cleaned_no_path:
            host_part = cleaned_no_path[1:cleaned_no_path.index("]")]
            return {
                "raw": cleaned,
                "host": host_part.strip().lower(),
                "is_url": is_url
            }
        elif cleaned_no_path.count(":") == 1:
            # Single colon indicates host:port
            cleaned_no_path = cleaned_no_path.split(":")[0]

    # Clean any trailing characters and lowercase
    final_host = cleaned_no_path.rstrip("/").strip().lower()

    return {
        "raw": cleaned,
        "host": final_host,
        "is_url": is_url
    }


def is_valid_ip(ip_str: str) -> Tuple[bool, Optional[str]]:
    """Check whether a string is a valid IPv4 or IPv6 address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        ip_type = "IPv6" if isinstance(ip_obj, ipaddress.IPv6Address) else "IPv4"
        return True, ip_type
    except ValueError:
        return False, None


def is_valid_hostname(hostname: str) -> bool:
    """
    Validate hostname syntax according to RFC 1123.
    """
    if not hostname or len(hostname) > 253:
        return False
    if hostname == "localhost":
        return True
    
    # Strip trailing dot if present (FQDN)
    if hostname.endswith("."):
        hostname = hostname[:-1]
        
    allowed = re.compile(r"^(?!-)[A-Za-z0-9-_]{1,63}(?<!-)$")
    return all(allowed.match(label) for label in hostname.split("."))


def validate_target(target_input: str) -> Tuple[bool, Dict[str, Any], str]:
    """
    Validates, normalizes, and resolves target input.

    Returns:
        Tuple[bool, Dict[str, Any], str]:
            - is_valid (bool): True if target is syntactically valid and resolvable.
            - target_meta (dict): {
                'raw': raw_input,
                'host': normalized_host,
                'resolved_ip': resolved_ip,
                'ip_version': 'IPv4' | 'IPv6',
                'is_url': bool
              }
            - message (str): Human-readable status or error explanation.
    """
    if not target_input or not target_input.strip():
        return False, {}, "Target input cannot be empty. Please enter an IP address, hostname, or URL."

    norm = normalize_target_input(target_input)
    normalized_host = norm["host"]

    if not normalized_host:
        return False, {}, f"Could not extract a valid host from input '{target_input}'."

    # Check if host is direct IP
    is_ip, ip_type = is_valid_ip(normalized_host)
    
    resolved_ip = ""
    ip_version = ip_type or "IPv4"

    if is_ip:
        resolved_ip = normalized_host
    else:
        # Check hostname syntax
        if not is_valid_hostname(normalized_host):
            return False, {}, (
                f"Invalid target format: '{normalized_host}' is neither a valid IP address "
                "nor a valid hostname."
            )

        # Resolve via DNS
        try:
            # socket.getaddrinfo handles both IPv4 and IPv6
            addr_info = socket.getaddrinfo(normalized_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if not addr_info:
                return False, {}, f"DNS resolution yielded no addresses for '{normalized_host}'."
            
            # Prefer IPv4 for standard scanning if available
            ipv4_addrs = [ai[4][0] for ai in addr_info if ai[0] == socket.AF_INET]
            ipv6_addrs = [ai[4][0] for ai in addr_info if ai[0] == socket.AF_INET6]

            if ipv4_addrs:
                resolved_ip = ipv4_addrs[0]
                ip_version = "IPv4"
            elif ipv6_addrs:
                resolved_ip = ipv6_addrs[0]
                ip_version = "IPv6"
            else:
                resolved_ip = addr_info[0][4][0]
                ip_version = "IPv4"
        except socket.gaierror:
            return False, {}, (
                f"Unable to resolve host '{normalized_host}'. "
                "Verify network connection, DNS settings, and target spelling."
            )
        except Exception as e:
            return False, {}, f"Resolution error for '{normalized_host}': {str(e)}"

    target_meta = {
        "raw": norm["raw"],
        "host": normalized_host,
        "resolved_ip": resolved_ip,
        "ip_version": ip_version,
        "is_url": norm["is_url"]
    }

    return True, target_meta, f"Target '{normalized_host}' ({resolved_ip}) validated successfully."


def validate_custom_ports(port_input: str, max_ports: int = 50) -> Tuple[bool, List[int], str]:
    """
    Validate a comma-separated list of custom TCP ports.

    Requirements:
    - Integer only
    - Range 1-65535
    - Reasonable maximum number of ports (default 50)
    - Reject invalid input

    Returns:
        Tuple[bool, List[int], str]:
            - is_valid: bool
            - ports: List[int]
            - message: status or error message
    """
    if not port_input or not port_input.strip():
        return False, [], "Custom port list cannot be empty. Enter comma-separated port numbers (e.g., 22, 80, 443)."

    parts = [p.strip() for p in port_input.split(",") if p.strip()]
    if not parts:
        return False, [], "No valid port numbers provided in custom port input."

    if len(parts) > max_ports:
        return False, [], f"Too many ports specified ({len(parts)}). Maximum allowed is {max_ports} ports to avoid excessive network traffic."

    valid_ports = []
    seen = set()

    for p_str in parts:
        if not p_str.isdigit():
            return False, [], f"Invalid port '{p_str}'. Ports must be positive integers."
        
        p_int = int(p_str)
        if not (1 <= p_int <= 65535):
            return False, [], f"Port {p_int} out of range. TCP ports must be between 1 and 65535."
        
        if p_int not in seen:
            seen.add(p_int)
            valid_ports.append(p_int)

    if not valid_ports:
        return False, [], "No valid ports found."

    return True, sorted(valid_ports), f"Validated {len(valid_ports)} custom port(s)."
