"""
scanner.py - Controlled TCP Service Discovery Scanner
HospitalShield Level 1 — Network Exposure Dashboard
Authorized Target Assessment (Educational Defensive Scope)
"""

import socket
import time
import errno
from typing import List, Dict, Any, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd

from .service_map import get_service_name, get_service_exposure_metadata

# Predefined scan profiles
QUICK_SCAN_PORTS: List[int] = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389, 8080]
LEVEL1_PORTS: List[int] = [22, 53, 80, 443, 3389]
DEFAULT_PORTS: List[int] = LEVEL1_PORTS
EXTENDED_PORTS: List[int] = QUICK_SCAN_PORTS

# Common Windows / POSIX errno constants for network states
ERRNO_CONNREFUSED = {errno.ECONNREFUSED, 10061, 111}
ERRNO_TIMEDOUT = {errno.ETIMEDOUT, 10060, 110}
ERRNO_HOSTUNREACH = {getattr(errno, "EHOSTUNREACH", 10065), 10065, 113}
ERRNO_NETUNREACH = {getattr(errno, "ENETUNREACH", 10051), 10051, 101}
ERRNO_ACCES = {getattr(errno, "EACCES", 10013), 10013, 13}
ERRNO_RESET = {getattr(errno, "ECONNRESET", 10054), 10054, 104}


def check_tcp_port(
    target_ip: str,
    port: int,
    timeout: float = 1.0,
    ip_version: str = "IPv4"
) -> Dict[str, Any]:
    """
    Perform a benign, single TCP connect discovery probe on a single port.
    
    States:
        - OPEN: A TCP connection succeeds (SYN-ACK received, handshake complete).
        - CLOSED: Target host is reachable but port is not accepting connections (RST received).
        - FILTERED: Packets appeared dropped or blocked by firewall/filter (timeout or host/net unreachable).
        - UNFILTERED: Port is reachable, but open/closed state cannot be determined reliably from available response.
    
    Returns structured result dict:
        {
            "port": int,
            "protocol": "TCP",
            "state": "OPEN" | "CLOSED" | "FILTERED" | "UNFILTERED",
            "response_time": str (e.g. "35 ms", "-", "timeout"),
            "response_time_ms": float or None
        }
    """
    sock = None
    family = socket.AF_INET6 if ip_version == "IPv6" or ":" in target_ip else socket.AF_INET
    start_time = time.perf_counter()

    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "port": port,
            "protocol": "TCP",
            "state": "OPEN",
            "response_time": f"{elapsed_ms:.0f} ms",
            "response_time_ms": round(elapsed_ms, 1)
        }

    except ConnectionRefusedError:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return {
            "port": port,
            "protocol": "TCP",
            "state": "CLOSED",
            "response_time": f"{elapsed_ms:.0f} ms" if elapsed_ms < (timeout * 1000 * 0.95) else "-",
            "response_time_ms": round(elapsed_ms, 1)
        }
    except (socket.timeout, TimeoutError):
        return {
            "port": port,
            "protocol": "TCP",
            "state": "FILTERED",
            "response_time": "timeout",
            "response_time_ms": None
        }
    except OSError as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        err = getattr(e, "errno", None) or getattr(e, "winerror", None)

        if err in ERRNO_CONNREFUSED:
            return {
                "port": port,
                "protocol": "TCP",
                "state": "CLOSED",
                "response_time": f"{elapsed_ms:.0f} ms" if elapsed_ms < (timeout * 1000 * 0.95) else "-",
                "response_time_ms": round(elapsed_ms, 1)
            }
        elif err in ERRNO_TIMEDOUT:
            return {
                "port": port,
                "protocol": "TCP",
                "state": "FILTERED",
                "response_time": "timeout",
                "response_time_ms": None
            }
        elif err in ERRNO_HOSTUNREACH or err in ERRNO_NETUNREACH or err in ERRNO_ACCES:
            return {
                "port": port,
                "protocol": "TCP",
                "state": "FILTERED",
                "response_time": "filtered",
                "response_time_ms": None
            }
        elif err in ERRNO_RESET:
            return {
                "port": port,
                "protocol": "TCP",
                "state": "UNFILTERED",
                "response_time": f"{elapsed_ms:.0f} ms",
                "response_time_ms": round(elapsed_ms, 1)
            }
        else:
            return {
                "port": port,
                "protocol": "TCP",
                "state": "UNFILTERED",
                "response_time": "-",
                "response_time_ms": None
            }
    except Exception:
        return {
            "port": port,
            "protocol": "TCP",
            "state": "FILTERED",
            "response_time": "error",
            "response_time_ms": None
        }
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def scan_target(
    target_ip: str,
    ports: Optional[List[int]] = None,
    timeout: float = 0.8,
    ip_version: str = "IPv4",
    max_workers: int = 8,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> pd.DataFrame:
    """
    Perform controlled TCP service discovery against an authorized target.
    Uses modest concurrency and polite rate limiting to prevent network flooding.

    Args:
        target_ip: Validated IP address of the target.
        ports: List of TCP ports to inspect (defaults to LEVEL1_PORTS).
        timeout: Socket timeout in seconds per port.
        ip_version: 'IPv4' or 'IPv6'.
        max_workers: Concurrency limit (default 8).
        progress_callback: Optional callback receiving (completed_count, total_count).

    Returns:
        pd.DataFrame with schema:
            ['port', 'protocol', 'state', 'service', 'response_time',
             'response_time_ms', 'exposure', 'risk', 'segment', 'target']
    """
    if ports is None:
        ports = LEVEL1_PORTS

    sorted_ports = sorted(list(set(ports)))
    total_ports = len(sorted_ports)
    results = []

    if total_ports == 0:
        return pd.DataFrame(columns=[
            "port", "protocol", "state", "service", "response_time",
            "response_time_ms", "exposure", "risk", "segment", "target"
        ])

    completed = 0

    with ThreadPoolExecutor(max_workers=min(max_workers, total_ports)) as executor:
        future_to_port = {
            executor.submit(check_tcp_port, target_ip, p, timeout, ip_version): p
            for p in sorted_ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                probe_res = future.result()
            except Exception:
                probe_res = {
                    "port": port,
                    "protocol": "TCP",
                    "state": "FILTERED",
                    "response_time": "error",
                    "response_time_ms": None
                }

            # Enrich with service map and defensive Level 1 exposure metadata
            meta = get_service_exposure_metadata(port, probe_res["state"])

            record = {
                "port": int(port),
                "protocol": "TCP",
                "state": probe_res["state"],  # OPEN, CLOSED, FILTERED, UNFILTERED
                "service": meta["service"],
                "response_time": probe_res["response_time"],
                "response_time_ms": probe_res["response_time_ms"],
                "exposure": meta["exposure"],
                "risk": meta["risk"],
                "segment": meta["segment"],
                "target": meta["target"]
            }
            results.append(record)
            completed += 1

            if progress_callback:
                progress_callback(completed, total_ports)

    # Sort results by port ascending
    results.sort(key=lambda x: x["port"])
    df = pd.DataFrame(results)

    return df
