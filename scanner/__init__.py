"""
scanner package - Controlled service discovery for authorized target assessment.
Educational Defensive Cybersecurity Project (Level 1 Scope)
"""

from .validator import validate_target, validate_custom_ports, normalize_target_input
from .scanner import (
    scan_target,
    check_tcp_port,
    QUICK_SCAN_PORTS,
    LEVEL1_PORTS,
    DEFAULT_PORTS,
    EXTENDED_PORTS
)
from .service_map import get_service_name, get_service_exposure_metadata, PORT_SERVICE_MAP

__all__ = [
    "validate_target",
    "validate_custom_ports",
    "normalize_target_input",
    "scan_target",
    "check_tcp_port",
    "QUICK_SCAN_PORTS",
    "LEVEL1_PORTS",
    "DEFAULT_PORTS",
    "EXTENDED_PORTS",
    "get_service_name",
    "get_service_exposure_metadata",
    "PORT_SERVICE_MAP"
]
