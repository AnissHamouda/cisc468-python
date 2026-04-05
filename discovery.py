"""
mDNS peer discovery using python-zeroconf.
"""

import socket
import time
import logging
from typing import List, Tuple, Optional

log = logging.getLogger(__name__)

SERVICE_TYPE = "_p2pshare._tcp.local."


def get_local_ip() -> str:
    """Best-effort local LAN IP detection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def advertise_service(identity_fingerprint: str, port: int):
    """
    Register this node as a p2pshare service via mDNS.
    Returns the (Zeroconf, ServiceInfo) tuple so the caller can unregister later.
    """
    try:
        from zeroconf import Zeroconf, ServiceInfo
    except ImportError:
        raise ImportError("zeroconf package is required. Install with: pip install zeroconf")

    local_ip = get_local_ip()
    safe_fp = identity_fingerprint.replace(":", "")
    name = f"{safe_fp}.{SERVICE_TYPE}"
    info = ServiceInfo(
        SERVICE_TYPE,
        name,
        addresses=[socket.inet_aton(local_ip)],
        port=port,
        properties={
            "fingerprint": identity_fingerprint,
            "version": "1",
        },
        server=f"{socket.gethostname()}.local.",
    )
    zc = Zeroconf(interfaces=[local_ip])
    zc.register_service(info)
    log.info(f"Registered mDNS service: {name} at {local_ip}:{port}")
    return zc, info


def discover_peers(timeout: float = 5.0) -> List[dict]:
    """
    Browse for p2pshare peers on the LAN.
    Returns list of dicts: {host, port, fingerprint}
    """
    try:
        from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange
    except ImportError:
        raise ImportError("zeroconf package is required. Install with: pip install zeroconf")

    found = []

    def on_change(zeroconf, service_type, name, state_change):
        if state_change == ServiceStateChange.Added:
            info = zeroconf.get_service_info(service_type, name)
            if info:
                addr = socket.inet_ntoa(info.addresses[0]) if info.addresses else "?"
                port = info.port
                fp = info.properties.get(b"fingerprint", b"").decode()
                found.append({"host": addr, "port": port, "fingerprint": fp})

    zc = Zeroconf()
    browser = ServiceBrowser(zc, SERVICE_TYPE, handlers=[on_change])
    time.sleep(timeout)
    zc.close()
    return found
