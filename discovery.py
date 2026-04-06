"""
discovery.py — mDNS peer discovery for p2pshare.

Service type : _cisc468._tcp.local.
Service name : <first 16 hex chars of fingerprint>._cisc468._tcp.local.
TXT record   : fingerprint=<full 64-char hex fingerprint>
"""

import socket
import time
import logging
from typing import List, Dict, Optional

log = logging.getLogger(__name__)

SERVICE_TYPE = "_cisc468._tcp.local."


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


class MDNSAdvertiser:
    """Advertises this peer on the LAN via mDNS."""

    def __init__(self, fingerprint: str, port: int):
        self._fingerprint = fingerprint
        self._port = port
        self._zeroconf = None
        self._info = None

    def start(self):
        try:
            from zeroconf import Zeroconf, ServiceInfo
            ip = _get_local_ip()
            # Service name: first 16 hex chars of fingerprint
            service_name = self._fingerprint[:16]
            full_name = f"{service_name}.{SERVICE_TYPE}"
            self._info = ServiceInfo(
                SERVICE_TYPE,
                full_name,
                addresses=[socket.inet_aton(ip)],
                port=self._port,
                properties={
                    "fingerprint": self._fingerprint,
                    "version": "1",
                },
                server=f"{socket.gethostname()}.local.",
            )
            self._zeroconf = Zeroconf(interfaces=[ip])
            self._zeroconf.register_service(self._info)
            log.info(f"mDNS: advertising {full_name} at {ip}:{self._port}")
        except ImportError:
            log.warning("zeroconf not installed — mDNS advertisement disabled")
        except Exception as e:
            log.warning(f"mDNS advertisement failed: {e}")

    def stop(self):
        if self._zeroconf and self._info:
            try:
                self._zeroconf.unregister_service(self._info)
                self._zeroconf.close()
            except Exception:
                pass


def discover_peers(timeout: float = 5.0) -> List[Dict]:
    """
    Browse for p2pshare peers on the LAN.
    Returns list of {host, port, fingerprint} dicts.
    """
    try:
        from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange
    except ImportError:
        print("[ERROR] zeroconf not installed. Install with: pip install zeroconf")
        return []

    found: List[Dict] = []

    def on_change(zeroconf, service_type, name, state_change):
        if state_change == ServiceStateChange.Added:
            info = zeroconf.get_service_info(service_type, name)
            if info:
                try:
                    addr = socket.inet_ntoa(info.addresses[0])
                    port = info.port
                    props = info.properties or {}
                    fp_raw = props.get(b"fingerprint") or props.get("fingerprint", b"")
                    fp = fp_raw.decode() if isinstance(fp_raw, bytes) else fp_raw
                    found.append({"host": addr, "port": port, "fingerprint": fp})
                except Exception as e:
                    log.debug(f"mDNS parse error: {e}")

    zc = Zeroconf()
    browser = ServiceBrowser(zc, SERVICE_TYPE, handlers=[on_change])
    time.sleep(timeout)
    zc.close()
    return found
