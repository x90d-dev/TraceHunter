import ipaddress
import os
import platform
import socket
import subprocess
from typing import Any, Dict, List, Set, Tuple

from core.i18n import get_text

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

COMMONLY_ABUSED_PORTS: Set[int] = {
    4444,
    4445,
    5555,
    1337,
    31337,
    6667,
    6697,
    8443,
    9001,
    9050,
    3389,
    5985,
    5986,
}


class NetworkCorrelator:
    """Correlates active network sockets with host processes and classifies IP scope."""

    def __init__(self, lang: str = "en") -> None:
        self.lang = lang
        self.is_windows = platform.system().lower() == "windows"

    def classify_ip_scope(self, ip_str: str) -> Tuple[str, str, bool]:
        """
        Classify IP address into PUBLIC (Non-RFC1918), PRIVATE (RFC1918),
        LOOPBACK, or LISTENING.
        """
        if not ip_str or ip_str in ("*", "0.0.0.0", "::", "-"):
            return "LISTEN", get_text(self.lang, "scope_listen"), False

        # Strip zone index if IPv6 (e.g. fe80::1%eth0)
        clean_ip = ip_str.split("%")[0].strip("[]")
        try:
            addr = ipaddress.ip_address(clean_ip)
            if addr.is_loopback:
                return "LOOPBACK", get_text(self.lang, "scope_loopback"), False
            if addr.is_private or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
                return "PRIVATE", get_text(self.lang, "scope_private"), False
            if addr.is_global:
                return "PUBLIC", get_text(self.lang, "scope_public"), True
            return "PRIVATE", get_text(self.lang, "scope_private"), False
        except ValueError:
            return "UNKNOWN", "UNKNOWN", False

    def _get_process_metadata(self, pid: int) -> Dict[str, str]:
        """Resolve process name and executable path from PID."""
        if not pid or pid <= 0:
            return {"name": "System/Kernel", "exe": "N/A"}

        if psutil is not None:
            try:
                proc = psutil.Process(pid)
                return {
                    "name": proc.name() or "unknown",
                    "exe": proc.exe() or "N/A",
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                return {"name": f"PID-{pid}", "exe": "ACCESS_DENIED"}

        if not self.is_windows and os.path.isdir(f"/proc/{pid}"):
            name = f"PID-{pid}"
            exe = "N/A"
            try:
                with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="ignore") as f:
                    name = f.read().strip()
            except OSError:
                pass
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                pass
            return {"name": name, "exe": exe}

        return {"name": f"PID-{pid}", "exe": "N/A"}

    def _collect_sockets(self) -> List[Dict[str, Any]]:
        """Collect active TCP and UDP connections via psutil or OS fallback."""
        connections: List[Dict[str, Any]] = []

        if psutil is not None:
            try:
                net_conns = psutil.net_connections(kind="inet")
                for conn in net_conns:
                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    laddr_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
                    laddr_port = conn.laddr.port if conn.laddr else 0
                    raddr_ip = conn.raddr.ip if conn.raddr else ""
                    raddr_port = conn.raddr.port if conn.raddr else 0
                    pid = int(conn.pid or 0)
                    meta = self._get_process_metadata(pid)
                    connections.append(
                        {
                            "protocol": proto,
                            "local_ip": laddr_ip,
                            "local_port": laddr_port,
                            "remote_ip": raddr_ip,
                            "remote_port": raddr_port,
                            "state": str(conn.status or "NONE"),
                            "pid": pid,
                            "process_name": meta["name"],
                            "exe_path": meta["exe"],
                        }
                    )
                return connections
            except (psutil.AccessDenied, OSError):
                pass

        # Fallback for Windows using netstat -ano
        if self.is_windows:
            try:
                res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=15, check=False)
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 4 and parts[0].upper() in ("TCP", "UDP"):
                            proto = parts[0].upper()
                            laddr = parts[1]
                            raddr = parts[2]
                            if proto == "TCP" and len(parts) >= 5:
                                state = parts[3]
                                pid = int(parts[4]) if parts[4].isdigit() else 0
                            else:
                                state = "STATELESS"
                                pid = int(parts[3]) if parts[3].isdigit() else 0
                            l_ip, _, l_port = laddr.rpartition(":")
                            r_ip, _, r_port = raddr.rpartition(":")
                            meta = self._get_process_metadata(pid)
                            connections.append(
                                {
                                    "protocol": proto,
                                    "local_ip": l_ip.strip("[]"),
                                    "local_port": int(l_port) if l_port.isdigit() else 0,
                                    "remote_ip": "" if r_ip in ("*", "0.0.0.0") else r_ip.strip("[]"),
                                    "remote_port": int(r_port) if r_port.isdigit() else 0,
                                    "state": state,
                                    "pid": pid,
                                    "process_name": meta["name"],
                                    "exe_path": meta["exe"],
                                }
                            )
            except Exception:
                pass
        else:
            # Fallback for Linux /proc/net/tcp and /proc/net/udp
            connections.extend(self._parse_proc_net("/proc/net/tcp", "TCP"))
            connections.extend(self._parse_proc_net("/proc/net/udp", "UDP"))

        return connections

    def _parse_proc_net(self, path: str, proto: str) -> List[Dict[str, Any]]:
        """Parse Linux /proc/net/{tcp,udp} socket tables and correlate inode to PID."""
        results: List[Dict[str, Any]] = []
        if not os.path.isfile(path):
            return results

        # Map socket inode -> pid
        inode_to_pid: Dict[str, int] = {}
        if os.path.isdir("/proc"):
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                fd_dir = f"/proc/{entry}/fd"
                try:
                    for fd in os.listdir(fd_dir):
                        target = os.readlink(os.path.join(fd_dir, fd))
                        if target.startswith("socket:[") and target.endswith("]"):
                            inode = target[8:-1]
                            inode_to_pid[inode] = pid
                except OSError:
                    continue

        tcp_states = {
            "01": "ESTABLISHED",
            "02": "SYN_SENT",
            "03": "SYN_RECV",
            "04": "FIN_WAIT1",
            "05": "FIN_WAIT2",
            "06": "TIME_WAIT",
            "07": "CLOSE",
            "08": "CLOSE_WAIT",
            "09": "LAST_ACK",
            "0A": "LISTEN",
            "0B": "CLOSING",
        }

        def hex_to_ip_port(hex_str: str) -> tuple[str, int]:
            ip_hex, port_hex = hex_str.split(":")
            port = int(port_hex, 16)
            ip_int = int(ip_hex, 16)
            ip = socket.inet_ntoa(ip_int.to_bytes(4, byteorder="little"))
            return ip, port

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    l_ip, l_port = hex_to_ip_port(parts[1])
                    r_ip, r_port = hex_to_ip_port(parts[2])
                    state = tcp_states.get(parts[3].upper(), "UNKNOWN")
                    inode = parts[9]
                    pid = inode_to_pid.get(inode, 0)
                    meta = self._get_process_metadata(pid)
                    results.append(
                        {
                            "protocol": proto,
                            "local_ip": l_ip,
                            "local_port": l_port,
                            "remote_ip": "" if r_ip == "0.0.0.0" else r_ip,
                            "remote_port": r_port,
                            "state": state,
                            "pid": pid,
                            "process_name": meta["name"],
                            "exe_path": meta["exe"],
                        }
                    )
        except OSError:
            pass

        return results

    def run_audit(self) -> Dict[str, Any]:
        """Inspect active sockets, correlate to processes, and flag external/suspicious connections."""
        raw_sockets = self._collect_sockets()
        enriched_sockets: List[Dict[str, Any]] = []
        flagged_findings: List[Dict[str, Any]] = []

        for sock in raw_sockets:
            remote_ip = sock["remote_ip"]
            remote_port = sock["remote_port"]
            local_port = sock["local_port"]
            scope_code, scope_label, is_public = self.classify_ip_scope(remote_ip)

            laddr_fmt = f"{sock['local_ip']}:{local_port}"
            raddr_fmt = f"{remote_ip}:{remote_port}" if remote_ip else "*:*"

            severity = get_text(self.lang, "sev_info")
            notes = scope_label
            is_flagged = False

            if is_public:
                severity = get_text(self.lang, "sev_high") if remote_port in COMMONLY_ABUSED_PORTS else get_text(self.lang, "sev_medium")
                notes = get_text(self.lang, "anom_external_conn")
                is_flagged = True
            elif remote_port in COMMONLY_ABUSED_PORTS or local_port in COMMONLY_ABUSED_PORTS:
                severity = get_text(self.lang, "sev_medium")
                notes = get_text(self.lang, "anom_susp_port")
                is_flagged = True

            record = {
                "pid": sock["pid"],
                "process_name": sock["process_name"],
                "exe_path": sock["exe_path"],
                "protocol": sock["protocol"],
                "local_address": laddr_fmt,
                "remote_address": raddr_fmt,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": sock["state"],
                "scope_code": scope_code,
                "scope": scope_label,
                "is_public_non_rfc1918": is_public,
                "mitre_id": "T1049",
                "severity": severity,
                "description": notes,
            }
            enriched_sockets.append(record)
            if is_flagged:
                flagged_findings.append(record)

        return {
            "module": "network_correlator",
            "total_inspected": len(enriched_sockets),
            "anomalies_count": len(flagged_findings),
            "findings": flagged_findings,
            "all_sockets": enriched_sockets,
        }


