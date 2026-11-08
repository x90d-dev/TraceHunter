import hashlib
import os
import platform
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

from core.i18n import get_text

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore


# Canonical Windows system binary locations (normalized lowercase paths)
CANONICAL_WINDOWS_BINARIES: Dict[str, List[str]] = {
    "svchost.exe": [r"c:\windows\system32\svchost.exe", r"c:\windows\syswow64\svchost.exe"],
    "explorer.exe": [r"c:\windows\explorer.exe", r"c:\windows\syswow64\explorer.exe"],
    "lsass.exe": [r"c:\windows\system32\lsass.exe"],
    "services.exe": [r"c:\windows\system32\services.exe"],
    "wininit.exe": [r"c:\windows\system32\wininit.exe"],
    "winlogon.exe": [r"c:\windows\system32\winlogon.exe"],
    "csrss.exe": [r"c:\windows\system32\csrss.exe"],
    "smss.exe": [r"c:\windows\system32\smss.exe"],
    "taskhostw.exe": [r"c:\windows\system32\taskhostw.exe"],
    "spoolsv.exe": [r"c:\windows\system32\spoolsv.exe"],
    "dllhost.exe": [r"c:\windows\system32\dllhost.exe", r"c:\windows\syswow64\dllhost.exe"],
    "conhost.exe": [r"c:\windows\system32\conhost.exe"],
    "RuntimeBroker.exe": [r"c:\windows\system32\runtimebroker.exe"],
}

CANONICAL_POSIX_BINARIES: Dict[str, List[str]] = {
    "sshd": ["/usr/sbin/sshd", "/sbin/sshd"],
    "cron": ["/usr/sbin/cron", "/sbin/cron", "/usr/bin/cron"],
    "systemd": ["/lib/systemd/systemd", "/usr/lib/systemd/systemd", "/sbin/init"],
}

SUSPICIOUS_PARENT_CHILD_RULES: Dict[str, Set[str]] = {
    "winword.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"},
    "excel.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"},
    "powerpnt.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"},
    "outlook.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "acrord32.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "acrobat.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "chrome.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "msedge.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "firefox.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "brave.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "w3wp.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "net1.exe", "systeminfo.exe"},
    "httpd.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe"},
    "nginx.exe": {"cmd.exe", "powershell.exe", "pwsh.exe"},
    "tomcat.exe": {"cmd.exe", "powershell.exe", "pwsh.exe"},
    "sqlservr.exe": {"cmd.exe", "powershell.exe", "pwsh.exe"},
    "spoolsv.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe"},
    "lsass.exe": {"cmd.exe", "powershell.exe", "pwsh.exe"},
    "nginx": {"sh", "bash", "dash", "nc", "ncat", "python", "python3", "perl"},
    "apache2": {"sh", "bash", "dash", "nc", "ncat", "python", "python3"},
    "httpd": {"sh", "bash", "dash", "nc", "ncat", "python", "python3"},
    "php-fpm": {"sh", "bash", "dash", "nc", "ncat"},
}
EXPECTED_PARENT_CONSTRAINTS: Dict[str, Set[str]] = {
    "svchost.exe": {"services.exe", "mpcmdrun.exe", "MsMpEng.exe"},
    "lsass.exe": {"wininit.exe"},
    "services.exe": {"wininit.exe"},
}
SUSPICIOUS_EXEC_PATH_MARKERS: Tuple[str, ...] = (
    "\\appdata\\local\\temp",
    "\\windows\\temp",
    "\\users\\public\\",
    "\\programdata\\temp",
    "\\perflogs\\",
    "\\recycler\\",
    "\\$recycle.bin\\",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)


class ProcessEngine:
    """Inspects running processes for masquerading, parent-child anomalies, and binary hashes."""

    def __init__(self, lang: str = "en") -> None:
        self.lang = lang
        self.is_windows = platform.system().lower() == "windows"
        self._hash_cache: Dict[str, str] = {}

    def compute_sha256(self, file_path: str) -> str:
        """Compute SHA-256 hash of an executable binary on disk with caching."""
        if not file_path:
            return "N/A"
        if file_path in self._hash_cache:
            return self._hash_cache[file_path]
        if not os.path.isfile(file_path):
            return "N/A"

        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(chunk)
            digest = sha256_hash.hexdigest()
            self._hash_cache[file_path] = digest
            return digest
        except (PermissionError, OSError):
            return "ACCESS_DENIED"

    def _collect_processes(self) -> List[Dict[str, Any]]:
        """Collect active process list using psutil or OS fallback."""
        processes: List[Dict[str, Any]] = []
        if psutil is not None:
            proc_map: Dict[int, str] = {}
            raw_procs: List[Dict[str, Any]] = []
            for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username"]):
                try:
                    info = proc.info
                    pid = int(info.get("pid") or 0)
                    name = str(info.get("name") or "")
                    proc_map[pid] = name
                    raw_procs.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            for info in raw_procs:
                pid = int(info.get("pid") or 0)
                ppid = int(info.get("ppid") or 0)
                name = str(info.get("name") or "unknown")
                exe = str(info.get("exe") or "")
                cmdline_list = info.get("cmdline") or []
                cmdline = " ".join(cmdline_list) if isinstance(cmdline_list, list) else str(cmdline_list)
                parent_name = proc_map.get(ppid, "unknown")
                processes.append(
                    {
                        "pid": pid,
                        "ppid": ppid,
                        "name": name,
                        "parent_name": parent_name,
                        "exe": exe,
                        "cmdline": cmdline,
                        "username": str(info.get("username") or ""),
                    }
                )
            return processes

        if not self.is_windows and os.path.isdir("/proc"):
            proc_map = {}
            raw_entries = []
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                p_dir = os.path.join("/proc", entry)
                try:
                    with open(os.path.join(p_dir, "comm"), "r", encoding="utf-8", errors="ignore") as f:
                        name = f.read().strip()
                    ppid = 0
                    with open(os.path.join(p_dir, "stat"), "r", encoding="utf-8", errors="ignore") as f:
                        stat_content = f.read()
                        rpar = stat_content.rfind(")")
                        if rpar != -1:
                            fields = stat_content[rpar + 2 :].split()
                            if len(fields) >= 2:
                                ppid = int(fields[1])
                    try:
                        exe = os.readlink(os.path.join(p_dir, "exe"))
                    except OSError:
                        exe = ""
                    try:
                        with open(os.path.join(p_dir, "cmdline"), "rb") as f:
                            cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
                    except OSError:
                        cmdline = ""
                    proc_map[pid] = name
                    raw_entries.append((pid, ppid, name, exe, cmdline))
                except OSError:
                    continue

            for pid, ppid, name, exe, cmdline in raw_entries:
                processes.append(
                    {
                        "pid": pid,
                        "ppid": ppid,
                        "name": name,
                        "parent_name": proc_map.get(ppid, "unknown"),
                        "exe": exe,
                        "cmdline": cmdline,
                        "username": "",
                    }
                )
        elif self.is_windows:
            try:
                cmd = ["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
                if res.returncode == 0 and res.stdout.strip():
                    import json

                    data = json.loads(res.stdout)
                    if isinstance(data, dict):
                        data = [data]
                    proc_map = {int(item.get("ProcessId") or 0): str(item.get("Name") or "") for item in data}
                    for item in data:
                        pid = int(item.get("ProcessId") or 0)
                        ppid = int(item.get("ParentProcessId") or 0)
                        processes.append(
                            {
                                "pid": pid,
                                "ppid": ppid,
                                "name": str(item.get("Name") or ""),
                                "parent_name": proc_map.get(ppid, "unknown"),
                                "exe": str(item.get("ExecutablePath") or ""),
                                "cmdline": str(item.get("CommandLine") or ""),
                                "username": "",
                            }
                        )
            except Exception:
                pass
        return processes

    def _normalize_win_path(self, path: str) -> str:
        """Normalize file system path for case-insensitive comparison."""
        normalized = os.path.normpath(path.strip().strip('"')).lower()
        if normalized.startswith("\\??\\"):
            normalized = normalized[4:]
        system_root = os.environ.get("SystemRoot", r"C:\Windows").lower()
        if normalized.startswith("\\systemroot\\"):
            normalized = normalized.replace("\\systemroot\\", system_root + "\\", 1)
        return normalized

    def inspect_process(self, proc: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate a single process record against masquerading and parent-child rules."""
        findings: List[Dict[str, Any]] = []
        pid = proc["pid"]
        ppid = proc["ppid"]
        name = proc["name"]
        name_lower = name.lower()
        parent_name = proc["parent_name"]
        parent_lower = parent_name.lower()
        exe = proc["exe"]
        cmdline = proc["cmdline"]

        if exe:
            norm_exe = self._normalize_win_path(exe) if self.is_windows else exe.strip()
            canonical_map = CANONICAL_WINDOWS_BINARIES if self.is_windows else CANONICAL_POSIX_BINARIES
            for bin_name, valid_paths in canonical_map.items():
                if name_lower == bin_name.lower():
                    compare_target = norm_exe.lower() if self.is_windows else norm_exe
                    valid_set = {p.lower() if self.is_windows else p for p in valid_paths}
                    if compare_target and compare_target not in valid_set:
                        sha256 = self.compute_sha256(exe)
                        findings.append(
                            {
                                "pid": pid,
                                "ppid": ppid,
                                "process_name": name,
                                "parent_name": parent_name,
                                "exe_path": exe,
                                "cmdline": cmdline,
                                "sha256": sha256,
                                "category": "Process Masquerading",
                                "mitre_id": "T1036.005",
                                "severity": get_text(self.lang, "sev_high"),
                                "description": f"{get_text(self.lang, 'anom_masq_path')} ({exe})",
                            }
                        )

            lower_exe = norm_exe.lower().replace("/", "\\") if self.is_windows else norm_exe.lower()
            for marker in SUSPICIOUS_EXEC_PATH_MARKERS:
                if marker in lower_exe or marker in exe.lower():
                    sha256 = self.compute_sha256(exe)
                    findings.append(
                        {
                            "pid": pid,
                            "ppid": ppid,
                            "process_name": name,
                            "parent_name": parent_name,
                            "exe_path": exe,
                            "cmdline": cmdline,
                            "sha256": sha256,
                            "category": "Suspicious Execution Path",
                            "mitre_id": "T1036",
                            "severity": get_text(self.lang, "sev_high"),
                            "description": f"{get_text(self.lang, 'anom_masq_temp')}: {exe}",
                        }
                    )
                    break

        if parent_lower in SUSPICIOUS_PARENT_CHILD_RULES:
            blocked_children = {c.lower() for c in SUSPICIOUS_PARENT_CHILD_RULES[parent_lower]}
            if name_lower in blocked_children:
                sha256 = self.compute_sha256(exe)
                findings.append(
                    {
                        "pid": pid,
                        "ppid": ppid,
                        "process_name": name,
                        "parent_name": parent_name,
                        "exe_path": exe or cmdline or "N/A",
                        "cmdline": cmdline,
                        "sha256": sha256,
                        "category": "Anomalous Parent-Child Chain",
                        "mitre_id": "T1059",
                        "severity": get_text(self.lang, "sev_high"),
                        "description": f"{get_text(self.lang, 'anom_parent_child')}: {parent_name} (PID {ppid}) -> {name} (PID {pid})",
                    }
                )

        if self.is_windows and name_lower in EXPECTED_PARENT_CONSTRAINTS:
            allowed_parents = {p.lower() for p in EXPECTED_PARENT_CONSTRAINTS[name_lower]}
            if parent_lower not in allowed_parents and parent_lower != "unknown":
                sha256 = self.compute_sha256(exe)
                findings.append(
                    {
                        "pid": pid,
                        "ppid": ppid,
                        "process_name": name,
                        "parent_name": parent_name,
                        "exe_path": exe or "N/A",
                        "cmdline": cmdline,
                        "sha256": sha256,
                        "category": "Unexpected System Parent",
                        "mitre_id": "T1036.005",
                        "severity": get_text(self.lang, "sev_medium"),
                        "description": f"{name} spawned by non-standard parent {parent_name} (PID {ppid})",
                    }
                )

        return findings

    def run_audit(self) -> Dict[str, Any]:
        """Execute full process tree inspection and return structured summary + findings."""
        processes = self._collect_processes()
        all_findings: List[Dict[str, Any]] = []
        process_inventory: List[Dict[str, Any]] = []

        for proc in processes:
            sha256 = self.compute_sha256(proc["exe"]) if proc["exe"] else "N/A"
            process_inventory.append(
                {
                    "pid": proc["pid"],
                    "ppid": proc["ppid"],
                    "process_name": proc["name"],
                    "parent_name": proc["parent_name"],
                    "exe_path": proc["exe"] or "N/A",
                    "cmdline": proc["cmdline"],
                    "sha256": sha256,
                }
            )
            proc_findings = self.inspect_process(proc)
            all_findings.extend(proc_findings)

        return {
            "module": "process_engine",
            "total_inspected": len(processes),
            "anomalies_count": len(all_findings),
            "findings": all_findings,
            "inventory_sample": process_inventory[:25],
        }
