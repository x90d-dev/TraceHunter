import csv
import io
import os
import platform
import re
import subprocess
from typing import Any, Dict, List, Tuple

from core.i18n import get_text

try:
    import winreg
except ImportError:
    winreg = None  # type: ignore


SUSPICIOUS_PERSISTENCE_PATHS: Tuple[str, ...] = (
    "\\appdata\\local\\temp",
    "\\appdata\\roaming\\",
    "\\users\\public\\",
    "\\windows\\temp",
    "\\programdata\\",
    "powershell",
    "cmd.exe /c",
    "mshta",
    "wscript",
    "cscript",
    "regsvr32",
    "rundll32",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)

STANDARD_WINDOWS_TASK_PREFIXES: Tuple[str, ...] = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\program files",
    r"c:\program files (x86)",
    r"%windir%",
    r"%systemroot%",
    r"%programfiles%",
)


class PersistenceEngine:
    """Scans system persistence mechanisms and flags anomalous or insecure configurations."""

    def __init__(self, lang: str = "en") -> None:
        self.lang = lang
        self.is_windows = platform.system().lower() == "windows"

    @staticmethod
    def is_unquoted_service_path(image_path: str) -> bool:
        """
        Determine whether a Windows service ImagePath contains spaces in the executable
        path without enclosing quotes, creating a path interception risk (MITRE T1574.009).
        """
        if not image_path:
            return False
        cleaned = image_path.strip()
        if not cleaned or cleaned.startswith('"') or cleaned.startswith("'"):
            return False

        lower = cleaned.lower()
        # Exclude standard driver paths without drive letters
        if lower.startswith("\\systemroot\\") or lower.startswith("system32\\") or lower.startswith("\\??\\"):
            return False

        # Match executable boundary (.exe or .sys)
        match = re.search(r"^([a-zA-Z]:\\[^\"']*?\.(?:exe|sys))(?:\s|$)", cleaned, re.IGNORECASE)
        if match:
            exe_segment = match.group(1)
            return " " in exe_segment
        return False

    def _classify_target_severity(self, target_cmd: str) -> Tuple[str, str]:
        """Classify severity and technical description of a persistence target command."""
        lower_cmd = target_cmd.lower()
        for marker in SUSPICIOUS_PERSISTENCE_PATHS:
            if marker in lower_cmd:
                return (
                    get_text(self.lang, "sev_high"),
                    get_text(self.lang, "anom_autorun_temp"),
                )
        return (
            get_text(self.lang, "sev_info"),
            get_text(self.lang, "anom_autorun_entry"),
        )

    def scan_registry_autoruns(self) -> Tuple[int, List[Dict[str, Any]]]:
        """Scan HKCU and HKLM Run and RunOnce keys on Windows (MITRE T1547.001)."""
        findings: List[Dict[str, Any]] = []
        inspected_count = 0

        if not self.is_windows or winreg is None:
            return inspected_count, findings

        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\WOW6432Node\\...\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\WOW6432Node\\...\\RunOnce"),
        ]

        for hive, subkey_path, short_loc in run_keys:
            try:
                with winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ) as key:
                    index = 0
                    while True:
                        try:
                            value_name, value_data, _ = winreg.EnumValue(key, index)
                            index += 1
                            inspected_count += 1
                            target_str = str(value_data)
                            severity, desc = self._classify_target_severity(target_str)
                            findings.append(
                                {
                                    "mechanism": "Registry Run Key",
                                    "entry_name": str(value_name),
                                    "target": target_str,
                                    "location": short_loc,
                                    "mitre_id": "T1547.001",
                                    "severity": severity,
                                    "description": desc,
                                }
                            )
                        except OSError:
                            break
            except OSError:
                continue

        return inspected_count, findings

    def scan_startup_directories(self) -> Tuple[int, List[Dict[str, Any]]]:
        """Inspect user and system Startup folders (MITRE T1547.001)."""
        findings: List[Dict[str, Any]] = []
        inspected_count = 0
        startup_dirs: List[str] = []

        if self.is_windows:
            appdata = os.environ.get("APPDATA", "")
            programdata = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
            if appdata:
                startup_dirs.append(os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
            if programdata:
                startup_dirs.append(os.path.join(programdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
        else:
            home = os.path.expanduser("~")
            startup_dirs.extend(
                [
                    os.path.join(home, ".config", "autostart"),
                    "/etc/xdg/autostart",
                    "/etc/rc.local",
                ]
            )

        for folder in startup_dirs:
            if os.path.isfile(folder):
                inspected_count += 1
                continue
            if not os.path.isdir(folder):
                continue
            try:
                for entry in os.listdir(folder):
                    if entry.lower() == "desktop.ini":
                        continue
                    full_path = os.path.join(folder, entry)
                    inspected_count += 1
                    severity, desc = self._classify_target_severity(full_path)
                    if severity == get_text(self.lang, "sev_info"):
                        severity = get_text(self.lang, "sev_medium")
                    findings.append(
                        {
                            "mechanism": "Startup Folder",
                            "entry_name": entry,
                            "target": full_path,
                            "location": folder,
                            "mitre_id": "T1547.001",
                            "severity": severity,
                            "description": desc,
                        }
                    )
            except OSError:
                continue

        return inspected_count, findings

    def scan_scheduled_tasks(self) -> Tuple[int, List[Dict[str, Any]]]:
        """Identify Scheduled Tasks executing binaries from non-system paths (MITRE T1053.005)."""
        findings: List[Dict[str, Any]] = []
        inspected_count = 0

        if self.is_windows:
            try:
                cmd = ["schtasks", "/query", "/fo", "CSV", "/v"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False, errors="ignore")
                if res.returncode == 0 and res.stdout.strip():
                    reader = csv.DictReader(io.StringIO(res.stdout))
                    seen_tasks = set()
                    for row in reader:
                        task_name = row.get("TaskName") or row.get("HostName") or ""
                        task_run = row.get("Task To Run") or ""
                        if not task_name or task_name == "TaskName" or task_name in seen_tasks:
                            continue
                        seen_tasks.add(task_name)
                        inspected_count += 1

                        cleaned_run = task_run.strip().strip('"').lower()
                        if not cleaned_run or cleaned_run in ("n/a", "com handler", "custom handler"):
                            continue

                        is_standard = any(cleaned_run.startswith(prefix) for prefix in STANDARD_WINDOWS_TASK_PREFIXES)
                        has_suspicious_marker = any(m in cleaned_run for m in SUSPICIOUS_PERSISTENCE_PATHS)

                        if has_suspicious_marker or not is_standard:
                            sev = get_text(self.lang, "sev_high") if has_suspicious_marker else get_text(self.lang, "sev_medium")
                            findings.append(
                                {
                                    "mechanism": "Scheduled Task",
                                    "entry_name": task_name,
                                    "target": task_run.strip(),
                                    "location": "Windows Task Scheduler",
                                    "mitre_id": "T1053.005",
                                    "severity": sev,
                                    "description": get_text(self.lang, "anom_non_std_task"),
                                }
                            )
            except Exception:
                pass
        else:
            # Inspect POSIX cron directories for non-standard script execution
            cron_paths = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"]
            for cpath in cron_paths:
                if os.path.isfile(cpath):
                    inspected_count += 1
                    try:
                        with open(cpath, "r", encoding="utf-8", errors="ignore") as f:
                            for line_no, line in enumerate(f, 1):
                                stripped = line.strip()
                                if not stripped or stripped.startswith("#"):
                                    continue
                                if any(m in stripped.lower() for m in ("/tmp/", "/var/tmp/", "/dev/shm/", "curl ", "wget ")):
                                    findings.append(
                                        {
                                            "mechanism": "Scheduled Cron Task",
                                            "entry_name": f"{os.path.basename(cpath)}:{line_no}",
                                            "target": stripped,
                                            "location": cpath,
                                            "mitre_id": "T1053.003",
                                            "severity": get_text(self.lang, "sev_high"),
                                            "description": get_text(self.lang, "anom_non_std_task"),
                                        }
                                    )
                    except OSError:
                        continue
                elif os.path.isdir(cpath):
                    try:
                        for entry in os.listdir(cpath):
                            inspected_count += 1
                    except OSError:
                        continue

        return inspected_count, findings

    def scan_unquoted_service_paths(self) -> Tuple[int, List[Dict[str, Any]]]:
        """Scan Windows Services Registry for unquoted service binary paths (MITRE T1574.009)."""
        findings: List[Dict[str, Any]] = []
        inspected_count = 0

        if not self.is_windows or winreg is None:
            return inspected_count, findings

        services_reg_path = r"SYSTEM\CurrentControlSet\Services"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_reg_path, 0, winreg.KEY_READ) as srv_root:
                idx = 0
                while True:
                    try:
                        service_name = winreg.EnumKey(srv_root, idx)
                        idx += 1
                        inspected_count += 1
                        with winreg.OpenKey(srv_root, service_name, 0, winreg.KEY_READ) as srv_key:
                            try:
                                image_path_val, _ = winreg.QueryValueEx(srv_key, "ImagePath")
                                image_path = str(image_path_val)
                            except OSError:
                                continue

                            if self.is_unquoted_service_path(image_path):
                                findings.append(
                                    {
                                        "mechanism": "Service Configuration",
                                        "entry_name": service_name,
                                        "target": image_path,
                                        "location": f"HKLM\\{services_reg_path}\\{service_name}",
                                        "mitre_id": "T1574.009",
                                        "severity": get_text(self.lang, "sev_high"),
                                        "description": get_text(self.lang, "anom_unquoted_svc"),
                                    }
                                )
                    except OSError:
                        break
        except OSError:
            pass

        return inspected_count, findings

    def run_audit(self) -> Dict[str, Any]:
        """Execute all persistence checks and return consolidated results."""
        total_inspected = 0
        all_findings: List[Dict[str, Any]] = []

        for scanner in (
            self.scan_registry_autoruns,
            self.scan_startup_directories,
            self.scan_scheduled_tasks,
            self.scan_unquoted_service_paths,
        ):
            count, items = scanner()
            total_inspected += count
            all_findings.extend(items)

        return {
            "module": "persistence_engine",
            "total_inspected": total_inspected,
            "anomalies_count": len(all_findings),
            "findings": all_findings,
        }
