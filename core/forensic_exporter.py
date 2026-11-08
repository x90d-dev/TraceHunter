import datetime
import json
import os
import platform
import socket
import uuid
from typing import Any, Dict, List, Optional

from core import __repository__, __version__


# Deterministic namespace for generating reproducible STIX 2.1 UUIDv5 identifiers
TRACEHUNTER_STIX_NAMESPACE = uuid.UUID("7a4e8c92-3b15-4f61-9c2a-1e8b9d0c4f32")

MITRE_ATTACK_METADATA: Dict[str, Dict[str, str]] = {
    "T1036": {
        "name": "Masquerading",
        "tactic": "defense-evasion",
        "url": "https://attack.mitre.org/techniques/T1036/",
    },
    "T1036.005": {
        "name": "Masquerading: Match Legitimate Name or Location",
        "tactic": "defense-evasion",
        "url": "https://attack.mitre.org/techniques/T1036/005/",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "execution",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1547.001": {
        "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "tactic": "persistence",
        "url": "https://attack.mitre.org/techniques/T1547/001/",
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "persistence",
        "url": "https://attack.mitre.org/techniques/T1053/005/",
    },
    "T1053.003": {
        "name": "Scheduled Task/Job: Cron",
        "tactic": "persistence",
        "url": "https://attack.mitre.org/techniques/T1053/003/",
    },
    "T1574.009": {
        "name": "Hijack Execution Flow: Path Interception by Unquoted Path",
        "tactic": "persistence",
        "url": "https://attack.mitre.org/techniques/T1574/009/",
    },
    "T1049": {
        "name": "System Network Connections Discovery",
        "tactic": "discovery",
        "url": "https://attack.mitre.org/techniques/T1049/",
    },
    "T1505.003": {
        "name": "Server Software Component: Web Shell",
        "tactic": "persistence",
        "url": "https://attack.mitre.org/techniques/T1505/003/",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "defense-evasion",
        "url": "https://attack.mitre.org/techniques/T1027/",
    },
}


class ForensicExporter:
    """Serializes TraceHunter audit findings to JSON or OASIS STIX 2.1 bundles."""

    def __init__(self) -> None:
        self.hostname = socket.gethostname()
        self.os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"

    @staticmethod
    def _utc_timestamp() -> str:
        """Return ISO-8601 UTC timestamp formatted for STIX 2.1 compliance."""
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def build_json_report(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Construct structured JSON forensic report from module audit outputs."""
        total_anomalies = sum(
            mod.get("anomalies_count", 0)
            for mod in audit_results.values()
            if isinstance(mod, dict)
        )
        return {
            "metadata": {
                "tool": "TraceHunter",
                "version": __version__,
                "repository": __repository__,
                "generated_at_utc": self._utc_timestamp(),
                "hostname": self.hostname,
                "operating_system": self.os_info,
                "total_flagged_anomalies": total_anomalies,
            },
            "modules": audit_results,
        }

    def export_json(self, audit_results: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Write structured JSON report to disk or return serialized JSON string."""
        report = self.build_json_report(audit_results)
        serialized = json.dumps(report, indent=2, ensure_ascii=False)
        if output_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(serialized + "\n")
        return serialized

    def build_stix_bundle(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Construct a valid OASIS STIX 2.1 Bundle representing discovered host anomalies."""
        now_ts = self._utc_timestamp()
        objects: List[Dict[str, Any]] = []
        attack_pattern_ids: Dict[str, str] = {}

        # 1. Identity Object representing TraceHunter collector on the inspected host
        identity_id = f"identity--{uuid.uuid5(TRACEHUNTER_STIX_NAMESPACE, self.hostname)}"
        objects.append(
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": now_ts,
                "modified": now_ts,
                "name": f"TraceHunter Collector ({self.hostname})",
                "description": f"Automated Host Audit & Forensic Engine running on {self.os_info}",
                "identity_class": "system",
            }
        )

        def ensure_attack_pattern(mitre_id: str) -> str:
            if mitre_id in attack_pattern_ids:
                return attack_pattern_ids[mitre_id]
            meta = MITRE_ATTACK_METADATA.get(
                mitre_id,
                {
                    "name": f"MITRE ATT&CK {mitre_id}",
                    "tactic": "defense-evasion",
                    "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
                },
            )
            ap_id = f"attack-pattern--{uuid.uuid5(TRACEHUNTER_STIX_NAMESPACE, mitre_id)}"
            objects.append(
                {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": ap_id,
                    "created": now_ts,
                    "modified": now_ts,
                    "name": meta["name"],
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": mitre_id,
                            "url": meta["url"],
                        }
                    ],
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": meta["tactic"],
                        }
                    ],
                }
            )
            attack_pattern_ids[mitre_id] = ap_id
            return ap_id

        # 2. Convert Process Findings into STIX 2.1 Indicators & Relationships
        proc_mod = audit_results.get("process_engine", {})
        for item in proc_mod.get("findings", []):
            mitre_id = item.get("mitre_id", "T1036")
            ap_id = ensure_attack_pattern(mitre_id)
            ind_id = f"indicator--{uuid.uuid4()}"
            sha = item.get("sha256", "")
            proc_name = item.get("process_name", "unknown").replace("'", "\\'")
            if sha and len(sha) == 64:
                pattern = f"[process:name = '{proc_name}' AND file:hashes.'SHA-256' = '{sha}']"
            else:
                pattern = f"[process:name = '{proc_name}' AND process:pid = {int(item.get('pid', 0))}]"

            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created": now_ts,
                    "modified": now_ts,
                    "created_by_ref": identity_id,
                    "name": f"{item.get('category', 'Process Anomaly')}: {item.get('process_name')}",
                    "description": item.get("description", ""),
                    "indicator_types": ["anomalous-activity"],
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now_ts,
                }
            )
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": now_ts,
                    "modified": now_ts,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": ap_id,
                }
            )

        # 3. Convert Persistence Findings into STIX 2.1 Indicators
        pers_mod = audit_results.get("persistence_engine", {})
        for item in pers_mod.get("findings", []):
            mitre_id = item.get("mitre_id", "T1547.001")
            ap_id = ensure_attack_pattern(mitre_id)
            ind_id = f"indicator--{uuid.uuid4()}"
            target_escaped = str(item.get("target", "")).replace("\\", "\\\\").replace("'", "\\'")
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created": now_ts,
                    "modified": now_ts,
                    "created_by_ref": identity_id,
                    "name": f"{item.get('mechanism')}: {item.get('entry_name')}",
                    "description": f"{item.get('description')} (Location: {item.get('location')})",
                    "indicator_types": ["persistence-mechanism"],
                    "pattern": f"[process:command_line = '{target_escaped}']",
                    "pattern_type": "stix",
                    "valid_from": now_ts,
                }
            )
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": now_ts,
                    "modified": now_ts,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": ap_id,
                }
            )

        # 4. Convert Network Findings into STIX 2.1 Indicators
        net_mod = audit_results.get("network_correlator", {})
        for item in net_mod.get("findings", []):
            mitre_id = item.get("mitre_id", "T1049")
            ap_id = ensure_attack_pattern(mitre_id)
            ind_id = f"indicator--{uuid.uuid4()}"
            remote_ip = item.get("remote_ip") or "0.0.0.0"
            remote_port = int(item.get("remote_port") or 0)
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created": now_ts,
                    "modified": now_ts,
                    "created_by_ref": identity_id,
                    "name": f"External Socket: {item.get('process_name')} -> {item.get('remote_address')}",
                    "description": item.get("description", ""),
                    "indicator_types": ["anomalous-activity"],
                    "pattern": f"[network-traffic:dst_ref.value = '{remote_ip}' AND network-traffic:dst_port = {remote_port}]",
                    "pattern_type": "stix",
                    "valid_from": now_ts,
                }
            )
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": now_ts,
                    "modified": now_ts,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": ap_id,
                }
            )

        # 5. Convert YARA Matches into STIX 2.1 Indicators
        yara_mod = audit_results.get("yara_scanner", {})
        for item in yara_mod.get("findings", []):
            mitre_id = item.get("mitre_id", "T1027")
            ap_id = ensure_attack_pattern(mitre_id)
            ind_id = f"indicator--{uuid.uuid4()}"
            sha = item.get("sha256", "")
            fname = os.path.basename(item.get("file_path", "unknown")).replace("'", "\\'")
            if sha and len(sha) == 64:
                pattern = f"[file:name = '{fname}' AND file:hashes.'SHA-256' = '{sha}']"
            else:
                pattern = f"[file:name = '{fname}']"

            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created": now_ts,
                    "modified": now_ts,
                    "created_by_ref": identity_id,
                    "name": f"YARA Match: {item.get('rule_name')}",
                    "description": f"{item.get('description')} | File: {item.get('file_path')}",
                    "indicator_types": ["malicious-activity"],
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now_ts,
                }
            )
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": now_ts,
                    "modified": now_ts,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": ap_id,
                }
            )

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

    def export_stix(self, audit_results: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Write STIX 2.1 bundle to disk or return serialized JSON string."""
        bundle = self.build_stix_bundle(audit_results)
        serialized = json.dumps(bundle, indent=2, ensure_ascii=False)
        if output_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(serialized + "\n")
        return serialized
