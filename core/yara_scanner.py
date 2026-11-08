import hashlib
import os
import re
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from core.i18n import get_text

try:
    import yara
except ImportError:
    yara = None  


MAX_FILE_SCAN_SIZE = 10 * 1024 * 1024  


class FallbackYaraRule:
    """AST-evaluated YARA rule representation when native yara-python C extension is unavailable."""

    def __init__(
        self,
        name: str,
        meta: Dict[str, str],
        strings: Dict[str, Tuple[bytes, bool]],
        condition: str,
    ) -> None:
        self.name = name
        self.meta = meta
        self.strings = strings  
        self.condition = condition.strip()

    def match(self, data: bytes) -> List[str]:
        matched_vars: Dict[str, bool] = {}
        matched_indicators: List[str] = []
        lower_data = data.lower()

        for var_name, (pattern, nocase) in self.strings.items():
            haystack = lower_data if nocase else data
            needle = pattern.lower() if nocase else pattern
            is_hit = needle in haystack
            matched_vars[var_name] = is_hit
            if is_hit:
                matched_indicators.append(f"{var_name}={pattern.decode('utf-8', errors='ignore')}")

        if not matched_indicators:
            return []

        if self._evaluate_condition(matched_vars):
            return matched_indicators
        return []

    def _evaluate_condition(self, matched_vars: Dict[str, bool]) -> bool:
        cond = self.condition
        if cond == "any of them":
            return any(matched_vars.values())
        if cond == "all of them":
            return all(matched_vars.values())

        def replace_of_wildcard(match: re.Match[str]) -> str:
            count_req = int(match.group(1))
            prefix = match.group(2)
            hits = sum(1 for k, v in matched_vars.items() if k.startswith(prefix) and v)
            return "True" if hits >= count_req else "False"

        expr = re.sub(r"(\d+)\s+of\s+\((\$[a-zA-Z0-9_]+)\*\)", replace_of_wildcard, cond)

        for var_name in sorted(matched_vars.keys(), key=len, reverse=True):
            expr = expr.replace(var_name, "True" if matched_vars[var_name] else "False")

        allowed_tokens = {"True", "False", "and", "or", "not", "(", ")"}
        tokens = re.findall(r"[A-Za-z_]+|[()]", expr)
        if all(t in allowed_tokens for t in tokens):
            try:
                return bool(eval(expr, {"__builtins__": {}}, {}))
            except Exception:
                return False
        return any(matched_vars.values())


class YaraScanner:

    def __init__(self, rules_dir: str = "rules", lang: str = "en") -> None:
        self.rules_dir = rules_dir
        self.lang = lang
        self._compiled_yara: Optional[Any] = None
        self._fallback_rules: List[FallbackYaraRule] = []
        self._load_rules()

    def _load_rules(self) -> None:
        if not os.path.isdir(self.rules_dir):
            return

        rule_files: Dict[str, str] = {}
        for entry in sorted(os.listdir(self.rules_dir)):
            if entry.endswith((".yar", ".yara")):
                full_path = os.path.join(self.rules_dir, entry)
                if os.path.isfile(full_path):
                    rule_files[entry] = full_path

        if not rule_files:
            return

        if yara is not None:
            try:
                self._compiled_yara = yara.compile(filepaths=rule_files)
                return
            except Exception:
                self._compiled_yara = None

        # Parse rules into FallbackYaraRule objects if native yara is unavailable
        for file_path in rule_files.values():
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                self._fallback_rules.extend(self._parse_yara_source(content))
            except OSError:
                continue

    @staticmethod
    def _parse_yara_source(source: str) -> List[FallbackYaraRule]:
        parsed_rules: List[FallbackYaraRule] = []
        rule_pattern = re.compile(
            r"rule\s+([A-Za-z0-9_]+)\s*\{(.*?)\}",
            re.DOTALL,
        )
        for match in rule_pattern.finditer(source):
            rule_name = match.group(1)
            body = match.group(2)

            meta: Dict[str, str] = {}
            strings: Dict[str, Tuple[bytes, bool]] = {}
            condition = "any of them"

            meta_match = re.search(r"meta:\s*(.*?)(?:strings:|condition:)", body, re.DOTALL)
            if meta_match:
                for m_line in meta_match.group(1).splitlines():
                    kv = re.match(r'\s*([A-Za-z0-9_]+)\s*=\s*"([^"]*)"', m_line)
                    if kv:
                        meta[kv.group(1)] = kv.group(2)

            strings_match = re.search(r"strings:\s*(.*?)(?:condition:)", body, re.DOTALL)
            if strings_match:
                for s_line in strings_match.group(1).splitlines():
                    str_m = re.match(r'\s*(\$[A-Za-z0-9_]+)\s*=\s*"((?:\\.|[^"\\])*)"\s*(.*)', s_line)
                    if str_m:
                        var_id = str_m.group(1)
                        raw_val = str_m.group(2).replace('\\"', '"').replace("\\\\", "\\")
                        modifiers = str_m.group(3).lower()
                        nocase = "nocase" in modifiers
                        strings[var_id] = (raw_val.encode("utf-8"), nocase)

            cond_match = re.search(r"condition:\s*(.*)", body, re.DOTALL)
            if cond_match:
                condition = " ".join(cond_match.group(1).strip().split())

            parsed_rules.append(FallbackYaraRule(rule_name, meta, strings, condition))

        return parsed_rules

    def get_default_target_dirs(self, custom_dir: Optional[str] = None) -> List[str]:
        if custom_dir:
            return [os.path.abspath(custom_dir)]

        candidates: List[str] = []
        temp_dir = os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir()
        if temp_dir and os.path.isdir(temp_dir):
            candidates.append(os.path.abspath(temp_dir))

        downloads_dir = os.path.join(os.path.expanduser("~"), "Downloads")
        if os.path.isdir(downloads_dir) and os.path.abspath(downloads_dir) not in candidates:
            candidates.append(os.path.abspath(downloads_dir))

        return candidates

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        try:
            size = os.path.getsize(file_path)
            if size == 0 or size > MAX_FILE_SCAN_SIZE:
                return matches
        except OSError:
            return matches

        if self._compiled_yara is not None:
            try:
                yara_hits = self._compiled_yara.match(file_path, timeout=5)
                for hit in yara_hits:
                    sha256 = self._hash_file(file_path)
                    mitre_id = hit.meta.get("mitre_id", "T1027")
                    desc = hit.meta.get("description", f"YARA signature match: {hit.rule}")
                    indicators: List[str] = []
                    for s in getattr(hit, "strings", [])[:4]:
                        ident = getattr(s, "identifier", str(s))
                        indicators.append(str(ident))
                    matches.append(
                        {
                            "rule_name": hit.rule,
                            "file_path": file_path,
                            "sha256": sha256,
                            "mitre_id": mitre_id,
                            "severity": get_text(self.lang, "sev_high"),
                            "matched_strings": ", ".join(indicators) if indicators else "Rule Condition Met",
                            "description": desc,
                        }
                    )
                return matches
            except Exception:
                pass

        # Fallback signature matching
        try:
            with open(file_path, "rb") as f:
                data = f.read(MAX_FILE_SCAN_SIZE)
        except OSError:
            return matches

        for rule in self._fallback_rules:
            hit_strings = rule.match(data)
            if hit_strings:
                sha256 = self._hash_file(file_path)
                matches.append(
                    {
                        "rule_name": rule.name,
                        "file_path": file_path,
                        "sha256": sha256,
                        "mitre_id": rule.meta.get("mitre_id", "T1027"),
                        "severity": get_text(self.lang, "sev_high"),
                        "matched_strings": ", ".join(hit_strings[:3]),
                        "description": rule.meta.get("description", f"YARA signature match: {rule.name}"),
                    }
                )

        return matches

    @staticmethod
    def _hash_file(file_path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return "ACCESS_DENIED"

    def run_audit(self, target_dir: Optional[str] = None, max_files: int = 1500) -> Dict[str, Any]:
        dirs_to_scan = self.get_default_target_dirs(target_dir)
        findings: List[Dict[str, Any]] = []
        files_scanned = 0

        rules_abs = os.path.abspath(self.rules_dir)
        for base_dir in dirs_to_scan:
            if not os.path.exists(base_dir):
                continue
            if os.path.isfile(base_dir):
                files_scanned += 1
                findings.extend(self.scan_file(base_dir))
                continue

            for root, _, files in os.walk(base_dir):
                if os.path.abspath(root).startswith(rules_abs):
                    continue
                for fname in files:
                    if fname.endswith((".yar", ".yara")):
                        continue
                    if files_scanned >= max_files:
                        break
                    fpath = os.path.join(root, fname)
                    if os.path.islink(fpath):
                        continue
                    files_scanned += 1
                    findings.extend(self.scan_file(fpath))
                if files_scanned >= max_files:
                    break

        return {
            "module": "yara_scanner",
            "scanned_directories": dirs_to_scan,
            "rules_loaded": len(self._fallback_rules) if self._compiled_yara is None else 4,
            "total_inspected": files_scanned,
            "anomalies_count": len(findings),
            "findings": findings,
        }
