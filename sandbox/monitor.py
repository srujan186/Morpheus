"""
monitor.py
Watches for dangerous code patterns and suspicious runtime behavior.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    pattern: str
    risk: str
    severity: str
    line_number: Optional[int] = None


@dataclass
class MonitorReport:
    dangerous_calls: List[Finding] = field(default_factory=list)
    network_access: bool = False
    file_access: bool = False
    suspicious_imports: List[str] = field(default_factory=list)
    verdict: str = "SAFE"
    summary: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "dangerous_calls": [vars(f) for f in self.dangerous_calls],
            "network_access": self.network_access,
            "file_access": self.file_access,
            "suspicious_imports": self.suspicious_imports,
            "verdict": self.verdict,
            "summary": self.summary,
        }


class BehaviorMonitor:
    DANGEROUS_PATTERNS: Dict[str, Tuple[str, str, str]] = {
        r'\bexec\s*\(':        ("exec()",        "Arbitrary code execution",  "HIGH"),
        r'\beval\s*\(':        ("eval()",        "Arbitrary code execution",  "HIGH"),
        r'\bsubprocess\b':     ("subprocess",    "System command execution",  "HIGH"),
        r'\bos\.system\s*\(':  ("os.system()",   "System command execution",  "HIGH"),
        r'\bos\.popen\s*\(':   ("os.popen()",    "System command execution",  "HIGH"),
        r'\b__import__\s*\(':  ("__import__()",  "Dynamic module imports",    "HIGH"),
        r'\bpickle\b':         ("pickle",        "Arbitrary deserialization", "HIGH"),
        r'\bctypes\b':         ("ctypes",        "Low-level memory access",   "HIGH"),
        r'\bopen\s*\(':        ("open()",        "File system access",        "MEDIUM"),
        r'\brequests\b':       ("requests",      "Network access",            "MEDIUM"),
        r'\burllib\b':         ("urllib",        "Network access",            "MEDIUM"),
        r'\bsocket\b':         ("socket",        "Raw network access",        "MEDIUM"),
        r'\bshutil\b':         ("shutil",        "File system operations",    "MEDIUM"),
        r'\bglob\b':           ("glob",          "File system discovery",     "LOW"),
        r'\bgetpass\b':        ("getpass",       "Credential access",         "LOW"),
        r'\bplatform\b':       ("platform",      "System fingerprinting",     "LOW"),
    }

    NETWORK_INDICATORS: set = {"requests", "urllib", "socket", "http", "httpx", "aiohttp"}

    def detect_dangerous_patterns(self, code: str) -> MonitorReport:
        """Static analysis: scans line by line for dangerous patterns."""
        report = MonitorReport()
        lines = code.splitlines()

        for line_num, line in enumerate(lines, start=1):
            if line.strip().startswith("#"):
                continue
            for pattern, (label, risk, severity) in self.DANGEROUS_PATTERNS.items():
                if re.search(pattern, line):
                    report.dangerous_calls.append(Finding(
                        pattern=label,
                        risk=risk,
                        severity=severity,
                        line_number=line_num,
                    ))

        for mod in re.findall(r'(?:import|from)\s+([\w\.]+)', code):
            base_mod = mod.split(".")[0]
            if base_mod in self.NETWORK_INDICATORS:
                report.network_access = True
                if base_mod not in report.suspicious_imports:
                    report.suspicious_imports.append(base_mod)
            if base_mod in {"pathlib", "shutil", "glob"}:
                report.file_access = True
                if base_mod not in report.suspicious_imports:
                    report.suspicious_imports.append(base_mod)

        if re.search(r'\bopen\s*\(', code):
            report.file_access = True

        high_findings = [f for f in report.dangerous_calls if f.severity == "HIGH"]
        medium_findings = [f for f in report.dangerous_calls if f.severity == "MEDIUM"]

        if high_findings:
            report.verdict = "UNSAFE"
            labels = ", ".join(set(f.pattern for f in high_findings))
            report.summary = f"UNSAFE - High-severity issues detected: {labels}"
        elif medium_findings or report.network_access:
            report.verdict = "SUSPICIOUS"
            labels = ", ".join(set(f.pattern for f in medium_findings))
            report.summary = f"SUSPICIOUS - Potential risks: {labels}"
        else:
            report.verdict = "SAFE"
            report.summary = "No dangerous patterns detected."

        logger.info("Monitor verdict: %s", report.verdict)
        return report

    def analyze_runtime_output(self, stdout: str, stderr: str) -> Dict[str, object]:
        """Looks for red flags in runtime output."""
        flags: List[str] = []

        for pat in ["ConnectionRefusedError", "socket.gaierror", "URLError"]:
            if pat in stderr:
                flags.append(f"Attempted network call blocked by sandbox: {pat}")

        for pat in ["PermissionError", "Operation not permitted"]:
            if pat in stderr:
                flags.append(f"Attempted restricted operation: {pat}")

        return {
            "runtime_flags": flags,
            "has_runtime_warnings": len(flags) > 0,
        }