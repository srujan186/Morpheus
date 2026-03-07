"""
obfuscation_detector.py  +  dependency_scanner.py
Two lightweight layers combined:

Layer 6 — Obfuscation Detector
  Catches code that tries to HIDE what it does:
  - base64/zlib encoded payloads
  - chr() chains building strings character by character
  - hex-encoded strings
  - ROT13 and other simple ciphers
  - String reversal: "cexe"[::-1]
  - Unicode escapes hiding keywords
  - Excessive string concatenation of fragments

Layer 7 — Dependency Scanner
  Catches malicious or typosquatted packages:
  - Known malicious PyPI packages (updated database)
  - Typosquats of popular packages (requets, numpyy, etc.)
  - Packages with known CVEs
  - Suspicious package name patterns
"""

import ast
import re
import logging
from dataclasses import dataclass
from typing import List, Optional, Set

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data class
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ExtraFinding:
    pattern: str
    risk: str
    severity: str
    line_number: Optional[int] = None
    source: str = "obfuscation"


# ─────────────────────────────────────────────────────────────────────────────
# Layer 6 — Obfuscation Detector
# ─────────────────────────────────────────────────────────────────────────────

# Regex patterns that indicate obfuscation techniques
OBFUSCATION_PATTERNS = [
    # base64 encoded payloads
    (r'base64\.b64decode\s*\(',          "base64 decode",        "Encoded payload — base64",          "MEDIUM"),
    (r'base64\.decodebytes\s*\(',        "base64 decodebytes",   "Encoded payload — base64",          "MEDIUM"),
    (r'codecs\.decode.*base64',          "codecs base64",        "Encoded payload via codecs",        "MEDIUM"),

    # zlib/gzip compressed payloads
    (r'zlib\.decompress\s*\(',           "zlib decompress",      "Compressed payload",                "MEDIUM"),
    (r'gzip\.decompress\s*\(',           "gzip decompress",      "Compressed payload",                "MEDIUM"),
    (r'lzma\.decompress\s*\(',           "lzma decompress",      "Compressed payload",                "MEDIUM"),

    # String reversal: dangerous[::-1] or "cexe"[::-1]
    (r'["\'][\w\s]+["\'][^[]*\[::-1\]',  "string reversal",      "Reversed string — possible obfuscation", "HIGH"),
    (r'\w+\[::-1\]',                     "variable reversal",    "Reversed variable — possible obfuscation","MEDIUM"),

    # ROT13
    (r'codecs\.decode.*rot.?13',         "ROT13",                "ROT13 obfuscation",                 "MEDIUM"),
    (r'encode.*rot.?13',                 "ROT13 encode",         "ROT13 obfuscation",                 "MEDIUM"),

    # Excessive chr() chaining: chr(101)+chr(120)+chr(101)+chr(99)
    (r'(?:chr\s*\(\s*\d+\s*\)\s*\+\s*){3,}', "chr() chain",     "Chr()-based string obfuscation",    "HIGH"),

    # Hex-encoded strings: "\x65\x78\x65\x63"
    (r'(?:\\x[0-9a-fA-F]{2}){4,}',      "hex string",           "Hex-encoded payload",               "HIGH"),

    # Unicode escapes hiding keywords: \u0065\u0078\u0065\u0063
    (r'(?:\\u[0-9a-fA-F]{4}){3,}',      "unicode escape",       "Unicode-escaped payload",           "HIGH"),

    # Octal escapes
    (r'(?:\\[0-7]{3}){3,}',             "octal escape",         "Octal-encoded payload",             "MEDIUM"),

    # String join obfuscation: "".join(["e","x","e","c"])
    (r'["\']["\']\.join\s*\(',           "join obfuscation",     "String join — possible obfuscation","MEDIUM"),

    # Eval of decoded content (double layer)
    (r'eval\s*\(\s*.*decode',            "eval+decode",          "Eval of decoded content",           "HIGH"),
    (r'exec\s*\(\s*.*decode',            "exec+decode",          "Exec of decoded content",           "HIGH"),

    # compile() with dynamic source
    (r'compile\s*\(\s*\w+\s*,',          "dynamic compile",      "Dynamic code compilation",          "HIGH"),

    # type() to create new classes dynamically (sandbox escape)
    (r'type\s*\(\s*["\']',               "dynamic type",         "Dynamic class creation",            "MEDIUM"),

    # __reduce__ override (pickle exploit)
    (r'def\s+__reduce__',                "__reduce__",           "Custom __reduce__ — pickle exploit","HIGH"),

    # marshal.loads with dynamic data
    (r'marshal\.loads\s*\(',             "marshal.loads",        "Dynamic marshal deserialization",   "HIGH"),
]


class ObfuscationDetector:
    """Detects code obfuscation techniques used to hide malicious intent."""

    def detect(self, code: str) -> List[ExtraFinding]:
        findings: List[ExtraFinding] = []
        lines = code.splitlines()

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, label, risk, severity in OBFUSCATION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(ExtraFinding(
                        pattern=label,
                        risk=risk,
                        severity=severity,
                        line_number=line_num,
                        source="obfuscation",
                    ))

        # AST-level: detect excessive string fragmentation
        findings += self._detect_string_fragmentation(code)

        return findings

    def _detect_string_fragmentation(self, code: str) -> List[ExtraFinding]:
        """
        Detects: "e"+"x"+"e"+"c" or "ex"+"ec" style obfuscation
        by counting string concatenations in a single expression.
        """
        results = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    fragments = self._collect_string_parts(node)
                    if len(fragments) >= 3:
                        combined = "".join(fragments)
                        dangerous = {"exec", "eval", "subprocess", "pickle", "__import__", "os.system"}
                        if combined.lower() in dangerous:
                            results.append(ExtraFinding(
                                pattern=f"fragmented string → '{combined}'",
                                risk=f"String fragments combine to form dangerous call: '{combined}'",
                                severity="HIGH",
                                line_number=getattr(node, "lineno", None),
                                source="obfuscation-ast",
                            ))
        except SyntaxError:
            pass
        return results

    def _collect_string_parts(self, node: ast.expr) -> List[str]:
        """Recursively collect all string literal parts from a + chain."""
        parts = []
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            parts.append(node.value)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            parts += self._collect_string_parts(node.left)
            parts += self._collect_string_parts(node.right)
        return parts


# ─────────────────────────────────────────────────────────────────────────────
# Layer 7 — Dependency Scanner
# ─────────────────────────────────────────────────────────────────────────────

# Known malicious packages ever published to PyPI
# Source: PyPI malware reports, safety-db, GuardDog
KNOWN_MALICIOUS_PACKAGES: Set[str] = {
    # Real malicious packages (historical)
    "colourama",        # typosquat of colorama — stole crypto wallets
    "python-sqlite",    # fake sqlite — remote code execution
    "acqusition",       # typosquat — data exfiltration
    "apidev-coop",      # supply chain attack
    "beitcoin",         # crypto stealer
    "crypt",            # malicious crypt replacement
    "django-server",    # fake django — backdoor
    "setup-tools",      # typosquat of setuptools
    "python3-dateutil",  # fake dateutil — malware
    "pythonkafka",      # fake kafka — malware
    "redis-py",         # fake redis — malware
    "requesfs",         # typosquat of requests
    "request",          # typosquat of requests
    "requestz",         # typosquat of requests
    "requests-async",   # malicious async wrapper
    "urllib4",          # fake urllib3
    "urllib5",          # fake urllib3
    "beautifulsoup",    # typosquat (correct: beautifulsoup4)
    "bs4-parser",       # fake bs4
    "pycrypto",         # deprecated with CVEs (use pycryptodome)
    "pylibmc-py3",      # fake pylibmc
    "mongoclient",      # fake pymongo
    "mongodriver",      # fake pymongo
    "python-mongo",     # fake pymongo
    "nmap-python",      # malicious nmap wrapper
    "openssl",          # fake openssl
    "python-openssl",   # typosquat (correct: pyOpenSSL)
    "python-jwt",       # typosquat (correct: PyJWT)
    "jinja",            # typosquat (correct: jinja2)
    "djago",            # typosquat of django
    "diango",           # typosquat of django
    "flaskk",           # typosquat of flask
    "numpyy",           # typosquat of numpy
    "panads",           # typosquat of pandas
    "matplotlb",        # typosquat of matplotlib
    "scikit-learns",    # typosquat
    "tenserflow",       # typosquat of tensorflow
    "pytorch",          # typosquat (correct: torch)
    "cv2",              # typosquat (correct: opencv-python)
    "cryptography-io",  # fake cryptography
    "pyjwt2",           # fake PyJWT
    "loguru-dev",       # fake loguru
    "aiohttp-security", # malicious aiohttp extension
    "fastapi-utils-2",  # fake fastapi
    "httpx-async",      # fake httpx
    "sqlalchemy-plus",  # fake sqlalchemy
}

# Popular packages and their common typosquats
TYPOSQUAT_MAP: dict = {
    "requests":     ["requets", "reqests", "rquests", "request", "requestss"],
    "numpy":        ["numppy", "nmupy", "nnumpy", "numpyy"],
    "pandas":       ["pandass", "pndas", "padas", "panads"],
    "flask":        ["flaskk", "flaask", "falsk"],
    "django":       ["diango", "djago", "djanog", "dajngo"],
    "boto3":        ["botto3", "bot03", "boto33"],
    "tensorflow":   ["tenserflow", "tensoreflow", "tensoflow"],
    "torch":        ["pytorch", "pytoch"],
    "scipy":        ["scypi", "sciopy"],
    "setuptools":   ["setup-tools", "setuptoolz"],
    "colorama":     ["colourama", "collorama"],
    "beautifulsoup4": ["beautifulsoup", "beutifulsoup4"],
    "urllib3":      ["urllib4", "urllib5"],
    "PyJWT":        ["pyjwt2", "python-jwt"],
    "cryptography": ["cryptography-io"],
    "paramiko":     ["paramiko2", "paromiko"],
    "Pillow":       ["pillow2", "pillo"],
    "certifi":      ["certify", "certiifi"],
}

# Build reverse lookup: typosquat → real package
TYPOSQUAT_REVERSE: dict = {}
for real, fakes in TYPOSQUAT_MAP.items():
    for fake in fakes:
        TYPOSQUAT_REVERSE[fake.lower()] = real


class DependencyScanner:
    """
    Scans import statements for:
    - Known malicious packages
    - Typosquats of popular packages
    - Suspicious naming patterns
    """

    def scan(self, code: str) -> List[ExtraFinding]:
        findings: List[ExtraFinding] = []
        imported = self._extract_imports(code)

        for pkg, line_num in imported:
            pkg_lower = pkg.lower()

            # Check known malicious list
            if pkg_lower in {p.lower() for p in KNOWN_MALICIOUS_PACKAGES}:
                findings.append(ExtraFinding(
                    pattern=f"malicious package: {pkg}",
                    risk=f"'{pkg}' is a known malicious/typosquat package on PyPI",
                    severity="HIGH",
                    line_number=line_num,
                    source="dependency",
                ))
                continue

            # Check typosquat map
            if pkg_lower in TYPOSQUAT_REVERSE:
                real = TYPOSQUAT_REVERSE[pkg_lower]
                findings.append(ExtraFinding(
                    pattern=f"typosquat: {pkg}",
                    risk=f"'{pkg}' appears to be a typosquat of '{real}' — possible supply chain attack",
                    severity="HIGH",
                    line_number=line_num,
                    source="dependency",
                ))
                continue

            # Heuristic: suspicious naming patterns
            if self._looks_suspicious(pkg):
                findings.append(ExtraFinding(
                    pattern=f"suspicious package name: {pkg}",
                    risk=f"Package name '{pkg}' matches suspicious patterns",
                    severity="MEDIUM",
                    line_number=line_num,
                    source="dependency",
                ))

        return findings

    def _extract_imports(self, code: str) -> List[tuple]:
        """Extract (package_name, line_number) from all import statements."""
        imports = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                line = getattr(node, "lineno", None)
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append((alias.name.split(".")[0], line))
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append((node.module.split(".")[0], line))
        except SyntaxError:
            # Fallback: regex import extraction
            for match in re.finditer(r'(?:import|from)\s+([\w]+)', code):
                imports.append((match.group(1), None))
        return imports

    def _looks_suspicious(self, pkg: str) -> bool:
        """Heuristic checks for suspicious package names."""
        pkg_lower = pkg.lower()

        # Double letters in unusual places: requestss, flaskk
        if re.search(r'(.)\1{2,}', pkg_lower):
            return True

        # Ends with digit: urllib4, numpy2 (when not a real version)
        if re.match(r'.+[a-z]\d$', pkg_lower) and pkg_lower not in {"py3", "cv2"}:
            return True

        # Contains "python-" prefix (common in malicious packages)
        if pkg_lower.startswith("python-") and len(pkg_lower) > 12:
            return True

        return False