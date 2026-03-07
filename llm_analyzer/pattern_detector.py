"""
pattern_detector.py
-------------------
This file scans code for KNOWN dangerous patterns WITHOUT needing AI.
Think of it like a spell-checker, but for security problems.

It's fast because it just looks for specific keywords/patterns.
The AI (explainer.py) then explains WHY they're dangerous.
"""

import re
from dataclasses import dataclass  # Makes it easy to create structured data


# ============================================================
# Data structure for a single detected pattern
# @dataclass automatically creates __init__ and __repr__
# ============================================================
@dataclass
class DetectedPattern:
    pattern: str        # The dangerous thing found (e.g., "exec")
    line_number: int    # Which line it's on
    line_content: str   # The actual code on that line
    severity: str       # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    risk_type: str      # Category of risk (e.g., "Code Injection")
    description: str    # Short explanation


# ============================================================
# Dictionary of dangerous patterns to look for
# Format: "pattern_to_find": (severity, risk_type, description)
# ============================================================
DANGEROUS_PATTERNS = {
    # Code execution - most dangerous
    r"\bexec\s*\(": (
        "CRITICAL",
        "Arbitrary Code Execution",
        "exec() runs any Python code. If input comes from external source, attacker can run anything."
    ),
    r"\beval\s*\(": (
        "CRITICAL",
        "Arbitrary Code Execution",
        "eval() evaluates Python expressions. Extremely dangerous with untrusted input."
    ),

    # System commands
    r"\bsubprocess\b": (
        "HIGH",
        "System Command Execution",
        "subprocess can run shell commands. Could be used to execute malicious system commands."
    ),
    r"\bos\.system\s*\(": (
        "HIGH",
        "System Command Execution",
        "os.system() runs shell commands directly. Dangerous with external input."
    ),

    # Dynamic imports
    r"\b__import__\s*\(": (
        "HIGH",
        "Dynamic Import",
        "__import__() can load any Python module dynamically. Could load malicious modules."
    ),

    # File access
    r"\bopen\s*\(": (
        "MEDIUM",
        "File System Access",
        "open() accesses files. Could read sensitive files or overwrite system files."
    ),

    # Network access
    r"\brequests\.(get|post|put|delete)\s*\(": (
        "MEDIUM",
        "Network Access",
        "Makes HTTP requests. Could exfiltrate data or communicate with attacker servers."
    ),
    r"\bsocket\b": (
        "MEDIUM",
        "Network Access",
        "Raw socket access. Could be used for covert network communication."
    ),

    # Pickle (dangerous deserialization)
    r"\bpickle\.(loads|load)\s*\(": (
        "CRITICAL",
        "Unsafe Deserialization",
        "pickle.loads() can execute arbitrary code when deserializing untrusted data."
    ),

    # No input validation (indirect check)
    r"\.execute\s*\(.*\+": (
        "HIGH",
        "Potential SQL Injection",
        "String concatenation in SQL execute() is a classic SQL injection vulnerability."
    ),
}


class PatternDetector:
    """
    Scans Python code for dangerous security patterns.
    Fast, no AI needed - just pattern matching.
    """

    def scan(self, code: str, tool_name: str = "unknown") -> dict:
        """
        Scan a piece of code for dangerous patterns.

        Parameters:
        - code: The Python function/code as a string
        - tool_name: Name of the tool being scanned (for reporting)

        Returns:
        - Dictionary with all findings
        """
        findings = []
        lines = code.split("\n")  # Split code into individual lines

        # Check each dangerous pattern against the code
        for pattern_regex, (severity, risk_type, description) in DANGEROUS_PATTERNS.items():
            for line_num, line in enumerate(lines, start=1):
                # re.search finds the pattern anywhere in the line
                if re.search(pattern_regex, line):
                    findings.append(DetectedPattern(
                        pattern=pattern_regex,
                        line_number=line_num,
                        line_content=line.strip(),  # .strip() removes extra whitespace
                        severity=severity,
                        risk_type=risk_type,
                        description=description
                    ))

        # Calculate overall risk level based on worst finding
        overall_severity = self._calculate_overall_severity(findings)

        return {
            "tool_name": tool_name,
            "total_findings": len(findings),
            "overall_severity": overall_severity,
            "is_dangerous": len(findings) > 0,
            "findings": [
                {
                    "line": f.line_number,
                    "code": f.line_content,
                    "severity": f.severity,
                    "risk_type": f.risk_type,
                    "description": f.description,
                }
                for f in findings
            ]
        }

    def _calculate_overall_severity(self, findings: list) -> str:
        """Determine worst-case severity from all findings."""
        if not findings:
            return "SAFE"

        # Priority order
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

        for severity in severity_order:
            # If any finding has this severity, that's the overall level
            if any(f.severity == severity for f in findings):
                return severity

        return "LOW"


# ============================================================
# TEST: Run this file directly to test it
# Command: python pattern_detector.py
# ============================================================
if __name__ == "__main__":
    # This is the example vulnerable code from the hackathon brief
    test_code = """
def generate_docs(code):
    response = api.call(code)
    exec(response)
    return response
"""

    detector = PatternDetector()
    result = detector.scan(test_code, tool_name="DocGenerator")

    print("=== Pattern Detection Results ===")
    print(f"Tool: {result['tool_name']}")
    print(f"Overall Severity: {result['overall_severity']}")
    print(f"Total Issues Found: {result['total_findings']}")
    print()
    for finding in result['findings']:
        print(f"  Line {finding['line']}: {finding['code']}")
        print(f"  Severity: {finding['severity']} | Type: {finding['risk_type']}")
        print(f"  Why it's bad: {finding['description']}")
        print()