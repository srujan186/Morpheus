"""
Agent Analyzer — Risk Scorer
==============================
Calculates an overall risk score (0–100) for a scanned agent based on
the number and severity of discovered vulnerabilities.
"""

from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Points deducted per vulnerability at each severity level
SEVERITY_DEDUCTIONS: Dict[str, int] = {
    "CRITICAL": 30,
    "HIGH":     15,
    "MEDIUM":    7,
    "LOW":       3,
}

# Maximum possible score (perfect security)
BASELINE_SCORE: int = 100

# Score thresholds → label
_SCORE_THRESHOLDS: List[tuple] = [
    (0,  10,  "CRITICAL"),
    (11, 40,  "HIGH"),
    (41, 60,  "MEDIUM"),
    (61, 80,  "LOW"),
    (81, 100, "SAFE"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def calculate_risk_score(
    dependencies: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
) -> int:
    """
    Calculate a risk score for the agent.

    Scoring logic:
        - Start at 100
        - CRITICAL vulnerability → -30 points each
        - HIGH vulnerability     → -15 points each
        - MEDIUM vulnerability   → -7  points each
        - LOW vulnerability      → -3  points each
        - Score is clamped to [0, 100]

    Args:
        dependencies:    List of discovered tool dependency dicts.
        vulnerabilities: List of discovered vulnerability dicts, each with a
                         'severity' key (CRITICAL / HIGH / MEDIUM / LOW).

    Returns:
        Integer risk score in the range [0, 100].
    """
    score = BASELINE_SCORE
    for vuln in vulnerabilities:
        severity = str(vuln.get("severity", "LOW")).upper()
        score -= SEVERITY_DEDUCTIONS.get(severity, 0)
    return max(0, min(100, score))


def get_score_label(score: int) -> str:
    """
    Return a human-readable risk label for a given score.

    Returns:
        One of: "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"
    """
    for low, high, label in _SCORE_THRESHOLDS:
        if low <= score <= high:
            return label
    return "SAFE"


def get_score_emoji(score: int) -> str:
    """Return a colored emoji indicator for a score."""
    label = get_score_label(score)
    return {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🟢",
        "SAFE":     "✅",
    }.get(label, "⚪")


def build_score_summary(
    dependencies: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Build a full scoring summary dict for use in reports and the API.

    Args:
        dependencies:    Output of AgentAnalyzer.discover_tools().
        vulnerabilities: List of vulnerability dicts.

    Returns:
        Dict with:
            - score (int): 0–100
            - label (str): CRITICAL / HIGH / MEDIUM / LOW / SAFE
            - emoji (str): color indicator
            - total_dependencies (int)
            - total_vulnerabilities (int)
            - breakdown (dict): count per severity
            - deduction_detail (list): per-vulnerability deduction info
    """
    score = calculate_risk_score(dependencies, vulnerabilities)
    label = get_score_label(score)
    emoji = get_score_emoji(score)

    # Severity counts
    breakdown: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    deduction_detail: List[Dict[str, Any]] = []

    for vuln in vulnerabilities:
        severity = str(vuln.get("severity", "LOW")).upper()
        if severity in breakdown:
            breakdown[severity] += 1
        deduction = SEVERITY_DEDUCTIONS.get(severity, 0)
        deduction_detail.append({
            "tool": vuln.get("tool", "unknown"),
            "severity": severity,
            "type": vuln.get("type", "Unknown"),
            "deduction": deduction,
        })

    return {
        "score": score,
        "label": label,
        "emoji": emoji,
        "total_dependencies": len(dependencies),
        "total_vulnerabilities": len(vulnerabilities),
        "breakdown": breakdown,
        "deduction_detail": deduction_detail,
    }


def get_remediation_priority(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Return vulnerabilities sorted by remediation priority (CRITICAL first).

    Args:
        vulnerabilities: List of vulnerability dicts.

    Returns:
        Sorted list with a 'priority' rank added to each item.
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda v: severity_order.get(str(v.get("severity", "LOW")).upper(), 99),
    )
    return [
        {**v, "priority": i + 1}
        for i, v in enumerate(sorted_vulns)
    ]
