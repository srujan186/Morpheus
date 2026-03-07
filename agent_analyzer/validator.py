"""
Agent Analyzer — Validation Checker
=====================================
Determines whether a tool's source code contains proper input validation
before executing dangerous operations.
"""

import re
from typing import List


# ---------------------------------------------------------------------------
# Pattern constants
# ---------------------------------------------------------------------------

# Patterns that make code dangerous if present without validation
DANGEROUS_PATTERNS: List[str] = [
    "exec(",
    "eval(",
    "subprocess",
    "__import__(",
    "os.system(",
    "compile(",
    "pickle.loads(",
    "yaml.load(",
    "globals(",
    "locals(",
]

# Patterns that indicate the developer added some form of validation or guard
VALIDATION_PATTERNS: List[str] = [
    r"\bif\b",
    r"\bassert\b",
    r"\braise\b",
    r"\btry\b",
    r"\bvalidate\b",
    r"\bsanitize\b",
    r"\bwhitelist\b",
    r"\ballowlist\b",
    r"isinstance\(",
    r"re\.match\(",
    r"re\.fullmatch\(",
    r"re\.search\(",
    r"schema\.validate",
    r"pydantic",
    r"bleach\.",
    r"html\.escape",
]

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_validation(function_code: str) -> bool:
    """
    Determine whether a function's source code includes input validation
    before using dangerous patterns.

    Returns:
        True  — validation is present OR no dangerous patterns exist (safe).
        False — dangerous patterns exist without any validation guard.

    Logic:
        - If NO dangerous patterns → True (nothing to validate)
        - If dangerous patterns present AND validation patterns present → True
        - If dangerous patterns present but NO validation patterns → False
    """
    if not function_code or not function_code.strip():
        return True  # Empty code is not dangerous

    has_danger = _has_dangerous_patterns(function_code)
    if not has_danger:
        return True  # No dangerous calls — nothing to validate

    return _has_validation_patterns(function_code)


def get_dangerous_patterns_found(function_code: str) -> List[str]:
    """
    Return the list of dangerous patterns found in the function code.

    Useful for generating detailed vulnerability reports.

    Args:
        function_code: Raw source code string.

    Returns:
        List of pattern names (without trailing parentheses for readability).
    """
    found: List[str] = []
    for pattern in DANGEROUS_PATTERNS:
        if pattern in function_code:
            # Strip trailing '(' for display (e.g. 'exec(' → 'exec')
            found.append(pattern.rstrip("("))
    return found


def get_validation_patterns_found(function_code: str) -> List[str]:
    """
    Return the list of validation patterns found in the function code.

    Args:
        function_code: Raw source code string.

    Returns:
        List of matched pattern strings.
    """
    found: List[str] = []
    for pattern in VALIDATION_PATTERNS:
        if re.search(pattern, function_code):
            found.append(pattern)
    return found


def explain_validation_result(function_code: str) -> str:
    """
    Return a human-readable explanation of the validation check result.

    Args:
        function_code: Raw source code string.

    Returns:
        Explanation string for use in reports.
    """
    if not function_code.strip():
        return "No code to analyze."

    dangerous = get_dangerous_patterns_found(function_code)
    if not dangerous:
        return "✅ No dangerous operations detected — no validation required."

    validated = _has_validation_patterns(function_code)
    if validated:
        validation = get_validation_patterns_found(function_code)
        return (
            f"⚠️  Dangerous patterns found ({', '.join(dangerous)}) "
            f"but validation guards are present ({', '.join(validation[:3])})."
        )
    return (
        f"🔴 Dangerous patterns found ({', '.join(dangerous)}) "
        f"without any input validation — this is a vulnerability."
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _has_dangerous_patterns(code: str) -> bool:
    """Check if the code contains any dangerous operations."""
    return any(pattern in code for pattern in DANGEROUS_PATTERNS)


def _has_validation_patterns(code: str) -> bool:
    """Check if the code contains any validation/guard patterns."""
    return any(re.search(pattern, code) for pattern in VALIDATION_PATTERNS)
