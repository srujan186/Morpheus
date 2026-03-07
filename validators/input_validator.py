"""
input_validator.py
Validates and sanitizes inputs before they are passed to tool functions.
"""

import re
import logging
from typing import Any

logger = logging.getLogger(__name__)

MAX_CODE_LENGTH = 10_000  # characters
FORBIDDEN_SUBSTRINGS = [
    "\x00",       # Null bytes
    "\\x00",      # Escaped null bytes
    "../../",     # Path traversal
    "/etc/passwd",
    "/etc/shadow",
]


class InputValidationError(ValueError):
    pass


class InputValidator:
    def validate_code_string(self, code: str) -> str:
        """
        Validates a code string before sandbox execution.
        Returns the sanitized code or raises InputValidationError.
        """
        if not isinstance(code, str):
            raise InputValidationError(f"Code must be a string, got {type(code)}")

        if len(code) > MAX_CODE_LENGTH:
            raise InputValidationError(
                f"Code exceeds max length ({len(code)} > {MAX_CODE_LENGTH} chars)"
            )

        if not code.strip():
            raise InputValidationError("Code is empty.")

        for forbidden in FORBIDDEN_SUBSTRINGS:
            if forbidden in code:
                raise InputValidationError(
                    f"Code contains forbidden pattern: {repr(forbidden)}"
                )

        logger.info("Code input passed validation.")
        return code.strip()

    def validate_tool_name(self, name: str) -> str:
        """Tool names must be valid Python identifiers."""
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
            raise InputValidationError(
                f"Invalid tool name: {repr(name)}. Must be a valid Python identifier."
            )
        return name

    def validate_generic(self, value: Any, expected_type: type, field_name: str) -> Any:
        """Generic type check for any input field."""
        if not isinstance(value, expected_type):
            raise InputValidationError(
                f"Field '{field_name}' expected {expected_type.__name__}, got {type(value).__name__}"
            )
        return value