"""
output_validator.py
Validates sandbox execution results before passing them upstream.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

REQUIRED_RESULT_KEYS = {"executed", "verdict", "summary"}
VALID_VERDICTS = {"SAFE", "SUSPICIOUS", "UNSAFE"}
MAX_OUTPUT_LENGTH = 50_000  # characters


class OutputValidationError(ValueError):
    pass


class OutputValidator:
    def validate_sandbox_result(self, result: dict) -> dict:
        """
        Ensures the sandbox execution result has the expected shape and values.
        """
        if not isinstance(result, dict):
            raise OutputValidationError(
                f"Result must be a dict, got {type(result)}"
            )

        missing = REQUIRED_RESULT_KEYS - result.keys()
        if missing:
            raise OutputValidationError(
                f"Result is missing required keys: {missing}"
            )

        if result["verdict"] not in VALID_VERDICTS:
            raise OutputValidationError(
                f"Invalid verdict: {repr(result['verdict'])}. Must be one of {VALID_VERDICTS}"
            )

        # Truncate oversized output fields
        for field in ("stdout", "stderr", "summary"):
            if field in result and isinstance(result[field], str):
                if len(result[field]) > MAX_OUTPUT_LENGTH:
                    result[field] = result[field][:MAX_OUTPUT_LENGTH] + "\n... [TRUNCATED]"
                    logger.warning(f"Field '{field}' was truncated.")

        logger.info(f"Output validated. Verdict: {result['verdict']}")
        return result

    def is_safe(self, result: dict) -> bool:
        """Quick helper to check if execution was safe."""
        return result.get("verdict") == "SAFE"