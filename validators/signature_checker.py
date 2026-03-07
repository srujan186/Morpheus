"""
signature_checker.py
Validates that tool functions match expected signatures before execution.
"""

import inspect
import logging

logger = logging.getLogger(__name__)


class SignatureError(ValueError):
    pass


class SignatureChecker:
    def check(self, func, expected_params: list[str]) -> bool:
        """
        Checks that func has exactly the expected parameter names.
        Raises SignatureError if not.
        """
        sig = inspect.signature(func)
        actual_params = list(sig.parameters.keys())

        if actual_params != expected_params:
            raise SignatureError(
                f"Function '{func.__name__}' has params {actual_params}, "
                f"expected {expected_params}"
            )

        logger.info(f"Signature check passed for '{func.__name__}'")
        return True

    def get_signature_info(self, func) -> dict:
        """Returns a summary of the function's signature."""
        sig = inspect.signature(func)
        return {
            "name": func.__name__,
            "params": list(sig.parameters.keys()),
            "has_return_annotation": sig.return_annotation is not inspect.Parameter.empty,
        }