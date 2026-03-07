"""
test_validators.py
Tests for input/output validators, signature checker, and allowlist.
Run with: python -m pytest tests/ -v  (from inside morpheus/ folder)
"""

import pytest
from validators.input_validator import InputValidator, InputValidationError
from validators.output_validator import OutputValidator, OutputValidationError
from validators.signature_checker import SignatureChecker, SignatureError
from validators.allowlist import is_module_allowed, is_builtin_allowed


class TestInputValidator:
    validator: InputValidator

    def setup_method(self) -> None:
        self.validator = InputValidator()

    def test_valid_code_passes(self) -> None:
        code = "def add(a, b):\n    return a + b"
        result = self.validator.validate_code_string(code)
        assert result == code.strip()

    def test_rejects_non_string(self) -> None:
        with pytest.raises(InputValidationError):
            self.validator.validate_code_string(12345)  # type: ignore[arg-type]

    def test_rejects_empty(self) -> None:
        with pytest.raises(InputValidationError):
            self.validator.validate_code_string("   ")

    def test_rejects_null_bytes(self) -> None:
        with pytest.raises(InputValidationError):
            self.validator.validate_code_string("code\x00injection")

    def test_rejects_path_traversal(self) -> None:
        with pytest.raises(InputValidationError):
            self.validator.validate_code_string("open('../../etc/passwd')")

    def test_rejects_oversized_code(self) -> None:
        with pytest.raises(InputValidationError):
            self.validator.validate_code_string("x = 1\n" * 5000)

    def test_valid_tool_name(self) -> None:
        assert self.validator.validate_tool_name("my_tool") == "my_tool"

    def test_invalid_tool_name(self) -> None:
        with pytest.raises(InputValidationError):
            self.validator.validate_tool_name("my-tool!")


class TestOutputValidator:
    validator: OutputValidator

    def setup_method(self) -> None:
        self.validator = OutputValidator()

    def test_valid_result_passes(self) -> None:
        result = {"executed": True, "verdict": "SAFE", "summary": "All good."}
        assert self.validator.validate_sandbox_result(result)["verdict"] == "SAFE"

    def test_rejects_non_dict(self) -> None:
        with pytest.raises(OutputValidationError):
            self.validator.validate_sandbox_result("not a dict")  # type: ignore[arg-type]

    def test_rejects_missing_keys(self) -> None:
        with pytest.raises(OutputValidationError):
            self.validator.validate_sandbox_result({"executed": True})

    def test_rejects_invalid_verdict(self) -> None:
        with pytest.raises(OutputValidationError):
            self.validator.validate_sandbox_result({
                "executed": True, "verdict": "MAYBE", "summary": "hmm"
            })

    def test_truncates_large_output(self) -> None:
        result = {"executed": True, "verdict": "SAFE", "summary": "x" * 100_000}
        validated = self.validator.validate_sandbox_result(result)
        assert "[TRUNCATED]" in str(validated["summary"])

    def test_is_safe_helper(self) -> None:
        assert self.validator.is_safe({"verdict": "SAFE"}) is True
        assert self.validator.is_safe({"verdict": "UNSAFE"}) is False


class TestSignatureChecker:
    checker: SignatureChecker

    def setup_method(self) -> None:
        self.checker = SignatureChecker()

    def test_matching_signature_passes(self) -> None:
        def my_tool(code: str, context: str) -> None:
            pass
        assert self.checker.check(my_tool, ["code", "context"]) is True

    def test_wrong_params_raises(self) -> None:
        def my_tool(x: int, y: int) -> None:
            pass
        with pytest.raises(SignatureError):
            self.checker.check(my_tool, ["code", "context"])

    def test_get_signature_info(self) -> None:
        def analyze(code: str) -> None:
            pass
        info = self.checker.get_signature_info(analyze)
        assert info["name"] == "analyze"
        assert info["params"] == ["code"]


class TestAllowlist:
    def test_safe_module_allowed(self) -> None:
        assert is_module_allowed("math") is True
        assert is_module_allowed("json") is True

    def test_blocked_module_denied(self) -> None:
        assert is_module_allowed("subprocess") is False
        assert is_module_allowed("os") is False
        assert is_module_allowed("socket") is False

    def test_unknown_module_denied(self) -> None:
        assert is_module_allowed("some_unknown_lib") is False

    def test_safe_builtin_allowed(self) -> None:
        assert is_builtin_allowed("print") is True
        assert is_builtin_allowed("len") is True

    def test_blocked_builtin_denied(self) -> None:
        assert is_builtin_allowed("exec") is False
        assert is_builtin_allowed("eval") is False
        assert is_builtin_allowed("open") is False