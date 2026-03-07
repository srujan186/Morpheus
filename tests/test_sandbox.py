"""
test_sandbox.py
Tests for the sandbox execution environment.
Run with: python -m pytest tests/ -v  (from inside morpheus/ folder)
"""

import pytest
from unittest.mock import MagicMock, patch
from sandbox.monitor import BehaviorMonitor
from sandbox.resource_limiter import ResourceLimiter


class TestBehaviorMonitor:
    monitor: BehaviorMonitor

    def setup_method(self) -> None:
        self.monitor = BehaviorMonitor()

    def test_detects_exec(self) -> None:
        report = self.monitor.detect_dangerous_patterns("exec(user_input)")
        assert report.verdict == "UNSAFE"
        assert any(f.pattern == "exec()" for f in report.dangerous_calls)

    def test_detects_eval(self) -> None:
        report = self.monitor.detect_dangerous_patterns("result = eval('1+1')")
        assert report.verdict == "UNSAFE"

    def test_detects_subprocess(self) -> None:
        report = self.monitor.detect_dangerous_patterns("import subprocess\nsubprocess.run(['ls'])")
        assert report.verdict == "UNSAFE"

    def test_detects_network_import(self) -> None:
        report = self.monitor.detect_dangerous_patterns("import requests\nrequests.get('http://evil.com')")
        assert report.network_access is True

    def test_detects_file_access(self) -> None:
        report = self.monitor.detect_dangerous_patterns("f = open('/etc/passwd', 'r')")
        assert report.file_access is True

    def test_safe_code_passes(self) -> None:
        report = self.monitor.detect_dangerous_patterns("result = sum([1, 2, 3])\nprint(result)")
        assert report.verdict == "SAFE"
    # AST layer flags print() as LOW severity — verdict stays SAFE
    # Only HIGH/MEDIUM findings affect the verdict
        high_or_medium = [f for f in report.dangerous_calls if f.severity in ("HIGH", "MEDIUM")]
        assert len(high_or_medium) == 0

    def test_skips_comments(self) -> None:
        report = self.monitor.detect_dangerous_patterns("# exec(dangerous_thing)\nresult = 1 + 1")
        assert report.verdict == "SAFE"

    def test_detects_dunder_import(self) -> None:
        report = self.monitor.detect_dangerous_patterns("mod = __import__('os')")
        assert report.verdict == "UNSAFE"

    def test_runtime_output_network_flag(self) -> None:
        result = self.monitor.analyze_runtime_output("", "socket.gaierror: [Errno -2]")
        assert result["has_runtime_warnings"] is True

    def test_runtime_output_clean(self) -> None:
        result = self.monitor.analyze_runtime_output("6\n", "")
        assert result["has_runtime_warnings"] is False


class TestResourceLimiter:
    limiter: ResourceLimiter

    def setup_method(self) -> None:
        self.limiter = ResourceLimiter(max_execution_seconds=1)

    def test_timeout_raises(self) -> None:
        import time
        with pytest.raises(TimeoutError):
            self.limiter.run_with_timeout(time.sleep, 5)

    def test_fast_function_completes(self) -> None:
        result = self.limiter.run_with_timeout(lambda: 42)
        assert result == 42

    def test_container_config_keys(self) -> None:
        config = self.limiter.get_container_config()
        assert "mem_limit" in config
        assert "cpu_quota" in config
        assert "pids_limit" in config


class TestExecuteSafely:
    @patch("sandbox.executor.sandbox_manager")
    @patch("sandbox.executor.resource_limiter")
    def test_unsafe_code_skips_execution(
        self, mock_limiter: MagicMock, mock_sandbox: MagicMock
    ) -> None:
        from sandbox.executor import execute_safely
        result = execute_safely("exec(open('/etc/passwd').read())")
        assert result["verdict"] == "UNSAFE"
        mock_sandbox.create_sandbox.assert_not_called()

    @patch("sandbox.executor.sandbox_manager")
    @patch("sandbox.executor.resource_limiter")
    def test_safe_code_executes(
        self, mock_limiter: MagicMock, mock_sandbox: MagicMock
    ) -> None:
        from sandbox.executor import execute_safely
        mock_container = MagicMock()
        mock_sandbox.create_sandbox.return_value = mock_container
        mock_limiter.run_with_timeout.return_value = (0, "6\n", "")
        mock_limiter.check_container_stats.return_value = {
            "cpu_percent": 5.0,
            "memory_usage_mb": 32.0,
            "limits_exceeded": False,
        }
        result = execute_safely("print(2 + 4)")
        assert result["executed"] is True
        assert result["verdict"] == "SAFE"
        mock_sandbox.destroy_sandbox.assert_called_once_with(mock_container)