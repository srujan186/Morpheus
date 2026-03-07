"""
executor.py
Main entry point: safely executes tool code inside an isolated Docker container.
"""

import logging
import time
from typing import Any, Dict, List

from .docker_manager import SandboxManager
from .monitor import BehaviorMonitor
from .resource_limiter import ResourceLimiter

logger = logging.getLogger(__name__)

sandbox_manager = SandboxManager()
monitor = BehaviorMonitor()
resource_limiter = ResourceLimiter()


def execute_safely(tool_code: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Executes tool_code in an isolated Docker sandbox.
    Returns a full report dict with verdict, findings, and resource usage.
    """
    logger.info("Running static analysis...")
    static_report = monitor.detect_dangerous_patterns(tool_code)

    dangerous: List[Dict[str, Any]] = [vars(f) for f in static_report.dangerous_calls]
    runtime_flags: List[str] = []

    result: Dict[str, Any] = {
        "executed": False,
        "dangerous_calls": dangerous,
        "network_access": static_report.network_access,
        "file_access": static_report.file_access,
        "suspicious_imports": static_report.suspicious_imports,
        "cpu_usage": "N/A",
        "memory_usage": "N/A",
        "stdout": "",
        "stderr": "",
        "runtime_flags": runtime_flags,
        "verdict": static_report.verdict,
        "summary": static_report.summary,
    }

    high_severity = [f for f in static_report.dangerous_calls if f.severity == "HIGH"]
    if high_severity:
        logger.warning("HIGH severity issues found. Skipping execution.")
        result["summary"] = str(result["summary"]) + " | Execution skipped due to HIGH severity findings."
        return result

    if not sandbox_manager.is_available:
        logger.warning("Docker sandbox unavailable. Skipping dynamic execution.")
        result["summary"] = str(result["summary"]) + " | Execution skipped (Docker unavailable)."
        return result

    logger.info("Creating sandbox container...")
    container = sandbox_manager.create_sandbox()

    try:
        logger.info("Executing code in sandbox...")
        start_time = time.time()

        try:
            execution_result = resource_limiter.run_with_timeout(
                sandbox_manager.execute_code,
                container,
                tool_code,
                timeout=timeout,
            )
            exit_code: int = int(execution_result[0])
            stdout: str = str(execution_result[1])
            stderr: str = str(execution_result[2])
            elapsed: float = time.time() - start_time

            result["executed"] = True
            result["stdout"] = stdout
            result["stderr"] = stderr
            result["exit_code"] = exit_code
            result["execution_time_seconds"] = elapsed

        except TimeoutError as e:
            result["executed"] = False
            result["verdict"] = "UNSAFE"
            result["summary"] = f"UNSAFE - {e}"
            logger.error("Execution timed out: %s", e)
            return result

        stats = resource_limiter.check_container_stats(container)
        result["cpu_usage"] = f"{stats.get('cpu_percent', 'N/A')}%"
        result["memory_usage"] = f"{stats.get('memory_usage_mb', 'N/A')}MB"

        runtime_analysis = monitor.analyze_runtime_output(
            str(result["stdout"]), str(result["stderr"])
        )
        result["runtime_flags"] = runtime_analysis["runtime_flags"]

        if runtime_analysis["has_runtime_warnings"] and result["verdict"] == "SAFE":
            result["verdict"] = "SUSPICIOUS"
            result["summary"] = str(result["summary"]) + " | Runtime activity flagged."

    finally:
        logger.info("Destroying sandbox container...")
        sandbox_manager.destroy_sandbox(container)

    logger.info("Execution complete. Verdict: %s", result["verdict"])
    return result


class SandboxExecutor:
    """
    Class wrapper around execute_safely() so the orchestrator can import it
    as `from sandbox.executor import SandboxExecutor`.
    """

    def test_tools(self, dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Run each tool in the dependency list through the sandbox.
        Returns a list of result dicts, one per tool.
        """
        results = []
        for dep in dependencies:
            tool_name = dep.get("name", "unknown")
            tool_code = dep.get("function_code", "")
            if not tool_code:
                results.append({
                    "tool": tool_name,
                    "executed": False,
                    "verdict": "SKIPPED",
                    "summary": "No source code available",
                })
                continue
            logger.info("[SandboxExecutor] Testing tool: %s", tool_name)
            result = execute_safely(tool_code)
            result["tool"] = tool_name
            results.append(result)
        return results