"""
resource_limiter.py
Enforces CPU, memory, and time limits on sandbox containers.
"""

import logging
import threading
from typing import Any, Callable, Dict

logger = logging.getLogger(__name__)


class ResourceLimiter:
    def __init__(
        self,
        max_memory_mb: int = 256,
        max_cpu_percent: int = 50,
        max_execution_seconds: int = 5,
    ) -> None:
        self.max_memory_mb = max_memory_mb
        self.max_cpu_percent = max_cpu_percent
        self.max_execution_seconds = max_execution_seconds

    def get_container_config(self) -> Dict[str, Any]:
        """Returns Docker container kwargs that enforce resource limits."""
        return {
            "mem_limit": f"{self.max_memory_mb}m",
            "memswap_limit": f"{self.max_memory_mb}m",
            "cpu_quota": int(self.max_cpu_percent * 1000),
            "cpu_period": 100000,
            "pids_limit": 50,
        }

    def check_container_stats(self, container: Any) -> Dict[str, Any]:
        """Reads live container stats. Returns a summary dict."""
        try:
            stats: Dict[str, Any] = container.stats(stream=False)

            mem_usage: int = int(stats["memory_stats"].get("usage", 0))
            mem_limit: int = int(stats["memory_stats"].get("limit", 1))
            mem_mb: float = mem_usage / (1024 * 1024)
            mem_pct: float = (mem_usage / mem_limit) * 100

            cpu_delta: int = (
                stats["cpu_stats"]["cpu_usage"]["total_usage"]
                - stats["precpu_stats"]["cpu_usage"]["total_usage"]
            )
            system_delta: int = (
                stats["cpu_stats"].get("system_cpu_usage", 0)
                - stats["precpu_stats"].get("system_cpu_usage", 0)
            )
            percpu: list = stats["cpu_stats"]["cpu_usage"].get("percpu_usage", [1])
            num_cpus: int = len(percpu)
            cpu_pct: float = (cpu_delta / system_delta) * num_cpus * 100 if system_delta > 0 else 0.0

            over_memory: bool = mem_mb > self.max_memory_mb
            over_cpu: bool = cpu_pct > self.max_cpu_percent

            mem_mb_rounded: float = float(f"{mem_mb:.2f}")
            mem_pct_rounded: float = float(f"{mem_pct:.2f}")
            cpu_pct_rounded: float = float(f"{cpu_pct:.2f}")

            return {
                "memory_usage_mb": mem_mb_rounded,
                "memory_percent": mem_pct_rounded,
                "cpu_percent": cpu_pct_rounded,
                "over_memory_limit": over_memory,
                "over_cpu_limit": over_cpu,
                "limits_exceeded": over_memory or over_cpu,
            }

        except Exception as e:
            logger.warning("Could not read container stats: %s", e)
            return {"error": str(e), "limits_exceeded": False}

    def run_with_timeout(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """
        Runs func(*args, **kwargs) in a thread.
        Raises TimeoutError if it exceeds max_execution_seconds.
        """
        result: Dict[str, Any] = {"value": None, "error": None}

        def target() -> None:
            try:
                result["value"] = func(*args, **kwargs)
            except Exception as exc:
                result["error"] = exc

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(timeout=self.max_execution_seconds)

        if thread.is_alive():
            raise TimeoutError(
                f"Execution exceeded {self.max_execution_seconds}s time limit."
            )

        err = result["error"]
        if isinstance(err, BaseException):
            raise err

        return result["value"]