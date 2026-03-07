"""
docker_manager.py
Spins up and tears down isolated Docker containers for safe code execution.
"""

import logging
import uuid
from typing import Any, List, Tuple

logger = logging.getLogger(__name__)


class SandboxManager:
    def __init__(self) -> None:
        try:
            import docker  # type: ignore[import-untyped]
            self.client = docker.from_env()
            logger.info("Docker client initialized successfully.")
        except Exception as e:
            logger.error("Failed to connect to Docker daemon: %s", e)
            raise

    def create_sandbox(self) -> Any:
        """
        Spins up a new isolated Python container.
        - No network access
        - Limited memory and CPU
        """
        import docker  # type: ignore[import-untyped]
        container_name = f"morpheus_sandbox_{uuid.uuid4().hex[:8]}"

        container = self.client.containers.run(
            "python:3.10-slim",
            command="sleep infinity",
            name=container_name,
            detach=True,
            network_mode="none",
            mem_limit="256m",
            cpu_quota=50000,
            read_only=False,
            tmpfs={"/tmp": "size=64m"},
            security_opt=["no-new-privileges"],
            remove=False,
        )

        logger.info("Sandbox container created: %s", container_name)
        return container

    def execute_code(self, container: Any, code: str, timeout: int = 5) -> Tuple[int, str, str]:
        """
        Executes a Python code string inside the given container.
        Returns (exit_code, stdout, stderr).
        """
        container.exec_run(
            ["bash", "-c", f"cat > /tmp/user_code.py << 'MORPHEUS_EOF'\n{code}\nMORPHEUS_EOF"],
        )

        exec_result = container.exec_run(
            ["python", "/tmp/user_code.py"],
            demux=True,
        )

        raw_out, raw_err = exec_result.output
        stdout = raw_out.decode() if raw_out else ""
        stderr = raw_err.decode() if raw_err else ""

        return int(exec_result.exit_code), stdout, stderr

    def destroy_sandbox(self, container: Any) -> None:
        """Stops and removes the container. Always called in a finally block."""
        try:
            container.stop(timeout=2)
            container.remove(force=True)
            logger.info("Sandbox container %s destroyed.", container.name)
        except Exception as e:
            logger.warning("Error destroying container %s: %s", container.name, e)

    def list_active_sandboxes(self) -> List[Any]:
        """Lists all currently running morpheus sandbox containers."""
        return [
            c for c in self.client.containers.list()
            if c.name.startswith("morpheus_sandbox_")
        ]

    def emergency_cleanup(self) -> None:
        """Kill all active sandbox containers."""
        for container in self.list_active_sandboxes():
            self.destroy_sandbox(container)
            logger.warning("Emergency cleanup: destroyed %s", container.name)