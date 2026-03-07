"""
cleanup.py
Utility to find and destroy any orphaned sandbox containers.
Run this manually or on startup to ensure a clean state.
"""

import logging
from .docker_manager import SandboxManager

logger = logging.getLogger(__name__)


def cleanup_all_sandboxes():
    """Destroys all running morpheus_sandbox_* containers."""
    manager = SandboxManager()
    active = manager.list_active_sandboxes()

    if not active:
        logger.info("No active sandbox containers found.")
        return

    logger.warning(f"Found {len(active)} orphaned sandbox(es). Cleaning up...")
    for container in active:
        manager.destroy_sandbox(container)
        logger.info(f"Cleaned up: {container.name}")

    logger.info("Cleanup complete.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    cleanup_all_sandboxes()