"""
MORPHEUS API Routes
====================
Defines the scan-related HTTP endpoints.
"""

import importlib
import sys
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.orchestrator import get_orchestrator


router = APIRouter(tags=["scan"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Request body for starting a new scan."""
    agent_file: str  # Relative path to the agent Python file, e.g. "demo_agents/vulnerable_agent1.py"


class ScanStartResponse(BaseModel):
    scan_id: str
    message: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    progress: int
    current_step: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan", response_model=ScanStartResponse, summary="Start a security scan")
async def start_scan(request: ScanRequest) -> ScanStartResponse:
    """
    Start a security scan on the given agent file.

    The file will be dynamically imported and the agent object extracted.
    Returns a scan_id that can be used to poll status and retrieve results.
    """
    orchestrator = get_orchestrator()

    # Dynamically load the agent module
    agent_path = Path(request.agent_file)
    if not agent_path.exists():
        raise HTTPException(status_code=404, detail=f"Agent file not found: {request.agent_file}")

    try:
        agent = _load_agent_from_file(agent_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to load agent: {e}")

    scan_id = orchestrator.start_scan(agent)
    return ScanStartResponse(scan_id=scan_id, message="Scan started successfully")


@router.get(
    "/scan/status/{scan_id}",
    response_model=ScanStatusResponse,
    summary="Get scan progress",
)
async def get_scan_status(scan_id: str) -> ScanStatusResponse:
    """
    Get the current status and progress of a scan.
    """
    orchestrator = get_orchestrator()
    status = orchestrator.get_scan_status(scan_id)

    if "error" in status:
        raise HTTPException(status_code=404, detail=status["error"])

    return ScanStatusResponse(
        scan_id=scan_id,
        status=status.get("status", "unknown"),
        progress=status.get("progress", 0),
        current_step=status.get("current_step", ""),
    )


@router.get("/scan/result/{scan_id}", summary="Get full scan report")
async def get_scan_result(scan_id: str) -> Dict[str, Any]:
    """
    Get the full security report for a completed scan.
    Returns 404 if the scan is not found, and 400 if it hasn't completed yet.
    """
    orchestrator = get_orchestrator()
    report = orchestrator.get_scan_report(scan_id)

    if "error" in report:
        status_detail = report.get("error", "Unknown error")
        if "not found" in status_detail.lower():
            raise HTTPException(status_code=404, detail=status_detail)
        raise HTTPException(status_code=400, detail=status_detail)

    return report


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _load_agent_from_file(agent_path: Path) -> Any:
    """
    Dynamically import an agent module and look for a `build_agent()` function.
    Falls back to a mock agent object if the function is not found.
    """
    module_name = agent_path.stem  # e.g. "vulnerable_agent1"

    # Add parent directory to sys.path so the import resolves
    parent = str(agent_path.parent.resolve())
    if parent not in sys.path:
        sys.path.insert(0, parent)

    spec = importlib.util.spec_from_file_location(module_name, str(agent_path.resolve()))
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot find module spec for {agent_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]

    if hasattr(module, "build_agent"):
        return module.build_agent()

    # If the module doesn't have build_agent, return the module itself
    # so the orchestrator/agent_analyzer can still inspect it
    return module
