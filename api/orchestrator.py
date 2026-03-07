"""
MORPHEUS Orchestrator
====================
Coordinates all components and handles integration.
Automatically uses real implementations when available, falls back to mocks.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List
import logging

# Try to import real implementations, fall back to mocks
try:
    from agent_analyzer.discover import AgentAnalyzer
    AGENT_ANALYZER_READY = True
except ImportError:
    from integration_contracts import mock_agent_analyzer
    AGENT_ANALYZER_READY = False

try:
    from adversarial_tester.poison import AdversarialTester
    ADVERSARIAL_TESTER_READY = True
except ImportError:
    from integration_contracts import mock_adversarial_tester
    ADVERSARIAL_TESTER_READY = False

try:
    from sandbox.executor import SandboxExecutor
    SANDBOX_READY = True
except ImportError:
    from integration_contracts import mock_sandbox_executor
    SANDBOX_READY = False

try:
    from llm_analyzer.semantic_checker import LLMAnalyzer
    LLM_ANALYZER_READY = True
except ImportError:
    from integration_contracts import mock_llm_analyzer
    LLM_ANALYZER_READY = False

try:
    from report_generator.generator import ReportGenerator
    REPORT_GENERATOR_READY = True
except ImportError:
    from integration_contracts import mock_report_generator
    REPORT_GENERATOR_READY = False


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class MorpheusOrchestrator:
    """
    Main orchestrator that coordinates all MORPHEUS components.
    Handles the full scan pipeline from agent analysis to report generation.
    """

    def __init__(self) -> None:
        self.scan_status: Dict[str, Any] = {}
        self._log_component_status()

    def _log_component_status(self) -> None:
        """Log which components are real vs mocked."""
        logger.info("🔗 MORPHEUS Component Status:")
        logger.info(f"  Agent Analyzer:      {'✅ REAL' if AGENT_ANALYZER_READY else '🔄 MOCK'}")
        logger.info(f"  Adversarial Tester:  {'✅ REAL' if ADVERSARIAL_TESTER_READY else '🔄 MOCK'}")
        logger.info(f"  Sandbox:             {'✅ REAL' if SANDBOX_READY else '🔄 MOCK'}")
        logger.info(f"  LLM Analyzer:        {'✅ REAL' if LLM_ANALYZER_READY else '🔄 MOCK'}")
        logger.info(f"  Report Generator:    {'✅ REAL' if REPORT_GENERATOR_READY else '🔄 MOCK'}")

    def start_scan(self, agent: Any) -> str:
        """
        Initiate a full security scan of an AI agent.

        Args:
            agent: LangChain AgentExecutor or any object with .tools

        Returns:
            scan_id: Unique identifier for this scan
        """
        scan_id = str(uuid.uuid4())[:8]

        self.scan_status[scan_id] = {
            "status": "running",
            "progress": 0,
            "current_step": "Initializing",
            "started_at": datetime.now().isoformat(),
        }

        logger.info(f"🔍 Starting scan {scan_id}")

        try:
            report = self._run_pipeline(scan_id, agent)
            self.scan_status[scan_id].update({
                "status": "complete",
                "progress": 100,
                "current_step": "Done",
                "completed_at": datetime.now().isoformat(),
                "report": report,
            })
            logger.info(f"✅ Scan {scan_id} complete")

        except Exception as e:
            logger.error(f"❌ Scan {scan_id} failed: {e}")
            self.scan_status[scan_id].update({
                "status": "failed",
                "error": str(e),
            })

        return scan_id

    def _run_pipeline(self, scan_id: str, agent: Any) -> Dict[str, Any]:
        """Execute the full scan pipeline with all components."""

        # Step 1: Discover dependencies (20%)
        self._update_progress(scan_id, 20, "Discovering dependencies")
        dependencies = self._discover_dependencies(agent)
        logger.info(f"  Found {len(dependencies)} dependencies")

        # Step 2: Sandbox validation (40%)
        self._update_progress(scan_id, 40, "Validating in sandbox")
        sandbox_results = self._run_sandbox(dependencies)
        logger.info("  Sandbox analysis complete")

        # Step 3: Adversarial testing (60%)
        self._update_progress(scan_id, 60, "Running adversarial tests")
        vulnerabilities = self._run_adversarial_tests(dependencies)
        logger.info(f"  Found {len(vulnerabilities)} vulnerabilities")

        # Step 4: LLM enrichment (80%)
        self._update_progress(scan_id, 80, "Generating AI analysis")
        enriched_vulns = self._enrich_with_llm(vulnerabilities)
        logger.info("  AI analysis complete")

        # Step 5: Generate report (95%)
        self._update_progress(scan_id, 95, "Generating report")
        report = self._generate_report(scan_id, dependencies, enriched_vulns)
        logger.info("  Report generated")

        return report

    def _discover_dependencies(self, agent: Any) -> List[Dict[str, Any]]:
        """Step 1: Discover what tools/APIs the agent uses."""
        if AGENT_ANALYZER_READY:
            analyzer = AgentAnalyzer(agent)
            return analyzer.discover_tools()
        logger.warning("⚠️  Using mock agent analyzer")
        return mock_agent_analyzer(agent)

    def _run_sandbox(self, dependencies: List[Dict]) -> List[Dict[str, Any]]:
        """Step 2: Run tools in isolated sandbox."""
        if SANDBOX_READY:
            executor = SandboxExecutor()
            return executor.test_tools(dependencies)
        logger.warning("⚠️  Using mock sandbox")
        return mock_sandbox_executor(dependencies)

    def _run_adversarial_tests(self, dependencies: List[Dict]) -> List[Dict[str, Any]]:
        """Step 3: Test with poisoned inputs."""
        if ADVERSARIAL_TESTER_READY:
            tester = AdversarialTester()
            return tester.test_all(dependencies)
        logger.warning("⚠️  Using mock adversarial tester")
        return mock_adversarial_tester(dependencies)

    def _enrich_with_llm(self, vulnerabilities: List[Dict]) -> List[Dict[str, Any]]:
        """Step 4: Add LLM analysis."""
        if LLM_ANALYZER_READY:
            analyzer = LLMAnalyzer()
            return analyzer.enrich(vulnerabilities)
        logger.warning("⚠️  Using mock LLM analyzer")
        return mock_llm_analyzer(vulnerabilities)

    def _generate_report(
        self,
        scan_id: str,
        dependencies: List[Dict],
        vulnerabilities: List[Dict],
    ) -> Dict[str, Any]:
        """Step 5: Create final report."""
        if REPORT_GENERATOR_READY:
            generator = ReportGenerator()
            return generator.create(scan_id, dependencies, vulnerabilities)
        logger.warning("⚠️  Using mock report generator")
        return mock_report_generator(dependencies, vulnerabilities)

    def _update_progress(self, scan_id: str, progress: int, step: str) -> None:
        """Update scan progress."""
        if scan_id in self.scan_status:
            self.scan_status[scan_id].update({"progress": progress, "current_step": step})

    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get current status of a scan."""
        return self.scan_status.get(scan_id, {"error": "Scan not found"})

    def get_scan_report(self, scan_id: str) -> Dict[str, Any]:
        """Get final report for a completed scan."""
        status = self.scan_status.get(scan_id)
        if not status:
            return {"error": "Scan not found"}
        if status["status"] != "complete":
            return {
                "error": f"Scan {status['status']}",
                "current_progress": status.get("progress", 0),
            }
        return status.get("report", {})


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_orchestrator: MorpheusOrchestrator | None = None


def get_orchestrator() -> MorpheusOrchestrator:
    """Get the global orchestrator instance (singleton)."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = MorpheusOrchestrator()
    return _orchestrator
