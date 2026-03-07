"""
Adversarial Tester — Poison (Main Tester)
==========================================
Orchestrates adversarial testing of a discovered agent's tools.

Takes the dependency list from agent_analyzer and runs each tool
through relevant attack payloads to produce a vulnerability report.

Usage::

    from adversarial_tester import AdversarialTester

    tester = AdversarialTester(dependencies)
    vulnerabilities = tester.run()

Input (dependencies) format — matches agent_analyzer.discover_tools() output:
    [
        {
            "name": "web_search",
            "function_code": "...",
            "has_validation": False,
            "risk_indicators": ["requests.get"],
            "api_endpoint": "https://...",
            "prompt_injection_risk": True,
            "severity": "HIGH",
        },
        ...
    ]

Output (vulnerabilities) format — matches integration_contracts.Vulnerability:
    [
        {
            "tool": "web_search",
            "severity": "HIGH",
            "type": "Indirect Prompt Injection",
            "description": "...",
            "proof": "...",
            "recommendation": "...",
        },
        ...
    ]
"""

from typing import Any, Dict, List

from adversarial_tester.payloads import get_payloads_for_tool, PROMPT_INJECTION_PAYLOADS
from adversarial_tester.executor import SafeExecutor


# ---------------------------------------------------------------------------
# Recommendations library
# ---------------------------------------------------------------------------

_RECOMMENDATIONS: Dict[str, str] = {
    "Code Injection": (
        "Never pass LLM-generated or external API responses to exec(), eval(), or "
        "compile(). Use an allowlist of permitted operations. If dynamic code "
        "execution is required, run it in a sandboxed Docker container."
    ),
    "Indirect Prompt Injection": (
        "Sanitize all external content before including it in LLM prompts. "
        "Strip HTML comments, hidden elements, and invisible text. "
        "Treat third-party data as UNTRUSTED — never as instructions."
    ),
    "Data Exfiltration": (
        "Block outbound network calls from tool execution context. "
        "Use egress filtering and restrict tool network access to an allowlist of "
        "known-good domains. Never exec() API responses."
    ),
    "Supply Chain Poisoning": (
        "Validate API responses against a strict schema before use. "
        "Pin third-party API versions and checksums. "
        "Use yaml.safe_load() instead of yaml.load(). "
        "Never deserialize untrusted pickle data."
    ),
    "default": (
        "Apply strict input validation and use an allowlist approach. "
        "Isolate tool execution in a sandboxed environment."
    ),
}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class AdversarialTester:
    """
    Tests a list of tool dependencies against a curated attack payload library.

    Uses SafeExecutor (static AST analysis) to determine if each tool is
    exploitable — without executing any malicious code.
    """

    def __init__(
        self,
        dependencies: List[Dict[str, Any]],
        stop_on_first: bool = False,
    ) -> None:
        """
        Args:
            dependencies:  Output of AgentAnalyzer.discover_tools().
            stop_on_first: If True, stop testing each tool after its first
                           confirmed vulnerability (faster but less complete).
        """
        self.dependencies = dependencies
        self.stop_on_first = stop_on_first
        self._executor = SafeExecutor()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> List[Dict[str, Any]]:
        """
        Run adversarial tests on all discovered tools.

        Returns:
            List of vulnerability dicts, each with:
                tool, severity, type, description, proof, recommendation
        """
        vulnerabilities: List[Dict[str, Any]] = []

        for dep in self.dependencies:
            tool_vulns = self._test_tool(dep)
            vulnerabilities.extend(tool_vulns)

        # Deduplicate by (tool, type) — keep highest severity
        return self._deduplicate(vulnerabilities)

    def run_on_tool(self, tool_name: str) -> List[Dict[str, Any]]:
        """
        Run adversarial tests on a single named tool.

        Args:
            tool_name: Name of the tool to test.

        Returns:
            List of vulnerability dicts for that tool only.
        """
        dep = next((d for d in self.dependencies if d.get("name") == tool_name), None)
        if dep is None:
            return []
        return self._test_tool(dep)

    # ------------------------------------------------------------------
    # Private methods
    # ------------------------------------------------------------------

    def _test_tool(self, dep: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run all relevant payloads against a single tool dependency."""
        source = dep.get("function_code", "")
        tool_name = dep.get("name", "unknown")
        risk_indicators = dep.get("risk_indicators", [])
        prompt_injection_risk = dep.get("prompt_injection_risk", False)

        # Get payloads relevant to this tool's risk profile
        payloads = get_payloads_for_tool(risk_indicators)

        # Always test for prompt injection if the tool fetches external content
        if prompt_injection_risk:
            # Add prompt injection payloads if not already included
            pi_names = {p["name"] for p in PROMPT_INJECTION_PAYLOADS}
            existing_names = {p["name"] for p in payloads}
            for p in PROMPT_INJECTION_PAYLOADS:
                if p["name"] not in existing_names:
                    payloads.append(p)

        tool_vulns: List[Dict[str, Any]] = []

        for payload in payloads:
            result = self._executor.run(source, payload)

            if result["vulnerable"]:
                vuln = self._build_vulnerability(
                    tool_name=tool_name,
                    payload=payload,
                    result=result,
                )
                tool_vulns.append(vuln)

                if self.stop_on_first:
                    break

        return tool_vulns

    def _build_vulnerability(
        self,
        tool_name: str,
        payload: Dict[str, Any],
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build a vulnerability dict from a confirmed finding."""
        attack_type = payload["attack_type"]
        recommendation = _RECOMMENDATIONS.get(attack_type, _RECOMMENDATIONS["default"])

        confidence = result.get("confidence", "MEDIUM")
        severity = payload["severity"]

        # Downgrade severity if confidence is low
        if confidence == "LOW" and severity == "CRITICAL":
            severity = "HIGH"

        return {
            "tool":           tool_name,
            "severity":       severity,
            "type":           attack_type,
            "description":    payload["description"],
            "proof":          result.get("evidence", payload["payload"]),
            "recommendation": recommendation,
            # Extra fields for richer reports
            "payload_name":   payload["name"],
            "payload_used":   payload["payload"],
            "confidence":     confidence,
            "analysis":       result.get("analysis", ""),
        }

    def _deduplicate(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Remove duplicate (tool, type) findings, keeping the highest severity.
        """
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        seen: Dict[tuple, Dict[str, Any]] = {}

        for vuln in vulnerabilities:
            key = (vuln["tool"], vuln["type"])
            if key not in seen:
                seen[key] = vuln
            else:
                existing_rank = severity_rank.get(seen[key]["severity"], 0)
                new_rank = severity_rank.get(vuln["severity"], 0)
                if new_rank > existing_rank:
                    seen[key] = vuln

        # Sort: CRITICAL first
        return sorted(
            seen.values(),
            key=lambda v: severity_rank.get(v["severity"], 0),
            reverse=True,
        )


# ---------------------------------------------------------------------------
# Convenience function (matches integration_contracts interface)
# ---------------------------------------------------------------------------

def run_adversarial_tests(
    dependencies: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Convenience function matching the integration_contracts interface.

    Args:
        dependencies: Output of agent_analyzer.AgentAnalyzer.discover_tools()

    Returns:
        List of vulnerability dicts.
    """
    tester = AdversarialTester(dependencies)
    return tester.run()
