"""
Agent Analyzer — Tool Discovery
================================
Extracts and analyzes the tools registered on a LangChain agent.

Handles:
  - LangChain AgentExecutor (.tools)
  - StructuredTool, @tool-decorated functions
  - Fallback to module-level tool objects
"""

import ast
import inspect
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agent_analyzer.validator import check_validation, get_dangerous_patterns_found
from agent_analyzer.risk_scorer import build_score_summary


# ---------------------------------------------------------------------------
# Pattern constants
# ---------------------------------------------------------------------------

# Outbound network call patterns
_API_PATTERNS = re.compile(
    r"(?:requests\.(get|post|put|delete|patch)|httpx\.|aiohttp\.|urllib\.request|"
    r"api_endpoint|api_url|endpoint\s*=|base_url)",
    re.IGNORECASE,
)

# Dangerous code patterns that indicate a vulnerability
_RISK_INDICATORS: List[str] = [
    "exec(",
    "eval(",
    "subprocess",
    "__import__(",
    "os.system(",
    "compile(",
    "pickle.loads(",
    "yaml.load(",
    "open(",
    "globals(",
    "locals(",
    "getattr(",
    "setattr(",
]

# Patterns suggesting prompt injection susceptibility
_PROMPT_INJECTION_PATTERNS = re.compile(
    r"(?:system_prompt|ignore.{0,20}previous|override.{0,20}instruction|"
    r"new.{0,20}instruction|disregard|jailbreak)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class AgentAnalyzer:
    """
    Inspects a LangChain AgentExecutor (or any object with a `.tools` list)
    and extracts dependency metadata for each registered tool.

    Usage::

        from agent_analyzer import AgentAnalyzer

        analyzer = AgentAnalyzer(agent_executor)
        dependencies = analyzer.discover_tools()
        summary = analyzer.build_summary(dependencies)
    """

    def __init__(self, agent: Any) -> None:
        """
        Args:
            agent: A LangChain AgentExecutor or any object exposing `.tools`.
        """
        self.agent = agent
        self._scan_timestamp: str = datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover_tools(self) -> List[Dict[str, Any]]:
        """
        Extract metadata for every tool registered on the agent.

        Returns:
            A list of dependency dicts, each with keys:
                - name (str)
                - description (str)
                - function_code (str)
                - has_validation (bool)
                - risk_indicators (list[str])
                - dangerous_patterns (list[str])
                - api_endpoint (str | None)
                - prompt_injection_risk (bool)
                - severity (str): inferred from risk_indicators count
        """
        tools = self._get_tools()
        if not tools:
            return []

        dependencies: List[Dict[str, Any]] = []
        for t in tools:
            dep = self._analyze_tool(t)
            dependencies.append(dep)

        return dependencies

    def build_summary(
        self,
        dependencies: List[Dict[str, Any]],
        vulnerabilities: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Build a high-level scan summary dict from discovered dependencies.

        Args:
            dependencies:    Output of discover_tools().
            vulnerabilities: Optional list of vulnerability dicts from adversarial_tester.

        Returns:
            Dict with scan metadata, risk score, and tool overview.
        """
        vulns = vulnerabilities or self._infer_vulnerabilities(dependencies)
        score_summary = build_score_summary(dependencies, vulns)

        return {
            "scan_timestamp": self._scan_timestamp,
            "tool_count": len(dependencies),
            "tools": [
                {
                    "name": d["name"],
                    "severity": d["severity"],
                    "has_validation": d["has_validation"],
                    "risk_indicators": d["risk_indicators"],
                    "api_endpoint": d["api_endpoint"],
                    "prompt_injection_risk": d["prompt_injection_risk"],
                }
                for d in dependencies
            ],
            **score_summary,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_tools(self) -> List[Any]:
        """Retrieve the tool list from the agent, handling common structures."""
        # LangChain AgentExecutor exposes .tools directly
        if hasattr(self.agent, "tools") and isinstance(self.agent.tools, list):
            return self.agent.tools

        # Some chain objects expose .agent.tools
        if hasattr(self.agent, "agent") and hasattr(self.agent.agent, "tools"):
            tools = self.agent.agent.tools
            if isinstance(tools, list):
                return tools

        # Module-level: look for objects with a 'name' and 'description'
        if hasattr(self.agent, "__dict__"):
            candidates = []
            for val in vars(self.agent).values():
                if hasattr(val, "name") and hasattr(val, "description"):
                    candidates.append(val)
            if candidates:
                return candidates

        return []

    def _analyze_tool(self, tool: Any) -> Dict[str, Any]:
        """Build a complete dependency dict for a single tool."""
        name = self._get_tool_name(tool)
        description = self._get_tool_description(tool)
        source = self._get_source_code(tool)

        risk_indicators = self._find_risk_indicators(source)
        dangerous_patterns = get_dangerous_patterns_found(source)
        has_validation = check_validation(source)
        api_endpoint = self._find_api_endpoint(source, tool)
        prompt_injection_risk = self._check_prompt_injection(source)
        severity = self._infer_severity(risk_indicators, has_validation, prompt_injection_risk)

        return {
            "name": name,
            "description": description,
            "function_code": source,
            "has_validation": has_validation,
            "risk_indicators": risk_indicators,
            "dangerous_patterns": dangerous_patterns,
            "api_endpoint": api_endpoint,
            "prompt_injection_risk": prompt_injection_risk,
            "severity": severity,
        }

    def _get_tool_name(self, tool: Any) -> str:
        """Extract a human-readable name from a tool object."""
        for attr in ("name", "__name__"):
            val = getattr(tool, attr, None)
            if val and isinstance(val, str):
                return val
        return type(tool).__name__

    def _get_tool_description(self, tool: Any) -> str:
        """Extract the tool's description if available."""
        for attr in ("description", "__doc__"):
            val = getattr(tool, attr, None)
            if val and isinstance(val, str):
                # Return first non-empty line of docstring
                first_line = val.strip().splitlines()[0].strip()
                if first_line:
                    return first_line
        return "No description available."

    def _get_source_code(self, tool: Any) -> str:
        """Try to retrieve source code for the tool's underlying function."""
        # LangChain @tool-decorated functions expose func or coroutine
        for attr in ("func", "coroutine", "run", "__wrapped__"):
            fn = getattr(tool, attr, None)
            if callable(fn):
                try:
                    return inspect.getsource(fn)
                except (OSError, TypeError):
                    pass

        # Fallback: inspect the tool object itself
        try:
            return inspect.getsource(tool)
        except (OSError, TypeError):
            pass

        # Last resort: try the tool's class
        try:
            return inspect.getsource(type(tool))
        except (OSError, TypeError):
            pass

        return f"# Source unavailable for '{self._get_tool_name(tool)}'"

    def _find_risk_indicators(self, source: str) -> List[str]:
        """Return a list of dangerous patterns found in the source code."""
        return [ind for ind in _RISK_INDICATORS if ind in source]

    def _find_api_endpoint(self, source: str, tool: Any) -> Optional[str]:
        """Try to extract an API endpoint URL from source code or tool attributes."""
        # Check for a url/endpoint attribute on the tool object
        for attr in ("api_endpoint", "url", "base_url", "endpoint"):
            value = getattr(tool, attr, None)
            if value and isinstance(value, str) and value.startswith("http"):
                return value

        # Try to find a URL string literal in the source
        url_match = re.search(r'["\']((https?://)[^\s"\'<>]+)["\']', source)
        if url_match:
            return url_match.group(1)

        # If the source uses requests/http without a visible literal
        if _API_PATTERNS.search(source):
            return "dynamic (resolved at runtime)"

        return None

    def _check_prompt_injection(self, source: str) -> bool:
        """Return True if the source code shows signs of prompt injection risk."""
        # Risk if: source passes external content directly to LLM without sanitization
        passes_raw = bool(re.search(
            r"(?:response\.text|\.content|raw_html|fetched|html|page_content)",
            source,
            re.IGNORECASE,
        ))
        has_injection_terms = bool(_PROMPT_INJECTION_PATTERNS.search(source))
        return passes_raw or has_injection_terms

    def _infer_severity(
        self,
        risk_indicators: List[str],
        has_validation: bool,
        prompt_injection_risk: bool,
    ) -> str:
        """Infer a severity label from the risk profile of a tool."""
        critical_indicators = {"exec(", "eval(", "__import__(", "os.system(", "compile(", "pickle.loads("}
        has_critical = bool(critical_indicators & set(risk_indicators))

        if has_critical and not has_validation:
            return "CRITICAL"
        elif has_critical and has_validation:
            return "HIGH"
        elif risk_indicators and not has_validation:
            return "HIGH"
        elif prompt_injection_risk and not has_validation:
            return "MEDIUM"
        elif risk_indicators:
            return "MEDIUM"
        elif prompt_injection_risk:
            return "LOW"
        return "SAFE"

    def _infer_vulnerabilities(self, dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Infer a basic vulnerability list from dependency metadata.
        Used when no external adversarial_tester output is provided.
        """
        vulns: List[Dict[str, Any]] = []

        for dep in dependencies:
            if dep["severity"] in ("CRITICAL", "HIGH"):
                vuln_type = "Code Injection" if dep["dangerous_patterns"] else "Unsafe Operation"
                vulns.append({
                    "tool": dep["name"],
                    "severity": dep["severity"],
                    "type": vuln_type,
                    "description": (
                        f"Tool '{dep['name']}' uses dangerous patterns "
                        f"({', '.join(dep['dangerous_patterns'] or dep['risk_indicators'])}) "
                        f"without adequate validation."
                    ),
                    "proof": ", ".join(dep["risk_indicators"][:3]),
                    "recommendation": (
                        "Add strict input validation before executing dynamic code or "
                        "calling external APIs. Use allowlists where possible."
                    ),
                })
            elif dep["prompt_injection_risk"] and not dep["has_validation"]:
                vulns.append({
                    "tool": dep["name"],
                    "severity": "MEDIUM",
                    "type": "Indirect Prompt Injection",
                    "description": (
                        f"Tool '{dep['name']}' passes external/fetched content directly "
                        "to the LLM without sanitization, enabling prompt injection."
                    ),
                    "proof": "External content fed to LLM as trusted input.",
                    "recommendation": (
                        "Sanitize external content before including it in LLM prompts. "
                        "Never treat third-party data as trusted instructions."
                    ),
                })

        return vulns
