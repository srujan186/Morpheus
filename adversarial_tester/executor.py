"""
Adversarial Tester — Safe Payload Executor
============================================
Performs STATIC analysis of tool source code against attack payloads.

IMPORTANT: This module does NOT execute malicious payloads at runtime.
It uses AST-based static analysis to determine whether a tool's code
is VULNERABLE to each payload — safely, without side effects.

Design principles:
  - Zero execution of dangerous code
  - AST parsing for structural analysis
  - Pattern matching for heuristic checks
  - Sandboxed subprocess for optional dynamic probing (future)
"""

import ast
import re
import textwrap
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Result dataclass-style dict keys
# ---------------------------------------------------------------------------
#
# ExecutionResult dict keys:
#   vulnerable   (bool)          : True if tool appears vulnerable
#   evidence     (str)           : What was found in the code
#   payload_hit  (str)           : The payload that triggered the finding
#   analysis     (str)           : Explanation of the analysis
#   confidence   (str)           : HIGH / MEDIUM / LOW


class SafeExecutor:
    """
    Statically analyses tool source code to determine if it is vulnerable
    to a given attack payload.

    All checks are purely analytical — no dangerous code is ever run.
    """

    # ------------------------------------------------------------------
    # Public dispatch method
    # ------------------------------------------------------------------

    def run(
        self,
        tool_source: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Run the appropriate check for the given payload.

        Args:
            tool_source: Raw source code of the tool function.
            payload:     A payload dict from payloads.py.

        Returns:
            ExecutionResult dict.
        """
        check_fn_name = payload.get("check_fn", "check_exec_vulnerability")
        check_fn = getattr(self, check_fn_name, self._unknown_check)
        return check_fn(tool_source, payload)

    # ------------------------------------------------------------------
    # Check functions
    # ------------------------------------------------------------------

    def check_exec_vulnerability(
        self,
        source: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Check if the source code is vulnerable to code injection via
        exec(), eval(), compile(), or similar dangerous calls on
        unvalidated external input.

        Strategy:
          1. Parse AST and find all exec/eval/compile call nodes
          2. Check if the arguments to those calls are external/dynamic values
             (variables, function calls) rather than string literals
          3. Check for absence of validation before the dangerous call
        """
        if not source.strip():
            return self._safe_result("Empty source — nothing to test.")

        tree = self._parse_ast(source)
        if tree is None:
            # AST parse failed — fall back to pattern matching
            return self._pattern_based_exec_check(source, payload)

        dangerous_calls = self._find_dangerous_ast_calls(tree)
        if not dangerous_calls:
            return self._safe_result(
                "No exec/eval/compile/pickle calls found in source.",
                payload=payload,
            )

        # Check if validation precedes the dangerous call
        has_guard = self._ast_has_validation_guard(tree)
        external_input = self._ast_uses_external_input(tree)

        if external_input and not has_guard:
            return self._vuln_result(
                evidence=f"Dangerous call(s): {', '.join(dangerous_calls)} "
                         f"on unvalidated external input.",
                payload=payload,
                confidence="HIGH",
            )

        if dangerous_calls and not has_guard:
            return self._vuln_result(
                evidence=f"Dangerous call(s): {', '.join(dangerous_calls)} "
                         f"without validation guards.",
                payload=payload,
                confidence="MEDIUM",
            )

        return self._safe_result(
            f"Dangerous call(s) present but validation guard detected. "
            f"Payload likely blocked.",
            payload=payload,
        )

    def check_prompt_injection_vulnerability(
        self,
        source: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Check if the source code is vulnerable to indirect prompt injection.

        A tool is vulnerable if:
          - It fetches external content (HTTP requests, file reads)
          - AND passes that content directly to the LLM context
          - WITHOUT sanitizing HTML comments, hidden text, or hidden elements
        """
        if not source.strip():
            return self._safe_result("Empty source — nothing to test.")

        # Evidence of fetching external content
        fetches_external = bool(re.search(
            r"requests\.(get|post)|urllib\.request|httpx\.|aiohttp\.",
            source,
        ))

        # Evidence of passing raw HTML/content to LLM
        passes_raw = bool(re.search(
            r"(?:response\.text|\.content|raw_html|page_source|html_content)",
            source,
            re.IGNORECASE,
        ))

        # Evidence of sanitization
        sanitizes = bool(re.search(
            r"(?:bleach\.|html\.escape|BeautifulSoup|sanitize|strip_tags|"
            r"re\.sub.*<!--.*-->|lxml|markupsafe)",
            source,
            re.IGNORECASE,
        ))

        # HTML comments intentionally kept (our specific vulnerability pattern)
        keeps_comments = bool(re.search(
            r"#.*comment.*kept|#.*intentionally.*kept|#.*VULNERABLE",
            source,
            re.IGNORECASE,
        ))

        if (fetches_external or passes_raw) and not sanitizes:
            evidence_parts = []
            if fetches_external:
                evidence_parts.append("fetches external content via HTTP")
            if passes_raw:
                evidence_parts.append("passes raw response.text to LLM context")
            if keeps_comments:
                evidence_parts.append("explicitly keeps HTML comments (attack vector)")

            return self._vuln_result(
                evidence="Prompt injection path: " + "; ".join(evidence_parts) + ".",
                payload=payload,
                confidence="HIGH" if keeps_comments else "MEDIUM",
            )

        if fetches_external and sanitizes:
            return self._safe_result(
                "External content is fetched but sanitization is present.",
                payload=payload,
            )

        return self._safe_result(
            "No external content fetching detected — prompt injection unlikely.",
            payload=payload,
        )

    # ------------------------------------------------------------------
    # AST helpers
    # ------------------------------------------------------------------

    def _parse_ast(self, source: str) -> Optional[ast.Module]:
        """Attempt to parse source as an AST. Returns None on failure."""
        try:
            # Dedent first in case it's a method body
            return ast.parse(textwrap.dedent(source))
        except SyntaxError:
            return None

    def _find_dangerous_ast_calls(self, tree: ast.Module) -> List[str]:
        """Return names of dangerous built-in calls found in the AST."""
        DANGEROUS = {"exec", "eval", "compile", "__import__", "getattr", "setattr"}
        DANGEROUS_ATTR = {"loads"}  # pickle.loads, yaml.loads

        found: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Direct call: exec(...)
                if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS:
                    found.append(node.func.id)
                # Attribute call: pickle.loads(...), yaml.load(...)
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr in DANGEROUS_ATTR:
                        found.append(f"{ast.unparse(node.func)}")
                    elif node.func.attr == "system":
                        found.append("os.system")
        return list(set(found))

    def _ast_has_validation_guard(self, tree: ast.Module) -> bool:
        """Return True if the AST contains if-checks, try/except, or assert before dangerous calls."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.Try, ast.Assert)):
                return True
        return False

    def _ast_uses_external_input(self, tree: ast.Module) -> bool:
        """Return True if the tool appears to receive and use external/dynamic input."""
        for node in ast.walk(tree):
            # Function has parameters (receives input)
            if isinstance(node, ast.FunctionDef) and node.args.args:
                return True
            # Uses requests, urllib, etc.
            if isinstance(node, ast.Attribute):
                if node.attr in ("get", "post", "request", "urlopen"):
                    return True
        return False

    def _pattern_based_exec_check(self, source: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback pattern-based check when AST parse fails."""
        dangerous_patterns = ["exec(", "eval(", "compile(", "__import__(", "os.system("]
        validation_patterns = [r"\bif\b", r"\btry\b", r"\bassert\b", r"\bvalidate\b"]

        has_danger = any(p in source for p in dangerous_patterns)
        has_validation = any(re.search(p, source) for p in validation_patterns)

        if has_danger and not has_validation:
            return self._vuln_result(
                evidence="Pattern match found dangerous call without validation.",
                payload=payload,
                confidence="MEDIUM",
            )
        return self._safe_result(
            "Pattern analysis: no critical path found.",
            payload=payload,
        )

    # ------------------------------------------------------------------
    # Result builders
    # ------------------------------------------------------------------

    def _vuln_result(
        self,
        evidence: str,
        payload: Dict[str, Any],
        confidence: str = "HIGH",
    ) -> Dict[str, Any]:
        return {
            "vulnerable": True,
            "evidence": evidence,
            "payload_hit": payload.get("payload", ""),
            "analysis": payload.get("description", ""),
            "confidence": confidence,
        }

    def _safe_result(
        self,
        analysis: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "vulnerable": False,
            "evidence": "No exploitable path found.",
            "payload_hit": payload.get("payload", "") if payload else "",
            "analysis": analysis,
            "confidence": "HIGH",
        }

    def _unknown_check(self, source: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback for unknown check_fn values."""
        return self._safe_result(f"Unknown check function: {payload.get('check_fn')}", payload)
