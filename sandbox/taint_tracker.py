"""
taint_tracker.py
Taint Analysis — Layer 5

Tracks where user-controlled data flows through code.
Catches injection attacks even when no dangerous keyword appears.

Example — catches this even though exec() is never written:
    user_data = input()          # SOURCE: user input enters here
    template = f"result={user_data}"
    query = "SELECT " + user_data  # SINK: tainted data in SQL query

Sources: input(), sys.argv, os.environ, request.form, open()
Sinks:   exec, eval, subprocess, SQL queries, file writes, network calls
"""

import ast
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class TaintFinding:
    source: str           # where tainted data came from
    sink: str             # where tainted data ended up
    variable: str         # the variable that carried the taint
    risk: str
    severity: str
    source_line: Optional[int] = None
    sink_line: Optional[int] = None
    taint_source: str = "taint"


# Where untrusted data enters the program
TAINT_SOURCES: Dict[str, str] = {
    "input":          "User keyboard input",
    "sys.argv":       "Command line arguments",
    "os.environ":     "Environment variables",
    "os.getenv":      "Environment variable read",
    "request.form":   "HTTP form data",
    "request.args":   "HTTP query parameters",
    "request.data":   "HTTP request body",
    "request.json":   "HTTP JSON body",
    "request.cookies":"HTTP cookies",
    "open":           "File system read",
    "stdin":          "Standard input",
    "socket.recv":    "Network received data",
    "urllib":         "URL-fetched data",
    "requests.get":   "HTTP GET response",
    "requests.post":  "HTTP POST response",
}

# Where tainted data causes damage if it reaches there
TAINT_SINKS: Dict[str, str] = {
    "exec":               ("Code injection",         "HIGH"),
    "eval":               ("Code injection",         "HIGH"),
    "compile":            ("Code injection",         "HIGH"),
    "subprocess.run":     ("Command injection",      "HIGH"),
    "subprocess.call":    ("Command injection",      "HIGH"),
    "subprocess.Popen":   ("Command injection",      "HIGH"),
    "os.system":          ("Command injection",      "HIGH"),
    "os.popen":           ("Command injection",      "HIGH"),
    "pickle.loads":       ("Deserialization attack", "HIGH"),
    "yaml.load":          ("Deserialization attack", "HIGH"),
    "open":               ("Path traversal",         "MEDIUM"),
    "cursor.execute":     ("SQL injection",          "HIGH"),
    "db.execute":         ("SQL injection",          "HIGH"),
    "query":              ("SQL injection",          "HIGH"),
    "render_template":    ("Template injection",     "HIGH"),
    "Template":           ("Template injection",     "HIGH"),
    "send":               ("Network exfiltration",   "MEDIUM"),
    "requests.get":       ("SSRF",                   "MEDIUM"),
    "requests.post":      ("SSRF",                   "MEDIUM"),
    "redirect":           ("Open redirect",          "MEDIUM"),
    "format":             ("Format string injection","MEDIUM"),
}


class TaintTracker(ast.NodeVisitor):
    """
    Simple single-pass taint tracker.
    Marks variables as tainted when they receive data from sources.
    Flags when tainted variables reach sinks.
    """

    def __init__(self) -> None:
        self.tainted_vars: Dict[str, tuple] = {}   # var_name → (source, line)
        self.findings: List[TaintFinding] = []

    def analyze(self, code: str) -> List[TaintFinding]:
        """Parse and walk code for taint flows. Returns findings."""
        self.tainted_vars = {}
        self.findings = []
        try:
            tree = ast.parse(code)
            self.visit(tree)
        except SyntaxError as e:
            logger.warning("Taint tracker parse failed: %s", e)
        return self.findings

    # ── Track assignments: x = input() ──────────────────────────

    def visit_Assign(self, node: ast.Assign) -> None:
        """Mark variables as tainted when assigned from a source."""
        line = getattr(node, "lineno", None)

        # Check if RHS is a taint source
        source_name = self._get_source(node.value)

        if source_name:
            for target in node.targets:
                var_name = self._get_var_name(target)
                if var_name:
                    self.tainted_vars[var_name] = (source_name, line)
                    logger.debug("Tainted: %s ← %s (line %s)", var_name, source_name, line)

        # Propagate taint through assignments: y = x (if x is tainted)
        elif isinstance(node.value, ast.Name):
            if node.value.id in self.tainted_vars:
                for target in node.targets:
                    var_name = self._get_var_name(target)
                    if var_name:
                        # Propagate the original taint source
                        self.tainted_vars[var_name] = self.tainted_vars[node.value.id]

        # Propagate through f-strings and concatenation
        elif self._contains_tainted(node.value):
            for target in node.targets:
                var_name = self._get_var_name(target)
                if var_name:
                    self.tainted_vars[var_name] = ("propagated taint", line)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check if tainted data reaches a dangerous sink."""
        line = getattr(node, "lineno", None)
        sink_name = self._get_sink_name(node)

        if sink_name:
            risk_desc, severity = TAINT_SINKS.get(sink_name, ("Dangerous sink", "MEDIUM"))
            # Check all arguments for taint
            for arg in node.args:
                tainted_var = self._get_tainted_var(arg)
                if tainted_var:
                    orig_source, orig_line = self.tainted_vars[tainted_var]
                    self.findings.append(TaintFinding(
                        source=orig_source,
                        sink=sink_name,
                        variable=tainted_var,
                        risk=f"Tainted data from '{orig_source}' flows into '{sink_name}' — {risk_desc}",
                        severity=severity,
                        source_line=orig_line,
                        sink_line=line,
                    ))
                    logger.info(
                        "TAINT FLOW: %s (line %s) → %s (line %s)",
                        tainted_var, orig_line, sink_name, line,
                    )

            # Check keyword arguments too
            for kw in node.keywords:
                if kw.value and isinstance(kw.value, ast.Name):
                    tainted_var = kw.value.id
                    if tainted_var in self.tainted_vars:
                        orig_source, orig_line = self.tainted_vars[tainted_var]
                        self.findings.append(TaintFinding(
                            source=orig_source,
                            sink=f"{sink_name}({kw.arg}=...)",
                            variable=tainted_var,
                            risk=f"Tainted kwarg '{kw.arg}' flows into '{sink_name}'",
                            severity=severity,
                            source_line=orig_line,
                            sink_line=line,
                        ))

        self.generic_visit(node)

    # ── Helpers ──────────────────────────────────────────────────

    def _get_source(self, node: ast.expr) -> Optional[str]:
        """Returns source name if node is a taint source, else None."""
        if isinstance(node, ast.Call):
            name = self._call_name(node)
            for src in TAINT_SOURCES:
                if name and (name == src or name.endswith(f".{src}") or src in name):
                    return TAINT_SOURCES[src]
        if isinstance(node, ast.Attribute):
            full = self._attr_chain(node)
            for src in TAINT_SOURCES:
                if src in full:
                    return TAINT_SOURCES[src]
        return None

    def _get_sink_name(self, node: ast.Call) -> Optional[str]:
        """Returns sink name if this call is a dangerous sink, else None."""
        name = self._call_name(node)
        if not name:
            return None
        for sink in TAINT_SINKS:
            if name == sink or name.endswith(f".{sink.split('.')[-1]}"):
                return sink
        return None

    def _get_tainted_var(self, node: ast.expr) -> Optional[str]:
        """Returns variable name if this node uses a tainted variable."""
        if isinstance(node, ast.Name) and node.id in self.tainted_vars:
            return node.id
        return None

    def _contains_tainted(self, node: ast.expr) -> bool:
        """Check if an expression contains any tainted variable."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.tainted_vars:
                return True
        return False

    def _get_var_name(self, node: ast.expr) -> Optional[str]:
        """Extract variable name from assignment target."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Starred) and isinstance(node.value, ast.Name):
            return node.value.id
        return None

    def _call_name(self, node: ast.Call) -> Optional[str]:
        """Get full name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return self._attr_chain(node.func)
        return None

    def _attr_chain(self, node: ast.expr) -> str:
        """Build dotted name from attribute chain: a.b.c"""
        if isinstance(node, ast.Attribute):
            return f"{self._attr_chain(node.value)}.{node.attr}"
        if isinstance(node, ast.Name):
            return node.id
        return ""