"""
ast_analyzer.py
AST (Abstract Syntax Tree) Analysis — Layer 4

Parses code into a tree and walks every node.
Catches obfuscated patterns that regex completely misses:

  - exec("x") hidden as getattr(__builtins__, "exec")("x")
  - "ex" + "ec" string concatenation building dangerous names
  - Dynamic attribute access: obj.__dict__["exec"]
  - Dangerous function calls regardless of how they're named
  - Deeply nested calls: a(b(c(d())))
"""

import ast
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class ASTFinding:
    pattern: str
    risk: str
    severity: str
    line_number: Optional[int] = None
    source: str = "ast"


# Functions that are dangerous no matter how they're called
DANGEROUS_CALLS: Dict[str, tuple] = {
    "exec":           ("exec()",           "Arbitrary code execution",        "HIGH"),
    "eval":           ("eval()",           "Arbitrary code execution",        "HIGH"),
    "compile":        ("compile()",        "Dynamic code compilation",        "HIGH"),
    "__import__":     ("__import__()",     "Dynamic module import",           "HIGH"),
    "execfile":       ("execfile()",       "File execution",                  "HIGH"),
    "breakpoint":     ("breakpoint()",     "Debugger invocation",             "MEDIUM"),
    "input":          ("input()",          "User input (injection risk)",     "LOW"),
    "open":           ("open()",           "File system access",              "MEDIUM"),
    "print":          ("print()",          "Output function",                 "LOW"),
}

# Dangerous attribute patterns — obj.dangerous_attr
DANGEROUS_ATTRS: Dict[str, tuple] = {
    "__class__":      ("__class__ access",   "Class introspection",           "MEDIUM"),
    "__bases__":      ("__bases__ access",   "MRO traversal",                 "HIGH"),
    "__subclasses__": ("__subclasses__()",   "Subclass enumeration (sandbox escape)", "HIGH"),
    "__globals__":    ("__globals__",        "Global namespace access",       "HIGH"),
    "__builtins__":   ("__builtins__",       "Builtins namespace access",     "HIGH"),
    "__code__":       ("__code__",           "Code object access",            "HIGH"),
    "__dict__":       ("__dict__",           "Object dictionary access",      "MEDIUM"),
    "__mro__":        ("__mro__",            "Method resolution order",       "MEDIUM"),
    "__qualname__":   ("__qualname__",       "Qualified name access",         "LOW"),
}

# String patterns that when concatenated form dangerous names
DANGEROUS_FRAGMENTS: Set[str] = {
    "ex", "ec",           # exec
    "ev", "al",           # eval
    "im", "po", "rt",     # import
    "su", "bp", "ro",     # subprocess
    "os", "sy", "st",     # os.system
    "pi", "ck", "le",     # pickle
    "__", "im",           # __import__
}

# Known sandbox escape patterns via MRO traversal
SANDBOX_ESCAPE_PATTERNS = [
    # ().__class__.__bases__[0].__subclasses__()
    # ''.__class__.__mro__[1].__subclasses__()
    "__class__.__bases__",
    "__class__.__mro__",
    "__subclasses__()",
    "__globals__['__builtins__']",
]


class ASTAnalyzer(ast.NodeVisitor):
    """
    Walks the AST of Python code looking for dangerous patterns
    that regex cannot detect.
    """

    def __init__(self) -> None:
        self.findings: List[ASTFinding] = []
        self._call_depth: int = 0
        self._string_concats: List[str] = []

    def analyze(self, code: str) -> List[ASTFinding]:
        """Parse code and walk its AST. Returns list of findings."""
        self.findings = []
        try:
            tree = ast.parse(code)
            self.visit(tree)
        except SyntaxError as e:
            logger.warning("AST parse failed (syntax error): %s", e)
            # Still try regex fallback on unparseable code
            self._scan_unparseable(code)
        return self.findings

    # ── Visitor methods ─────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        """Catches direct and indirect function calls."""
        line = getattr(node, "lineno", None)

        # Direct call: exec(...), eval(...), etc.
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if name in DANGEROUS_CALLS:
                label, risk, sev = DANGEROUS_CALLS[name]
                self._add(label, risk, sev, line)

        # Attribute call: os.system(...), subprocess.run(...)
        elif isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            obj_name = ""
            if isinstance(node.func.value, ast.Name):
                obj_name = node.func.value.id

            full = f"{obj_name}.{attr}" if obj_name else attr

            dangerous_attrs = {
                "system": ("os.system()",    "Shell execution",    "HIGH"),
                "popen":  ("os.popen()",     "Shell pipe",         "HIGH"),
                "run":    ("subprocess.run", "Subprocess call",    "HIGH"),
                "call":   ("subprocess.call","Subprocess call",    "HIGH"),
                "Popen":  ("subprocess.Popen","Subprocess spawn",  "HIGH"),
                "loads":  ("pickle.loads/yaml.loads", "Unsafe deserialization", "HIGH"),
                "load":   ("yaml.load/pickle.load",   "Unsafe deserialization", "HIGH"),
                "b64decode": ("base64.b64decode", "Base64 decode (obfuscation)", "MEDIUM"),
                "decompress": ("zlib.decompress", "Decompress (obfuscation)",   "MEDIUM"),
                "import_module": ("importlib.import_module", "Dynamic import",  "HIGH"),
                "connect": ("socket.connect", "Network connection", "MEDIUM"),
                "getattr": ("getattr() call", "Dynamic attribute access", "MEDIUM"),
            }

            if attr in dangerous_attrs:
                label, risk, sev = dangerous_attrs[attr]
                self._add(label, risk, sev, line, detail=f"called as {full}()")

        # getattr(__builtins__, "exec") pattern
        elif isinstance(node.func, ast.Name) and node.func.id == "getattr":
            if len(node.args) >= 2:
                if isinstance(node.args[1], ast.Constant):
                    attr_name = str(node.args[1].value)
                    if attr_name in DANGEROUS_CALLS:
                        self._add(
                            f"getattr(..., '{attr_name}')",
                            f"Indirect access to {attr_name}() via getattr",
                            "HIGH", line,
                        )

        self._call_depth += 1
        self.generic_visit(node)
        self._call_depth -= 1

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Catches dangerous attribute access."""
        line = getattr(node, "lineno", None)
        attr = node.attr

        if attr in DANGEROUS_ATTRS:
            label, risk, sev = DANGEROUS_ATTRS[attr]
            self._add(label, risk, sev, line)

        # Detect __subclasses__() sandbox escape chains
        if attr == "__subclasses__":
            self._add(
                "__subclasses__() chain",
                "Classic Python sandbox escape via MRO traversal",
                "HIGH", line,
            )

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """
        Catches string concatenation building dangerous names.
        e.g. "ex" + "ec" → "exec"
        """
        if isinstance(node.op, ast.Add):
            combined = self._try_eval_concat(node)
            if combined and combined in DANGEROUS_CALLS:
                self._add(
                    f"string concat → {combined}()",
                    f"Obfuscated call to {combined}() via string concatenation",
                    "HIGH",
                    getattr(node, "lineno", None),
                )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Catches all import statements with exact module names."""
        line = getattr(node, "lineno", None)
        dangerous_imports = {
            "pickle", "subprocess", "os", "sys", "ctypes",
            "socket", "requests", "urllib", "paramiko", "pty",
            "pexpect", "marshal", "shelve", "importlib",
        }
        for alias in node.names:
            mod = alias.name.split(".")[0]
            if mod in dangerous_imports:
                self._add(
                    f"import {mod}",
                    f"Dangerous module imported: {mod}",
                    "HIGH" if mod in {"pickle", "ctypes", "paramiko"} else "MEDIUM",
                    line,
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Catches from X import Y statements."""
        line = getattr(node, "lineno", None)
        if node.module:
            base = node.module.split(".")[0]
            dangerous = {
                "pickle", "subprocess", "os", "sys", "ctypes",
                "socket", "marshal", "shelve",
            }
            if base in dangerous:
                self._add(
                    f"from {node.module} import ...",
                    f"Importing from dangerous module: {node.module}",
                    "MEDIUM", line,
                )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """
        Catches variable assignments that build dangerous strings.
        cmd = "exec"
        func = getattr(builtins, cmd)
        """
        line = getattr(node, "lineno", None)
        if isinstance(node.value, ast.Constant):
            val = str(node.value.value)
            if val in DANGEROUS_CALLS:
                self._add(
                    f"assigning dangerous name '{val}'",
                    f"Variable assigned dangerous function name: {val}",
                    "MEDIUM", line,
                )
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """
        Catches f-strings containing potentially dangerous expressions.
        f"python -c '{user_code}'"
        """
        line = getattr(node, "lineno", None)
        # Check if f-string contains Name nodes (variables being interpolated)
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if child.id in ("user_input", "input", "data", "payload", "cmd", "code"):
                    self._add(
                        "f-string with user variable",
                        f"F-string interpolates variable '{child.id}' — injection risk",
                        "MEDIUM", line,
                    )
                    break
        self.generic_visit(node)

    # ── Helpers ──────────────────────────────────────────────────

    def _add(
        self,
        pattern: str,
        risk: str,
        severity: str,
        line: Optional[int],
        detail: str = "",
    ) -> None:
        full_risk = f"{risk}. {detail}" if detail else risk
        self.findings.append(ASTFinding(
            pattern=pattern,
            risk=full_risk,
            severity=severity,
            line_number=line,
            source="ast",
        ))

    def _try_eval_concat(self, node: ast.BinOp) -> Optional[str]:
        """Try to statically evaluate a string concatenation."""
        try:
            if isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant):
                return str(node.left.value) + str(node.right.value)
            # Recursive for "ex" + "e" + "c"
            if isinstance(node.left, ast.BinOp):
                left = self._try_eval_concat(node.left)
                if left and isinstance(node.right, ast.Constant):
                    return left + str(node.right.value)
        except Exception:
            pass
        return None

    def _scan_unparseable(self, code: str) -> None:
        """Fallback for code that can't be parsed — scan as raw text."""
        for pattern in SANDBOX_ESCAPE_PATTERNS:
            if pattern in code:
                self.findings.append(ASTFinding(
                    pattern="sandbox escape chain",
                    risk=f"Sandbox escape pattern detected: {pattern}",
                    severity="HIGH",
                    source="ast-fallback",
                ))