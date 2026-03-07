"""
allowlist.py
Defines the whitelist of safe built-ins, modules, and function patterns.
Used as a reference by the monitor and validators.
"""

# Safe Python built-in functions (no I/O, no execution, no imports)
SAFE_BUILTINS = {
    "print", "len", "range", "enumerate", "zip", "map", "filter",
    "sorted", "reversed", "list", "dict", "set", "tuple", "str",
    "int", "float", "bool", "type", "isinstance", "issubclass",
    "abs", "round", "min", "max", "sum", "any", "all",
    "repr", "format", "hex", "oct", "bin", "chr", "ord",
    "hash", "id", "dir", "vars", "getattr", "setattr", "hasattr",
    "iter", "next", "callable",
}

# Safe standard library modules (no network, no execution, no file writes)
SAFE_MODULES = {
    "math", "random", "datetime", "collections", "itertools",
    "functools", "string", "re", "json", "copy", "time",
    "typing", "dataclasses", "enum", "uuid", "hashlib",
    "base64", "struct", "decimal", "fractions", "statistics",
    "textwrap", "difflib", "pprint",
}

# Modules that are NEVER allowed
BLOCKED_MODULES = {
    "subprocess", "os", "sys", "ctypes", "pickle", "shelve",
    "socket", "requests", "urllib", "http", "ftplib", "smtplib",
    "paramiko", "fabric", "pexpect", "pty", "tty", "termios",
    "signal", "mmap", "multiprocessing", "threading",
    "importlib", "builtins",
}

# Dangerous built-in function names that should never appear
BLOCKED_BUILTINS = {
    "exec", "eval", "compile", "open", "__import__",
    "breakpoint", "input",
}


def is_module_allowed(module_name: str) -> bool:
    base = module_name.split(".")[0]
    if base in BLOCKED_MODULES:
        return False
    return base in SAFE_MODULES


def is_builtin_allowed(name: str) -> bool:
    if name in BLOCKED_BUILTINS:
        return False
    return name in SAFE_BUILTINS