"""
MORPHEUS CLI
=============
Command-line interface for running agent security scans.

Usage:
    python main.py scan <agent_file>
    python main.py status <scan_id>
    python main.py report <scan_id>

Example:
    python main.py scan demo_agents/vulnerable_agent1.py
"""

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_agent(agent_file: str) -> Any:
    """Dynamically load and return the agent from the given Python file."""
    path = Path(agent_file)
    if not path.exists():
        print(f"❌ Error: Agent file not found → {agent_file}")
        sys.exit(1)

    # Add the file's directory to sys.path for relative imports
    parent = str(path.parent.resolve())
    if parent not in sys.path:
        sys.path.insert(0, parent)

    spec = importlib.util.spec_from_file_location(path.stem, str(path.resolve()))
    if spec is None or spec.loader is None:
        print(f"❌ Error: Cannot load module from {agent_file}")
        sys.exit(1)

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]

    if hasattr(module, "build_agent"):
        print(f"  → Found build_agent() in {path.name}")
        return module.build_agent()

    print(f"  → No build_agent() found in {path.name}; using module as agent object")
    return module


def _print_report(report: dict) -> None:
    """Pretty-print a scan report to the terminal."""
    summary = report.get("summary", {})
    print("\n" + "=" * 60)
    print("  MORPHEUS SECURITY SCAN REPORT")
    print("=" * 60)
    print(f"  Scan ID      : {report.get('scan_id', 'N/A')}")
    print(f"  Timestamp    : {report.get('timestamp', 'N/A')}")
    print(f"  Dependencies : {summary.get('total_dependencies', 0)}")
    print(f"  Vulns found  : {summary.get('total_vulnerabilities', 0)}")
    print(f"  Critical     : {summary.get('critical', 0)}")
    print(f"  Risk Score   : {summary.get('risk_score', 'N/A')}/100")
    print("=" * 60)

    vulnerabilities = report.get("vulnerabilities", [])
    if vulnerabilities:
        print("\n⚠️  Vulnerabilities:\n")
        for i, v in enumerate(vulnerabilities, 1):
            print(f"  [{i}] {v.get('severity', '?')} — {v.get('type', '?')}")
            print(f"      Tool   : {v.get('tool', 'N/A')}")
            print(f"      Desc   : {v.get('description', 'N/A')}")
            print(f"      Fix    : {v.get('recommendation', 'N/A')}")
            print()
    else:
        print("\n✅ No vulnerabilities found.\n")


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> None:
    """Run a security scan on an agent file."""
    from api.orchestrator import get_orchestrator

    print(f"\n🔍 MORPHEUS — Scanning: {args.agent_file}\n")
    agent = _load_agent(args.agent_file)
    orchestrator = get_orchestrator()

    scan_id = orchestrator.start_scan(agent)
    status = orchestrator.get_scan_status(scan_id)

    print(f"\n📋 Scan ID : {scan_id}")
    print(f"   Status  : {status['status']}")
    print(f"   Progress: {status['progress']}%")

    if status["status"] == "complete":
        report = orchestrator.get_scan_report(scan_id)
        _print_report(report)
    elif status["status"] == "failed":
        print(f"\n❌ Scan failed: {status.get('error', 'Unknown error')}")


def cmd_status(args: argparse.Namespace) -> None:
    """Get the current status of a scan."""
    from api.orchestrator import get_orchestrator

    orchestrator = get_orchestrator()
    status = orchestrator.get_scan_status(args.scan_id)

    if "error" in status:
        print(f"❌ {status['error']}")
        sys.exit(1)

    print(f"\n📊 Scan Status")
    print(f"   ID       : {args.scan_id}")
    print(f"   Status   : {status.get('status', 'unknown')}")
    print(f"   Progress : {status.get('progress', 0)}%")
    print(f"   Step     : {status.get('current_step', 'N/A')}")


def cmd_report(args: argparse.Namespace) -> None:
    """Print the full report for a completed scan."""
    from api.orchestrator import get_orchestrator

    orchestrator = get_orchestrator()
    report = orchestrator.get_scan_report(args.scan_id)

    if "error" in report:
        print(f"❌ {report['error']}")
        sys.exit(1)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="morpheus",
        description="MORPHEUS — AI Agent Supply Chain Security Scanner",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_parser = subparsers.add_parser("scan", help="Run a security scan on an agent file")
    scan_parser.add_argument("agent_file", help="Path to the agent Python file")
    scan_parser.set_defaults(func=cmd_scan)

    # status
    status_parser = subparsers.add_parser("status", help="Check the status of a scan")
    status_parser.add_argument("scan_id", help="Scan ID returned by the scan command")
    status_parser.set_defaults(func=cmd_status)

    # report
    report_parser = subparsers.add_parser("report", help="Print the full scan report")
    report_parser.add_argument("scan_id", help="Scan ID returned by the scan command")
    report_parser.add_argument("--json", action="store_true", help="Output raw JSON")
    report_parser.set_defaults(func=cmd_report)

    return parser


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
