def generate_txt_report(report_data: dict) -> str:
    morpheus = report_data.get("morpheus_report", {})
    summary = morpheus.get("summary", {})
    vulnerabilities = morpheus.get("vulnerabilities", [])

    lines = []
    lines.append("=" * 60)
    lines.append("MORPHEUS SECURITY REPORT")
    lines.append("=" * 60)
    lines.append(f"Agent: {morpheus.get('agent_analyzed', 'Unknown')}")
    lines.append(f"Scan ID: {morpheus.get('scan_id', 'N/A')}")
    lines.append(f"Timestamp: {morpheus.get('timestamp', 'N/A')}")
    lines.append("")
    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"Overall Risk: {summary.get('overall_risk', 'UNKNOWN')}")
    lines.append(f"Total Tools Scanned: {summary.get('total_tools_scanned', 0)}")
    lines.append(f"Vulnerable Tools: {summary.get('vulnerable_tools', 0)}")
    lines.append(f"Safe Tools: {summary.get('safe_tools', 0)}")
    lines.append(f"Recommendation: {summary.get('recommendation', '')}")
    lines.append("")
    lines.append("VULNERABILITIES")
    lines.append("-" * 40)

    for vuln in vulnerabilities:
        if not vuln.get("is_vulnerable"):
            continue
        lines.append(f"\nTool: {vuln.get('tool', 'Unknown')}")
        lines.append(f"Severity: {vuln.get('severity', 'UNKNOWN')}")
        lines.append(f"Type: {vuln.get('type', 'Unknown')}")
        lines.append(f"Explanation: {vuln.get('layman_explanation', 'N/A')}")
        lines.append(f"Business Impact: {vuln.get('business_impact', 'N/A')}")
        lines.append(f"Attack Scenario: {vuln.get('attack_scenario', 'N/A')}")
        lines.append(f"Fix: {vuln.get('fix_code', 'N/A')}")
        lines.append("-" * 40)

    return "\n".join(lines)

def save_txt_report(report_data: dict, output_path: str = "morpheus_report.txt"):
    txt = generate_txt_report(report_data)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(txt)
    print(f"[TXTTemplate] Report saved to: {output_path}")
    return output_path
