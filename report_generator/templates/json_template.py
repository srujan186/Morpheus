from datetime import datetime

def build_json_report(scan_id, agent_name, pattern_results, semantic_results, explanations, fixes):
    all_severities = [r.get("severity", "UNKNOWN") for r in semantic_results]
    severity_counts = {
        "CRITICAL": all_severities.count("CRITICAL"),
        "HIGH": all_severities.count("HIGH"),
        "MEDIUM": all_severities.count("MEDIUM"),
        "LOW": all_severities.count("LOW"),
        "SAFE": all_severities.count("SAFE"),
    }

    overall_risk = "SAFE"
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity_counts[level] > 0:
            overall_risk = level
            break

    vulnerabilities = []
    for i, semantic in enumerate(semantic_results):
        tool_name = semantic.get("tool_name", f"tool_{i}")
        pattern: dict = next((p for p in pattern_results if p.get("tool_name") == tool_name), {})
        explanation: dict = next((e for e in explanations if e.get("tool_name") == tool_name), {})
        fix: dict = next((f for f in fixes if f.get("tool_name") == tool_name), {})

        vulnerabilities.append({
            "tool": tool_name,
            "severity": semantic.get("severity", "UNKNOWN"),
            "type": semantic.get("vulnerability_type", "Unknown"),
            "is_vulnerable": semantic.get("is_vulnerable", False),
            "confidence": semantic.get("confidence", "LOW"),
            "detected_patterns": pattern.get("findings", []),
            "pattern_count": pattern.get("total_findings", 0),
            "llm_explanation": explanation.get("technical_explanation", ""),
            "layman_explanation": explanation.get("layman_explanation", ""),
            "business_impact": explanation.get("business_impact", ""),
            "attack_scenario": explanation.get("attack_scenario", ""),
            "fix_code": fix.get("fixed_code", ""),
            "changes_made": fix.get("changes_made", []),
            "prevention_tips": fix.get("prevention_tips", ""),
            "alternative_tools": fix.get("alternative_tools", []),
        })

    recommendations = {
        "CRITICAL": "DO NOT DEPLOY. Critical vulnerabilities found. Immediate remediation required.",
        "HIGH": "BLOCK DEPLOYMENT. High-severity issues must be fixed before production.",
        "MEDIUM": "DEPLOY WITH CAUTION. Address medium-severity issues in the next sprint.",
        "LOW": "APPROVED WITH NOTES. Low-severity findings noted. Schedule fixes.",
        "SAFE": "CLEARED FOR DEPLOYMENT. No significant vulnerabilities detected.",
    }

    return {
        "morpheus_report": {
            "version": "1.0",
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "agent_analyzed": agent_name,
            "summary": {
                "overall_risk": overall_risk,
                "total_tools_scanned": len(semantic_results),
                "vulnerable_tools": sum(1 for v in vulnerabilities if v["is_vulnerable"]),
                "safe_tools": sum(1 for v in vulnerabilities if not v["is_vulnerable"]),
                "severity_breakdown": severity_counts,
                "recommendation": recommendations.get(overall_risk, "Manual review recommended."),
            },
            "vulnerabilities": vulnerabilities,
            "metadata": {
                "analyzer_version": "morpheus-1.0",
                "models_used": ["llama3-70b-8192"],
            }
        }
    }
