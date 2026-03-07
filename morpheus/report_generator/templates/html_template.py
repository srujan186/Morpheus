def generate_html_report(report_data: dict) -> str:
    morpheus = report_data.get("morpheus_report", {})
    summary = morpheus.get("summary", {})
    vulnerabilities = morpheus.get("vulnerabilities", [])

    severity_colors = {
        "CRITICAL": "#ff2d55",
        "HIGH": "#ff9500",
        "MEDIUM": "#ffcc00",
        "LOW": "#34c759",
        "SAFE": "#30d158",
        "UNKNOWN": "#636366",
    }

    overall_risk = summary.get("overall_risk", "UNKNOWN")
    risk_color = severity_colors.get(overall_risk, "#636366")

    vuln_cards_html = ""
    for vuln in vulnerabilities:
        if not vuln.get("is_vulnerable"):
            continue
        sev = vuln.get("severity", "UNKNOWN")
        color = severity_colors.get(sev, "#636366")
        changes_html = "".join(f"<li>{c}</li>" for c in vuln.get("changes_made", []))

        vuln_cards_html += f"""
        <div style="background:#1c1c2e;border:1px solid #2c2c3e;border-left:4px solid {color};border-radius:12px;padding:28px;margin-bottom:20px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
                <div>
                    <h3 style="color:#f5f5f7;font-size:20px">{vuln.get('tool','Unknown')}</h3>
                    <span style="color:#8e8e93;font-size:13px">{vuln.get('type','Unknown')}</span>
                </div>
                <span style="background:{color};color:#fff;padding:6px 16px;border-radius:8px;font-weight:700">{sev}</span>
            </div>
            <h4 style="color:#8e8e93;font-size:13px;text-transform:uppercase;margin-bottom:8px">What's Wrong</h4>
            <p style="color:#d1d1d6;margin-bottom:20px">{vuln.get('layman_explanation','N/A')}</p>
            <h4 style="color:#8e8e93;font-size:13px;text-transform:uppercase;margin-bottom:8px">Business Impact</h4>
            <p style="color:#ff9f0a;margin-bottom:20px">{vuln.get('business_impact','N/A')}</p>
            <h4 style="color:#8e8e93;font-size:13px;text-transform:uppercase;margin-bottom:8px">Attack Scenario</h4>
            <p style="color:#d1d1d6;margin-bottom:20px">{vuln.get('attack_scenario','N/A')}</p>
            <h4 style="color:#8e8e93;font-size:13px;text-transform:uppercase;margin-bottom:8px">Recommended Fix</h4>
            <pre style="background:#0a0a0f;border:1px solid #3a3a4c;border-radius:8px;padding:16px;color:#30d158;font-size:13px;overflow-x:auto">{vuln.get('fix_code','# No fix generated').strip()}</pre>
            {"<ul style='color:#d1d1d6;margin-top:12px'>" + changes_html + "</ul>" if changes_html else ""}
        </div>"""

    sev_chips = "".join(
        f'<span style="padding:6px 14px;border-radius:20px;font-size:13px;font-weight:600;background:{severity_colors.get(k,"#636366")}22;color:{severity_colors.get(k,"#636366")};border:1px solid {severity_colors.get(k,"#636366")}44">{k}: {v}</span>'
        for k, v in summary.get("severity_breakdown", {}).items() if v > 0
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MORPHEUS Security Report</title>
</head>
<body style="background:#0a0a0f;color:#e5e5ea;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:0">
    <div style="background:linear-gradient(135deg,#1c1c2e,#0f0f1a);border-bottom:1px solid #2c2c3e;padding:32px 40px">
        <div style="display:flex;justify-content:space-between">
            <div style="font-size:28px;font-weight:800;background:linear-gradient(90deg,#00d4ff,#7b2fff);-webkit-background-clip:text;-webkit-text-fill-color:transparent">◈ MORPHEUS</div>
            <div style="color:#8e8e93;font-size:13px;text-align:right">Scan ID: {morpheus.get('scan_id','N/A')}</div>
        </div>
        <div style="font-size:22px;font-weight:600;margin-top:16px;color:#f5f5f7">{morpheus.get('agent_analyzed','Unknown Agent')}</div>
        <div style="color:#636366;font-size:13px;margin-top:4px">{morpheus.get('timestamp','')}</div>
    </div>

    <div style="background:{risk_color}18;border:1px solid {risk_color}44;border-radius:12px;padding:20px 24px;margin:32px 40px;display:flex;align-items:center;gap:16px">
        <div style="font-size:32px;font-weight:900;color:{risk_color}">{overall_risk}</div>
        <div style="color:#f5f5f7;font-size:16px;font-weight:500">{summary.get('recommendation','')}</div>
    </div>

    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;padding:0 40px;margin-bottom:32px">
        <div style="background:#1c1c2e;border:1px solid #2c2c3e;border-radius:12px;padding:20px;text-align:center">
            <div style="font-size:36px;font-weight:800;color:#f5f5f7">{summary.get('total_tools_scanned',0)}</div>
            <div style="font-size:12px;color:#8e8e93;text-transform:uppercase;letter-spacing:1px">Tools Scanned</div>
        </div>
        <div style="background:#1c1c2e;border:1px solid #2c2c3e;border-radius:12px;padding:20px;text-align:center">
            <div style="font-size:36px;font-weight:800;color:#ff2d55">{summary.get('vulnerable_tools',0)}</div>
            <div style="font-size:12px;color:#8e8e93;text-transform:uppercase;letter-spacing:1px">Vulnerable</div>
        </div>
        <div style="background:#1c1c2e;border:1px solid #2c2c3e;border-radius:12px;padding:20px;text-align:center">
            <div style="font-size:36px;font-weight:800;color:#30d158">{summary.get('safe_tools',0)}</div>
            <div style="font-size:12px;color:#8e8e93;text-transform:uppercase;letter-spacing:1px">Safe</div>
        </div>
        <div style="background:#1c1c2e;border:1px solid #2c2c3e;border-radius:12px;padding:20px;text-align:center">
            <div style="font-size:36px;font-weight:800;color:{risk_color}">{overall_risk}</div>
            <div style="font-size:12px;color:#8e8e93;text-transform:uppercase;letter-spacing:1px">Overall Risk</div>
        </div>
    </div>

    <div style="display:flex;gap:8px;padding:0 40px;margin-bottom:32px;flex-wrap:wrap">{sev_chips}</div>

    <div style="font-size:20px;font-weight:700;padding:0 40px;margin-bottom:20px;color:#f5f5f7">Vulnerability Details</div>

    <div style="padding:0 40px">
        {vuln_cards_html if vuln_cards_html else '<p style="color:#30d158">No vulnerabilities detected.</p>'}
    </div>

    <div style="text-align:center;padding:40px;color:#3a3a4c;font-size:13px">Generated by MORPHEUS · {morpheus.get('timestamp','')}</div>
</body>
</html>"""

def save_html_report(report_data: dict, output_path: str = "morpheus_report.html"):
    html = generate_html_report(report_data)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[HTMLTemplate] Report saved to: {output_path}")
    return output_path
