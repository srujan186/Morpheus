import json
from .groq_client import GroqClient

EXPLAINER_PROMPT = """You are a cybersecurity expert explaining vulnerabilities to both technical teams and business executives.
Respond ONLY in this exact JSON format:
{
    "layman_explanation": "2-3 sentences in plain English for a non-technical CEO",
    "technical_explanation": "2-3 sentences with technical details for developers",
    "business_impact": "what could actually happen to the company if exploited",
    "attack_scenario": "step-by-step how an attacker would exploit this",
    "urgency": "why this needs to be fixed before deployment"
}
Only JSON, no other text."""

class VulnerabilityExplainer:
    def __init__(self):
        self.groq = GroqClient()

    def explain(self, vulnerability_data: dict, code: str) -> dict:
        tool_name = vulnerability_data.get("tool_name", "Unknown Tool")
        severity = vulnerability_data.get("severity", "UNKNOWN")
        vuln_type = vulnerability_data.get("vulnerability_type", "Security Issue")

        user_message = f"""
Tool Name: {tool_name}
Severity: {severity}
Vulnerability Type: {vuln_type}
Vulnerable Code:
```python
{code}
```
Explain this vulnerability clearly for both technical and non-technical audiences."""

        raw_response = self.groq.ask(EXPLAINER_PROMPT, user_message)
        explanation = self._parse_explanation(raw_response)
        explanation["tool_name"] = tool_name
        explanation["severity"] = severity
        return explanation

    def _parse_explanation(self, raw_response: str) -> dict:
        try:
            cleaned = raw_response.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                cleaned = "\n".join([lines[i] for i in range(1, len(lines) - 1)])
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return {
                "layman_explanation": f"{raw_response:.300s}",
                "technical_explanation": "Manual review required.",
                "business_impact": "Potential security breach.",
                "attack_scenario": "Could not generate attack scenario.",
                "urgency": "Review required before deployment."
            }

    def explain_multiple(self, vulnerabilities: list, codes: dict) -> list:
        results = []
        for vuln in vulnerabilities:
            tool_name = vuln.get("tool_name", "unknown")
            code = codes.get(tool_name, "# Code not available")
            print(f"[Explainer] Generating explanation for: {tool_name}...")
            explanation = self.explain(vuln, code)
            results.append(explanation)
        return results
