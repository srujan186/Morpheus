import json
from typing import List, Dict, Any
from llm_analyzer.groq_client import GroqClient

FIX_GENERATOR_PROMPT = """You are a Python security expert who writes secure code fixes.
Respond ONLY in this exact JSON format:
{
    "fixed_code": "the complete fixed function as a string",
    "changes_made": ["list", "of", "specific", "changes"],
    "why_each_change": "explanation of the security improvements",
    "alternative_tools": ["SafeTool1", "SafeTool2"],
    "prevention_tips": "general advice to prevent this class of vulnerability"
}
Only JSON, no other text."""

class RecommendationEngine:
    def __init__(self):
        self.groq = GroqClient()

    def generate_fix(self, code: str, vulnerability_info: dict) -> dict:
        tool_name = vulnerability_info.get("tool_name", "unknown")
        severity = vulnerability_info.get("severity", "UNKNOWN")
        vuln_type = vulnerability_info.get("vulnerability_type", "security issue")

        user_message = f"""
Tool: {tool_name}
Severity: {severity}
Vulnerability: {vuln_type}
Vulnerable code to fix:
```python
{code}
```
Provide a secure fixed version with input validation and proper error handling."""

        raw_response = self.groq.ask(FIX_GENERATOR_PROMPT, user_message)
        fix = self._parse_fix(raw_response)
        fix["tool_name"] = tool_name
        fix["original_code"] = code
        return fix

    def _parse_fix(self, raw_response: str) -> dict:
        try:
            cleaned = raw_response.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                cleaned = "\n".join([lines[i] for i in range(1, len(lines) - 1)])
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return {
                "fixed_code": "# Could not auto-generate fix - manual review required",
                "changes_made": ["Manual review required"],
                "why_each_change": "Parse error - check logs",
                "alternative_tools": [],
                "prevention_tips": f"{raw_response:.500s}"
            }

    def generate_fixes_for_all(self, vulnerabilities: list, codes: dict) -> list:
        fixes = []
        for vuln in vulnerabilities:
            tool_name = vuln.get("tool_name", "unknown")
            code = codes.get(tool_name, "")
            if not code:
                continue
            print(f"[Recommendations] Generating fix for: {tool_name}...")
            fix = self.generate_fix(code, vuln)
            fixes.append(fix)
        return fixes
