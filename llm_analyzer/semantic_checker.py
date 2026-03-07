import json
from .groq_client import GroqClient

SECURITY_ANALYST_PROMPT = """You are an expert cybersecurity analyst specializing in AI agent security.
Analyze Python code for security vulnerabilities.
Respond ONLY with valid JSON in this exact format:
{
    "is_vulnerable": true,
    "confidence": "HIGH",
    "vulnerability_type": "main type or NONE",
    "attack_vector": "how attacker exploits this or N/A",
    "severity": "CRITICAL/HIGH/MEDIUM/LOW/SAFE",
    "brief_summary": "one sentence summary"
}
Only JSON, no other text."""

class SemanticChecker:
    def __init__(self):
        self.groq = GroqClient()

    def analyze(self, code: str, tool_name: str = "unknown") -> dict:
        user_message = f"Analyze this Python function from tool '{tool_name}' for security vulnerabilities:\n```python\n{code}\n```"
        raw_response = self.groq.ask(SECURITY_ANALYST_PROMPT, user_message)
        return self._parse_response(raw_response, tool_name)

    def _parse_response(self, raw_response: str, tool_name: str) -> dict:
        try:
            cleaned = raw_response.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                cleaned = "\n".join([lines[i] for i in range(1, len(lines) - 1)])
            data = json.loads(cleaned)
            data["tool_name"] = tool_name
            return data
        except json.JSONDecodeError:
            return {
                "tool_name": tool_name,
                "is_vulnerable": False,
                "confidence": "LOW",
                "vulnerability_type": "PARSE_ERROR",
                "severity": "UNKNOWN",
                "brief_summary": "Analysis failed - manual review required"
            }

    def analyze_multiple(self, tools: list) -> list:
        results = []
        for tool in tools:
            print(f"[SemanticChecker] Analyzing: {tool['name']}...")
            result = self.analyze(code=tool['code'], tool_name=tool['name'])
            results.append(result)
        return results
