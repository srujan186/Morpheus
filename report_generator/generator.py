import json
import uuid
import os
from llm_analyzer.pattern_detector import PatternDetector
from llm_analyzer.semantic_checker import SemanticChecker
from llm_analyzer.explainer import VulnerabilityExplainer
from .recommendations import RecommendationEngine
from .templates.json_template import build_json_report
from .templates.txt_template import save_txt_report

class MorpheusReportGenerator:
    def __init__(self):
        print("[Generator] Initializing MORPHEUS...")
        self.pattern_detector = PatternDetector()
        self.semantic_checker = SemanticChecker()
        self.explainer = VulnerabilityExplainer()
        self.recommendation_engine = RecommendationEngine()
        print("[Generator] Ready.")

    def run_full_analysis(self, tools, agent_name="Unknown Agent", scan_id=None, output_dir="outputs"):
        if not scan_id:
            scan_id = str(uuid.uuid4())[:8]
        codes = {tool["name"]: tool["code"] for tool in tools}
        print("Step 1/4: Pattern detection...")
        pattern_results = []
        for tool in tools:
            result = self.pattern_detector.scan(code=tool["code"], tool_name=tool["name"])
            pattern_results.append(result)
            print(f"  {tool['name']}: {result['total_findings']} patterns found")
        print("Step 2/4: AI semantic analysis...")
        semantic_results = self.semantic_checker.analyze_multiple(tools)
        print("Step 3/4: Generating explanations...")
        vulnerable_tools = [r for r in semantic_results if r.get("is_vulnerable")]
        explanations = self.explainer.explain_multiple(vulnerable_tools, codes)
        print(f"  Generated {len(explanations)} explanations")
        print("Step 4/4: Generating fixes...")
        fixes = self.recommendation_engine.generate_fixes_for_all(vulnerable_tools, codes)
        print(f"  Generated {len(fixes)} fixes")
        json_report = build_json_report(scan_id=scan_id, agent_name=agent_name, pattern_results=pattern_results, semantic_results=semantic_results, explanations=explanations, fixes=fixes)
        os.makedirs(output_dir, exist_ok=True)
        json_path = os.path.join(output_dir, f"morpheus_report_{scan_id}.json")
        txt_path = os.path.join(output_dir, f"morpheus_report_{scan_id}.txt")
        save_txt_report(json_report, txt_path)
        with open(json_path, "w") as f:
            json.dump(json_report, f, indent=2)
        summary = json_report["morpheus_report"]["summary"]
        print(f"Overall Risk: {summary['overall_risk']}")
        print(f"TXT: {txt_path} | JSON: {json_path}")
        return json_report


if __name__ == "__main__":
    from morpheus.report_generator.generator import MorpheusReportGenerator
    import json
    test_tools = [
        {"name": "DocGenerator", "code": "def generate_docs(code):\n    response = api.call(code)\n    exec(response)\n    return response"},
        {"name": "SafeCalculator", "code": "def calculate(a, b):\n    return a + b"}
    ]
    generator = MorpheusReportGenerator()
    report = generator.run_full_analysis(tools=test_tools, agent_name="VulnerableAgent_Demo_v1", output_dir="outputs")
    print(json.dumps(report["morpheus_report"]["summary"], indent=2))
