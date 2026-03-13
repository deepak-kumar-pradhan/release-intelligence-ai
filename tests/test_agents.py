import unittest
from src.agents.release_notes_agent import ReleaseNotesAgent
from src.agents.risk_analysis_agent import RiskAnalysisAgent
from src.agents.dependency_impact_agent import DependencyImpactAgent

class TestReleaseNotesAgent(unittest.TestCase):
    def setUp(self):
        self.agent = ReleaseNotesAgent()

    def test_generate_release_notes(self):
        commits = ["fix auth timeout", "upgrade requests", "add telemetry"]
        notes = self.agent.generate_release_notes(commits)
        self.assertIsInstance(notes, str)
        self.assertIn("fix auth timeout", notes)
        self.assertIn("upgrade requests", notes)

class TestRiskAnalysisAgent(unittest.TestCase):
    def setUp(self):
        self.agent = RiskAnalysisAgent()

    def test_analyze_risks(self):
        risk_factors = [
            {"name": "critical_vulnerabilities", "impact": "high", "likelihood": "high"},
            {"name": "deployment_window", "impact": "low", "likelihood": "medium"},
        ]
        output = self.agent.analyze_risks(risk_factors)
        self.assertIsInstance(output, dict)
        self.assertIn("overall_risk", output)
        self.assertIn("risk_factors", output)
        self.assertEqual(len(output["risk_factors"]), 2)

class TestDependencyImpactAgent(unittest.TestCase):
    def setUp(self):
        self.agent = DependencyImpactAgent()

    def test_assess_dependency_impact(self):
        self.agent.load_dependencies(
            {
                "requests": {"version": "2.25.0"},
                "flask": {"version": "2.0.0"},
            }
        )
        self.agent.load_vulnerabilities(
            [
                {
                    "id": "CVE-1",
                    "dependency": "requests",
                    "severity": "HIGH",
                    "description": "requests allows ...",
                },
                {
                    "id": "CVE-2",
                    "component": "flask",
                    "severity": "MEDIUM",
                },
                {
                    "id": "CVE-3",
                    "dependency": "django",
                    "severity": "LOW",
                },
            ]
        )

        report = self.agent.assess_impact()
        self.assertIn("requests", report)
        self.assertIn("flask", report)
        self.assertEqual(len(report["requests"]["vulnerabilities"]), 1)
        self.assertEqual(len(report["flask"]["vulnerabilities"]), 1)
        self.assertGreaterEqual(len(report["requests"]["mitigations"]), 2)

if __name__ == '__main__':
    unittest.main()