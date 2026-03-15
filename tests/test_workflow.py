import unittest
from src.workflow.ri_workflow import SecurityReviewWorkflow


class StubExpertAgent:
    def analyze_service_findings(self, service_payload):
        return []


class StubPolicyAgent:
    def evaluate_release(self, summary_rows, rules, triage_findings=None):
        return {
            "status": "GO",
            "reason": "Stub policy evaluation completed.",
            "counts": {"critical": 0, "high": 0},
            "requires_approval": False,
            "decision_record": {
                "final_decision": "PASS",
                "policy_violations": [],
                "approver_role_required": "Security_Lead",
                "requires_approval": False,
            },
        }

class TestSecurityReviewWorkflow(unittest.TestCase):

    def setUp(self):
        self.workflow = SecurityReviewWorkflow(
            expert_agent=StubExpertAgent(),
            policy_agent=StubPolicyAgent(),
        )

    def test_initialization(self):
        self.assertIsNotNone(self.workflow)

    def test_fetch_data(self):
        data = self.workflow.fetch_data()
        self.assertIsInstance(data, dict)  # Assuming fetch_data returns a dictionary

    def test_orchestrate_workflow(self):
        result = self.workflow.orchestrate()
        self.assertIsInstance(result, dict)
        self.assertIn("status", result)
        self.assertIn("summary", result)
        self.assertIn("governance", result)

    def test_aggregate_results(self):
        results = self.workflow.aggregate_results()
        self.assertIsInstance(results, list)  # Assuming aggregate_results returns a list

if __name__ == '__main__':
    unittest.main()