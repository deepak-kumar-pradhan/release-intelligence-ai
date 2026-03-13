import unittest
from src.workflow.ri_workflow import SecurityReviewWorkflow

class TestSecurityReviewWorkflow(unittest.TestCase):

    def setUp(self):
        self.workflow = SecurityReviewWorkflow()

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