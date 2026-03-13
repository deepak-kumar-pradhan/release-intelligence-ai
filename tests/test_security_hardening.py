import unittest

from src.models.release_context import ReleaseContext
from src.workflow.ri_workflow import SecurityReviewWorkflow


class TestSecurityHardening(unittest.TestCase):
    def test_release_context_rejects_invalid_manifest_type(self):
        with self.assertRaises(TypeError):
            ReleaseContext(release_manifest=["not-a-dict"])

    def test_release_context_rejects_invalid_session_key(self):
        context = ReleaseContext()
        with self.assertRaises(ValueError):
            context.update_session_data("", "value")

    def test_workflow_rejects_invalid_service_name(self):
        workflow = SecurityReviewWorkflow()
        with self.assertRaises(ValueError):
            workflow.orchestrate(
                services=[
                    {
                        "service_name": "../../etc/passwd",
                        "release_version": "main",
                    }
                ]
            )

    def test_workflow_rejects_invalid_release_version(self):
        workflow = SecurityReviewWorkflow()
        with self.assertRaises(ValueError):
            workflow.orchestrate(
                services=[
                    {
                        "service_name": "orders-api",
                        "release_version": "release branch?bad",
                    }
                ]
            )


if __name__ == "__main__":
    unittest.main()
