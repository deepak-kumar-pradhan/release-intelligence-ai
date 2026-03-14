import unittest
import json
from pathlib import Path
from tempfile import TemporaryDirectory

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

    def test_workflow_rejects_invalid_reviewer_action(self):
        workflow = SecurityReviewWorkflow()
        with self.assertRaises(ValueError):
            workflow.orchestrate(
                services=[],
                reviewer_name="Security Lead",
                reviewer_action="MAYBE",
            )

    def test_workflow_requires_reviewer_name_when_action_present(self):
        workflow = SecurityReviewWorkflow()
        with self.assertRaises(ValueError):
            workflow.orchestrate(
                services=[],
                reviewer_name="",
                reviewer_action="APPROVED",
            )

    def test_workflow_writes_evidence_ledger_record(self):
        workflow = SecurityReviewWorkflow()
        with TemporaryDirectory() as tmpdir:
            ledger_path = Path(tmpdir) / "evidence_ledger.jsonl"
            workflow.ledger_path = ledger_path

            result = workflow.orchestrate(services=[])

            self.assertTrue(ledger_path.exists())
            lines = [line for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertGreaterEqual(len(lines), 1)

            record = json.loads(lines[-1])
            self.assertEqual(record["run_id"], result["run_id"])
            self.assertIn("status", record)
            self.assertIn("policy_version", record)
            self.assertIn("report_sha256", record)


if __name__ == "__main__":
    unittest.main()
