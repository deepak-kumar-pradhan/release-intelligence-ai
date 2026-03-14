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
            self.assertIn("prev_record_hash", record)
            self.assertIn("record_hash", record)

    def test_workflow_ledger_hash_chain_links_records(self):
        workflow = SecurityReviewWorkflow()
        with TemporaryDirectory() as tmpdir:
            ledger_path = Path(tmpdir) / "evidence_ledger.jsonl"
            workflow.ledger_path = ledger_path

            workflow.orchestrate(services=[])
            workflow.orchestrate(services=[])

            lines = [line for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            first = json.loads(lines[0])
            second = json.loads(lines[1])
            self.assertEqual(first["prev_record_hash"], "GENESIS")
            self.assertEqual(second["prev_record_hash"], first["record_hash"])

    def test_workflow_rejects_role_mismatch_for_manual_action(self):
        workflow = SecurityReviewWorkflow()
        with self.assertRaises(ValueError):
            workflow.orchestrate(
                services=[],
                reviewer_name="Deepak",
                reviewer_action="APPROVED",
                reviewer_principal_id="aad:123",
                reviewer_role="Developer",
                reviewer_identity_verified=True,
            )

    def test_workflow_strict_enterprise_mode_requires_verified_identity(self):
        workflow = SecurityReviewWorkflow()
        workflow.strict_enterprise_approval = True
        with self.assertRaises(ValueError):
            workflow.orchestrate(
                services=[],
                reviewer_name="Deepak",
                reviewer_action="APPROVED",
                reviewer_principal_id="",
                reviewer_role="Security_Lead",
                reviewer_identity_verified=False,
            )

    def test_verify_evidence_ledger_reports_valid_chain(self):
        workflow = SecurityReviewWorkflow()
        with TemporaryDirectory() as tmpdir:
            ledger_path = Path(tmpdir) / "evidence_ledger.jsonl"
            workflow.ledger_path = ledger_path
            workflow.orchestrate(services=[])
            verification = workflow.verify_evidence_ledger()
            self.assertTrue(verification["valid"])
            self.assertEqual(verification["records_checked"], 1)

    def test_verify_evidence_ledger_detects_hash_tampering(self):
        workflow = SecurityReviewWorkflow()
        with TemporaryDirectory() as tmpdir:
            ledger_path = Path(tmpdir) / "evidence_ledger.jsonl"
            workflow.ledger_path = ledger_path
            workflow.orchestrate(services=[])

            original = ledger_path.read_text(encoding="utf-8").strip()
            record = json.loads(original)
            record["status"] = "TAMPERED"
            ledger_path.write_text(json.dumps(record), encoding="utf-8")

            verification = workflow.verify_evidence_ledger()
            self.assertFalse(verification["valid"])
            self.assertIn("mismatch", verification["error"].lower())


if __name__ == "__main__":
    unittest.main()
