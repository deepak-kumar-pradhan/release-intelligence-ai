import unittest
import json
import os
from pathlib import Path
from contextlib import contextmanager
from tempfile import TemporaryDirectory
from unittest.mock import patch

import src.agents.expert_security_agent as expert_security_agent_module
from src.agents.expert_security_agent import ExpertSecurityAgent
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


class TestSecurityHardening(unittest.TestCase):
    def _build_workflow(self):
        return SecurityReviewWorkflow(
            expert_agent=StubExpertAgent(),
            policy_agent=StubPolicyAgent(),
        )

    def test_expert_agent_reuses_one_foundry_conversation_per_service(self):
        class FakeConversationItems:
            def __init__(self):
                self.created = []

            def create(self, conversation_id, items):
                self.created.append((conversation_id, items))

        class FakeConversations:
            def __init__(self):
                self.created = []
                self.deleted = []
                self.items = FakeConversationItems()

            def create(self, items):
                self.created.append(items)
                return {"id": "conv-1"}

            def delete(self, conversation_id):
                self.deleted.append(conversation_id)

        class FakeOpenAIClient:
            def __init__(self):
                self.conversations = FakeConversations()
                self.responses_created = []
                self._response_index = 0

            def responses_create_payload(self):
                payloads = [
                    {
                        "issue_id": "SONAR-101",
                        "tool_source": "Sonar",
                        "is_false_positive": False,
                        "triage_reasoning": "First critical finding analyzed with shared service context.",
                        "remediation_diff": "diff --git a/a b/a",
                        "impact_score": 9,
                        "category": "BLOCKER",
                    },
                    {
                        "issue_id": "SCA-202",
                        "tool_source": "Checkmarx",
                        "is_false_positive": False,
                        "triage_reasoning": "Second finding analyzed in the same service conversation.",
                        "remediation_diff": "diff --git a/requirements.txt b/requirements.txt",
                        "impact_score": 8,
                        "category": "WARNING",
                    },
                ]
                payload = payloads[self._response_index]
                self._response_index += 1
                return payload

            @property
            def responses(self):
                return self

            def create(self, conversation, extra_body):
                self.responses_created.append((conversation, extra_body))
                return {"output_text": json.dumps(self.responses_create_payload())}

        fake_openai_client = FakeOpenAIClient()

        @contextmanager
        def fake_open_agent_service_clients(self):
            yield None, None, fake_openai_client

        service_payload = {
            "service_name": "orders-api",
            "release_version": "2026.03.15",
            "sonar": {
                "issues": [
                    {
                        "id": "SONAR-101",
                        "severity": "CRITICAL",
                        "rule": "sql-injection",
                        "message": "Unsanitized SQL input",
                        "file": "src/orders.py",
                    }
                ]
            },
            "checkmarx": {
                "sast": {"findings": []},
                "sca": {
                    "findings": [
                        {
                            "id": "SCA-202",
                            "severity": "HIGH",
                            "cve": "CVE-2026-0001",
                            "package": "requests",
                            "message": "Known vulnerable dependency",
                            "file": "requirements.txt",
                        }
                    ]
                },
            },
        }

        original_project_client = expert_security_agent_module.AIProjectClient
        original_credential = expert_security_agent_module.DefaultAzureCredential
        expert_security_agent_module.AIProjectClient = object
        expert_security_agent_module.DefaultAzureCredential = object
        try:
            with patch.dict(
                os.environ,
                {
                    "AZURE_AI_PROJECT_ENDPOINT": "https://example.services.ai.azure.com/api/projects/demo",
                    "FOUNDRY_EXPERT_AGENT_NAME": "expert-security-agent",
                    "LLM_MAX_FINDINGS_PER_SERVICE": "2",
                    "LLM_CACHE_ENABLED": "false",
                },
                clear=False,
            ):
                agent = ExpertSecurityAgent(use_llm=True)
                agent._open_agent_service_clients = fake_open_agent_service_clients.__get__(agent, ExpertSecurityAgent)

                analyses = agent.analyze_service_findings(service_payload)

            self.assertEqual(len(fake_openai_client.conversations.created), 1)
            self.assertEqual(len(fake_openai_client.conversations.items.created), 2)
            self.assertEqual(len(fake_openai_client.responses_created), 2)
            self.assertEqual(fake_openai_client.conversations.deleted, ["conv-1"])
            self.assertEqual(analyses[0]["issue_id"], "SONAR-101")
            self.assertEqual(analyses[1]["issue_id"], "SCA-202")
        finally:
            expert_security_agent_module.AIProjectClient = original_project_client
            expert_security_agent_module.DefaultAzureCredential = original_credential

    def test_workflow_rejects_invalid_service_name(self):
        workflow = self._build_workflow()
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
        workflow = self._build_workflow()
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
        workflow = self._build_workflow()
        with self.assertRaises(ValueError):
            workflow.orchestrate(
                services=[],
                reviewer_name="Security Lead",
                reviewer_action="MAYBE",
            )

    def test_workflow_requires_reviewer_name_when_action_present(self):
        workflow = self._build_workflow()
        with self.assertRaises(ValueError):
            workflow.orchestrate(
                services=[],
                reviewer_name="",
                reviewer_action="APPROVED",
            )

    def test_workflow_writes_evidence_ledger_record(self):
        workflow = self._build_workflow()
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
        workflow = self._build_workflow()
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
        workflow = self._build_workflow()
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
        workflow = self._build_workflow()
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
        workflow = self._build_workflow()
        with TemporaryDirectory() as tmpdir:
            ledger_path = Path(tmpdir) / "evidence_ledger.jsonl"
            workflow.ledger_path = ledger_path
            workflow.orchestrate(services=[])
            verification = workflow.verify_evidence_ledger()
            self.assertTrue(verification["valid"])
            self.assertEqual(verification["records_checked"], 1)

    def test_verify_evidence_ledger_detects_hash_tampering(self):
        workflow = self._build_workflow()
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
