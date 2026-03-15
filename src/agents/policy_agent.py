import json
import os
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Tuple

try:
    from azure.ai.projects import AIProjectClient
    from azure.identity import DefaultAzureCredential
except ImportError:
    AIProjectClient = None
    DefaultAzureCredential = None

from src.observability import get_tracer


class PolicyAgent:
    def __init__(self, use_llm: bool = False):
        self.use_llm = use_llm
        self.model = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        self.max_response_tokens = 180
        self.llm_only_amber = os.getenv("POLICY_LLM_ONLY_AMBER", "true").lower() == "true"
        self.foundry_project_endpoint = os.getenv("AZURE_AI_PROJECT_ENDPOINT", "").strip()
        self.foundry_policy_agent_name = os.getenv("FOUNDRY_POLICY_AGENT_NAME", "").strip()
        self.foundry_policy_agent_version = os.getenv("FOUNDRY_POLICY_AGENT_VERSION", "").strip()
        self.foundry_enabled = bool(
            self.foundry_project_endpoint
            and self.foundry_policy_agent_name
            and AIProjectClient is not None
            and DefaultAzureCredential is not None
        )
        self.tracer = get_tracer("release_intelligence.policy_agent")
        if self.foundry_enabled:
            print(
                "[LLM][PolicyAgent] Foundry Agent Service enabled "
                f"project_endpoint={self.foundry_project_endpoint} agent_name={self.foundry_policy_agent_name}"
            )
            if self.foundry_policy_agent_version:
                print(
                    "[LLM][PolicyAgent] Foundry agent version pinned "
                    f"version={self.foundry_policy_agent_version}"
                )
        else:
            print("[LLM][PolicyAgent] Disabled: Foundry Agent Service config or SDK unavailable")

    def _is_placeholder_secret(self, value: str) -> bool:
        normalized = str(value or "").strip()
        if not normalized:
            return True
        upper = normalized.upper()
        return upper.startswith("REPLACE_WITH_") or "YOUR_" in upper

    def _extract_object_attr(self, value: Any, key: str, default: Any = None) -> Any:
        if isinstance(value, dict):
            return value.get(key, default)
        return getattr(value, key, default)

    @contextmanager
    def _open_agent_service_clients(self) -> Iterator[Tuple[Any, Any, Any]]:
        if AIProjectClient is None or DefaultAzureCredential is None:
            raise RuntimeError(
                "azure-ai-projects and azure-identity are required for Foundry Agent Service execution."
            )

        credential = DefaultAzureCredential()
        project_client = AIProjectClient(endpoint=self.foundry_project_endpoint, credential=credential)
        openai_client = project_client.get_openai_client()
        try:
            yield credential, project_client, openai_client
        finally:
            for resource in (openai_client, project_client, credential):
                close_fn = getattr(resource, "close", None)
                if callable(close_fn):
                    close_fn()

    def evaluate_release(
        self,
        summary_rows: List[Dict[str, Any]],
        rules: Dict[str, Any],
        triage_findings: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        with self.tracer.start_as_current_span("policy_agent.evaluate_release") as span:
            deterministic = self._deterministic_evaluate(summary_rows, rules, triage_findings or {})
            decision_record = deterministic.get("decision_record", {})
            final_decision = str(decision_record.get("final_decision", "FAIL")).upper()
            span.set_attribute("policy.final_decision", final_decision)
            span.set_attribute("policy.llm_only_amber", self.llm_only_amber)
            span.set_attribute("policy.foundry_only", True)

            if not self.foundry_enabled:
                raise RuntimeError(
                    "Policy agent requires Foundry Agent Service, but the project endpoint, agent name, or SDK dependencies are unavailable."
                )

            if self.llm_only_amber and final_decision != "AMBER":
                span.add_event("policy.llm_skipped", {"reason": f"final_decision={final_decision}"})
                print(f"[LLM][PolicyAgent] Skipping LLM for final_decision={final_decision} (cost optimization)")
                return deterministic

            try:
                print("[LLM][PolicyAgent] Escalating governance evaluation to LLM")
                llm_decision = self._llm_evaluate(summary_rows, rules, triage_findings or {})
                if "reason" not in llm_decision:
                    llm_decision["reason"] = deterministic.get("reason", "Policy evaluation completed.")
                if "counts" not in llm_decision:
                    llm_decision["counts"] = deterministic.get("counts", {"critical": 0, "high": 0})
                span.add_event("policy.llm_used")
                return llm_decision
            except Exception as error:
                span.record_exception(error)
                print(f"[LLM][PolicyAgent] Foundry mode failed: {error}")
                raise RuntimeError(f"Policy Foundry mode failed: {error}") from error

    def _llm_evaluate(self, summary_rows: List[Dict[str, Any]], rules: Dict[str, Any], triage_findings: Dict[str, Any]) -> Dict[str, Any]:
        with self.tracer.start_as_current_span("policy_agent.llm_evaluate") as span:
            payload = {
                "summary_rows": self._compact_summary(summary_rows),
                "rules": self._compact_rules(rules),
                "triage_summary": self._compact_triage(triage_findings),
                "output_contract": {
                    "final_decision": "PASS|FAIL|AMBER",
                    "policy_violations": ["string"],
                    "requires_approval": True,
                    "approver_role_required": "Security_Manager",
                },
            }

            span.set_attribute("llm.model", self.model)
            span.set_attribute("llm.step", "policy_governance_evaluation")
            span.set_attribute("policy.services_count", len(summary_rows))
            user_prompt = (
                "Evaluate release policy from this compact payload and return JSON only. "
                f"Payload: {json.dumps(payload, separators=(',', ':'))}"
            )
            span.set_attribute("llm.prompt_preview", user_prompt[:400])

            if self.foundry_enabled:
                return self._llm_evaluate_via_agent_service(summary_rows, user_prompt, span)

            raise ValueError("Foundry Agent Service is not configured for policy evaluation")

    def _llm_evaluate_via_agent_service(self, summary_rows: List[Dict[str, Any]], user_prompt: str, span) -> Dict[str, Any]:
        with self._open_agent_service_clients() as (_, _, openai_client):
            conversation = openai_client.conversations.create(
                items=[{"type": "message", "role": "user", "content": user_prompt}]
            )
            conversation_id = str(self._extract_object_attr(conversation, "id", ""))
            if not conversation_id:
                raise ValueError("Foundry Agent Service did not return a conversation id")

            agent_reference: Dict[str, Any] = {
                "name": self.foundry_policy_agent_name,
                "type": "agent_reference",
            }
            if self.foundry_policy_agent_version:
                agent_reference["version"] = self.foundry_policy_agent_version

            span.set_attribute("llm.provider", "azure_ai_foundry_agent_service")
            span.set_attribute("llm.agent_name", self.foundry_policy_agent_name)
            span.set_attribute("llm.conversation_id", conversation_id)

            try:
                response = openai_client.responses.create(
                    conversation=conversation_id,
                    extra_body={"agent_reference": agent_reference},
                )
            finally:
                try:
                    openai_client.conversations.delete(conversation_id=conversation_id)
                except Exception as cleanup_error:
                    span.add_event("policy.conversation_delete_failed", {"error": str(cleanup_error)[:300]})

        usage = self._extract_object_attr(response, "usage", None)
        if usage:
            span.set_attribute("llm.prompt_tokens", int(self._extract_object_attr(usage, "input_tokens", 0) or 0))
            span.set_attribute("llm.completion_tokens", int(self._extract_object_attr(usage, "output_tokens", 0) or 0))
            total_tokens = self._extract_object_attr(usage, "total_tokens", None)
            if total_tokens is not None:
                span.set_attribute("llm.total_tokens", int(total_tokens or 0))

        content = self._extract_agent_service_text(response)
        cleaned = content.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        try:
            result = json.loads(cleaned)
        except json.JSONDecodeError as error:
            raise ValueError("Foundry policy response was not valid JSON") from error

        violations = result.get("policy_violations", [])
        span.set_attribute("policy.final_decision", str(result.get("final_decision", "")))
        span.set_attribute("policy.violations_count", len(violations))
        span.set_attribute("policy.violations", "; ".join(violations[:5])[:300])
        span.set_attribute("policy.requires_approval", bool(result.get("requires_approval", False)))
        span.set_attribute("policy.approver_role", str(result.get("approver_role_required", ""))[:80])
        span.add_event(
            "llm.response_received",
            {
                "model": self.model,
                "final_decision": str(result.get("final_decision", "")),
                "violations_count": str(len(violations)),
            },
        )
        print(f"[LLM][PolicyAgent] Governance response parsed successfully agent={self.foundry_policy_agent_name}")

        return self._normalize_decision(result, summary_rows)

    def _extract_agent_service_text(self, response_payload: Any) -> str:
        output_text = self._extract_object_attr(response_payload, "output_text", None)
        if isinstance(output_text, str) and output_text.strip():
            return output_text

        output = self._extract_object_attr(response_payload, "output", [])
        if isinstance(output, list):
            parts: List[str] = []
            for item in output:
                content = self._extract_object_attr(item, "content", [])
                if not isinstance(content, list):
                    continue
                for block in content:
                    text_value = self._extract_object_attr(block, "text", None)
                    if not text_value:
                        text_value = self._extract_object_attr(block, "output_text", None)
                    if not text_value:
                        text_value = self._extract_object_attr(block, "value", None)
                    if isinstance(text_value, str) and text_value.strip():
                        parts.append(text_value)
            if parts:
                return "\n".join(parts)

        return "{}"

    def _compact_summary(self, summary_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        compact_rows = []
        for row in summary_rows:
            compact_rows.append(
                {
                    "service": row.get("service_name"),
                    "version": row.get("release_version"),
                    "sonar": row.get("sonar_status"),
                    "sast_c": row.get("checkmarx_sast", {}).get("critical", 0),
                    "sast_h": row.get("checkmarx_sast", {}).get("high", 0),
                    "sca_c": row.get("checkmarx_sca", {}).get("critical", 0),
                    "sca_h": row.get("checkmarx_sca", {}).get("high", 0),
                }
            )
        return compact_rows

    def _compact_rules(self, rules: Dict[str, Any]) -> Dict[str, Any]:
        quality_gates = rules.get("quality_gates", {})
        return {
            "sonar_required": quality_gates.get("sonarqube", {}).get("min_quality_gate_status", "PASSED"),
            "sast_block_on": quality_gates.get("checkmarx_sast", {}).get("block_on", ["CRITICAL", "HIGH"]),
            "sca_max_cvss": quality_gates.get("checkmarx_sca", {}).get("max_cvss_score_allowed", 8.9),
            "approval_role": rules.get("agentic_rules", {}).get("human_in_the_loop", {}).get("required_role", "Security_Manager"),
        }

    def _compact_triage(self, triage_findings: Dict[str, Any]) -> Dict[str, Any]:
        top_findings = []
        warning_count = 0
        blocker_count = 0

        for service_name, payload in triage_findings.items():
            analyses = payload.get("analysis", []) if isinstance(payload, dict) else []
            for item in analyses:
                category = str(item.get("category", "")).upper()
                if category == "WARNING":
                    warning_count += 1
                if category == "BLOCKER":
                    blocker_count += 1

                top_findings.append(
                    {
                        "service": service_name,
                        "id": item.get("finding_id", item.get("issue_id", "unknown")),
                        "severity": item.get("severity", "UNKNOWN"),
                        "category": item.get("category", "N/A"),
                        "impact": item.get("impact_score", 0),
                        "false_positive": bool(item.get("is_false_positive", item.get("false_positive", False))),
                    }
                )

        top_findings = sorted(top_findings, key=lambda x: int(x.get("impact", 0)), reverse=True)[:6]
        return {
            "warning_count": warning_count,
            "blocker_count": blocker_count,
            "top_findings": top_findings,
        }

    def _coerce_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _deterministic_evaluate(
        self,
        summary_rows: List[Dict[str, Any]],
        rules: Dict[str, Any],
        triage_findings: Dict[str, Any],
    ) -> Dict[str, Any]:
        critical = 0
        high = 0
        has_sonar_fail = False
        policy_violations = []
        requires_approval = False
        justification_request = None

        sonar_gate = rules.get("quality_gates", {}).get("sonarqube", {})
        sonar_fail_statuses = {"ERROR", "FAILED"}
        if sonar_gate.get("min_quality_gate_status") == "PASSED":
            sonar_fail_statuses.add("WARN")

        triage_items = []
        for service_name, payload in triage_findings.items():
            analyses = payload.get("analysis", []) if isinstance(payload, dict) else []
            for item in analyses:
                item_copy = dict(item)
                item_copy.setdefault("service_name", service_name)
                triage_items.append(item_copy)

        for row in summary_rows:
            critical += row["checkmarx_sast"]["critical"] + row["checkmarx_sca"]["critical"]
            high += row["checkmarx_sast"]["high"] + row["checkmarx_sca"]["high"]
            has_sonar_fail = has_sonar_fail or row["sonar_status"] in sonar_fail_statuses

        production_service = any("prod" in row.get("release_version", "").lower() or row.get("release_version", "") == "main" for row in summary_rows)
        has_warning = any(str(item.get("category", "")).upper() == "WARNING" for item in triage_items if not item.get("is_false_positive", item.get("false_positive", False)))
        has_high_impact_production = any(
            int(item.get("impact_score", 0)) > 8 and production_service
            for item in triage_items
            if not item.get("is_false_positive", item.get("false_positive", False))
        )

        if has_high_impact_production:
            final_decision = "FAIL"
            reason = "Critical vulnerabilities detected; human approval required before release."
            policy_violations.append("impact_score_gt_8_production")
            requires_approval = True
        elif critical > 0:
            final_decision = "FAIL"
            reason = "Critical vulnerabilities detected; human approval required before release."
            policy_violations.append("critical_vulnerability_block")
            requires_approval = True
        elif has_sonar_fail:
            final_decision = "FAIL"
            reason = "SonarQube quality gate failed for one or more services."
            policy_violations.append("sonarqube_quality_gate")
        elif has_warning:
            final_decision = "AMBER"
            reason = "Warnings present that require human-in-the-loop approval."
            policy_violations.append("warning_requires_hitl")
            requires_approval = True
            first_warning = next((item for item in triage_items if str(item.get("category", "")).upper() == "WARNING"), {})
            justification_request = (
                f"System detected a potential risk in Service [{first_warning.get('service_name', 'Unknown Service')}]. "
                f"Analysis suggests it is a [{first_warning.get('finding_type', first_warning.get('category', 'Risk'))}]. "
                "Requires manual override to proceed."
            )
        else:
            final_decision = "PASS"
            reason = "All governance gates passed."
            policy_violations.append("none")

        decision_record = {
            "final_decision": final_decision,
            "policy_violations": policy_violations,
            "requires_approval": requires_approval,
            "approver_role_required": (
                rules.get("agentic_rules", {})
                .get("human_in_the_loop", {})
                .get("required_role", "Security_Manager")
            ),
        }
        if justification_request:
            decision_record["justification_request"] = justification_request

        normalized = self._normalize_decision(decision_record, summary_rows)
        normalized["reason"] = reason
        normalized["counts"] = {"critical": critical, "high": high}
        normalized["confidence"] = "high"
        return normalized

    def _normalize_decision(self, decision_record: Dict[str, Any], summary_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        final_decision = str(decision_record.get("final_decision", "FAIL")).upper()
        status = "GO" if final_decision == "PASS" else "NO-GO"
        counts = {
            "critical": sum(row["checkmarx_sast"]["critical"] + row["checkmarx_sca"]["critical"] for row in summary_rows),
            "high": sum(row["checkmarx_sast"]["high"] + row["checkmarx_sca"]["high"] for row in summary_rows),
        }
        reason = decision_record.get("reason", "Policy evaluation completed.")
        # A clean PASS must never require approval, regardless of what the LLM may have returned
        raw_requires = bool(decision_record.get("requires_approval", final_decision == "AMBER"))
        requires_approval_final = raw_requires if final_decision != "PASS" else False
        return {
            "status": status,
            "reason": reason,
            "counts": counts,
            "triggered_rules": decision_record.get("policy_violations", []),
            "confidence": decision_record.get("confidence", "medium"),
            "decision_record": {
                "final_decision": final_decision,
                "policy_violations": decision_record.get("policy_violations", []),
                "requires_approval": requires_approval_final,
                "approver_role_required": decision_record.get("approver_role_required", "Security_Manager"),
                **(
                    {"justification_request": decision_record["justification_request"]}
                    if "justification_request" in decision_record
                    else {}
                ),
            },
            "requires_approval": requires_approval_final,
        }
