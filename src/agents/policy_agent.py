import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import requests

from src.observability import get_tracer

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


class PolicyAgent:
    def __init__(self, use_llm: bool = False):
        self.use_llm = use_llm
        self.model = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        self.max_response_tokens = self._coerce_int(os.getenv("POLICY_LLM_MAX_RESPONSE_TOKENS", "180"), default=180)
        self.llm_only_amber = os.getenv("POLICY_LLM_ONLY_AMBER", "true").lower() == "true"
        self.policy_foundry_only = os.getenv("POLICY_FOUNDRY_ONLY", "false").lower() == "true"
        self.foundry_responses_endpoint = os.getenv("FOUNDRY_POLICY_RESPONSES_ENDPOINT", "").strip()
        self.foundry_activity_endpoint = os.getenv("FOUNDRY_POLICY_ACTIVITY_ENDPOINT", "").strip()
        foundry_key = os.getenv("FOUNDRY_API_KEY", "").strip()
        azure_key = os.getenv("AZURE_OPENAI_API_KEY", "").strip()
        foundry_key_valid = bool(foundry_key and not self._is_placeholder_secret(foundry_key))
        azure_key_valid = bool(azure_key and not self._is_placeholder_secret(azure_key))
        self.foundry_api_key = foundry_key if foundry_key_valid else azure_key
        self.foundry_enabled = bool(
            self.foundry_responses_endpoint
            and self.foundry_api_key
            and not self._is_placeholder_secret(self.foundry_api_key)
        )
        self.tracer = get_tracer("release_intelligence.policy_agent")
        self.client = self._build_client() if (use_llm and not self.policy_foundry_only) else None
        if self.foundry_enabled:
            print(
                f"[LLM][PolicyAgent] Foundry responses enabled endpoint={self.foundry_responses_endpoint}"
            )
            if self.foundry_activity_endpoint:
                print(
                    f"[LLM][PolicyAgent] Foundry activity trace endpoint enabled endpoint={self.foundry_activity_endpoint}"
                )
        if self.policy_foundry_only:
            print("[LLM][PolicyAgent] Local OpenAI SDK path disabled (POLICY_FOUNDRY_ONLY=true)")
        elif self.foundry_responses_endpoint and not (foundry_key_valid or azure_key_valid):
            print("[LLM][PolicyAgent] Foundry endpoint set, but API key is missing or placeholder")
        elif not use_llm:
            print("[LLM][PolicyAgent] Disabled: missing AZURE_OPENAI_ENDPOINT/API_KEY")

    def _build_client(self):
        if OpenAI is None:
            print("[LLM][PolicyAgent] OpenAI SDK import failed")
            return None

        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        api_key = os.getenv("AZURE_OPENAI_API_KEY")
        if not endpoint or not api_key or self._is_placeholder_secret(api_key):
            print("[LLM][PolicyAgent] Missing endpoint or api_key")
            return None

        print(
            f"[LLM][PolicyAgent] Initializing client model={self.model} endpoint={endpoint} api_key={'set' if api_key else 'missing'}"
        )

        return OpenAI(
            base_url=endpoint,
            api_key=api_key,
        )

    def _is_placeholder_secret(self, value: str) -> bool:
        normalized = str(value or "").strip()
        if not normalized:
            return True
        upper = normalized.upper()
        return upper.startswith("REPLACE_WITH_") or "YOUR_" in upper

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
            span.set_attribute("policy.foundry_only", self.policy_foundry_only)

            if not self.client and not self.foundry_enabled:
                span.add_event("policy.deterministic_only")
                print("[LLM][PolicyAgent] Using deterministic policy path")
                return deterministic

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
                print(f"[LLM][PolicyAgent] LLM evaluation failed, using deterministic path: {error}")
                return deterministic

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
                self._emit_foundry_activity_trace(user_prompt, span)
                return self._llm_evaluate_via_foundry(summary_rows, user_prompt, span)

            if not self.client:
                raise ValueError("No LLM client configured for policy evaluation")

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a release policy evaluator. Return JSON only using output_contract.",
                    },
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.0,
                max_tokens=self.max_response_tokens,
            )

            content = response.choices[0].message.content or "{}"
            usage = getattr(response, "usage", None)
            if usage:
                span.set_attribute("llm.prompt_tokens", int(getattr(usage, "prompt_tokens", 0)))
                span.set_attribute("llm.completion_tokens", int(getattr(usage, "completion_tokens", 0)))
                span.set_attribute("llm.total_tokens", int(getattr(usage, "total_tokens", 0)))

            cleaned = content.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            try:
                result = json.loads(cleaned)
            except json.JSONDecodeError as error:
                raise ValueError("Policy LLM response was not valid JSON") from error

            violations = result.get("policy_violations", [])
            span.set_attribute("policy.response_bytes", len(content))
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
            print("[LLM][PolicyAgent] Governance response parsed successfully")

            return self._normalize_decision(result, summary_rows)

    def _llm_evaluate_via_foundry(self, summary_rows: List[Dict[str, Any]], user_prompt: str, span) -> Dict[str, Any]:
        headers = {
            "Content-Type": "application/json",
            "api-key": self.foundry_api_key,
        }
        body = {
            "input": [
                {
                    "type": "message",
                    "role": "system",
                    "content": [
                        {
                            "type": "input_text",
                            "text": "You are a release policy evaluator. Return JSON only using output_contract.",
                        }
                    ],
                },
                {
                    "type": "message",
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": user_prompt,
                        }
                    ],
                },
            ]
        }

        response = requests.post(
            self.foundry_responses_endpoint,
            headers=headers,
            json=body,
            timeout=45,
        )
        if not response.ok:
            error_excerpt = (response.text or "").strip().replace("\n", " ")[:800]
            span.set_attribute("llm.response_status", response.status_code)
            span.set_attribute("llm.error_excerpt", error_excerpt[:300])
            print(
                "[LLM][PolicyAgent] Foundry responses call failed "
                f"status={response.status_code} body={error_excerpt or 'empty'}"
            )
            raise ValueError(
                "Foundry responses call failed "
                f"status={response.status_code} body={error_excerpt or 'empty'}"
            )

        payload = response.json()
        content = self._extract_foundry_text(payload)

        usage = payload.get("usage", {}) if isinstance(payload, dict) else {}
        span.set_attribute("llm.provider", "azure_ai_foundry_responses")
        span.set_attribute("llm.response_status", response.status_code)
        span.set_attribute("policy.response_bytes", len(content))
        if usage:
            span.set_attribute("llm.prompt_tokens", int(usage.get("input_tokens", 0)))
            span.set_attribute("llm.completion_tokens", int(usage.get("output_tokens", 0)))
            span.set_attribute("llm.total_tokens", int(usage.get("total_tokens", 0)))

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
        print("[LLM][PolicyAgent] Governance response parsed successfully (Foundry)")

        return self._normalize_decision(result, summary_rows)

    def _extract_foundry_text(self, response_payload: Dict[str, Any]) -> str:
        if not isinstance(response_payload, dict):
            return "{}"

        output_text = response_payload.get("output_text")
        if isinstance(output_text, str) and output_text.strip():
            return output_text

        output = response_payload.get("output", [])
        if isinstance(output, list):
            parts: List[str] = []
            for item in output:
                if not isinstance(item, dict):
                    continue
                content = item.get("content", [])
                if not isinstance(content, list):
                    continue
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    text_value = block.get("text") or block.get("output_text") or block.get("value")
                    if isinstance(text_value, str) and text_value.strip():
                        parts.append(text_value)
            if parts:
                return "\n".join(parts)

        return "{}"

    def _emit_foundry_activity_trace(self, user_prompt: str, span) -> None:
        if not self.foundry_activity_endpoint:
            return

        headers = {
            "Content-Type": "application/json",
            "api-key": self.foundry_api_key,
        }
        activity_payload = {
            "type": "message",
            "id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "serviceUrl": "https://ri-hackathon-resource.services.ai.azure.com",
            "channelId": "release-intelligence",
            "from": {"id": "release-intelligence-app", "name": "Release Intelligence"},
            "conversation": {"id": str(uuid4())},
            "recipient": {"id": "policy-governance-agent"},
            "text": user_prompt,
        }

        try:
            response = requests.post(
                self.foundry_activity_endpoint,
                headers=headers,
                json=activity_payload,
                timeout=20,
            )
            span.set_attribute("llm.activity_status", response.status_code)
            if response.status_code in (200, 201, 202):
                print(
                    "[LLM][PolicyAgent] Foundry activity trace emitted "
                    f"status={response.status_code}"
                )
                return

            error_excerpt = (response.text or "").strip().replace("\n", " ")[:400]
            span.add_event(
                "policy.activity_emit_failed",
                {
                    "status": response.status_code,
                    "error": error_excerpt,
                },
            )
            print(
                "[LLM][PolicyAgent] Foundry activity trace failed "
                f"status={response.status_code} body={error_excerpt or 'empty'}"
            )
        except Exception as error:
            span.add_event("policy.activity_emit_error", {"error": str(error)[:300]})
            print(f"[LLM][PolicyAgent] Foundry activity trace error: {error}")

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
