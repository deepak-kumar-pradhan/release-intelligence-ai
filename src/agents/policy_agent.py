import json
import os
from typing import Any, Dict, List, Optional

try:
    from openai import OpenAI
except Exception:
    OpenAI = None


class PolicyAgent:
    def __init__(self, use_llm: bool = False):
        self.use_llm = use_llm
        self.model = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        self.max_response_tokens = self._coerce_int(os.getenv("POLICY_LLM_MAX_RESPONSE_TOKENS", "180"), default=180)
        self.client = self._build_client() if use_llm else None
        if not use_llm:
            print("[LLM][PolicyAgent] Disabled: missing AZURE_OPENAI_ENDPOINT/API_KEY")

    def _build_client(self):
        if OpenAI is None:
            print("[LLM][PolicyAgent] OpenAI SDK import failed")
            return None

        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        api_key = os.getenv("AZURE_OPENAI_API_KEY")
        if not endpoint or not api_key:
            print("[LLM][PolicyAgent] Missing endpoint or api_key")
            return None

        print(
            f"[LLM][PolicyAgent] Initializing client model={self.model} endpoint={endpoint} api_key={'set' if api_key else 'missing'}"
        )

        return OpenAI(
            base_url=endpoint,
            api_key=api_key,
        )

    def evaluate_release(
        self,
        summary_rows: List[Dict[str, Any]],
        rules: Dict[str, Any],
        triage_findings: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if self.client:
            try:
                print("[LLM][PolicyAgent] Evaluating governance with LLM")
                return self._llm_evaluate(summary_rows, rules, triage_findings or {})
            except Exception as error:
                print(f"[LLM][PolicyAgent] LLM evaluation failed, using deterministic path: {error}")
                return self._deterministic_evaluate(summary_rows, rules, triage_findings or {})
        print("[LLM][PolicyAgent] Using deterministic policy path")
        return self._deterministic_evaluate(summary_rows, rules, triage_findings or {})

    def _llm_evaluate(self, summary_rows: List[Dict[str, Any]], rules: Dict[str, Any], triage_findings: Dict[str, Any]) -> Dict[str, Any]:
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

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a release policy evaluator. Return JSON only using output_contract.",
                },
                {
                    "role": "user",
                    "content": (
                        "Evaluate release policy from this compact payload and return JSON only. "
                        f"Payload: {json.dumps(payload, separators=(',', ':'))}"
                    ),
                },
            ],
            temperature=0.0,
            max_tokens=self.max_response_tokens,
        )

        content = response.choices[0].message.content or "{}"
        cleaned = content.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        result = json.loads(cleaned)
        print("[LLM][PolicyAgent] Governance response parsed successfully")

        return self._normalize_decision(result, summary_rows)

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
        except Exception:
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
        return {
            "status": status,
            "reason": reason,
            "counts": counts,
            "triggered_rules": decision_record.get("policy_violations", []),
            "confidence": decision_record.get("confidence", "medium"),
            "decision_record": {
                "final_decision": final_decision,
                "policy_violations": decision_record.get("policy_violations", []),
                "requires_approval": bool(decision_record.get("requires_approval", final_decision == "AMBER")),
                "approver_role_required": decision_record.get("approver_role_required", "Security_Manager"),
                **(
                    {"justification_request": decision_record["justification_request"]}
                    if "justification_request" in decision_record
                    else {}
                ),
            },
            "requires_approval": bool(decision_record.get("requires_approval", final_decision == "AMBER")),
        }
