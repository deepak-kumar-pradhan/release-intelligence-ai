import os
from typing import Any, Dict, List

from .agent_instructions import RISK_AGENT_SYSTEM_PROMPT

try:
    from openai import AzureOpenAI
except Exception:
    AzureOpenAI = None


class ExpertSecurityAgent:
    def __init__(self, use_llm: bool = False):
        self.use_llm = use_llm
        self.model = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        self.client = self._build_client() if use_llm else None

    def _build_client(self):
        if AzureOpenAI is None:
            return None

        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        api_key = os.getenv("AZURE_OPENAI_API_KEY")
        api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview")
        if not endpoint or not api_key:
            return None

        return AzureOpenAI(
            api_key=api_key,
            azure_endpoint=endpoint,
            api_version=api_version,
        )

    def analyze_service_findings(self, service_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        sonar_findings = service_payload.get("sonar", {}).get("issues", [])
        sast_findings = service_payload.get("checkmarx", {}).get("sast", {}).get("findings", [])
        sca_findings = service_payload.get("checkmarx", {}).get("sca", {}).get("findings", [])
        findings.extend(sonar_findings)
        findings.extend(sast_findings)
        findings.extend(sca_findings)

        analyses = []
        for finding in findings:
            if self.client:
                analyses.append(self._llm_analyze_finding(finding))
            else:
                analyses.append(self._heuristic_analyze_finding(finding))

        analyses.extend(self._detect_toxic_combinations(sonar_findings, sca_findings))
        return analyses

    def _llm_analyze_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        prompt = (
            "Analyze this vulnerability and return strict JSON only using keys: "
            "issue_id, tool_source, is_false_positive, triage_reasoning, remediation_diff, impact_score, category. "
            f"Finding: {finding}"
        )
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": RISK_AGENT_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
            )
            return {
                "issue_id": finding.get("id", "unknown"),
                "tool_source": self._tool_source(finding),
                "is_false_positive": False,
                "triage_reasoning": "LLM analysis produced structured guidance.",
                "remediation_diff": "See LLM response for patch guidance.",
                "impact_score": 7,
                "category": "WARNING",
                "confidence": "medium",
                "reason": "LLM analysis produced structured guidance.",
                "real_world_risk": response.choices[0].message.content,
                "proposed_fix_snippet": "See LLM response for patch guidance.",
                "verification_steps": ["Validate fix with static scan and targeted unit/integration tests."],
                "finding_id": finding.get("id", "unknown"),
                "false_positive": False,
            }
        except Exception as error:
            fallback = self._heuristic_analyze_finding(finding)
            fallback["reason"] = f"LLM unavailable: {error}. {fallback['reason']}"
            return fallback

    def _heuristic_analyze_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        finding_id = finding.get("id", "unknown")
        severity = str(finding.get("severity", "")).upper()
        category = finding.get("category") or finding.get("rule") or "Generic Security Finding"
        context = str(finding.get("code_context", "")).lower()
        file_path = str(finding.get("file", "")).lower()
        source = self._tool_source(finding)

        incomplete = not (finding.get("id") and (finding.get("severity") or finding.get("cve")))
        false_positive = "test/" in file_path or "mock" in context
        reason = "Likely test/mock-only context." if false_positive else "Impacts production code path."
        triage_category = "ADVISORY"
        impact_score = 3

        if incomplete:
            risk = "INCOMPLETE_DATA"
            fix = "# INCOMPLETE_DATA: provide full finding metadata and execution context"
            triage_category = "WARNING"
            impact_score = 5
        elif "sql" in category.lower() or "injection" in category.lower() or "rce" in category.lower():
            risk = "Attacker-controlled input could execute unintended commands/queries, exposing data or host access."
            fix = (
                "# Use parameterized APIs\n"
                "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_input,))"
            )
            triage_category = "BLOCKER"
            impact_score = 9
        elif "secret" in category.lower():
            risk = "Hardcoded credentials can be exfiltrated from source/history and reused across environments."
            fix = (
                "import os\n"
                "API_KEY = os.getenv(\"API_KEY\")\n"
                "if not API_KEY:\n"
                "    raise RuntimeError(\"API_KEY must be configured\")"
            )
            triage_category = "WARNING"
            impact_score = 8
        elif finding.get("cve"):
            risk = "Known vulnerable dependency could allow compromise through known exploit paths."
            fix = "# Upgrade dependency to a patched version in requirements.txt and regenerate lockfile"
            triage_category = "WARNING"
            impact_score = 7
        else:
            risk = "Potential security weakness in runtime path; exploitability depends on input controls and reachability."
            fix = "# Apply secure coding guardrails and input validation at trust boundaries"
            triage_category = "ADVISORY"
            impact_score = 4

        if severity == "CRITICAL" and not false_positive:
            risk = f"CRITICAL: {risk}"
            triage_category = "BLOCKER"
            impact_score = max(impact_score, 9)
        elif severity == "HIGH" and not false_positive:
            impact_score = max(impact_score, 8)

        remediation_diff = f"diff --git a/{finding.get('file', 'src/file.py')} b/{finding.get('file', 'src/file.py')}\n--- a/{finding.get('file', 'src/file.py')}\n+++ b/{finding.get('file', 'src/file.py')}\n@@\n-# vulnerable pattern\n+{fix}"

        return {
            "issue_id": finding_id,
            "tool_source": source,
            "is_false_positive": false_positive,
            "triage_reasoning": reason,
            "remediation_diff": remediation_diff,
            "impact_score": impact_score,
            "category": triage_category,
            "finding_id": finding_id,
            "false_positive": false_positive,
            "confidence": "high" if not false_positive else "medium",
            "reason": reason,
            "real_world_risk": risk,
            "proposed_fix_snippet": fix,
            "verification_steps": [
                "Re-run SAST/SCA on the affected branch.",
                "Add/execute regression tests for the vulnerable code path.",
            ],
            "severity": severity or "UNKNOWN",
            "finding_type": category,
        }

    def _tool_source(self, finding: Dict[str, Any]) -> str:
        if finding.get("cve") or finding.get("package"):
            return "Checkmarx"
        if finding.get("rule"):
            return "Sonar"
        return "Checkmarx"

    def _detect_toxic_combinations(self, sonar_findings: List[Dict[str, Any]], sca_findings: List[Dict[str, Any]]):
        has_medium_code_bug = any(str(item.get("severity", "")).upper() == "MEDIUM" for item in sonar_findings)
        critical_dependency = next(
            (item for item in sca_findings if str(item.get("severity", "")).upper() == "CRITICAL"),
            None,
        )

        if not (has_medium_code_bug and critical_dependency):
            return []

        return [
            {
                "issue_id": "TOXIC-COMBO-001",
                "tool_source": "Sonar/Checkmarx",
                "is_false_positive": False,
                "triage_reasoning": "Medium severity code weakness coexists with critical vulnerable dependency, creating a compound exploit path.",
                "remediation_diff": "diff --git a/requirements.txt b/requirements.txt\n--- a/requirements.txt\n+++ b/requirements.txt\n@@\n-# vulnerable dependency\n+# upgrade to patched dependency and harden calling code",
                "impact_score": 9,
                "category": "BLOCKER",
                "finding_id": "TOXIC-COMBO-001",
                "false_positive": False,
                "confidence": "medium",
                "reason": "Compound SAST + SCA risk pattern detected.",
                "real_world_risk": "Combined exploitability increases attack success likelihood and blast radius.",
                "proposed_fix_snippet": "# Patch vulnerable dependency and apply strict input validation in associated code path",
                "verification_steps": [
                    "Re-run SAST and SCA scans after dependency upgrade.",
                    "Execute targeted security regression tests for impacted endpoints.",
                ],
                "severity": "CRITICAL",
                "finding_type": "Toxic Combination",
            }
        ]
