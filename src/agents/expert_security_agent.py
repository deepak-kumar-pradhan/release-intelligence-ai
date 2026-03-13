import os
import json
import hashlib
from pathlib import Path
from typing import Any, Dict, List

from src.observability import get_tracer

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


class ExpertSecurityAgent:
    def __init__(self, use_llm: bool = False):
        self.use_llm = use_llm
        self.model = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        self.max_llm_findings = self._coerce_int(os.getenv("LLM_MAX_FINDINGS_PER_SERVICE", "2"), default=2)
        self.max_response_tokens = self._coerce_int(os.getenv("LLM_MAX_RESPONSE_TOKENS", "220"), default=220)
        self.cache_enabled = os.getenv("LLM_CACHE_ENABLED", "true").lower() == "true"
        self.cache_path = Path(os.getenv("LLM_CACHE_PATH", "session/llm_cache.json"))
        self._cache = self._load_cache()
        self.tracer = get_tracer("release_intelligence.expert_security_agent")
        self.client = self._build_client() if use_llm else None
        if not use_llm:
            print("[LLM][ExpertSecurityAgent] Disabled: missing AZURE_OPENAI_ENDPOINT/API_KEY")

    def _build_client(self):
        if OpenAI is None:
            print("[LLM][ExpertSecurityAgent] OpenAI SDK import failed")
            return None

        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        api_key = os.getenv("AZURE_OPENAI_API_KEY")
        print(
            f"[LLM][ExpertSecurityAgent] Initializing client model={self.model} endpoint={endpoint} api_key={'set' if api_key else 'missing'}"
        )
        if not endpoint or not api_key or self._is_placeholder_secret(api_key):
            print("[LLM][ExpertSecurityAgent] Missing endpoint or api_key")
            return None

        if "/openai/v1" not in endpoint:
            print("[LLM][ExpertSecurityAgent] Warning: endpoint should typically end with /openai/v1")

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

    def analyze_service_findings(self, service_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        with self.tracer.start_as_current_span("expert_security_agent.analyze_service_findings") as span:
            service_name = service_payload.get("service_name", "unknown")
            span.set_attribute("service.name", service_name)

            findings = []
            sonar_findings = service_payload.get("sonar", {}).get("issues", [])
            sast_findings = service_payload.get("checkmarx", {}).get("sast", {}).get("findings", [])
            sca_findings = service_payload.get("checkmarx", {}).get("sca", {}).get("findings", [])
            findings.extend(sonar_findings)
            findings.extend(sast_findings)
            findings.extend(sca_findings)

            prioritized_findings = sorted(
                findings,
                key=lambda item: self._severity_rank(str(item.get("severity", "UNKNOWN"))),
                reverse=True,
            )

            analyses = []
            llm_calls = 0
            for finding in prioritized_findings:
                if self.client and llm_calls < self.max_llm_findings and self._should_use_llm_for_finding(finding):
                    analyses.append(self._llm_analyze_finding(finding))
                    llm_calls += 1
                else:
                    analyses.append(self._heuristic_analyze_finding(finding))

            span.set_attribute("findings.total", len(findings))
            span.set_attribute("findings.llm_calls", llm_calls)
            if findings:
                print(
                    f"[LLM][ExpertSecurityAgent] Cost mode: llm_calls={llm_calls}/{len(findings)} max_llm_findings={self.max_llm_findings}"
                )

            analyses.extend(self._detect_toxic_combinations(sonar_findings, sca_findings))
            return analyses

    def _llm_analyze_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        compact_finding = self._compact_finding(finding)
        cache_key = self._cache_key(compact_finding)
        with self.tracer.start_as_current_span("expert_security_agent.llm_analyze_finding") as span:
            span.set_attribute("finding.id", str(finding.get("id", "unknown")))
            span.set_attribute("finding.severity", str(finding.get("severity", "UNKNOWN")))
            span.set_attribute("llm.model", self.model)
            span.set_attribute("llm.cache_enabled", self.cache_enabled)
            span.set_attribute("finding.rule", str(finding.get("rule", finding.get("category", "")))[:120])
            span.set_attribute("finding.description", str(finding.get("description", finding.get("message", "")))[:200])
            span.set_attribute("finding.file", str(finding.get("file", finding.get("component", "")))[:120])

            if self.cache_enabled and cache_key in self._cache:
                span.add_event("llm.cache_hit")
                print(f"[LLM][ExpertSecurityAgent] Cache hit finding_id={finding.get('id', 'unknown')}")
                return dict(self._cache[cache_key])

            prompt = (
                "Analyze this security finding and return JSON only with keys: "
                "issue_id, tool_source, is_false_positive, triage_reasoning, remediation_diff, impact_score, category. "
                f"Finding: {json.dumps(compact_finding, separators=(',', ':'))}"
            )
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a concise AppSec triage assistant. Return JSON only.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.0,
                    max_tokens=self.max_response_tokens,
                )
                raw_content = response.choices[0].message.content or ""
                parsed = self._parse_llm_json(raw_content)
                span.set_attribute("llm.prompt_preview", prompt[:400])
                usage = getattr(response, "usage", None)
                if usage:
                    span.set_attribute("llm.prompt_tokens", int(getattr(usage, "prompt_tokens", 0)))
                    span.set_attribute("llm.completion_tokens", int(getattr(usage, "completion_tokens", 0)))
                    span.set_attribute("llm.total_tokens", int(getattr(usage, "total_tokens", 0)))

                remediation = str(parsed.get("remediation_diff", "")).strip()
                triage_reasoning = str(parsed.get("triage_reasoning", "")).strip()
                category = str(parsed.get("category", "WARNING")).upper() if parsed else "WARNING"
                impact_score = self._coerce_int(parsed.get("impact_score", 7), default=7)
                is_false_positive = bool(parsed.get("is_false_positive", False)) if parsed else False

                if not remediation:
                    remediation = "No remediation details returned by model."
                if not triage_reasoning:
                    triage_reasoning = "LLM analysis produced structured guidance."

                llm_result = {
                    "issue_id": parsed.get("issue_id", finding.get("id", "unknown")) if parsed else finding.get("id", "unknown"),
                    "tool_source": parsed.get("tool_source", self._tool_source(finding)) if parsed else self._tool_source(finding),
                    "is_false_positive": is_false_positive,
                    "triage_reasoning": triage_reasoning,
                    "remediation_diff": remediation,
                    "impact_score": impact_score,
                    "category": category,
                    "confidence": "medium",
                    "reason": triage_reasoning,
                    "real_world_risk": triage_reasoning,
                    "proposed_fix_snippet": remediation,
                    "verification_steps": ["Validate fix with static scan and targeted unit/integration tests."],
                    "finding_id": finding.get("id", "unknown"),
                    "false_positive": is_false_positive,
                    "severity": str(finding.get("severity", "UNKNOWN")).upper() or "UNKNOWN",
                    "llm_raw_response": raw_content,
                }
                print(
                    f"[LLM][ExpertSecurityAgent] Success finding_id={finding.get('id', 'unknown')} model={self.model}"
                )
                span.set_attribute("llm.category", category)
                span.set_attribute("llm.impact_score", impact_score)
                span.set_attribute("llm.false_positive", is_false_positive)
                span.set_attribute("llm.triage_reasoning", triage_reasoning[:300])
                span.set_attribute("llm.remediation_preview", remediation[:200])
                span.set_attribute("llm.step", "security_finding_triage")
                span.add_event("llm.response_received", {
                    "model": self.model,
                    "category": category,
                    "impact_score": str(impact_score),
                    "is_false_positive": str(is_false_positive),
                })

                if self.cache_enabled:
                    self._cache[cache_key] = llm_result
                    self._save_cache()

                return llm_result
            except Exception as error:
                span.record_exception(error)
                print(f"[LLM][ExpertSecurityAgent] Error finding_id={finding.get('id', 'unknown')}: {error}")
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

    def _parse_llm_json(self, raw_content: str) -> Dict[str, Any]:
        cleaned = (raw_content or "").strip()
        if not cleaned:
            return {}

        # Handle fenced markdown payloads as commonly returned by chat models.
        cleaned = cleaned.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

        try:
            parsed = json.loads(cleaned)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start >= 0 and end > start:
                try:
                    parsed = json.loads(cleaned[start : end + 1])
                    return parsed if isinstance(parsed, dict) else {}
                except Exception:
                    return {}
            return {}

    def _coerce_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _cache_key(self, compact_finding: Dict[str, Any]) -> str:
        serialized = json.dumps(compact_finding, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _load_cache(self) -> Dict[str, Dict[str, Any]]:
        if not self.cache_enabled:
            return {}
        if not self.cache_path.exists():
            return {}
        try:
            raw = self.cache_path.read_text(encoding="utf-8")
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return {}

    def _save_cache(self) -> None:
        if not self.cache_enabled:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache, ensure_ascii=True), encoding="utf-8")
        except Exception as error:
            print(f"[LLM][ExpertSecurityAgent] Cache write failed: {error}")

    def _severity_rank(self, severity: str) -> int:
        rank = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
        }
        return rank.get(str(severity).upper(), 0)

    def _should_use_llm_for_finding(self, finding: Dict[str, Any]) -> bool:
        severity = str(finding.get("severity", "")).upper()
        return severity in {"CRITICAL", "HIGH"} or bool(finding.get("cve"))

    def _compact_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": finding.get("id"),
            "severity": finding.get("severity"),
            "rule_or_category": finding.get("rule") or finding.get("category"),
            "message": str(finding.get("message", ""))[:220],
            "file": finding.get("file"),
            "line": finding.get("line"),
            "cve": finding.get("cve"),
            "package": finding.get("package"),
            "code_context": str(finding.get("code_context", ""))[:220],
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
