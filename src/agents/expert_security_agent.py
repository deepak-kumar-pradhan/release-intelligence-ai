import os
import json
import hashlib
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

try:
    from azure.ai.projects import AIProjectClient
    from azure.identity import DefaultAzureCredential
except ImportError:
    AIProjectClient = None
    DefaultAzureCredential = None

from src.observability import get_tracer


class ExpertSecurityAgent:
    def __init__(self, use_llm: bool = False):
        self.use_llm = use_llm
        self.model = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        self.max_llm_findings = self._coerce_int(os.getenv("LLM_MAX_FINDINGS_PER_SERVICE", "2"), default=2)
        self.max_response_tokens = 220
        self.cache_enabled = os.getenv("LLM_CACHE_ENABLED", "true").lower() == "true"
        self.foundry_project_endpoint = os.getenv("AZURE_AI_PROJECT_ENDPOINT", "").strip()
        self.foundry_expert_agent_name = os.getenv("FOUNDRY_EXPERT_AGENT_NAME", "").strip()
        self.foundry_expert_agent_version = os.getenv("FOUNDRY_EXPERT_AGENT_VERSION", "").strip()
        self.expert_foundry_enabled = bool(
            self.foundry_project_endpoint
            and self.foundry_expert_agent_name
            and AIProjectClient is not None
            and DefaultAzureCredential is not None
        )
        self.cache_path = Path(os.getenv("LLM_CACHE_PATH", "session/llm_cache.json"))
        self._cache = self._load_cache()
        self.tracer = get_tracer("release_intelligence.expert_security_agent")
        if self.expert_foundry_enabled:
            print(
                "[LLM][ExpertSecurityAgent] Foundry Agent Service enabled "
                f"project_endpoint={self.foundry_project_endpoint} agent_name={self.foundry_expert_agent_name}"
            )
            if self.foundry_expert_agent_version:
                print(
                    "[LLM][ExpertSecurityAgent] Foundry agent version pinned "
                    f"version={self.foundry_expert_agent_version}"
                )
        else:
            print("[LLM][ExpertSecurityAgent] Disabled: Foundry Agent Service config or SDK unavailable")

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

    def analyze_service_findings(self, service_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        with self.tracer.start_as_current_span("expert_security_agent.analyze_service_findings") as span:
            if not self.expert_foundry_enabled:
                raise RuntimeError(
                    "Expert agent requires Foundry Agent Service, but the project endpoint, agent name, or SDK dependencies are unavailable."
                )

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

            should_open_service_session = self.expert_foundry_enabled and self.max_llm_findings > 0 and any(
                self._should_use_llm_for_finding(item) for item in prioritized_findings
            )

            analyses = []
            llm_calls = 0
            session_context = (
                self._open_service_review_session(service_payload, span)
                if should_open_service_session
                else nullcontext(None)
            )
            with session_context as service_session:
                for finding in prioritized_findings:
                    if self.expert_foundry_enabled and llm_calls < self.max_llm_findings and self._should_use_llm_for_finding(finding):
                        analyses.append(self._llm_analyze_finding(finding, service_session=service_session))
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

    @contextmanager
    def _open_service_review_session(self, service_payload: Dict[str, Any], span) -> Iterator[Dict[str, Any]]:
        conversation_id = ""
        with self._open_agent_service_clients() as (_, _, openai_client):
            conversation = openai_client.conversations.create(
                items=[
                    {
                        "type": "message",
                        "role": "user",
                        "content": self._build_service_review_session_prompt(service_payload),
                    }
                ]
            )
            conversation_id = str(self._extract_object_attr(conversation, "id", ""))
            if not conversation_id:
                raise ValueError("Foundry Agent Service did not return a conversation id")

            span.set_attribute("llm.service_conversation_id", conversation_id)
            span.add_event(
                "expert.service_session_started",
                {"conversation_id": conversation_id, "service_name": str(service_payload.get("service_name", "unknown"))},
            )
            try:
                yield {
                    "openai_client": openai_client,
                    "conversation_id": conversation_id,
                }
            finally:
                try:
                    openai_client.conversations.delete(conversation_id=conversation_id)
                except Exception as cleanup_error:
                    span.add_event("expert.service_session_delete_failed", {"error": str(cleanup_error)[:300]})

    def _build_service_review_session_prompt(self, service_payload: Dict[str, Any]) -> str:
        sonar_findings = service_payload.get("sonar", {}).get("issues", [])
        sast_findings = service_payload.get("checkmarx", {}).get("sast", {}).get("findings", [])
        sca_findings = service_payload.get("checkmarx", {}).get("sca", {}).get("findings", [])
        service_context = {
            "service_name": service_payload.get("service_name", "unknown"),
            "release_version": service_payload.get("release_version", "main"),
            "sonar_issue_count": len(sonar_findings),
            "sast_finding_count": len(sast_findings),
            "sca_finding_count": len(sca_findings),
        }

        return (
            "You are the expert security triage agent for a single release review. "
            "Maintain memory across all subsequent findings in this conversation so you can detect correlated risk, repeated patterns, and compound exploit paths. "
            "For each later finding, respond with JSON only using the requested schema. "
            f"Service context: {json.dumps(service_context, separators=(',', ':'))}"
        )

    def _llm_analyze_finding(self, finding: Dict[str, Any], service_session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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
                if self.expert_foundry_enabled:
                    if service_session is None:
                        raise ValueError("Foundry service review session was not initialized for expert finding triage")
                    llm_result = self._llm_analyze_finding_via_agent_service(finding, prompt, span, service_session)
                    if self.cache_enabled:
                        self._cache[cache_key] = llm_result
                        self._save_cache()
                    return llm_result
                raise ValueError("Foundry Agent Service is not configured for expert finding triage")
            except Exception as error:
                span.record_exception(error)
                print(f"[LLM][ExpertSecurityAgent] Error finding_id={finding.get('id', 'unknown')}: {error}")
                raise RuntimeError(
                    f"Expert Foundry mode failed for finding {finding.get('id', 'unknown')}: {error}"
                ) from error

    def _llm_analyze_finding_via_agent_service(
        self,
        finding: Dict[str, Any],
        prompt: str,
        span,
        service_session: Dict[str, Any],
    ) -> Dict[str, Any]:
        openai_client = service_session["openai_client"]
        conversation_id = str(service_session["conversation_id"])

        agent_reference: Dict[str, Any] = {
            "name": self.foundry_expert_agent_name,
            "type": "agent_reference",
        }
        if self.foundry_expert_agent_version:
            agent_reference["version"] = self.foundry_expert_agent_version

        span.set_attribute("llm.provider", "azure_ai_foundry_agent_service")
        span.set_attribute("llm.agent_name", self.foundry_expert_agent_name)
        span.set_attribute("llm.conversation_id", conversation_id)
        span.set_attribute("llm.prompt_preview", prompt[:400])

        openai_client.conversations.items.create(
            conversation_id=conversation_id,
            items=[{"type": "message", "role": "user", "content": prompt}],
        )
        response = openai_client.responses.create(
            conversation=conversation_id,
            extra_body={"agent_reference": agent_reference},
        )

        usage = self._extract_object_attr(response, "usage", None)
        if usage:
            span.set_attribute("llm.prompt_tokens", int(self._extract_object_attr(usage, "input_tokens", 0) or 0))
            span.set_attribute("llm.completion_tokens", int(self._extract_object_attr(usage, "output_tokens", 0) or 0))
            total_tokens = self._extract_object_attr(usage, "total_tokens", None)
            if total_tokens is not None:
                span.set_attribute("llm.total_tokens", int(total_tokens or 0))

        content = self._extract_agent_service_text(response)
        parsed = self._parse_llm_json(content)
        finding_result = self._normalize_foundry_finding_result(parsed, finding)
        span.set_attribute("llm.category", str(finding_result.get("category", ""))[:80])
        span.set_attribute("llm.impact_score", int(finding_result.get("impact_score", 0)))
        span.set_attribute("llm.false_positive", bool(finding_result.get("is_false_positive", False)))
        span.set_attribute("llm.triage_reasoning", str(finding_result.get("triage_reasoning", ""))[:300])
        span.set_attribute("llm.remediation_preview", str(finding_result.get("remediation_diff", ""))[:200])
        span.set_attribute("llm.step", "security_finding_triage")
        span.add_event(
            "llm.response_received",
            {
                "model": self.model,
                "category": str(finding_result.get("category", "")),
                "impact_score": str(finding_result.get("impact_score", "")),
                "is_false_positive": str(finding_result.get("is_false_positive", False)),
            },
        )
        print(
            f"[LLM][ExpertSecurityAgent] Success finding_id={finding.get('id', 'unknown')} agent={self.foundry_expert_agent_name}"
        )
        return finding_result

    def _normalize_foundry_finding_result(self, parsed: Dict[str, Any], finding: Dict[str, Any]) -> Dict[str, Any]:
        candidate = parsed
        if isinstance(parsed.get("analysis"), list) and parsed.get("analysis"):
            first = parsed["analysis"][0]
            if isinstance(first, dict):
                candidate = first

        remediation = str(candidate.get("remediation_diff", "")).strip()
        triage_reasoning = str(candidate.get("triage_reasoning", "")).strip()
        category = str(candidate.get("category", "WARNING")).upper()
        impact_score = self._coerce_int(candidate.get("impact_score", 7), default=7)
        is_false_positive = bool(candidate.get("is_false_positive", candidate.get("false_positive", False)))

        if not remediation:
            remediation = "No remediation details returned by model."
        if not triage_reasoning:
            triage_reasoning = "LLM analysis produced structured guidance."

        return {
            "issue_id": candidate.get("issue_id", finding.get("id", "unknown")),
            "tool_source": candidate.get("tool_source", self._tool_source(finding)),
            "is_false_positive": is_false_positive,
            "triage_reasoning": triage_reasoning,
            "remediation_diff": remediation,
            "impact_score": impact_score,
            "category": category,
            "confidence": str(candidate.get("confidence", "medium")),
            "reason": str(candidate.get("reason", triage_reasoning)),
            "real_world_risk": str(candidate.get("real_world_risk", triage_reasoning)),
            "proposed_fix_snippet": str(candidate.get("proposed_fix_snippet", remediation)),
            "verification_steps": candidate.get("verification_steps", ["Validate fix with static scan and targeted unit/integration tests."]),
            "finding_id": candidate.get("finding_id", finding.get("id", "unknown")),
            "false_positive": is_false_positive,
            "severity": str(candidate.get("severity", finding.get("severity", "UNKNOWN"))).upper() or "UNKNOWN",
            "llm_raw_response": json.dumps(parsed, ensure_ascii=True),
        }

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
