"""Release intelligence workflow orchestrator.

This module coordinates the end-to-end security review lifecycle.
Key responsibilities:
- Validate inbound service/reviewer payloads.
- Fetch scan data via MCP integrations.
- Invoke expert triage and policy governance agents.
- Drive HITL gating, attestation PDF generation, blob upload, and evidence ledger.

Architecture map:
MCP reports -> Expert triage -> Policy decision -> HITL gate -> PDF attestation ->
Blob upload (optional) -> Evidence ledger append/verify.
"""

import json
import re
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
import textwrap
from typing import Any, Dict, List, Optional
import os
from uuid import uuid4

from fpdf import FPDF

try:
    from azure.storage.blob import BlobServiceClient, ContentSettings
except ImportError:
    BlobServiceClient = None
    ContentSettings = None

from src.agents.expert_security_agent import ExpertSecurityAgent
from src.agents.policy_agent import PolicyAgent
from src.mcp.mcp_client import MCPClient
from src.observability import configure_observability, current_trace_id, get_tracer


class SecurityReviewWorkflow:
    """Coordinates data collection, analysis, governance, and attestation outputs."""

    _SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9._ -]{1,64}$")
    _RELEASE_VERSION_RE = re.compile(r"^[A-Za-z0-9._/:-]{1,80}$")
    _VALID_REVIEWER_ACTIONS = {"APPROVED", "REJECTED"}

    def _is_placeholder_secret(self, value: str) -> bool:
        """Return True when a secret-like value is empty or still templated."""
        value_normalized = str(value or "").strip()
        if not value_normalized:
            return True
        upper = value_normalized.upper()
        return upper.startswith("REPLACE_WITH_") or "YOUR_" in upper

    def __init__(
        self,
        agents: Optional[List[Any]] = None,
        mcp_client: Optional[MCPClient] = None,
        expert_agent: Optional[ExpertSecurityAgent] = None,
        policy_agent: Optional[PolicyAgent] = None,
        rules_path: str = "governance/policy.json",
    ):
        """Initialize workflow dependencies, feature toggles, and storage settings.

        Environment variables determine whether MCP live mode, Foundry agents,
        and blob uploads are enabled.
        """
        configure_observability()
        self.tracer = get_tracer("release_intelligence.workflow")
        # Determine if using real tools based on environment variables
        use_real_mcp = bool(os.getenv("SONAR_URL") and os.getenv("CHECKMARX_URL") and os.getenv("MCP_API_KEY"))
        project_endpoint = os.getenv("AZURE_AI_PROJECT_ENDPOINT", "")
        policy_agent_name = os.getenv("FOUNDRY_POLICY_AGENT_NAME", "")
        expert_agent_name = os.getenv("FOUNDRY_EXPERT_AGENT_NAME", "")
        use_llm = bool(project_endpoint and (policy_agent_name or expert_agent_name))
        llm_endpoint = project_endpoint
        llm_model = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        print(
            f"[WORKFLOW] Boot use_llm={use_llm} model={llm_model} endpoint={llm_endpoint or 'missing'} use_real_mcp={use_real_mcp}"
        )
        
        self.agents = agents or []
        self.mcp_client = mcp_client or MCPClient(
            sonar_url=os.getenv("SONAR_URL", ""),
            checkmarx_url=os.getenv("CHECKMARX_URL", ""),
            api_key=os.getenv("MCP_API_KEY", ""),
            use_mock=not use_real_mcp
        )
        self.expert_agent = expert_agent or ExpertSecurityAgent(use_llm=use_llm)
        self.policy_agent = policy_agent or PolicyAgent(use_llm=use_llm)
        self.rules_path = rules_path
        self.ledger_path = Path("session") / "evidence_ledger.jsonl"
        self.strict_enterprise_approval = os.getenv("STRICT_ENTERPRISE_APPROVAL", "false").lower() == "true"
        self.blob_connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING", "").strip()
        self.blob_container = os.getenv("AZURE_STORAGE_CONTAINER", "").strip()
        self.blob_prefix = os.getenv("AZURE_STORAGE_BLOB_PREFIX", "attestations").strip("/")
        self.blob_upload_enabled = bool(self.blob_connection_string and self.blob_container)
        if self.blob_upload_enabled and BlobServiceClient is None:
            print("[BLOB] Disabled: azure-storage-blob package is not installed")
            self.blob_upload_enabled = False

    def execute(self) -> Dict[str, Any]:
        """Compatibility entrypoint that runs orchestration with no services."""
        return self.orchestrate(services=[])

    def orchestrate(
        self,
        services: Optional[List[Dict[str, str]]] = None,
        hitl_approved: bool = False,
        reviewer_name: str = "",
        reviewer_action: str = "",
        reviewer_principal_id: str = "",
        reviewer_role: str = "",
        reviewer_identity_verified: bool = False,
    ) -> Dict[str, Any]:
        """Validate inbound payloads and delegate to the security review pipeline."""
        normalized_services = self._validate_services(services or [])
        return self.run_security_review(
            services=normalized_services,
            hitl_approved=hitl_approved,
            reviewer_name=reviewer_name.strip(),
            reviewer_action=reviewer_action.strip(),
            reviewer_principal_id=reviewer_principal_id.strip(),
            reviewer_role=reviewer_role.strip(),
            reviewer_identity_verified=bool(reviewer_identity_verified),
        )

    def fetch_data(self, services: Optional[List[Dict[str, str]]] = None) -> Dict[str, Dict[str, Any]]:
        """Fetch scanner reports for services in parallel via MCP client calls."""
        if services is None:
            return {}

        with ThreadPoolExecutor(max_workers=max(1, len(services))) as executor:
            results = list(executor.map(self._fetch_service_data, services))

        return {item["service_name"]: item for item in results}

    def _fetch_service_data(self, service: Dict[str, str]) -> Dict[str, Any]:
        """Fetch one service report bundle (Sonar + Checkmarx payloads)."""
        service_name = service.get("service_name", "Unknown Service")
        release_version = service.get("release_version", "main")
        return self.mcp_client.fetch_full_reports(service_name, release_version)

    def _validate_services(self, services: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Validate and normalize service descriptors for safe downstream processing."""
        normalized: List[Dict[str, str]] = []

        for index, service in enumerate(services):
            if not isinstance(service, dict):
                raise ValueError(f"Service entry at index {index} must be an object.")

            service_name = str(service.get("service_name", "")).strip()
            release_version = str(service.get("release_version", "main")).strip() or "main"

            if not service_name:
                continue

            if not self._SERVICE_NAME_RE.fullmatch(service_name):
                raise ValueError(
                    f"Invalid service_name '{service_name}'. Use 1-64 chars: letters, numbers, space, dot, underscore, hyphen."
                )

            if not self._RELEASE_VERSION_RE.fullmatch(release_version):
                raise ValueError(
                    f"Invalid release_version '{release_version}'. Allowed chars: letters, numbers, . _ / : -"
                )

            normalized.append(
                {
                    "service_name": service_name,
                    "release_version": release_version,
                }
            )

        if len(normalized) > 20:
            raise ValueError("At most 20 services are allowed per review run.")

        return normalized

    def aggregate_results(self, results: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Convert raw results into workflow summary rows or generic agent output rows."""
        if results is None:
            return []

        if isinstance(results, dict) and all(
            isinstance(value, dict) and "sonar" in value and "checkmarx" in value
            for value in results.values()
        ):
            return [self._build_service_summary(value) for value in results.values()]

        return [
            {"agent": agent_name, "result": agent_result}
            for agent_name, agent_result in results.items()
        ]

    def _build_service_summary(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Build normalized per-service counters used by governance and PDF views."""
        checkmarx = payload.get("checkmarx", {})
        sast = checkmarx.get("sast", {})
        sca = checkmarx.get("sca", {})

        return {
            "service_name": payload.get("service_name", "Unknown Service"),
            "release_version": payload.get("release_version", "main"),
            "sonar_status": payload.get("sonar", {}).get("status", "UNKNOWN"),
            "checkmarx_sast": {
                "critical": int(sast.get("critical", 0)),
                "high": int(sast.get("high", 0)),
            },
            "checkmarx_sca": {
                "critical": int(sca.get("critical", 0)),
                "high": int(sca.get("high", 0)),
            },
        }

    def run_security_review(
        self,
        services: List[Dict[str, str]],
        hitl_approved: bool = False,
        reviewer_name: str = "",
        reviewer_action: str = "",
        reviewer_principal_id: str = "",
        reviewer_role: str = "",
        reviewer_identity_verified: bool = False,
    ) -> Dict[str, Any]:
        """Run full release review: fetch, analyze, govern, attest, and record evidence.

        Returns a contract containing summary/deep-dive results, governance outcome,
        HITL state, generated artifact paths, and trace metadata.
        """
        with self.tracer.start_as_current_span("workflow.run_security_review") as span:
            run_id = self._new_run_id()
            span.set_attribute("services.count", len(services))
            span.set_attribute("workflow.hitl_approved", hitl_approved)
            span.set_attribute("workflow.run_id", run_id)

            reviewer_action_normalized = self._validate_reviewer_action(reviewer_action)
            reviewer_name_clean = reviewer_name.strip()
            if reviewer_action_normalized and not reviewer_name_clean:
                raise ValueError("Reviewer name is required when manual action is provided.")
            reviewer_principal_id_clean = reviewer_principal_id.strip()
            reviewer_role_clean = reviewer_role.strip()
            reviewer_identity_verified_flag = bool(reviewer_identity_verified)

            raw_results = self.fetch_data(services)
            summary_rows = self.aggregate_results(raw_results)

            deep_dive = {}
            for service_name, payload in raw_results.items():
                with self.tracer.start_as_current_span("workflow.service_analysis") as service_span:
                    service_span.set_attribute("service.name", service_name)
                    deep_dive[service_name] = {
                        "raw": payload,
                        # Expert agent evaluates each service payload and returns normalized triage findings.
                        "analysis": self.expert_agent.analyze_service_findings(payload),
                    }

            decision = self._evaluate_governance(summary_rows, deep_dive)
            critical_count = decision["counts"]["critical"]
            final_decision_str = str(decision.get("decision_record", {}).get("final_decision", "FAIL")).upper()
            requires_hitl = bool(decision.get("requires_approval", False)) or critical_count > 0
            # Never block a clean PASS with zero critical findings
            if final_decision_str == "PASS" and critical_count == 0:
                requires_hitl = False

            # If a reviewer has explicitly acted, do not pause — use their decision
            reviewer_acted = bool(reviewer_action_normalized)
            if reviewer_acted and not reviewer_principal_id_clean:
                # Preserve accountability when an approval is provided without enterprise identity context.
                reviewer_principal_id_clean = self._derive_self_asserted_principal_id(reviewer_name_clean)
                reviewer_identity_verified_flag = False

            required_reviewer_role = str(decision.get("decision_record", {}).get("approver_role_required", "")).strip()
            if reviewer_acted and required_reviewer_role and reviewer_role_clean:
                if reviewer_role_clean.lower() != required_reviewer_role.lower():
                    raise ValueError(
                        f"Reviewer role '{reviewer_role_clean}' is not allowed. Required role: {required_reviewer_role}."
                    )

            if reviewer_acted and self.strict_enterprise_approval:
                if not reviewer_identity_verified_flag or not reviewer_principal_id_clean:
                    raise ValueError(
                        "Strict enterprise approval mode requires verified reviewer identity and principal ID."
                    )
                if not reviewer_role_clean:
                    raise ValueError(
                        "Strict enterprise approval mode requires reviewer role to be present."
                    )
                if required_reviewer_role and reviewer_role_clean.lower() != required_reviewer_role.lower():
                    raise ValueError(
                        f"Reviewer role '{reviewer_role_clean}' is not allowed. Required role: {required_reviewer_role}."
                    )

            paused_for_hitl = requires_hitl and not hitl_approved and not reviewer_acted

            if reviewer_acted:
                final_status = "GO" if reviewer_action_normalized == "APPROVED" else "REJECTED"
            else:
                final_status = "NO-GO" if paused_for_hitl else decision["status"]
            span.set_attribute("workflow.final_status", final_status)
            span.set_attribute("workflow.requires_hitl", requires_hitl)
            span.set_attribute("workflow.paused_for_hitl", paused_for_hitl)

            pdf_path = None
            if paused_for_hitl:
                # Generate a preliminary PDF so the reviewer can read findings before deciding
                pdf_path = self.generate_attestation_pdf(
                    summary_rows=summary_rows,
                    deep_dive=deep_dive,
                    status="PENDING REVIEW",
                    governance_reason=decision["reason"],
                    governance_decision=decision,
                    reviewer_name=None,
                    reviewer_action=None,
                )
            else:
                pdf_path = self.generate_attestation_pdf(
                    summary_rows=summary_rows,
                    deep_dive=deep_dive,
                    status=final_status,
                    governance_reason=decision["reason"],
                    governance_decision=decision,
                    reviewer_name=reviewer_name_clean or None,
                    reviewer_action=reviewer_action_normalized or None,
                )
            if pdf_path:
                span.add_event("pdf.generated", {"pdf.path": pdf_path})

            # Upload finalized attestations for both approved and explicitly rejected outcomes.
            should_upload_blob = bool(pdf_path) and final_status in {"GO", "REJECTED"}
            blob_upload = {
                "blob_path": None,
                "blob_url": None,
                "error": None,
            }
            if should_upload_blob:
                blob_upload = self._upload_report_to_blob(pdf_path=pdf_path, run_id=run_id)
                if blob_upload.get("error"):
                    span.add_event("blob.upload_failed", {"error": str(blob_upload.get("error"))[:300]})
                elif blob_upload.get("blob_url"):
                    span.add_event("blob.uploaded", {"blob.url": blob_upload["blob_url"]})

            trace_id = current_trace_id()
            if trace_id:
                print(f"[TRACE] workflow.run_security_review trace_id={trace_id}")

            analysis_stats = self._summarize_analysis_stats(deep_dive)

            self._append_evidence_record(
                {
                    "run_id": run_id,
                    "generated_at": datetime.now().isoformat(timespec="seconds"),
                    "status": final_status,
                    "requires_hitl": requires_hitl,
                    "paused_for_hitl": paused_for_hitl,
                    "policy_version": decision.get("policy_version", "unknown"),
                    "policy_decision": final_decision_str,
                    "policy_reason": decision.get("reason", ""),
                    "critical_count": int(decision.get("counts", {}).get("critical", 0)),
                    "high_count": int(decision.get("counts", {}).get("high", 0)),
                    "total_findings": analysis_stats["total_findings"],
                    "false_positive_count": analysis_stats["false_positive_count"],
                    "services": [item.get("service_name", "") for item in services],
                    "reviewer_name": reviewer_name_clean or None,
                    "reviewer_action": reviewer_action_normalized or None,
                    "reviewer_principal_id": reviewer_principal_id_clean or None,
                    "reviewer_role": reviewer_role_clean or None,
                    "reviewer_identity_verified": reviewer_identity_verified_flag,
                    "report_path": pdf_path,
                    "report_blob_path": blob_upload.get("blob_path"),
                    "report_blob_url": blob_upload.get("blob_url"),
                    "report_blob_error": blob_upload.get("error"),
                    "report_sha256": self._sha256_file(pdf_path),
                    "trace_id": trace_id,
                }
            )

            return {
                "run_id": run_id,
                "summary": summary_rows,
                "deep_dive": deep_dive,
                "governance": decision,
                "requires_hitl": requires_hitl,
                "paused_for_hitl": paused_for_hitl,
                "status": final_status,
                "attestation_pdf": pdf_path,
                "attestation_blob_path": blob_upload.get("blob_path"),
                "attestation_blob_url": blob_upload.get("blob_url"),
                "attestation_blob_error": blob_upload.get("error"),
                "trace_id": trace_id,
                "reviewer_name": reviewer_name_clean or None,
                "reviewer_action": reviewer_action_normalized or None,
                "reviewer_principal_id": reviewer_principal_id_clean or None,
                "reviewer_role": reviewer_role_clean or None,
                "reviewer_identity_verified": reviewer_identity_verified_flag,
                "analysis_stats": analysis_stats,
            }

    def _evaluate_governance(self, summary_rows: List[Dict[str, Any]], deep_dive: Dict[str, Any]) -> Dict[str, Any]:
        """Apply policy evaluation and enforce default fields for contract stability."""
        rules = self._load_rules()
        policy_version = rules.get("policy_metadata", {}).get("version", "unknown")
        result = self.policy_agent.evaluate_release(summary_rows, rules, deep_dive)
        result.setdefault("status", "NO-GO")
        result.setdefault("reason", "Governance evaluation completed.")
        result.setdefault("counts", {"critical": 0, "high": 0})
        result.setdefault("requires_approval", False)
        result.setdefault("policy_version", policy_version)
        return result

    def _new_run_id(self) -> str:
        """Generate unique run identifier with timestamp and random suffix."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"run_{timestamp}_{uuid4().hex[:8]}"

    def _summarize_analysis_stats(self, deep_dive: Dict[str, Any]) -> Dict[str, int]:
        """Summarize analysis volume and false-positive totals for evidence records."""
        total_findings = 0
        false_positive_count = 0
        for payload in deep_dive.values():
            analyses = payload.get("analysis", []) if isinstance(payload, dict) else []
            total_findings += len(analyses)
            false_positive_count += sum(
                1 for item in analyses if bool(item.get("is_false_positive", item.get("false_positive", False)))
            )
        return {
            "total_findings": total_findings,
            "false_positive_count": false_positive_count,
        }

    def _derive_self_asserted_principal_id(self, reviewer_name: str) -> str:
        """Create deterministic pseudo-principal ID when enterprise identity is missing."""
        digest = hashlib.sha256(reviewer_name.encode("utf-8")).hexdigest()[:16]
        return f"self-asserted:{digest}"

    def _validate_reviewer_action(self, action: str) -> str:
        """Normalize and validate reviewer action against allowed decision set."""
        normalized = str(action or "").strip().upper()
        if not normalized:
            return ""
        if normalized not in self._VALID_REVIEWER_ACTIONS:
            raise ValueError(
                f"Invalid reviewer_action '{action}'. Allowed values: APPROVED or REJECTED."
            )
        return normalized

    def _append_evidence_record(self, record: Dict[str, Any]) -> None:
        """Append tamper-evident run record to JSONL ledger with hash chaining."""
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(record)
        # Chain each record to the previous hash to make tampering detectable.
        payload["prev_record_hash"] = self._get_last_record_hash()
        payload["record_hash"] = self._hash_record(payload)
        with self.ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, separators=(",", ":")) + "\n")

    def _get_last_record_hash(self) -> str:
        """Return previous ledger hash, or GENESIS when ledger is empty/missing."""
        if not self.ledger_path.exists():
            return "GENESIS"

        last_non_empty = ""
        with self.ledger_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                candidate = line.strip()
                if candidate:
                    last_non_empty = candidate

        if not last_non_empty:
            return "GENESIS"

        try:
            parsed = json.loads(last_non_empty)
            existing_hash = str(parsed.get("record_hash", "")).strip()
            if existing_hash:
                return existing_hash
        except json.JSONDecodeError:
            pass

        return hashlib.sha256(last_non_empty.encode("utf-8")).hexdigest()

    def _hash_record(self, record: Dict[str, Any]) -> str:
        """Compute canonical SHA-256 hash for one ledger record payload."""
        hash_source = dict(record)
        hash_source.pop("record_hash", None)
        payload = json.dumps(hash_source, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _upload_report_to_blob(self, pdf_path: str, run_id: str) -> Dict[str, Optional[str]]:
        """Upload finalized attestation PDF to Azure Blob and return upload metadata."""
        if not self.blob_upload_enabled:
            return {"blob_path": None, "blob_url": None, "error": "Blob upload not configured."}

        if BlobServiceClient is None:
            return {"blob_path": None, "blob_url": None, "error": "azure-storage-blob package missing."}

        path = Path(pdf_path)
        if not path.exists() or not path.is_file():
            return {"blob_path": None, "blob_url": None, "error": f"PDF file not found: {pdf_path}"}

        timestamp = datetime.now().strftime("%Y/%m/%d")
        blob_name = f"{self.blob_prefix}/{timestamp}/{run_id}_{path.name}"

        try:
            service = BlobServiceClient.from_connection_string(self.blob_connection_string)
            container = service.get_container_client(self.blob_container)
            try:
                container.create_container()
            except Exception:
                # Container already exists or caller has no create rights; upload may still succeed.
                pass

            content_settings = None
            if ContentSettings is not None:
                content_settings = ContentSettings(content_type="application/pdf")

            with path.open("rb") as data:
                container.upload_blob(
                    name=blob_name,
                    data=data,
                    overwrite=True,
                    content_settings=content_settings,
                )

            blob_url = f"{container.url}/{blob_name}"
            return {
                "blob_path": blob_name,
                "blob_url": blob_url,
                "error": None,
            }
        except Exception as error:
            return {
                "blob_path": None,
                "blob_url": None,
                "error": str(error),
            }

    def verify_evidence_ledger(self) -> Dict[str, Any]:
        """Verify ledger JSON validity, hash continuity, and per-record integrity."""
        if not self.ledger_path.exists():
            return {
                "valid": True,
                "records_checked": 0,
                "error": None,
            }

        records_checked = 0
        expected_prev_hash = "GENESIS"
        with self.ledger_path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                records_checked += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    return {
                        "valid": False,
                        "records_checked": records_checked,
                        "error": f"Invalid JSON at ledger line {line_number}.",
                    }

                prev_record_hash = str(record.get("prev_record_hash", ""))
                if prev_record_hash != expected_prev_hash:
                    return {
                        "valid": False,
                        "records_checked": records_checked,
                        "error": f"Hash chain mismatch at ledger line {line_number}.",
                    }

                actual_hash = str(record.get("record_hash", ""))
                expected_hash = self._hash_record(record)
                if actual_hash != expected_hash:
                    return {
                        "valid": False,
                        "records_checked": records_checked,
                        "error": f"Record hash mismatch at ledger line {line_number}.",
                    }

                expected_prev_hash = actual_hash

        return {
            "valid": True,
            "records_checked": records_checked,
            "error": None,
        }

    def _sha256_file(self, file_path: Optional[str]) -> Optional[str]:
        """Return SHA-256 hash of a file, or None when path is absent/invalid."""
        if not file_path:
            return None
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return None

        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _load_rules(self) -> Dict[str, Any]:
        """Load governance rules from disk, or return embedded secure defaults."""
        rules_file = Path(self.rules_path)
        if not rules_file.exists():
            return {
                "policy_metadata": {
                    "version": "2026.1",
                    "org_standard": "ISO-27001-Agentic-Baseline",
                    "enforcement_mode": "Strict",
                },
                "quality_gates": {
                    "sonarqube": {
                        "min_quality_gate_status": "PASSED",
                        "max_technical_debt_hours": 8,
                        "block_on_new_critical_issues": True,
                        "min_code_coverage_percent": 80,
                    },
                    "checkmarx_sast": {
                        "block_on": ["CRITICAL", "HIGH"],
                        "allow_amber_on": ["MEDIUM"],
                        "false_positive_triage_required": True,
                    },
                    "checkmarx_sca": {
                        "block_on_malicious_packages": True,
                        "max_cvss_score_allowed": 8.9,
                        "allow_exceptions_for_dev_dependencies": True,
                    },
                },
                "agentic_rules": {
                    "correlation_threshold": "HIGH",
                    "auto_fix_eligibility": ["Sonar_Minor", "SCA_Outdated_Library"],
                    "human_in_the_loop": {
                        "trigger_on": ["AMBER_STATUS", "POLICY_EXCEPTION_REQUEST"],
                        "required_role": "Security_Lead",
                        "timeout_hours": 24,
                    },
                },
            }

        with rules_file.open("r", encoding="utf-8") as file:
            return json.load(file)

    def generate_attestation_pdf(
        self,
        summary_rows: List[Dict[str, Any]],
        deep_dive: Dict[str, Any],
        status: str,
        governance_reason: str,
        governance_decision: Optional[Dict[str, Any]] = None,
        reviewer_name: Optional[str] = None,
        reviewer_action: Optional[str] = None,
    ) -> str:
        """Render attestation PDF containing executive summary and deep-dive findings."""
        output_dir = Path("reports")
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"release_attestation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        content_width = pdf.w - pdf.l_margin - pdf.r_margin
        generated_at = datetime.now().isoformat(timespec="seconds")
        governance_decision = governance_decision or {}
        decision_record = governance_decision.get("decision_record", {})

        total_critical = sum(
            row["checkmarx_sast"]["critical"] + row["checkmarx_sca"]["critical"] for row in summary_rows
        )
        total_high = sum(
            row["checkmarx_sast"]["high"] + row["checkmarx_sca"]["high"] for row in summary_rows
        )

        def write_block(text: str, line_height: int = 7):
            """Write wrapped text block constrained to current content width."""
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(
                content_width,
                line_height,
                self._safe_pdf_text(text),
                new_x="LMARGIN",
                new_y="NEXT",
            )

        pdf.set_fill_color(16, 56, 112)
        pdf.rect(0, 0, pdf.w, 34, style="F")
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(pdf.l_margin, 10)
        pdf.set_font("Helvetica", "B", 20)
        pdf.cell(content_width, 10, "Release Attestation", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        pdf.set_x(pdf.l_margin)
        pdf.cell(content_width, 6, f"Generated: {generated_at}", new_x="LMARGIN", new_y="NEXT")

        pdf.set_text_color(0, 0, 0)
        pdf.set_y(40)

        status_r, status_g, status_b = self._status_color(status)
        pdf.set_fill_color(status_r, status_g, status_b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_x(pdf.l_margin)
        status_text = f"Executive Status: {status}"
        status_width = min(content_width, pdf.get_string_width(self._safe_pdf_text(status_text)) + 10)
        pdf.cell(status_width, 10, status_text, border=0, fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

        pdf.set_font("Helvetica", size=11)
        write_block(f"Governance Decision: {governance_reason}", line_height=8)
        pdf.ln(1)

        final_decision = decision_record.get("final_decision", "N/A")
        policy_violations = decision_record.get("policy_violations", [])
        approver_role = decision_record.get("approver_role_required", "N/A")
        requires_approval = decision_record.get("requires_approval", False)

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(pdf.l_margin)
        pdf.cell(content_width, 7, "Policy Decision", new_x="LMARGIN", new_y="NEXT")
        pdf.set_fill_color(242, 247, 255)
        pdf.set_draw_color(180, 200, 225)
        box_y = pdf.get_y()
        box_h = 24
        pdf.rect(pdf.l_margin, box_y, content_width, box_h, style="DF")
        pdf.set_xy(pdf.l_margin + 2, box_y + 2)
        pdf.set_font("Helvetica", size=10)
        pdf.cell(content_width - 4, 5, f"Final Decision: {final_decision}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_x(pdf.l_margin + 2)
        pdf.cell(
            content_width - 4,
            5,
            f"Requires Approval: {requires_approval} | Approver Role: {approver_role}",
            new_x="LMARGIN",
            new_y="NEXT",
        )
        violations_text = ", ".join(policy_violations) if policy_violations else "none"
        pdf.set_x(pdf.l_margin + 2)
        pdf.cell(content_width - 4, 5, f"Policy Violations: {violations_text[:140]}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_y(box_y + box_h + 2)

        justification_request = decision_record.get("justification_request")
        if justification_request:
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_x(pdf.l_margin)
            pdf.cell(content_width, 6, "HITL Justification Request", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", size=10)
            write_block(justification_request, line_height=6)

        if reviewer_name and reviewer_action:
            review_ts = datetime.now().isoformat(timespec="seconds")
            action_upper = reviewer_action.upper()
            if action_upper == "APPROVED":
                rev_r, rev_g, rev_b = 31, 143, 79   # green
            else:
                rev_r, rev_g, rev_b = 184, 28, 53   # red
            pdf.ln(1)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_x(pdf.l_margin)
            pdf.cell(content_width, 7, "Manual Review Decision", new_x="LMARGIN", new_y="NEXT")
            pdf.set_fill_color(rev_r, rev_g, rev_b)
            pdf.set_text_color(255, 255, 255)
            box_y2 = pdf.get_y()
            pdf.rect(pdf.l_margin, box_y2, content_width, 22, style="F")
            pdf.set_xy(pdf.l_margin + 3, box_y2 + 3)
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(content_width - 6, 7, f"Decision: Manually {action_upper}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_x(pdf.l_margin + 3)
            pdf.set_font("Helvetica", size=10)
            pdf.cell(content_width - 6, 5, f"Reviewer: {reviewer_name}   |   Timestamp: {review_ts}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            pdf.set_y(box_y2 + 25)

        pdf.ln(1)

        card_w = (content_width - 8) / 3
        card_y = pdf.get_y()
        cards = [
            ("Services", str(len(summary_rows)), (32, 100, 170)),
            ("Critical", str(total_critical), (184, 28, 53)),
            ("High", str(total_high), (237, 137, 54)),
        ]
        for index, (label, value, color) in enumerate(cards):
            x = pdf.l_margin + index * (card_w + 4)
            pdf.set_fill_color(*color)
            pdf.rect(x, card_y, card_w, 20, style="F")
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_xy(x + 2, card_y + 3)
            pdf.cell(card_w - 4, 6, label)
            pdf.set_font("Helvetica", "B", 15)
            pdf.set_xy(x + 2, card_y + 10)
            pdf.cell(card_w - 4, 7, value)
        pdf.set_text_color(0, 0, 0)
        pdf.set_y(card_y + 24)

        pdf.set_font("Helvetica", "B", 12)
        pdf.set_x(pdf.l_margin)
        pdf.cell(content_width, 8, "Summary", new_x="LMARGIN", new_y="NEXT")
        self._draw_summary_table(pdf, summary_rows, content_width)
        pdf.ln(3)

        pdf.set_font("Helvetica", "B", 12)
        pdf.set_x(pdf.l_margin)
        pdf.cell(content_width, 8, "Vulnerability Distribution", new_x="LMARGIN", new_y="NEXT")
        self._draw_summary_chart(pdf, summary_rows, content_width)

        for service_name, details in deep_dive.items():
            analyses = details.get("analysis", [])
            failing_analyses = [
                item
                for item in analyses
                if not bool(item.get("is_false_positive", item.get("false_positive", False)))
            ]

            # Skip clean services to avoid empty "No findings" pages in the report.
            if not failing_analyses:
                continue

            pdf.add_page()
            pdf.set_fill_color(240, 247, 255)
            pdf.rect(0, 0, pdf.w, 18, style="F")
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_x(pdf.l_margin)
            pdf.set_y(7)
            pdf.cell(content_width, 8, f"Deep Dive - {service_name}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", size=10)
            pdf.set_y(22)

            for item in failing_analyses:
                if pdf.get_y() > pdf.h - 55:
                    pdf.add_page()
                    pdf.set_y(20)

                label = "False Positive" if item.get("false_positive") else "Valid Finding"
                severity = item.get("severity", "UNKNOWN")
                sev_r, sev_g, sev_b = self._severity_color(severity, item.get("false_positive", False))

                pdf.set_fill_color(sev_r, sev_g, sev_b)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_x(pdf.l_margin)
                pdf.cell(
                    content_width,
                    8,
                    f"{severity} | {item.get('finding_id', 'N/A')} | {label}",
                    border=0,
                    fill=True,
                    new_x="LMARGIN",
                    new_y="NEXT",
                )

                pdf.set_text_color(0, 0, 0)
                pdf.set_font("Helvetica", size=10)
                write_block(f"Category: {item.get('category', 'N/A')}")
                write_block(f"Reason: {item.get('reason', '')}")
                write_block(f"Real-World Risk: {item.get('real_world_risk', '')}")
                write_block("Proposed Fix:")

                pdf.set_fill_color(248, 250, 252)
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(
                    content_width,
                    6,
                    self._safe_pdf_text(item.get("proposed_fix_snippet", ""), width=100),
                    border=1,
                    fill=True,
                    new_x="LMARGIN",
                    new_y="NEXT",
                )
                pdf.ln(3)

        pdf.output(str(output_path))
        return str(output_path)

    def _draw_summary_table(self, pdf: FPDF, summary_rows: List[Dict[str, Any]], content_width: float) -> None:
        """Draw tabular service summary with severity-aware color accents."""
        columns = [
            ("Service", 42),
            ("Version", 30),
            ("Sonar", 22),
            ("SAST C", 15),
            ("SAST H", 15),
            ("SCA C", 15),
            ("SCA H", 15),
            ("Total", 16),
        ]

        scale = content_width / sum(width for _, width in columns)
        scaled_columns = [(name, width * scale) for name, width in columns]

        pdf.set_fill_color(31, 78, 121)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_x(pdf.l_margin)
        for label, width in scaled_columns:
            pdf.cell(width, 8, label, border=1, align="C", fill=True)
        pdf.ln(8)

        pdf.set_font("Helvetica", size=9)
        for row_index, row in enumerate(summary_rows):
            fill = (246, 249, 252) if row_index % 2 == 0 else (255, 255, 255)
            pdf.set_fill_color(*fill)
            pdf.set_text_color(0, 0, 0)
            pdf.set_x(pdf.l_margin)

            values = [
                row["service_name"][:20],
                row["release_version"][:16],
                row["sonar_status"],
                str(row["checkmarx_sast"]["critical"]),
                str(row["checkmarx_sast"]["high"]),
                str(row["checkmarx_sca"]["critical"]),
                str(row["checkmarx_sca"]["high"]),
                str(
                    row["checkmarx_sast"]["critical"]
                    + row["checkmarx_sast"]["high"]
                    + row["checkmarx_sca"]["critical"]
                    + row["checkmarx_sca"]["high"]
                ),
            ]

            for col_index, (value, (_, width)) in enumerate(zip(values, scaled_columns)):
                align = "L" if col_index < 2 else "C"
                if col_index >= 3 and value.isdigit() and int(value) > 0:
                    if col_index in (3, 5):
                        pdf.set_text_color(184, 28, 53)
                    else:
                        pdf.set_text_color(180, 83, 9)
                else:
                    pdf.set_text_color(0, 0, 0)
                pdf.cell(width, 8, value, border=1, align=align, fill=True)
            pdf.ln(8)

        pdf.set_text_color(0, 0, 0)

    def _draw_summary_chart(self, pdf: FPDF, summary_rows: List[Dict[str, Any]], content_width: float) -> None:
        """Draw compact bar chart of critical/high findings by service."""
        if not summary_rows:
            return

        chart_x = pdf.l_margin
        chart_y = pdf.get_y()
        chart_w = content_width
        chart_h = 52
        baseline_y = chart_y + chart_h - 10

        pdf.set_draw_color(205, 214, 224)
        pdf.rect(chart_x, chart_y, chart_w, chart_h)
        pdf.line(chart_x + 6, baseline_y, chart_x + chart_w - 6, baseline_y)

        critical_values = [
            row["checkmarx_sast"]["critical"] + row["checkmarx_sca"]["critical"]
            for row in summary_rows
        ]
        high_values = [
            row["checkmarx_sast"]["high"] + row["checkmarx_sca"]["high"]
            for row in summary_rows
        ]
        max_value = max(1, *(critical_values + high_values))

        group_w = (chart_w - 16) / len(summary_rows)
        bar_w = max(4, group_w * 0.22)

        for index, row in enumerate(summary_rows):
            group_x = chart_x + 8 + index * group_w
            critical = critical_values[index]
            high = high_values[index]

            critical_h = ((chart_h - 18) * critical) / max_value
            high_h = ((chart_h - 18) * high) / max_value

            pdf.set_fill_color(184, 28, 53)
            pdf.rect(group_x + 3, baseline_y - critical_h, bar_w, critical_h, style="F")
            pdf.set_fill_color(217, 119, 6)
            pdf.rect(group_x + 3 + bar_w + 2, baseline_y - high_h, bar_w, high_h, style="F")

            pdf.set_font("Helvetica", size=7)
            pdf.set_text_color(70, 70, 70)
            pdf.set_xy(group_x, baseline_y + 1)
            pdf.cell(group_w - 2, 4, row["service_name"][:12], align="C")

        legend_y = chart_y + 2
        legend_x = chart_x + chart_w - 60
        pdf.set_fill_color(184, 28, 53)
        pdf.rect(legend_x, legend_y, 4, 4, style="F")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", size=8)
        pdf.set_xy(legend_x + 6, legend_y - 1)
        pdf.cell(20, 5, "Critical")

        pdf.set_fill_color(217, 119, 6)
        pdf.rect(legend_x + 30, legend_y, 4, 4, style="F")
        pdf.set_xy(legend_x + 36, legend_y - 1)
        pdf.cell(16, 5, "High")

        pdf.set_text_color(0, 0, 0)
        pdf.set_y(chart_y + chart_h + 2)

    def _status_color(self, status: str):
        """Map overall status string to RGB color used in the PDF header."""
        return (22, 163, 74) if status.upper() == "GO" else (184, 28, 53)

    def _severity_color(self, severity: str, false_positive: bool):
        """Map finding severity/false-positive flag to report palette colors."""
        if false_positive:
            return (5, 150, 105)

        sev = severity.upper()
        if sev == "CRITICAL":
            return (184, 28, 53)
        if sev == "HIGH":
            return (217, 119, 6)
        if sev == "MEDIUM":
            return (2, 132, 199)
        return (71, 85, 105)

    def _safe_pdf_text(self, value: str, width: int = 110) -> str:
        """Normalize whitespace/newlines and wrap text for safe PDF rendering."""
        text = str(value).replace("\t", "    ").replace("\r\n", "\n").replace("\r", "\n")
        wrapped_lines = []
        for line in text.split("\n"):
            line = line if line.strip() else " "
            wrapped = textwrap.fill(
                line,
                width=width,
                break_long_words=True,
                break_on_hyphens=True,
            )
            wrapped_lines.append(wrapped)
        return "\n".join(wrapped_lines)

    def manage_hitl(self, aggregated_results):
        """Reserved extension point for external HITL controller integrations."""
        return None