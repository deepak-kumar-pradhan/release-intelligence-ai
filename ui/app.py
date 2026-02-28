import json
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.workflow.ri_workflow import SecurityReviewWorkflow


SESSION_DIR = ROOT / "session"
MANIFEST_PATH = SESSION_DIR / "release_manifest.json"


def _ensure_session_dir():
    SESSION_DIR.mkdir(parents=True, exist_ok=True)


def _save_manifest(services):
    _ensure_session_dir()
    payload = {
        "services": services,
        "session": st.session_state.get("session_id", "default"),
    }
    MANIFEST_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def _load_manifest():
    if not MANIFEST_PATH.exists():
        return {"services": [], "session": "default"}
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _render_service_inputs():
    st.subheader("Release Manifest")
    count = st.number_input("Number of services", min_value=1, max_value=20, value=2, step=1)

    services = []
    for index in range(int(count)):
        col1, col2 = st.columns(2)
        service_name = col1.text_input(f"Service Name {index + 1}", value=f"Service {'AB'[index] if index < 2 else index + 1}")
        release_version = col2.text_input(f"Release Version / Branch {index + 1}", value="main" if index == 0 else "release/2.1")

        if service_name.strip():
            services.append(
                {
                    "service_name": service_name.strip(),
                    "release_version": release_version.strip() or "main",
                }
            )

    if st.button("Save release_manifest.json"):
        saved = _save_manifest(services)
        st.success(f"Saved {len(saved['services'])} services to {MANIFEST_PATH}")


def _render_workflow_controls():
    st.subheader("Security Review Workflow")
    manifest = _load_manifest()
    services = manifest.get("services", [])

    if not services:
        st.info("No services in manifest yet. Add services and save first.")
        return

    st.write("Loaded services:")
    st.json(services)

    if "workflow_result" not in st.session_state:
        st.session_state.workflow_result = None

    workflow = SecurityReviewWorkflow()

    if st.button("Run Security Review"):
        st.session_state.workflow_result = workflow.orchestrate(services=services, hitl_approved=False)

    result = st.session_state.workflow_result
    if not result:
        return

    st.write("### Stage 2 Aggregated Summary")
    st.table(result["summary"])

    st.write("### Governance Status")
    st.json(result["governance"])

    decision_record = result.get("governance", {}).get("decision_record", {})
    if decision_record:
        st.write("### Policy Decision")
        col1, col2, col3 = st.columns(3)
        col1.metric("Final Decision", decision_record.get("final_decision", "N/A"))
        col2.metric("Requires Approval", str(decision_record.get("requires_approval", False)))
        col3.metric("Approver Role", decision_record.get("approver_role_required", "N/A"))

        violations = decision_record.get("policy_violations", [])
        if violations:
            st.write("Policy Violations:")
            st.write(", ".join(violations))

        if decision_record.get("justification_request"):
            st.warning(decision_record["justification_request"])

    if result.get("paused_for_hitl"):
        st.warning("Critical vulnerabilities found. Human-in-the-loop approval is required to proceed.")
        approved = st.checkbox("I approve release after manual review", value=False)
        if st.button("Finalize Attestation"):
            if not approved:
                st.error("Approval is required before final attestation.")
            else:
                final = workflow.orchestrate(services=services, hitl_approved=True)
                st.session_state.workflow_result = final
                st.success(f"Final Status: {final['status']}")
                if final.get("attestation_pdf"):
                    pdf_file = Path(final["attestation_pdf"])
                    st.download_button(
                        label="Download Release Attestation PDF",
                        data=pdf_file.read_bytes(),
                        file_name=pdf_file.name,
                        mime="application/pdf",
                    )
        return

    if result.get("attestation_pdf"):
        pdf_file = Path(result["attestation_pdf"])
        st.success(f"Final Status: {result['status']}")
        st.download_button(
            label="Download Release Attestation PDF",
            data=pdf_file.read_bytes(),
            file_name=pdf_file.name,
            mime="application/pdf",
        )


def main():
    if "session_id" not in st.session_state:
        st.session_state.session_id = "current-session"

    st.set_page_config(page_title="Release Intelligence", layout="wide")
    st.title("Release Intelligence (RI) - Security Review")
    st.caption("MCP fetch + AI analysis + HITL attestation")

    _render_service_inputs()
    st.divider()
    _render_workflow_controls()


if __name__ == "__main__":
    main()
