import json
import os
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.workflow.ri_workflow import SecurityReviewWorkflow


SESSION_DIR = ROOT / "session"
MANIFEST_PATH = SESSION_DIR / "release_manifest.json"
REPORTS_DIR = ROOT / "reports"
LEDGER_PATH = SESSION_DIR / "evidence_ledger.jsonl"


def _inject_ui_theme():
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&display=swap');

        :root {
            --ri-bg: #f3f6f9;
            --ri-panel: #ffffff;
            --ri-text: #1e2430;
            --ri-muted: #5f6b7a;
            --ri-accent: #0f7b8f;
            --ri-accent-2: #1462a6;
            --ri-pass: #1f8f4f;
            --ri-fail: #b64040;
            --ri-amber: #b27a14;
            --ri-border: #dce4ec;
        }

        html, body, [class*="css"] {
            font-family: 'Space Grotesk', sans-serif;
        }

        .stApp {
            background:
                radial-gradient(1200px 500px at 85% -100px, rgba(20, 98, 166, 0.16), transparent 60%),
                radial-gradient(900px 400px at -5% 5%, rgba(15, 123, 143, 0.13), transparent 55%),
                var(--ri-bg);
            color: var(--ri-text);
        }

        .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
        }

        .ri-hero {
            border: 1px solid var(--ri-border);
            border-radius: 16px;
            background: linear-gradient(120deg, #0f3f67 0%, #13658a 52%, #1a7fa1 100%);
            padding: 1.35rem 1.4rem;
            margin-bottom: 1rem;
            animation: riseIn 420ms ease-out;
            box-shadow: 0 12px 28px rgba(13, 47, 76, 0.22);
            color: #ffffff;
        }

        .ri-subtle {
            color: var(--ri-muted);
            font-size: 0.95rem;
        }

        .ri-hero .ri-subtle {
            color: rgba(255, 255, 255, 0.88);
            font-size: 1rem;
            text-align: left;
            max-width: 780px;
        }

        .ri-hero h1 {
            color: #ffffff;
            letter-spacing: 0.01em;
            text-align: left;
        }

        .ri-meta {
            margin-top: 0.4rem;
            color: #163f57;
            font-size: 0.88rem;
            background: rgba(15, 123, 143, 0.10);
            border: 1px solid rgba(15, 123, 143, 0.28);
            border-radius: 999px;
            padding: 0.3rem 0.7rem;
            display: inline-block;
        }

        .ri-card {
            border: 1px solid var(--ri-border);
            border-radius: 14px;
            background: var(--ri-panel);
            padding: 0.9rem 1rem;
            margin: 0.5rem 0 0.8rem 0;
            box-shadow: 0 5px 16px rgba(18, 32, 48, 0.05);
        }

        .ri-kpi-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 0.7rem;
            margin: 0.35rem 0 1rem;
        }

        .ri-kpi {
            border: 1px solid var(--ri-border);
            border-radius: 12px;
            background: linear-gradient(180deg, #ffffff, #f7fbff);
            padding: 0.72rem 0.8rem;
            box-shadow: 0 6px 14px rgba(18, 32, 48, 0.04);
            text-align: left;
        }

        .ri-kpi-k {
            color: #667589;
            font-size: 0.79rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            margin-bottom: 0.2rem;
        }

        .ri-kpi-v {
            font-size: 1.15rem;
            font-weight: 700;
            line-height: 1.2;
            color: #1f2a36;
        }

        .ri-kpi-risk {
            color: #b64040;
        }

        .ri-policy {
            border: 1px solid var(--ri-border);
            border-radius: 14px;
            background: linear-gradient(180deg, #ffffff, #f4f9ff);
            padding: 1rem 1.1rem;
            margin: 0.55rem 0 0.9rem;
            box-shadow: 0 8px 22px rgba(12, 29, 45, 0.06);
        }

        .ri-policy-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 0.75rem;
            margin-top: 0.35rem;
        }

        .ri-policy-tile {
            border: 1px solid #dbe5ee;
            border-radius: 10px;
            background: #ffffff;
            padding: 0.62rem 0.7rem;
        }

        .ri-policy-k {
            color: #667589;
            font-size: 0.82rem;
            margin-bottom: 0.25rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        .ri-policy-v {
            font-size: 1.15rem;
            font-weight: 700;
            color: #1f2a36;
            line-height: 1.2;
            word-break: break-word;
        }

        .ri-pill {
            display: inline-block;
            border-radius: 999px;
            padding: 0.22rem 0.55rem;
            font-size: 0.84rem;
            font-weight: 700;
            border: 1px solid;
        }

        .ri-pill-pass {
            color: var(--ri-pass);
            background: #ebf8f0;
            border-color: #b8e2c6;
        }

        .ri-pill-fail {
            color: var(--ri-fail);
            background: #fff0f0;
            border-color: #efbcbc;
        }

        .ri-pill-amber {
            color: var(--ri-amber);
            background: #fff7e8;
            border-color: #f1d9a9;
        }

        .ri-violations {
            margin-top: 0.75rem;
            color: #3d4a59;
            font-size: 0.95rem;
        }

        .ri-status {
            border-radius: 12px;
            border: 1px solid;
            padding: 0.9rem 1rem;
            margin: 0.6rem 0 0.7rem;
            font-weight: 600;
            text-align: left;
        }

        h3 {
            color: #173e59;
            letter-spacing: 0.01em;
        }

        .ri-status-pass {
            background: #e9f8ee;
            border-color: #b8e2c6;
            color: var(--ri-pass);
        }

        .ri-status-fail {
            background: #fdeeee;
            border-color: #efbcbc;
            color: var(--ri-fail);
        }

        .ri-status-amber {
            background: #fff7e8;
            border-color: #f1d9a9;
            color: var(--ri-amber);
        }

        div.stButton > button,
        div.stDownloadButton > button {
            border-radius: 11px;
            border: 1px solid #1f6b93;
            background: linear-gradient(135deg, #0f7b8f, #1462a6);
            color: #ffffff;
            font-weight: 600;
            letter-spacing: 0.1px;
            box-shadow: 0 8px 18px rgba(20, 98, 166, 0.25);
            transition: transform 0.16s ease, box-shadow 0.16s ease;
        }

        div.stButton > button:hover,
        div.stDownloadButton > button:hover {
            transform: translateY(-1px);
            box-shadow: 0 11px 22px rgba(20, 98, 166, 0.35);
        }

        div[data-testid="stNumberInput"] input,
        div[data-testid="stTextInput"] input {
            border-radius: 10px;
            border-color: #d2deea;
            background-color: #ffffff;
        }

        div[data-testid="stNumberInput"] label,
        div[data-testid="stTextInput"] label {
            font-weight: 600;
            color: #344459;
        }

        div[data-testid="stRadio"] > div {
            background: linear-gradient(180deg, #ffffff, #f2f8ff);
            border: 1px solid #c8d7e7;
            border-radius: 12px;
            padding: 0.28rem;
            width: fit-content;
        }

        div[data-testid="stRadio"] label {
            border-radius: 9px;
            padding: 0.36rem 0.85rem;
            margin-right: 0.25rem;
            border: 1px solid transparent;
            transition: background-color 0.15s ease, border-color 0.15s ease;
        }

        div[data-testid="stRadio"] label:has(input:checked) {
            background: linear-gradient(135deg, #0f7b8f, #1462a6);
            color: #ffffff;
            border-color: #1f6b93;
            box-shadow: 0 6px 14px rgba(20, 98, 166, 0.25);
        }

        @keyframes riseIn {
            from { opacity: 0; transform: translateY(6px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @media (max-width: 900px) {
            .block-container {
                padding-top: 1.2rem;
            }
            .ri-hero {
                padding: 0.9rem 1rem;
            }
            .ri-kpi-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
            .ri-policy-grid {
                grid-template-columns: 1fr;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _status_label_style(status: str) -> str:
    status_upper = str(status or "").upper()
    if status_upper in {"GO", "PASS"}:
        return "ri-status ri-status-pass"
    if status_upper in {"AMBER", "PENDING REVIEW"}:
        return "ri-status ri-status-amber"
    return "ri-status ri-status-fail"


def _decision_pill_class(decision: str) -> str:
    decision_upper = str(decision or "").upper()
    if decision_upper == "PASS":
        return "ri-pill ri-pill-pass"
    if decision_upper == "AMBER":
        return "ri-pill ri-pill-amber"
    return "ri-pill ri-pill-fail"


def _render_summary_table(summary_rows):
    if not summary_rows:
        st.info("No summary rows available.")
        return

    records = []
    for row in summary_rows:
        sast_c = int(row.get("checkmarx_sast", {}).get("critical", 0))
        sast_h = int(row.get("checkmarx_sast", {}).get("high", 0))
        sca_c = int(row.get("checkmarx_sca", {}).get("critical", 0))
        sca_h = int(row.get("checkmarx_sca", {}).get("high", 0))
        records.append(
            {
                "Service": row.get("service_name", "N/A"),
                "Version": row.get("release_version", "N/A"),
                "Sonar": row.get("sonar_status", "UNKNOWN"),
                "SAST C": sast_c,
                "SAST H": sast_h,
                "SCA C": sca_c,
                "SCA H": sca_h,
                "Total": sast_c + sast_h + sca_c + sca_h,
            }
        )

    df = pd.DataFrame.from_records(records)

    def _row_background(row):
        even = row.name % 2 == 0
        color = "#f8fbff" if even else "#ffffff"
        return [f"background-color: {color}"] * len(row)

    def _sonar_color(value):
        status = str(value).upper()
        if status in {"ERROR", "FAILED"}:
            return "color: #b64040; font-weight: 700"
        if status in {"WARN", "WARNING"}:
            return "color: #b27a14; font-weight: 700"
        return "color: #1f8f4f; font-weight: 700"

    def _count_color(value):
        number = int(value)
        if number <= 0:
            return "color: #3f4e5f"
        return "color: #b64040; font-weight: 700"

    styled = (
        df.style
        .apply(_row_background, axis=1)
        .map(_sonar_color, subset=["Sonar"])
        .map(_count_color, subset=["SAST C", "SAST H", "SCA C", "SCA H", "Total"])
    )

    st.dataframe(styled, use_container_width=True, hide_index=True)


def _compute_summary_kpis(summary_rows):
    kpis = {
        "services": len(summary_rows or []),
        "critical": 0,
        "high": 0,
        "failing_sonar": 0,
    }
    for row in summary_rows or []:
        sast = row.get("checkmarx_sast", {})
        sca = row.get("checkmarx_sca", {})
        kpis["critical"] += int(sast.get("critical", 0)) + int(sca.get("critical", 0))
        kpis["high"] += int(sast.get("high", 0)) + int(sca.get("high", 0))
        if str(row.get("sonar_status", "")).upper() in {"ERROR", "FAILED"}:
            kpis["failing_sonar"] += 1
    return kpis


def _render_risk_snapshot(result):
    kpis = _compute_summary_kpis(result.get("summary", []))
    final_status = str(result.get("status", "NO-GO")).upper()
    status_class = _decision_pill_class(final_status if final_status != "GO" else "PASS")
    st.markdown(
        f"""
        <div class="ri-kpi-grid">
            <div class="ri-kpi">
                <div class="ri-kpi-k">Final Status</div>
                <div class="ri-kpi-v"><span class="{status_class}">{final_status}</span></div>
            </div>
            <div class="ri-kpi">
                <div class="ri-kpi-k">Services Assessed</div>
                <div class="ri-kpi-v">{kpis['services']}</div>
            </div>
            <div class="ri-kpi">
                <div class="ri-kpi-k">Critical Findings</div>
                <div class="ri-kpi-v ri-kpi-risk">{kpis['critical']}</div>
            </div>
            <div class="ri-kpi">
                <div class="ri-kpi-k">High Findings</div>
                <div class="ri-kpi-v ri-kpi-risk">{kpis['high']}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _ensure_session_dir():
    SESSION_DIR.mkdir(parents=True, exist_ok=True)


def _format_file_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    size = float(size_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024
    return f"{int(size_bytes)} B"


def _get_report_files():
    return sorted(REPORTS_DIR.glob("release_attestation_*.pdf"), key=lambda p: p.stat().st_mtime, reverse=True)


def _load_evidence_records():
    if not LEDGER_PATH.exists():
        return []

    records = []
    for raw_line in LEDGER_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        records.append(payload)

    records.sort(key=lambda item: str(item.get("generated_at", "")), reverse=True)
    return records


def _render_report_history_panel():
    report_files = _get_report_files()
    count = len(report_files)
    st.markdown(
        f'<div class="ri-card" style="margin-top:0;"><b>Report History</b><br><span class="ri-subtle">{count} saved report(s)</span></div>',
        unsafe_allow_html=True,
    )

    with st.expander("Open History", expanded=False):
        if not report_files:
            st.info("No previous attestation reports found yet.")
            return

        options = []
        for path in report_files:
            generated_local = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            options.append(f"{generated_local} | {path.name}")

        selected_label = st.selectbox(
            "Select report",
            options=options,
            index=0,
            key="report_history_select_top",
            label_visibility="collapsed",
        )
        selected_name = selected_label.split(" | ", 1)[1]
        selected_path = next((p for p in report_files if p.name == selected_name), None)

        if selected_path:
            stat = selected_path.stat()
            st.caption(f"Size: {_format_file_size(stat.st_size)}")
            st.download_button(
                label="Download",
                data=selected_path.read_bytes(),
                file_name=selected_path.name,
                mime="application/pdf",
                key="report_history_download_top",
                use_container_width=True,
            )


def _render_report_history_page():
    st.subheader("Report History")
    st.markdown(
        '<div class="ri-card"><span class="ri-subtle">Audit-ready report evidence with governance and reviewer context.</span></div>',
        unsafe_allow_html=True,
    )

    records = _load_evidence_records()
    if records:
        all_statuses = sorted({str(item.get("status", "UNKNOWN")) for item in records})
        status_filter_col, reviewer_filter_col, service_filter_col = st.columns([1.1, 1.2, 1.2])
        with status_filter_col:
            status_filter = st.selectbox(
                "Status",
                options=["All"] + all_statuses,
                index=0,
                key="history_status_filter",
            )
        with reviewer_filter_col:
            reviewer_filter = st.text_input(
                "Reviewer",
                value="",
                placeholder="Filter by reviewer name",
                key="history_reviewer_filter",
            ).strip().lower()
        with service_filter_col:
            service_filter = st.text_input(
                "Service",
                value="",
                placeholder="Filter by service",
                key="history_service_filter",
            ).strip().lower()

        filtered = []
        for item in records:
            item_status = str(item.get("status", "UNKNOWN"))
            item_reviewer = str(item.get("reviewer_name", "") or "")
            item_services = item.get("services", [])
            service_blob = ", ".join(item_services) if isinstance(item_services, list) else str(item_services)

            if status_filter != "All" and item_status != status_filter:
                continue
            if reviewer_filter and reviewer_filter not in item_reviewer.lower():
                continue
            if service_filter and service_filter not in service_blob.lower():
                continue
            filtered.append(item)

        if not filtered:
            st.info("No report records match the current filters.")
            return

        history_rows = []
        for item in filtered:
            report_path = str(item.get("report_path") or "")
            report_name = Path(report_path).name if report_path else "N/A"
            history_rows.append(
                {
                    "Generated": str(item.get("generated_at", "N/A")),
                    "Run ID": str(item.get("run_id", "N/A")),
                    "Status": str(item.get("status", "N/A")),
                    "Reviewer": str(item.get("reviewer_name") or "-"),
                    "Services": ", ".join(item.get("services", [])) if isinstance(item.get("services"), list) else "-",
                    "Report": report_name,
                }
            )

        history_df = pd.DataFrame.from_records(history_rows)
        st.dataframe(history_df, use_container_width=True, hide_index=True)

        downloadable_records = [
            item
            for item in filtered
            if str(item.get("report_path") or "") and Path(str(item.get("report_path"))).exists()
        ]
        if not downloadable_records:
            st.info("No downloadable report file found for the selected records.")
            return

        options = []
        for item in downloadable_records:
            report_name = Path(str(item.get("report_path"))).name
            options.append(f"{item.get('generated_at', 'N/A')} | {item.get('status', 'N/A')} | {report_name}")

        selected_option = st.selectbox(
            "Select report to download",
            options=options,
            index=0,
            key="report_history_page_select",
        )
        selected_record = downloadable_records[options.index(selected_option)]
        selected_path = Path(str(selected_record.get("report_path")))
        st.download_button(
            label="Download Selected Report",
            data=selected_path.read_bytes(),
            file_name=selected_path.name,
            mime="application/pdf",
            key="report_history_page_download",
        )
        return

    # Backward compatibility: if ledger is absent, fall back to files-only history.
    report_files = _get_report_files()
    if not report_files:
        st.info("No previous attestation reports found yet.")
        return

    fallback_rows = []
    for path in report_files:
        stat = path.stat()
        fallback_rows.append(
            {
                "Report": path.name,
                "Generated": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "Size": _format_file_size(stat.st_size),
            }
        )
    st.dataframe(pd.DataFrame.from_records(fallback_rows), use_container_width=True, hide_index=True)


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
    try:
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        st.error("release_manifest.json is invalid JSON. Please save the manifest again.")
        return {"services": [], "session": "default"}

    if not isinstance(payload, dict):
        st.error("release_manifest.json must be a JSON object.")
        return {"services": [], "session": "default"}

    services = payload.get("services", [])
    if not isinstance(services, list):
        st.error("release_manifest.json field 'services' must be a list.")
        return {"services": [], "session": "default"}

    return payload


def _render_service_inputs():
    st.subheader("Stage 1: Release Manifest")
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

    if st.button("Next"):
        saved = _save_manifest(services)
        st.session_state.stage1_complete = len(saved.get("services", [])) > 0
        st.success(f"Saved {len(saved['services'])} services to {MANIFEST_PATH}")


def _render_workflow_controls():
    st.subheader("Stage 2: Run Review")
    manifest = _load_manifest()
    services = manifest.get("services", [])

    if not services:
        st.info("No services in manifest yet. Add services and save first.")
        return

    st.markdown('<div class="ri-card"><span class="ri-subtle">Loaded services from manifest</span></div>', unsafe_allow_html=True)
    manifest_df = pd.DataFrame.from_records(
        [
            {
                "Service": item.get("service_name", "N/A"),
                "Release Version": item.get("release_version", "N/A"),
            }
            for item in services
        ]
    )
    st.dataframe(manifest_df, use_container_width=True, hide_index=True)
    with st.expander("View raw manifest JSON"):
        st.json(services)

    if "workflow_result" not in st.session_state:
        st.session_state.workflow_result = None

    workflow = SecurityReviewWorkflow()

    if st.button("Run Security Review"):
        try:
            st.session_state.workflow_result = workflow.orchestrate(services=services, hitl_approved=False)
        except ValueError as error:
            st.error(f"Input validation failed: {error}")
            st.session_state.workflow_result = None
            return

    result = st.session_state.workflow_result
    if not result:
        return

    st.write("### Risk Snapshot")
    _render_risk_snapshot(result)

    st.write("### Stage 2 Aggregated Summary")
    _render_summary_table(result["summary"])

    final_status = str(result.get("status", "NO-GO")).upper()
    is_passing = final_status == "GO"

    if not is_passing:
        decision_record = result.get("governance", {}).get("decision_record", {})
        if decision_record:
            st.write("### Policy Decision")
            final_decision = str(decision_record.get("final_decision", "N/A")).upper()
            requires_approval = str(decision_record.get("requires_approval", False))
            approver_role = str(decision_record.get("approver_role_required", "N/A"))
            pill_class = _decision_pill_class(final_decision)

            st.markdown(
                f"""
                <div class="ri-policy">
                    <div class="ri-policy-grid">
                        <div class="ri-policy-tile">
                            <div class="ri-policy-k">Final Decision</div>
                            <div class="ri-policy-v"><span class="{pill_class}">{final_decision}</span></div>
                        </div>
                        <div class="ri-policy-tile">
                            <div class="ri-policy-k">Requires Approval</div>
                            <div class="ri-policy-v">{requires_approval}</div>
                        </div>
                        <div class="ri-policy-tile">
                            <div class="ri-policy-k">Approver Role</div>
                            <div class="ri-policy-v">{approver_role}</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            violations = [v for v in decision_record.get("policy_violations", []) if v != "none"]
            if violations:
                st.markdown(
                    '<div class="ri-violations"><b>Policy Violations:</b> '
                    + ", ".join(violations)
                    + "</div>",
                    unsafe_allow_html=True,
                )

            if decision_record.get("justification_request"):
                st.warning(decision_record["justification_request"])

    status_css = _status_label_style(final_status)
    st.markdown(
        f'<div class="{status_css}">Final Status: {final_status}</div>',
        unsafe_allow_html=True,
    )

    if result.get("paused_for_hitl"):
        # Always show preliminary PDF so reviewer can read findings before deciding
        if result.get("attestation_pdf"):
            prelim_file = Path(result["attestation_pdf"])
            st.download_button(
                label="Download Preliminary Report (for review)",
                data=prelim_file.read_bytes(),
                file_name=prelim_file.name,
                mime="application/pdf",
            )

        st.markdown(
            """
            <div class="ri-policy" style="border-left: 4px solid #b27a14; margin-top:1rem;">
                <div style="font-size:1rem;font-weight:700;color:#8a5f10;margin-bottom:0.5rem;">
                    Manual Review Required
                </div>
                <div class="ri-subtle">
                    Critical findings were detected. A security reviewer must approve or reject
                    this release before a final attestation can be generated.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        reviewer_name = st.text_input("Reviewer Name", placeholder="e.g. Jane Smith")
        col_approve, col_reject = st.columns(2)

        with col_approve:
            if st.button("Approve Release", use_container_width=True):
                if not reviewer_name.strip():
                    st.error("Please enter the reviewer name before approving.")
                else:
                    try:
                        final = workflow.orchestrate(
                            services=services,
                            hitl_approved=True,
                            reviewer_name=reviewer_name,
                            reviewer_action="APPROVED",
                        )
                        st.session_state.workflow_result = final
                        st.rerun()
                    except ValueError as error:
                        st.error(f"Input validation failed: {error}")

        with col_reject:
            if st.button("Reject Release", use_container_width=True):
                if not reviewer_name.strip():
                    st.error("Please enter the reviewer name before rejecting.")
                else:
                    try:
                        final = workflow.orchestrate(
                            services=services,
                            hitl_approved=False,
                            reviewer_name=reviewer_name,
                            reviewer_action="REJECTED",
                        )
                        st.session_state.workflow_result = final
                        st.rerun()
                    except ValueError as error:
                        st.error(f"Input validation failed: {error}")
        return

    # Final attestation PDF (includes manual review stamp if reviewer info present)
    if result.get("attestation_pdf"):
        pdf_file = Path(result["attestation_pdf"])
        st.download_button(
            label="Download Release Attestation PDF",
            data=pdf_file.read_bytes(),
            file_name=pdf_file.name,
            mime="application/pdf",
        )

def main():
    if "session_id" not in st.session_state:
        st.session_state.session_id = "current-session"

    if "stage1_complete" not in st.session_state:
        st.session_state.stage1_complete = False

    if "current_view" not in st.session_state:
        st.session_state.current_view = "home"

    st.set_page_config(page_title="Release Intelligence", layout="wide")
    _inject_ui_theme()

    st.markdown(
        """
        <div class="ri-hero">
            <h1 style="margin:0;">Release Intelligence</h1>
            <p class="ri-subtle" style="margin:0.35rem 0 0 0;">Agentic security review and policy attestation with traceable AI decisions.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    view_label = st.radio(
        "Navigation",
        options=["Home", "Report History"],
        horizontal=True,
        label_visibility="collapsed",
        index=0 if st.session_state.current_view == "home" else 1,
        key="nav_segmented",
    )
    st.session_state.current_view = "home" if view_label == "Home" else "reports"

    if st.session_state.current_view == "reports":
        _render_report_history_page()
        return

    _render_service_inputs()

    if st.session_state.stage1_complete:
        st.divider()
        _render_workflow_controls()


if __name__ == "__main__":
    main()
