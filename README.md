# Release Intelligence (RI) System

## Overview
The Release Intelligence (RI) system is an **AI-powered security review and attestation platform** that automates the analysis of security vulnerabilities across microservices. It combines expert security agents, policy governance, and human-in-the-loop (HITL) workflows to generate comprehensive release attestation reports.

**Key Capabilities:**
- 🔍 **Security Triage**: Expert AI agent analyzes SAST/SCA findings with toxic combination detection
- 📋 **Policy Governance**: Sovereign policy agent enforces ISO-27001-Agentic-Baseline rules
- 🤝 **HITL Workflow**: Pauses for Security Lead approval when policy violations detected
- 📄 **PDF Attestation**: Generates styled reports with KPIs, charts, and policy decisions
- 🧠 **Instruction Engineering**: XML-tagged system prompts for advanced 2026 reasoning patterns

## Directory Structure
```
release-intelligence-ri/
├── ui/
│   └── app.py                          # Streamlit UI for workflow management
├── src/
│   ├── main.py                         # CLI entry point
│   ├── agents/
│   │   ├── agent_instructions.py       # XML-tagged system prompts
│   │   ├── expert_security_agent.py    # Risk triage with toxic combo detection
│   │   ├── policy_agent.py             # Governance decision engine
│   │   ├── risk_analysis_agent.py      # Legacy agent placeholder
│   │   ├── release_notes_agent.py      # Legacy agent placeholder
│   │   └── dependency_impact_agent.py  # Legacy agent placeholder
│   ├── workflow/
│   │   └── ri_workflow.py              # Core orchestration + PDF generation
│   ├── mcp/
│   │   ├── mcp_client.py               # MCP protocol client
│   │   └── mock_mcp_servers.py         # Mock SonarQube/Checkmarx data
│   └── models/
│       └── release_context.py          # Data models
├── governance/
│   ├── policy.json                     # 2026.1 policy rules (active)
│   └── rules.json                      # Legacy rules
├── tests/
│   ├── test_agents.py
│   └── test_workflow.py
├── reports/                            # Generated PDF attestations
├── session/                            # Runtime session data
├── requirements.txt
└── README.md
```

## Setup Instructions

### 1. Clone the Repository
```bash
git clone <repository-url>
cd release-intelligence-ri
```

### 2. Create Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure for Live Demo with Real Tools
To use actual tools instead of mock data, set the following environment variables:

#### Azure OpenAI (for AI Analysis)
```bash
export AZURE_OPENAI_API_KEY="your-azure-openai-api-key"
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com/openai/v1"
export AZURE_OPENAI_DEPLOYMENT="gpt-4o-mini"
export AZURE_OPENAI_API_VERSION="2024-07-18"
export APPLICATIONINSIGHTS_CONNECTION_STRING="InstrumentationKey=...;IngestionEndpoint=https://..."
```

#### SonarQube and Checkmarx (for Security Scanning)
```bash
export SONAR_URL="https://your-sonarqube-instance.com"
export CHECKMARX_URL="https://your-checkmarx-instance.com"
export MCP_API_KEY="your-api-key-for-tools"
```

*Note: If these are not set, the system defaults to mock data for development.*

#### Deploy to Azure AI Foundry (Microsoft Foundry)
1. Create an Azure AI Foundry project.
2. Use the Azure AI SDK to deploy the workflow as an AI app.
3. Set the above environment variables in your Azure AI Foundry environment.

For detailed deployment steps, refer to [Azure AI Foundry documentation](https://learn.microsoft.com/en-us/azure/ai-studio/).

### Azure Tracing for Hackathon Demo
To show Microsoft-native reasoning traces during your walkthrough, configure Application Insights / Azure Monitor and restart the app.

1. Create or reuse an Application Insights resource in Azure.
2. Copy its connection string into `APPLICATIONINSIGHTS_CONNECTION_STRING`.
3. Rebuild and run the app.
4. Run a security review and copy the `trace_id` shown in the UI.
5. In Azure Portal, open Application Insights -> Transaction Search or Logs and filter by that trace ID.

You will see spans such as:
- `workflow.run_security_review`
- `workflow.service_analysis`
- `expert_security_agent.analyze_service_findings`
- `expert_security_agent.llm_analyze_finding`
- `policy_agent.evaluate_release`
- `policy_agent.llm_evaluate`

This is the strongest Microsoft demo path because it combines Azure AI Foundry model hosting with Azure Monitor traces for agent reasoning flow.

## Running the Application

### Streamlit UI (Recommended)
```bash
streamlit run ui/app.py --server.headless true --server.port 8503
```
Then open http://localhost:8503 in your browser.

### CLI Mode
```bash
python src/main.py
```

### Programmatic Usage
```python
from src.workflow.ri_workflow import SecurityReviewWorkflow

services = [
    {"service_name": "Service A", "release_version": "main"},
    {"service_name": "Service B", "release_version": "release/2.1"}
]

workflow = SecurityReviewWorkflow()
result = workflow.orchestrate(services=services, hitl_approved=True)

print(f"Status: {result['status']}")
print(f"PDF: {result['attestation_pdf']}")
```

### Demo Script
Run a quick demo with mock data:
```bash
python demo.py
```

For live demo with real tools, set the environment variables above and run the same script.

## Key Features

### 🔍 Expert Security Agent
- **Toxic Combination Detection**: Identifies compound risks (e.g., Medium SAST + Critical SCA)
- **False Positive Filtering**: AI-powered analysis to reduce alert fatigue
- **Impact Scoring**: Calculates risk scores based on severity, exploitability, and deployment context
- **Remediation Diffs**: Generates example code fixes for vulnerabilities

### 📋 Policy Agent
- **DecisionRecord Schema**: Structured output with `PASS/FAIL/AMBER` states
- **Policy Violations**: Tracks which governance rules failed (e.g., `impact_score_gt_8_production`)
- **HITL Protocol**: Triggers Security Lead approval for AMBER status or exceptions
- **Backward Compatibility**: Maps decisions to `GO/NO-GO` for legacy systems

### 🤝 HITL Workflow
- **Pause Mechanism**: Workflow halts when `requires_approval=true`
- **Resume Control**: Security Lead approves/rejects via UI or API
- **Audit Trail**: All decisions logged in attestation PDF

### 📄 PDF Attestation Reports
- **Styled Layout**: Blue headers, KPI cards, summary tables, vulnerability charts
- **Policy Decision Box**: Shows final decision, violations, required approver role
- **Deep-Dive Sections**: Per-service analysis with finding details and remediation steps

### 🧠 XML-Tagged Instruction Engineering
- **2026 Microsoft Agent Framework**: System prompts structured with XML tags
- **Role Definition**: `<role>`, `<task_logic>`, `<response_format>` sections
- **Governance Rules**: Embedded directly in Policy Agent prompt
- **HITL Protocol**: Explicit instructions for AMBER status handling

## Testing

### Run Unit Tests
```bash
pytest -q
```

### Run E2E Simulation
```bash
python -c 'from src.workflow.ri_workflow import SecurityReviewWorkflow; \
services=[{"service_name":"Service A","release_version":"main"}, \
          {"service_name":"Service B","release_version":"release/2.1"}]; \
wf=SecurityReviewWorkflow(); \
result=wf.orchestrate(services=services, hitl_approved=True); \
print(f"Status: {result[\"status\"]}\nPDF: {result[\"attestation_pdf\"]}")'
```

## Mock Data
The system includes mock MCP servers for demo purposes:
- **Service A**: Clean (0 critical/high vulnerabilities)
- **Service B**: Vulnerable (1 critical SAST, 2 high SAST, 1 critical SCA, 1 high SCA)

Service B triggers:
- Policy violation: `impact_score_gt_8_production`
- HITL approval requirement
- `NO-GO` decision (if not approved)

## Configuration

### Policy Rules (`governance/policy.json`)
```json
{
  "version": "2026.1",
  "standard": "ISO-27001-Agentic-Baseline",
  "quality_gates": {
    "sonarqube": {"min_quality_gate_status": "PASSED"},
    "checkmarx_sast": {"block_on": ["CRITICAL", "HIGH"]},
    "checkmarx_sca": {"max_cvss_score_allowed": 8.9}
  },
  "agentic_rules": {
    "correlation_threshold": "HIGH",
    "human_in_the_loop": {
      "trigger_on": ["AMBER_STATUS", "POLICY_EXCEPTION_REQUEST"],
      "required_role": "Security_Lead"
    }
  }
}
```

## Architecture

### Workflow Orchestration
1. **Fetch Data**: MCP client retrieves SonarQube + Checkmarx data in parallel
2. **Security Triage**: Expert agent analyzes findings, detects toxic combinations
3. **Policy Evaluation**: Policy agent applies governance rules, generates DecisionRecord
4. **HITL Gate**: Pauses if approval required, resumes on Security Lead action
5. **Attestation**: Generates PDF with summary, charts, policy decision, deep-dive sections

### Agent Communication
- **Stateless**: Each orchestration run is independent
- **Retry Logic**: Built-in resilience for API failures
- **Failover**: Deterministic fallback if Azure OpenAI unavailable

## Troubleshooting

**Port 8502 already in use**
```bash
streamlit run ui/app.py --server.port 8503
```

**Azure OpenAI timeout**
- System automatically falls back to deterministic analysis
- Check `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_API_KEY` if AI analysis desired

**PDF not generating**
- Ensure `reports/` directory exists (auto-created)
- Check file permissions

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.