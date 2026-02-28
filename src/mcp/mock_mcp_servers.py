from copy import deepcopy


class MockMCPServers:
    def __init__(self):
        self._sonar_data = {
            "Service A": {
                "status": "OK",
                "issues": [],
                "branch": "main",
            },
            "Service B": {
                "status": "ERROR",
                "issues": [
                    {
                        "id": "SONAR-101",
                        "rule": "python:S3649",
                        "severity": "CRITICAL",
                        "message": "Potential SQL injection in string-formatted query.",
                        "file": "src/db/repository.py",
                        "line": 42,
                        "code_context": "query = f\"SELECT * FROM users WHERE id = {user_input}\"",
                    }
                ],
                "branch": "release/2.1",
            },
        }

        self._checkmarx_data = {
            "Service A": {
                "sast": {
                    "critical": 0,
                    "high": 0,
                    "findings": [],
                },
                "sca": {
                    "critical": 0,
                    "high": 0,
                    "findings": [],
                },
            },
            "Service B": {
                "sast": {
                    "critical": 1,
                    "high": 2,
                    "findings": [
                        {
                            "id": "CXSAST-9001",
                            "severity": "CRITICAL",
                            "category": "OS Command Injection",
                            "file": "src/exec/runner.py",
                            "line": 18,
                            "code_context": "os.system(f\"tar -xvf {archive_name}\")",
                        },
                        {
                            "id": "CXSAST-9002",
                            "severity": "HIGH",
                            "category": "Hardcoded Secret",
                            "file": "src/config/settings.py",
                            "line": 7,
                            "code_context": "API_KEY = \"abcd-plain-text-secret\"",
                        },
                    ],
                },
                "sca": {
                    "critical": 1,
                    "high": 1,
                    "findings": [
                        {
                            "id": "CXSCa-88",
                            "severity": "CRITICAL",
                            "package": "pyyaml",
                            "version": "5.3",
                            "cve": "CVE-2020-14343",
                            "description": "Arbitrary code execution via unsafe loader",
                        },
                        {
                            "id": "CXSCa-144",
                            "severity": "HIGH",
                            "package": "urllib3",
                            "version": "1.25.8",
                            "cve": "CVE-2021-33503",
                            "description": "Request smuggling risk in specific proxy setups",
                        },
                    ],
                },
            },
        }

    def get_sonar_report(self, service_name: str, branch_name: str) -> dict:
        report = deepcopy(self._sonar_data.get(service_name, {
            "status": "OK",
            "issues": [],
            "branch": branch_name,
        }))
        report["branch"] = branch_name
        return report

    def get_checkmarx_report(self, service_name: str, branch_name: str) -> dict:
        report = deepcopy(self._checkmarx_data.get(service_name, {
            "sast": {"critical": 0, "high": 0, "findings": []},
            "sca": {"critical": 0, "high": 0, "findings": []},
        }))
        report["branch"] = branch_name
        return report
