import os
from typing import Any, Dict

from .mock_mcp_servers import MockMCPServers


class MCPClient:
    def __init__(
        self,
        sonar_url: str = "",
        checkmarx_url: str = "",
        api_key: str = "",
        use_mock: bool = True,
    ):
        self.sonar_url = sonar_url
        self.checkmarx_url = checkmarx_url
        self.api_key = api_key or os.getenv("MCP_API_KEY", "")
        self.use_mock = use_mock
        self._mock_servers = MockMCPServers() if use_mock else None

    def connect_sonarqube(self) -> bool:
        if self.use_mock:
            return True
        return bool(self.sonar_url and self.api_key)

    def connect_checkmarx(self) -> bool:
        if self.use_mock:
            return True
        return bool(self.checkmarx_url and self.api_key)

    def fetch_sonar_report(self, service_name: str, branch_name: str) -> Dict[str, Any]:
        if self.use_mock and self._mock_servers:
            return self._mock_servers.get_sonar_report(service_name, branch_name)
        return {
            "status": "UNKNOWN",
            "issues": [],
            "branch": branch_name,
            "service": service_name,
        }

    def fetch_checkmarx_report(self, service_name: str, branch_name: str) -> Dict[str, Any]:
        if self.use_mock and self._mock_servers:
            return self._mock_servers.get_checkmarx_report(service_name, branch_name)
        return {
            "sast": {"critical": 0, "high": 0, "findings": []},
            "sca": {"critical": 0, "high": 0, "findings": []},
            "branch": branch_name,
            "service": service_name,
        }

    def fetch_full_reports(self, service_name: str, branch_name: str) -> Dict[str, Any]:
        sonar_connected = self.connect_sonarqube()
        checkmarx_connected = self.connect_checkmarx()

        return {
            "service_name": service_name,
            "release_version": branch_name,
            "connections": {
                "sonarqube": sonar_connected,
                "checkmarx": checkmarx_connected,
            },
            "sonar": self.fetch_sonar_report(service_name, branch_name),
            "checkmarx": self.fetch_checkmarx_report(service_name, branch_name),
        }