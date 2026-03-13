from typing import Any, Dict, List


class DependencyImpactAgent:
    def __init__(self):
        self.dependencies: Dict[str, Dict[str, Any]] = {}
        self.vulnerabilities: List[Dict[str, Any]] = []

    def load_dependencies(self, dependencies: Dict[str, Dict[str, Any]]):
        self.dependencies = dependencies or {}

    def load_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]):
        self.vulnerabilities = vulnerabilities or []

    def assess_impact(self) -> Dict[str, Dict[str, Any]]:
        impact_report: Dict[str, Dict[str, Any]] = {}
        for dependency_name in self.dependencies:
            impacted = [
                vulnerability
                for vulnerability in self.vulnerabilities
                if self.is_vulnerability_impacting(dependency_name, vulnerability)
            ]

            mitigations: List[str] = []
            for vulnerability in impacted:
                for mitigation in self.suggest_mitigations(vulnerability):
                    if mitigation not in mitigations:
                        mitigations.append(mitigation)

            impact_report[dependency_name] = {
                "vulnerabilities": impacted,
                "mitigations": mitigations,
            }

        return impact_report

    def is_vulnerability_impacting(self, dependency: str, vulnerability: Dict[str, Any]) -> bool:
        dependency_normalized = str(dependency).strip().lower()
        if not dependency_normalized:
            return False

        potential_targets = [
            vulnerability.get("dependency"),
            vulnerability.get("package"),
            vulnerability.get("library"),
            vulnerability.get("component"),
            vulnerability.get("artifact"),
            vulnerability.get("module"),
            vulnerability.get("affected_dependency"),
            vulnerability.get("name"),
        ]

        for target in potential_targets:
            if dependency_normalized == str(target or "").strip().lower():
                return True

        # Fallback when scanners only provide a free-text description.
        description = str(vulnerability.get("description", "")).lower()
        return dependency_normalized in description and bool(description)

    def suggest_mitigations(self, vulnerability: Dict[str, Any]) -> List[str]:
        severity = str(vulnerability.get("severity", "")).upper()
        base_actions = ["Update dependency to a fixed version", "Patch or replace vulnerable component"]

        if severity in {"CRITICAL", "HIGH"}:
            return [
                "Block release until dependency is remediated",
                *base_actions,
                "Validate fix with SCA rescan",
            ]

        return [*base_actions, "Schedule remediation in next release cycle"]