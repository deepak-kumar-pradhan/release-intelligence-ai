from typing import Any, Dict, List


class RiskAnalysisAgent:
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.false_positives: List[Dict[str, Any]] = []

    def analyze_vulnerabilities(self, vulnerability_data: List[Dict[str, Any]]) -> None:
        self.vulnerabilities = self._filter_vulnerabilities(vulnerability_data)
        self.false_positives = self._identify_false_positives(vulnerability_data)

    def analyze_risks(self, risk_factors: List[Dict[str, Any]]) -> Dict[str, Any]:
        scored = []
        total_score = 0
        for factor in risk_factors:
            impact = self._weight(str(factor.get("impact", "low")))
            likelihood = self._weight(str(factor.get("likelihood", "low")))
            score = impact * likelihood
            total_score += score
            scored.append({**factor, "score": score})

        if total_score >= 16:
            overall = "high"
        elif total_score >= 6:
            overall = "medium"
        else:
            overall = "low"

        return {
            "overall_risk": overall,
            "score": total_score,
            "risk_factors": scored,
        }

    def _filter_vulnerabilities(self, vulnerability_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [v for v in vulnerability_data if not self._is_false_positive(v)]

    def _identify_false_positives(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [v for v in vulnerabilities if self._is_false_positive(v)]

    def _is_false_positive(self, vulnerability: Dict[str, Any]) -> bool:
        return bool(vulnerability.get("false_positive", False))

    def provide_risk_assessment(self) -> Dict[str, Any]:
        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "false_positives": len(self.false_positives),
            "risk_level": self._assess_risk_level(),
        }

    def _assess_risk_level(self) -> str:
        critical_or_high = sum(
            1
            for vulnerability in self.vulnerabilities
            if str(vulnerability.get("severity", "")).upper() in {"CRITICAL", "HIGH"}
        )
        if critical_or_high >= 3:
            return "High"
        if critical_or_high >= 1 or len(self.vulnerabilities) >= 5:
            return "Medium"
        return "Low"

    def _weight(self, value: str) -> int:
        mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return mapping.get(value.lower(), 1)