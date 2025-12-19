"""Compliance models for AEGIS.

Pydantic models for representing compliance findings, OWASP categories,
and EU AI Act requirements.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class OWASPCategory(str, Enum):
    """OWASP LLM Top 10 2025 Categories.

    Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    Version: 2025.1
    """

    LLM01 = "LLM01:2025 - Prompt Injection"
    LLM02 = "LLM02:2025 - Sensitive Information Disclosure"
    LLM03 = "LLM03:2025 - Supply Chain Vulnerabilities"
    LLM04 = "LLM04:2025 - Data and Model Poisoning"
    LLM05 = "LLM05:2025 - Insecure Output Handling"
    LLM06 = "LLM06:2025 - Excessive Agency"
    LLM07 = "LLM07:2025 - System Prompt Leakage"
    LLM08 = "LLM08:2025 - Vector and Embedding Weaknesses"
    LLM09 = "LLM09:2025 - Misinformation"
    LLM10 = "LLM10:2025 - Unbounded Consumption"


class Severity(str, Enum):
    """Severity levels for compliance findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class ComplianceStatus(str, Enum):
    """Overall compliance status."""

    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_ASSESSED = "not_assessed"


@dataclass
class OWASPVulnerability:
    """Detailed OWASP vulnerability information."""

    category: OWASPCategory
    name: str
    description: str
    risk_rating: Severity
    attack_vectors: list[str] = field(default_factory=list)
    business_impact: str = ""
    technical_impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)


@dataclass
class EUAIActArticle:
    """EU AI Act article reference."""

    article_number: str
    title: str
    description: str
    requirements: list[str] = field(default_factory=list)
    applicable_to: str = "High-Risk AI Systems"


@dataclass
class ComplianceFinding:
    """A single compliance finding from an assessment."""

    finding_id: str
    title: str
    description: str
    severity: Severity
    category: str  # OWASP category or EU AI Act article
    evidence: str = ""
    attack_name: str = ""
    attack_payload: str = ""
    target_response: str = ""
    remediation: str = ""
    status: ComplianceStatus = ComplianceStatus.NOT_ASSESSED
    detected_at: datetime = field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "evidence": self.evidence,
            "attack_name": self.attack_name,
            "attack_payload": self.attack_payload,
            "target_response": self.target_response,
            "remediation": self.remediation,
            "status": self.status.value,
            "detected_at": self.detected_at.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class ComplianceReport:
    """Aggregated compliance report."""

    report_id: str
    target_system: str
    target_model: str
    assessment_date: datetime

    # Overall status
    overall_status: ComplianceStatus = ComplianceStatus.NOT_ASSESSED

    # OWASP compliance
    owasp_status: ComplianceStatus = ComplianceStatus.NOT_ASSESSED
    owasp_findings: list[ComplianceFinding] = field(default_factory=list)
    owasp_categories_tested: list[OWASPCategory] = field(default_factory=list)
    owasp_categories_failed: list[OWASPCategory] = field(default_factory=list)

    # EU AI Act compliance
    eu_ai_act_status: ComplianceStatus = ComplianceStatus.NOT_ASSESSED
    eu_ai_act_findings: list[ComplianceFinding] = field(default_factory=list)
    eu_ai_act_articles_checked: list[str] = field(default_factory=list)

    # Summary statistics
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0

    # Metadata
    assessor: str = "AEGIS Automated Assessment"
    version: str = "1.0"
    metadata: dict[str, Any] = field(default_factory=dict)

    def calculate_statistics(self) -> None:
        """Calculate summary statistics from findings."""
        all_findings = self.owasp_findings + self.eu_ai_act_findings
        self.total_findings = len(all_findings)
        self.critical_findings = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        self.high_findings = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        self.medium_findings = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        self.low_findings = sum(1 for f in all_findings if f.severity == Severity.LOW)

        # Determine overall status
        if self.critical_findings > 0 or self.high_findings > 0:
            self.overall_status = ComplianceStatus.NON_COMPLIANT
        elif self.medium_findings > 0:
            self.overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        elif self.total_findings == 0:
            self.overall_status = ComplianceStatus.COMPLIANT
        else:
            self.overall_status = ComplianceStatus.PARTIALLY_COMPLIANT

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "report_id": self.report_id,
            "target_system": self.target_system,
            "target_model": self.target_model,
            "assessment_date": self.assessment_date.isoformat(),
            "overall_status": self.overall_status.value,
            "owasp": {
                "status": self.owasp_status.value,
                "categories_tested": [c.value for c in self.owasp_categories_tested],
                "categories_failed": [c.value for c in self.owasp_categories_failed],
                "findings": [f.to_dict() for f in self.owasp_findings],
            },
            "eu_ai_act": {
                "status": self.eu_ai_act_status.value,
                "articles_checked": self.eu_ai_act_articles_checked,
                "findings": [f.to_dict() for f in self.eu_ai_act_findings],
            },
            "summary": {
                "total_findings": self.total_findings,
                "critical": self.critical_findings,
                "high": self.high_findings,
                "medium": self.medium_findings,
                "low": self.low_findings,
            },
            "assessor": self.assessor,
            "version": self.version,
            "metadata": self.metadata,
        }
