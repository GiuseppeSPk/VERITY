"""Compliance checking module.

Provides compliance mapping and reporting for:
- OWASP LLM Top 10 2025
- EU AI Act (Regulation 2024/1689)
"""

from verity.compliance.eu_ai_act import (
    EU_AI_ACT_ARTICLES,
    EUAIActAssessment,
    EUAIActChecker,
)
from verity.compliance.models import (
    ComplianceFinding,
    ComplianceReport,
    ComplianceStatus,
    EUAIActArticle,
    OWASPCategory,
    OWASPVulnerability,
    Severity,
)
from verity.compliance.owasp import (
    OWASP_VULNERABILITIES,
    OWASPMapper,
)

__all__ = [
    # Models
    "ComplianceFinding",
    "ComplianceReport",
    "ComplianceStatus",
    "EUAIActArticle",
    "OWASPCategory",
    "OWASPVulnerability",
    "Severity",
    # OWASP
    "OWASP_VULNERABILITIES",
    "OWASPMapper",
    # EU AI Act
    "EU_AI_ACT_ARTICLES",
    "EUAIActAssessment",
    "EUAIActChecker",
]
