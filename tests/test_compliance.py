"""Tests for EU AI Act compliance checker."""

import pytest
from unittest.mock import MagicMock

from verity.compliance.eu_ai_act import (
    EUAIActChecker,
    EUAIActAssessment,
    EU_AI_ACT_ARTICLES,
    COMPLIANCE_THRESHOLDS,
)
from verity.compliance.models import ComplianceStatus, Severity
from verity.judges.llm_judge import CampaignEvaluation, JudgeEvaluation, JudgeVerdict


def create_mock_evaluation(
    total_attacks: int = 10,
    successful_attacks: int = 0,
    borderline_attacks: int = 0,
    asr: float = 0.0,
) -> CampaignEvaluation:
    """Helper to create mock campaign evaluations."""
    return CampaignEvaluation(
        total_attacks=total_attacks,
        successful_attacks=successful_attacks,
        failed_attacks=total_attacks - successful_attacks - borderline_attacks,
        borderline_attacks=borderline_attacks,
        asr=asr,
        asr_ci_lower=max(0, asr - 0.05),
        asr_ci_upper=min(1, asr + 0.05),
        average_harm_score=asr * 10,
        evaluations=[],
        category_breakdown={},
    )


class TestEUAIActArticles:
    """Test EU AI Act article definitions."""

    def test_article_9_defined(self):
        """Test Article 9 is properly defined."""
        assert "Article 9" in EU_AI_ACT_ARTICLES
        article = EU_AI_ACT_ARTICLES["Article 9"]
        assert article.title == "Risk Management System"
        assert len(article.requirements) > 0

    def test_article_14_defined(self):
        """Test Article 14 is properly defined."""
        assert "Article 14" in EU_AI_ACT_ARTICLES
        article = EU_AI_ACT_ARTICLES["Article 14"]
        assert article.title == "Human Oversight"

    def test_article_15_defined(self):
        """Test Article 15 is properly defined."""
        assert "Article 15" in EU_AI_ACT_ARTICLES
        article = EU_AI_ACT_ARTICLES["Article 15"]
        assert article.title == "Accuracy, Robustness and Cybersecurity"


class TestComplianceThresholds:
    """Test compliance threshold values."""

    def test_thresholds_exist(self):
        """Test all required thresholds are defined."""
        assert "asr_critical" in COMPLIANCE_THRESHOLDS
        assert "asr_high" in COMPLIANCE_THRESHOLDS
        assert "asr_medium" in COMPLIANCE_THRESHOLDS
        assert "min_robustness_score" in COMPLIANCE_THRESHOLDS

    def test_thresholds_ordering(self):
        """Test thresholds are in correct order."""
        assert COMPLIANCE_THRESHOLDS["asr_medium"] < COMPLIANCE_THRESHOLDS["asr_high"]
        assert COMPLIANCE_THRESHOLDS["asr_high"] < COMPLIANCE_THRESHOLDS["asr_critical"]


class TestEUAIActChecker:
    """Test EUAIActChecker class."""

    def test_checker_initialization(self):
        """Test checker initializes correctly."""
        checker = EUAIActChecker()
        assert checker.articles == EU_AI_ACT_ARTICLES
        assert checker.thresholds == COMPLIANCE_THRESHOLDS

    def test_article_9_compliant(self):
        """Test Article 9 compliance with low ASR."""
        checker = EUAIActChecker()
        evaluation = create_mock_evaluation(asr=0.02, successful_attacks=2, total_attacks=100)

        assessment = checker.check_article_9_risk_management(evaluation)

        assert assessment.status == ComplianceStatus.COMPLIANT
        assert assessment.score > 90

    def test_article_9_partially_compliant_medium(self):
        """Test Article 9 partial compliance with medium ASR."""
        checker = EUAIActChecker()
        evaluation = create_mock_evaluation(asr=0.08, successful_attacks=8, total_attacks=100)

        assessment = checker.check_article_9_risk_management(evaluation)

        assert assessment.status == ComplianceStatus.PARTIALLY_COMPLIANT
        assert len(assessment.findings) > 0

    def test_article_9_non_compliant(self):
        """Test Article 9 non-compliance with high ASR."""
        checker = EUAIActChecker()
        evaluation = create_mock_evaluation(asr=0.25, successful_attacks=25, total_attacks=100)

        assessment = checker.check_article_9_risk_management(evaluation)

        assert assessment.status == ComplianceStatus.NON_COMPLIANT
        assert len(assessment.findings) > 0
        assert any(f.severity == Severity.CRITICAL for f in assessment.findings)

    def test_article_15_compliant(self):
        """Test Article 15 compliance with high robustness."""
        checker = EUAIActChecker()
        evaluation = create_mock_evaluation(
            asr=0.05,
            successful_attacks=5,
            borderline_attacks=5,
            total_attacks=100,
        )

        assessment = checker.check_article_15_robustness(evaluation)

        assert assessment.status == ComplianceStatus.COMPLIANT

    def test_article_15_non_compliant(self):
        """Test Article 15 non-compliance with low robustness."""
        checker = EUAIActChecker()
        # Create evaluation with many unsafe responses
        evaluation = create_mock_evaluation(
            asr=0.30,
            successful_attacks=30,
            borderline_attacks=10,
            total_attacks=100,
        )
        # Add mock evaluations with unsafe verdicts
        evaluation.evaluations = [
            JudgeEvaluation(
                attack_name=f"attack_{i}",
                verdict=JudgeVerdict.UNSAFE,
                harm_score=8.0,
                confidence=0.9,
                reasoning="Attack succeeded",
                attack_category="jailbreak",
            )
            for i in range(30)
        ]

        assessment = checker.check_article_15_robustness(evaluation)

        assert assessment.status == ComplianceStatus.NON_COMPLIANT

    def test_article_14_without_oversight(self):
        """Test Article 14 when human oversight is missing for high-risk system."""
        checker = EUAIActChecker()
        evaluation = create_mock_evaluation(asr=0.15, successful_attacks=15, total_attacks=100)

        assessment = checker.check_article_14_human_oversight(
            evaluation,
            has_human_oversight=False,
            has_override_mechanism=False,
        )

        assert assessment.status == ComplianceStatus.NON_COMPLIANT

    def test_article_14_with_oversight(self):
        """Test Article 14 when human oversight is present."""
        checker = EUAIActChecker()
        evaluation = create_mock_evaluation(asr=0.15, successful_attacks=15, total_attacks=100)

        assessment = checker.check_article_14_human_oversight(
            evaluation,
            has_human_oversight=True,
            has_override_mechanism=True,
        )

        assert assessment.status == ComplianceStatus.COMPLIANT

    def test_generate_compliance_report(self):
        """Test full compliance report generation."""
        checker = EUAIActChecker()
        evaluation = create_mock_evaluation(asr=0.05, successful_attacks=5, total_attacks=100)

        report = checker.generate_compliance_report(
            evaluation=evaluation,
            target_system="TestSystem",
            target_model="test-model-v1",
            has_human_oversight=True,
        )

        assert report.target_system == "TestSystem"
        assert report.target_model == "test-model-v1"
        assert len(report.eu_ai_act_articles_checked) == 3
        assert "Article 9" in report.eu_ai_act_articles_checked

    def test_get_article_requirements(self):
        """Test retrieving article requirements."""
        checker = EUAIActChecker()

        article = checker.get_article_requirements("Article 15")

        assert article is not None
        assert article.title == "Accuracy, Robustness and Cybersecurity"
        assert len(article.requirements) > 0

    def test_get_all_articles(self):
        """Test retrieving all articles."""
        checker = EUAIActChecker()

        articles = checker.get_all_articles()

        assert isinstance(articles, list)
        assert len(articles) >= 3


class TestEUAIActAssessment:
    """Test EUAIActAssessment dataclass."""

    def test_assessment_to_dict(self):
        """Test assessment serialization."""
        assessment = EUAIActAssessment(
            article="Article 9",
            article_title="Risk Management System",
            status=ComplianceStatus.COMPLIANT,
            score=95.0,
            findings=[],
            recommendations=["Maintain current security posture"],
        )

        result = assessment.to_dict()

        assert isinstance(result, dict)
        assert result["article"] == "Article 9"
        assert result["status"] == "compliant"
        assert result["compliance_score"] == 95.0
