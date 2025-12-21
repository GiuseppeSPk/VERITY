"""Tests for Report Generator."""

import pytest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from verity.reporting.report_generator import (
    ReportGenerator,
    ReportMetadata,
)
from verity.judges.llm_judge import (
    JudgeVerdict,
    JudgeEvaluation,
    CampaignEvaluation,
)


class TestReportMetadata:
    """Test ReportMetadata dataclass."""

    def test_create_metadata(self):
        """Test creating report metadata."""
        now = datetime.now()
        metadata = ReportMetadata(
            title="Test Report",
            target_system="ollama",
            target_model="llama3",
            assessment_date=now,
        )

        assert metadata.title == "Test Report"
        assert metadata.target_system == "ollama"
        assert metadata.target_model == "llama3"
        assert metadata.assessment_date == now
        assert metadata.assessor == "VERITY Automated Assessment"
        assert metadata.report_version == "1.0"
        assert metadata.classification == "CONFIDENTIAL"


class TestReportGenerator:
    """Test ReportGenerator class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = TemporaryDirectory()
        self.generator = ReportGenerator(self.temp_dir.name)

        # Create sample evaluations
        self.evaluations = [
            JudgeEvaluation(
                attack_name="test_attack_1",
                verdict=JudgeVerdict.UNSAFE,
                harm_score=8.0,
                confidence=0.9,
                reasoning="Attack succeeded",
                harmful_instructions=True,
                safety_bypass=True,
            ),
            JudgeEvaluation(
                attack_name="test_attack_2",
                verdict=JudgeVerdict.SAFE,
                harm_score=1.0,
                confidence=0.95,
                reasoning="Attack blocked",
            ),
            JudgeEvaluation(
                attack_name="test_attack_3",
                verdict=JudgeVerdict.BORDERLINE,
                harm_score=5.0,
                confidence=0.6,
                reasoning="Unclear result",
            ),
        ]

        self.campaign = CampaignEvaluation(
            total_attacks=3,
            successful_attacks=1,
            failed_attacks=1,
            borderline_attacks=1,
            asr=0.333,
            asr_ci_lower=0.1,
            asr_ci_upper=0.6,
            average_harm_score=4.67,
            evaluations=self.evaluations,
            category_breakdown={"prompt_injection": 2, "jailbreak": 1},
        )

        self.metadata = ReportMetadata(
            title="Test Security Assessment",
            target_system="ollama",
            target_model="llama3",
            assessment_date=datetime.now(),
        )

    def teardown_method(self):
        """Clean up temp directory."""
        self.temp_dir.cleanup()

    def test_output_dir_created(self):
        """Test that output directory is created."""
        assert Path(self.temp_dir.name).exists()

    def test_generate_markdown(self):
        """Test generating markdown report."""
        report = self.generator.generate_markdown(self.campaign, self.metadata)

        assert "# 🛡️ VERITY Security Assessment Report" in report
        assert "Executive Summary" in report
        assert "OWASP LLM Top 10" in report
        assert "EU AI Act Compliance" in report
        assert "Recommendations" in report
        assert "llama3" in report

    def test_markdown_contains_metrics(self):
        """Test that markdown contains key metrics."""
        report = self.generator.generate_markdown(self.campaign, self.metadata)

        assert "Attack Success Rate" in report
        assert "Total Attack Vectors Tested" in report or "Statistical Confidence" in report
        assert "95% CI" in report or "Confidence" in report

    def test_markdown_contains_findings(self):
        """Test that markdown contains detailed findings."""
        report = self.generator.generate_markdown(self.campaign, self.metadata)

        assert "test_attack_1" in report
        assert "UNSAFE" in report or "unsafe" in report
        assert "Harm Score" in report

    def test_save_markdown_report(self):
        """Test saving markdown report to file."""
        filepath = self.generator.save_report(
            self.campaign,
            self.metadata,
            format="markdown",
        )

        assert filepath.exists()
        assert filepath.suffix == ".md"
        assert filepath.stat().st_size > 0

        content = filepath.read_text(encoding="utf-8")
        assert "VERITY" in content

    def test_save_json_report(self):
        """Test saving JSON report to file."""
        filepath = self.generator.save_report(
            self.campaign,
            self.metadata,
            format="json",
        )

        assert filepath.exists()
        assert filepath.suffix == ".json"

        import json

        with open(filepath) as f:
            data = json.load(f)

        assert "metadata" in data
        assert "summary" in data
        assert data["summary"]["total_attacks"] == 3

    def test_save_html_report(self):
        """Test saving HTML report to file."""
        filepath = self.generator.save_report(
            self.campaign,
            self.metadata,
            format="html",
        )

        assert filepath.exists()
        assert filepath.suffix == ".html"

        content = filepath.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "<style>" in content


class TestReportRiskLevels:
    """Test risk level determination."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = TemporaryDirectory()
        self.generator = ReportGenerator(self.temp_dir.name)
        self.metadata = ReportMetadata(
            title="Test",
            target_system="test",
            target_model="test",
            assessment_date=datetime.now(),
        )

    def teardown_method(self):
        """Clean up."""
        self.temp_dir.cleanup()

    def test_critical_risk(self):
        """Test critical risk level for high ASR."""
        campaign = CampaignEvaluation(
            total_attacks=10,
            successful_attacks=8,
            failed_attacks=2,
            borderline_attacks=0,
            asr=0.8,  # 80% ASR
            asr_ci_lower=0.7,
            asr_ci_upper=0.9,
            average_harm_score=8.0,
        )

        report = self.generator.generate_markdown(campaign, self.metadata)
        assert "CRITICAL" in report

    def test_low_risk(self):
        """Test low risk level for low ASR."""
        campaign = CampaignEvaluation(
            total_attacks=10,
            successful_attacks=1,
            failed_attacks=9,
            borderline_attacks=0,
            asr=0.1,  # 10% ASR
            asr_ci_lower=0.05,
            asr_ci_upper=0.2,
            average_harm_score=2.0,
        )

        report = self.generator.generate_markdown(campaign, self.metadata)
        assert "LOW" in report
