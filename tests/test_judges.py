"""Tests for LLM-as-Judge."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from verity.judges.llm_judge import (
    LLMJudge,
    JudgeVerdict,
    JudgeEvaluation,
    CampaignEvaluation,
    JUDGE_SYSTEM_PROMPT,
)
from verity.red_team.base_agent import AttackResult, AttackCategory, AttackSeverity


class TestJudgeVerdict:
    """Test JudgeVerdict enum."""

    def test_verdict_values(self):
        """Test all verdict values exist."""
        assert JudgeVerdict.SAFE.value == "safe"
        assert JudgeVerdict.UNSAFE.value == "unsafe"
        assert JudgeVerdict.BORDERLINE.value == "borderline"
        assert JudgeVerdict.ERROR.value == "error"


class TestJudgeEvaluation:
    """Test JudgeEvaluation dataclass."""

    def test_create_evaluation(self):
        """Test creating a judge evaluation."""
        eval_result = JudgeEvaluation(
            attack_name="test_attack",
            verdict=JudgeVerdict.UNSAFE,
            harm_score=8.5,
            confidence=0.95,
            reasoning="Attack succeeded",
            harmful_instructions=True,
            safety_bypass=True,
            information_leakage=False,
        )

        assert eval_result.attack_name == "test_attack"
        assert eval_result.verdict == JudgeVerdict.UNSAFE
        assert eval_result.harm_score == 8.5
        assert eval_result.confidence == 0.95
        assert eval_result.harmful_instructions is True
        assert eval_result.safety_bypass is True
        assert eval_result.information_leakage is False


class TestLLMJudge:
    """Test LLMJudge class."""

    def test_system_prompt_exists(self):
        """Test that system prompt is defined."""
        assert JUDGE_SYSTEM_PROMPT is not None
        assert "EVALUATION FRAMEWORK" in JUDGE_SYSTEM_PROMPT
        assert "HARMFUL_INSTRUCTIONS" in JUDGE_SYSTEM_PROMPT
        assert "SAFETY_BYPASS" in JUDGE_SYSTEM_PROMPT
        assert "INFORMATION_LEAKAGE" in JUDGE_SYSTEM_PROMPT

    def test_parse_valid_json(self):
        """Test parsing valid JSON response."""
        mock_provider = MagicMock()
        judge = LLMJudge(mock_provider)

        response = '{"verdict": "unsafe", "harm_score": 7, "confidence": 0.8, "reasoning": "test"}'
        result = judge._parse_judge_response(response)

        assert result["verdict"] == "unsafe"
        assert result["harm_score"] == 7
        assert result["confidence"] == 0.8

    def test_parse_json_with_markdown(self):
        """Test parsing JSON wrapped in markdown code blocks."""
        mock_provider = MagicMock()
        judge = LLMJudge(mock_provider)

        response = '```json\n{"verdict": "safe", "harm_score": 1, "confidence": 0.9}\n```'
        result = judge._parse_judge_response(response)

        assert result["verdict"] == "safe"
        assert result["harm_score"] == 1

    def test_parse_invalid_json(self):
        """Test parsing invalid JSON returns error."""
        mock_provider = MagicMock()
        judge = LLMJudge(mock_provider)

        response = "This is not JSON at all"
        result = judge._parse_judge_response(response)

        assert result["verdict"] == "error"
        assert result["harm_score"] == 0

    def test_bootstrap_ci_empty(self):
        """Test bootstrap CI with empty outcomes."""
        mock_provider = MagicMock()
        judge = LLMJudge(mock_provider)

        lower, upper = judge._bootstrap_ci([])

        assert lower == 0.0
        assert upper == 0.0

    def test_bootstrap_ci_all_success(self):
        """Test bootstrap CI with all successful attacks."""
        mock_provider = MagicMock()
        judge = LLMJudge(mock_provider)

        outcomes = [1, 1, 1, 1, 1]  # 100% success
        lower, upper = judge._bootstrap_ci(outcomes, n_samples=100)

        assert lower == 1.0
        assert upper == 1.0

    def test_bootstrap_ci_all_failure(self):
        """Test bootstrap CI with all failed attacks."""
        mock_provider = MagicMock()
        judge = LLMJudge(mock_provider)

        outcomes = [0, 0, 0, 0, 0]  # 0% success
        lower, upper = judge._bootstrap_ci(outcomes, n_samples=100)

        assert lower == 0.0
        assert upper == 0.0

    def test_bootstrap_ci_mixed(self):
        """Test bootstrap CI with mixed outcomes."""
        mock_provider = MagicMock()
        judge = LLMJudge(mock_provider)

        outcomes = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0]  # 50% success
        lower, upper = judge._bootstrap_ci(outcomes, n_samples=500)

        # CI should be around 50% with some variance
        assert 0.0 <= lower <= 0.5
        assert 0.5 <= upper <= 1.0


class TestCampaignEvaluation:
    """Test CampaignEvaluation dataclass."""

    def test_create_campaign_evaluation(self):
        """Test creating a campaign evaluation."""
        eval_result = CampaignEvaluation(
            total_attacks=10,
            successful_attacks=3,
            failed_attacks=6,
            borderline_attacks=1,
            asr=0.3,
            asr_ci_lower=0.1,
            asr_ci_upper=0.5,
            average_harm_score=4.5,
            evaluations=[],
            category_breakdown={"prompt_injection": 5, "jailbreak": 5},
        )

        assert eval_result.total_attacks == 10
        assert eval_result.asr == 0.3
        assert eval_result.asr_ci_lower == 0.1
        assert eval_result.asr_ci_upper == 0.5
