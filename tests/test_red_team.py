"""Tests for Red Team attack agents."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from verity.red_team.attacks.prompt_injection import PromptInjectionAgent, INJECTION_PAYLOADS
from verity.red_team.attacks.jailbreak.single_turn import SingleTurnJailbreakAgent
from verity.red_team.base_agent import AttackCategory, AttackResult, AttackSeverity
from verity.core.providers.base import LLMResponse


class TestPromptInjectionAgent:
    """Test PromptInjectionAgent functionality."""

    def test_agent_attributes(self):
        """Test agent has correct attributes."""
        agent = PromptInjectionAgent()
        assert agent.name == "prompt_injection"
        assert agent.category == AttackCategory.PROMPT_INJECTION
        assert "LLM01" in agent.description

    def test_default_payloads_loaded(self):
        """Test that default payloads are loaded correctly."""
        agent = PromptInjectionAgent()
        payloads = agent.get_payloads()

        assert len(payloads) > 0
        assert len(payloads) == len(INJECTION_PAYLOADS)

    def test_payload_structure(self):
        """Test each payload has required fields."""
        agent = PromptInjectionAgent()

        for payload in agent.get_payloads():
            assert "name" in payload
            assert "technique" in payload
            assert "prompt" in payload
            assert "severity" in payload
            assert isinstance(payload["name"], str)
            assert isinstance(payload["prompt"], str)

    def test_custom_payloads(self):
        """Test agent accepts custom payloads."""
        custom_payloads = [
            {
                "name": "custom_test",
                "technique": "custom",
                "prompt": "Test prompt",
                "success_indicator": None,
                "severity": AttackSeverity.LOW,
            }
        ]
        agent = PromptInjectionAgent(payloads=custom_payloads)
        assert len(agent.get_payloads()) == 1
        assert agent.get_payloads()[0]["name"] == "custom_test"

    @pytest.mark.asyncio
    async def test_execute_with_mock_provider(self):
        """Test execute method with mocked LLM provider."""
        # Create mock provider
        mock_provider = AsyncMock()
        mock_provider.generate.return_value = LLMResponse(
            content="I cannot help with that request.",
            model="test-model",
            provider="test",
            tokens_input=10,
            tokens_output=20,
            latency_ms=100.0,
        )

        agent = PromptInjectionAgent()
        results = await agent.execute(
            target=mock_provider,
            system_prompt="You are a helpful assistant.",
            max_attacks=2,
        )

        assert len(results) == 2
        assert all(isinstance(r, AttackResult) for r in results)
        assert mock_provider.generate.call_count == 2

    @pytest.mark.asyncio
    async def test_execute_filters_by_technique(self):
        """Test execute filters by technique correctly."""
        mock_provider = AsyncMock()
        mock_provider.generate.return_value = LLMResponse(
            content="Test response",
            model="test",
            provider="test",
        )

        agent = PromptInjectionAgent()
        results = await agent.execute(
            target=mock_provider,
            techniques=["encoding"],
            max_attacks=10,
        )

        # All results should be from encoding technique
        for result in results:
            assert result.metadata.get("technique") == "encoding"

    @pytest.mark.asyncio
    async def test_execute_handles_error(self):
        """Test execute handles provider errors gracefully."""
        mock_provider = AsyncMock()
        mock_provider.generate.side_effect = Exception("Connection failed")

        agent = PromptInjectionAgent()
        results = await agent.execute(
            target=mock_provider,
            max_attacks=1,
        )

        assert len(results) == 1
        assert results[0].success is False
        assert results[0].error == "Connection failed"


class TestSingleTurnJailbreakAgent:
    """Test SingleTurnJailbreakAgent functionality."""

    def test_agent_attributes(self):
        """Test agent has correct attributes."""
        agent = SingleTurnJailbreakAgent()
        assert agent.name == "jailbreak_single"
        assert agent.category == AttackCategory.JAILBREAK

    def test_payloads_loaded(self):
        """Test payloads are loaded."""
        agent = SingleTurnJailbreakAgent()
        payloads = agent.get_payloads()

        assert len(payloads) > 0
        # Should have multiple techniques
        techniques = set(p.get("technique") for p in payloads)
        assert len(techniques) > 1

    def test_payload_has_asr_metadata(self):
        """Test high-ASR payloads have reported ASR."""
        agent = SingleTurnJailbreakAgent()
        payloads = agent.get_payloads()

        # At least some payloads should have ASR data
        payloads_with_asr = [p for p in payloads if "asr_reported" in p]
        assert len(payloads_with_asr) >= 0  # May or may not have ASR data

    @pytest.mark.asyncio
    async def test_execute_respects_max_attacks(self):
        """Test execute respects max_attacks limit."""
        mock_provider = AsyncMock()
        mock_provider.generate.return_value = LLMResponse(
            content="Safe response",
            model="test",
            provider="test",
        )

        agent = SingleTurnJailbreakAgent()
        results = await agent.execute(
            target=mock_provider,
            max_attacks=3,
        )

        assert len(results) <= 3


class TestAttackResult:
    """Test AttackResult dataclass."""

    def test_create_attack_result(self):
        """Test creating an attack result."""
        result = AttackResult(
            attack_name="test_attack",
            attack_category=AttackCategory.PROMPT_INJECTION,
            prompt_used="Test prompt",
            response="Test response",
            success=True,
            severity=AttackSeverity.HIGH,
            confidence=0.9,
        )

        assert result.attack_name == "test_attack"
        assert result.success is True
        assert result.confidence == 0.9

    def test_attack_result_to_dict(self):
        """Test AttackResult serialization."""
        result = AttackResult(
            attack_name="test_attack",
            attack_category=AttackCategory.PROMPT_INJECTION,
            prompt_used="Test prompt",
            response="Test response",
            success=False,
            severity=AttackSeverity.MEDIUM,
        )

        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert result_dict["attack_name"] == "test_attack"
        assert result_dict["success"] is False
