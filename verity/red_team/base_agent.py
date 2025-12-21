"""Base attack agent interface and result model."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class AttackCategory(str, Enum):
    """Categories of attacks based on OWASP LLM Top 10."""

    PROMPT_INJECTION = "prompt_injection"  # LLM01
    SENSITIVE_INFO = "sensitive_info"  # LLM02
    TRAINING_POISONING = "training_poisoning"  # LLM03
    DENIAL_OF_SERVICE = "denial_of_service"  # LLM04
    SUPPLY_CHAIN = "supply_chain"  # LLM05
    PII_DISCLOSURE = "pii_disclosure"  # LLM06
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"  # LLM07
    VECTOR_EMBEDDING = "vector_embedding"  # LLM08
    MISINFORMATION = "misinformation"  # LLM09
    UNBOUNDED_CONSUMPTION = "unbounded_consumption"  # LLM10
    JAILBREAK = "jailbreak"
    BIAS_TOXICITY = "bias_toxicity"


class AttackSeverity(str, Enum):
    """Severity levels for successful attacks."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AttackResult:
    """Result of an attack execution."""

    attack_name: str
    attack_category: AttackCategory
    prompt_used: str
    response: str
    success: bool
    severity: AttackSeverity = AttackSeverity.INFO
    confidence: float = 0.0  # 0-1 confidence in success assessment
    tokens_used: int = 0
    latency_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "attack_name": self.attack_name,
            "attack_category": self.attack_category.value,
            "prompt_used": self.prompt_used,
            "response": self.response,
            "success": self.success,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "tokens_used": self.tokens_used,
            "latency_ms": self.latency_ms,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "error": self.error,
        }


class BaseAttackAgent(ABC):
    """Abstract base class for attack agents."""

    name: str = "base_attack"
    category: AttackCategory = AttackCategory.PROMPT_INJECTION
    description: str = "Base attack agent"

    @abstractmethod
    async def execute(
        self,
        target,  # BaseLLMProvider
        system_prompt: str | None = None,
        **kwargs,
    ) -> list[AttackResult]:
        """Execute the attack against a target.

        Args:
            target: LLM provider to attack
            system_prompt: Optional system prompt for attack context
            **kwargs: Additional attack-specific parameters

        Returns:
            List of attack results
        """
        ...

    @abstractmethod
    def get_payloads(self) -> list[dict[str, Any]]:
        """Get the attack payloads/prompts.

        Returns:
            List of payload configurations
        """
        ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r}, category={self.category.value!r})"
