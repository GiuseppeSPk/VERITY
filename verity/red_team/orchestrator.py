"""Red Team orchestrator for running attack campaigns."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from verity.core.providers.base import BaseLLMProvider
from verity.red_team import (
    AttackResult,
    BaseAttackAgent,
    get_agent_by_name,
    get_all_agents,
)


@dataclass
class CampaignResult:
    """Result of a red team campaign."""

    target_provider: str
    target_model: str
    started_at: datetime
    completed_at: datetime | None = None
    total_attacks: int = 0
    successful_attacks: int = 0
    failed_attacks: int = 0
    results: list[AttackResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        """Calculate attack success rate (ASR)."""
        if self.total_attacks == 0:
            return 0.0
        return self.successful_attacks / self.total_attacks

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target_provider": self.target_provider,
            "target_model": self.target_model,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_attacks": self.total_attacks,
            "successful_attacks": self.successful_attacks,
            "failed_attacks": self.failed_attacks,
            "success_rate": self.success_rate,
            "results": [r.to_dict() for r in self.results],
            "metadata": self.metadata,
        }


class RedTeamOrchestrator:
    """Orchestrates red team attack campaigns."""

    def __init__(
        self,
        target: BaseLLMProvider,
        agents: list[BaseAttackAgent] | None = None,
    ):
        """Initialize orchestrator.

        Args:
            target: LLM provider to attack
            agents: List of attack agents (or None for all)
        """
        self.target = target
        self.agents = agents or get_all_agents()

    async def run_campaign(
        self,
        system_prompt: str | None = None,
        max_attacks_per_agent: int | None = None,
        attack_types: list[str] | None = None,
    ) -> CampaignResult:
        """Run a full red team campaign.

        Args:
            system_prompt: System prompt for target
            max_attacks_per_agent: Limit attacks per agent
            attack_types: Filter by attack type names

        Returns:
            Campaign results with all attack outcomes
        """
        result = CampaignResult(
            target_provider=self.target.provider_name,
            target_model=getattr(self.target, "model", "unknown"),
            started_at=datetime.now(UTC),
        )

        # Filter agents if specific types requested
        agents_to_run = self.agents
        if attack_types:
            agents_to_run = [get_agent_by_name(t) for t in attack_types if get_agent_by_name(t)]

        # Run all agents
        for agent in agents_to_run:
            agent_results = await agent.execute(
                target=self.target,
                system_prompt=system_prompt,
                max_attacks=max_attacks_per_agent,
            )

            for attack_result in agent_results:
                result.results.append(attack_result)
                result.total_attacks += 1

                if attack_result.success:
                    result.successful_attacks += 1
                elif attack_result.error:
                    result.failed_attacks += 1

        result.completed_at = datetime.now(UTC)
        return result

    async def quick_scan(
        self,
        system_prompt: str | None = None,
    ) -> CampaignResult:
        """Run a quick scan with limited attacks.

        Args:
            system_prompt: System prompt for target

        Returns:
            Quick campaign results
        """
        return await self.run_campaign(
            system_prompt=system_prompt,
            max_attacks_per_agent=3,
        )
