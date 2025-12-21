"""Red Team attack agents."""

from verity.red_team.attacks import (
    MultiTurnJailbreakAgent,
    PromptInjectionAgent,
    SingleTurnJailbreakAgent,
    SystemLeakerAgent,
)
from verity.red_team.base_agent import (
    AttackCategory,
    AttackResult,
    AttackSeverity,
    BaseAttackAgent,
)

__all__ = [
    "AttackCategory",
    "AttackResult",
    "AttackSeverity",
    "BaseAttackAgent",
    "PromptInjectionAgent",
    "SingleTurnJailbreakAgent",
    "MultiTurnJailbreakAgent",
    "SystemLeakerAgent",
]


def get_all_agents() -> list[BaseAttackAgent]:
    """Get instances of all available attack agents."""
    return [
        PromptInjectionAgent(),
        SingleTurnJailbreakAgent(),
        MultiTurnJailbreakAgent(),
        SystemLeakerAgent(),
    ]


def get_agent_by_name(name: str) -> BaseAttackAgent | None:
    """Get attack agent by name."""
    agents = {
        "injection": PromptInjectionAgent,
        "prompt_injection": PromptInjectionAgent,
        "jailbreak": SingleTurnJailbreakAgent,
        "jailbreak_single": SingleTurnJailbreakAgent,
        "jailbreak_multi": MultiTurnJailbreakAgent,
        "multi_turn": MultiTurnJailbreakAgent,
        "crescendo": MultiTurnJailbreakAgent,
        "tap": MultiTurnJailbreakAgent,
        "pair": MultiTurnJailbreakAgent,
        "system_leak": SystemLeakerAgent,
        "leak": SystemLeakerAgent,
    }
    agent_class = agents.get(name.lower())
    return agent_class() if agent_class else None
