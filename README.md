<div align="center">

# 🛡️ AEGIS

### Advanced Ethical Guardian & Intelligence System

**Multi-Agent LLM Red/Blue Teaming Platform**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010%202025-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Compliant-blue.svg)](https://artificialintelligenceact.eu/)

[Documentation](./docs/README.md) · [Installation](./docs/INSTALLATION.md) · [Usage](./docs/USAGE.md) · [Attack Catalog](./docs/ATTACKS.md) · [API](./docs/API.md)

</div>

---

## ⚠️ Important Disclaimer

> **This tool is designed for AUTHORIZED SECURITY TESTING ONLY.**

- 🔒 **Authorized Use Only**: Only use AEGIS against systems you own or have explicit written permission to test
- 📜 **Legal Compliance**: You are responsible for complying with all applicable laws and regulations
- 🎓 **Educational Purpose**: This tool is intended for security research and improving AI safety
- ❌ **No Malicious Use**: Do not use this tool for unauthorized access, harassment, or illegal activities
- 🛡️ **Responsible Disclosure**: If you discover vulnerabilities, follow responsible disclosure practices

**By using AEGIS, you agree to use it ethically and legally.**

---

## ✨ Features

### 🔴 Red Team Capabilities

| Feature | Description |
|---------|-------------|
| **40+ Attack Payloads** | Prompt injection, jailbreaking, system prompt leakage |
| **Multi-Turn Attacks** | SOTA 2025: Crescendo, TAP, PAIR |
| **Automated Campaigns** | Orchestrated attack execution with configurable parameters |
| **Multiple Providers** | Ollama, OpenAI, Anthropic, Google Gemini |

### 🔵 Blue Team Analysis

| Feature | Description |
|---------|-------------|
| **LLM-as-Judge** | Automated safety evaluation with structured prompts |
| **Bootstrap CI** | Statistical confidence intervals for Attack Success Rate |
| **Harm Scoring** | Granular severity assessment (1-10 scale) |
| **Detailed Reasoning** | Explainable verdicts for each attack |

### 📊 Compliance & Reporting

| Feature | Description |
|---------|-------------|
| **OWASP LLM Top 10 2025** | Complete vulnerability mapping |
| **EU AI Act** | Articles 9, 14, 15 compliance checking |
| **Professional Reports** | Markdown, HTML, JSON formats |
| **Remediation Guidance** | Actionable security recommendations |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI / API                            │
├─────────────────────────────────────────────────────────────┤
│                    Red Team Orchestrator                     │
├─────────────┬─────────────┬─────────────┬──────────────────┤
│   Prompt    │  Jailbreak  │  Jailbreak  │     System       │
│  Injection  │  Single     │  Multi-Turn │     Leakage      │
│   Agent     │  Turn       │  (SOTA '25) │     Agent        │
├─────────────┴─────────────┴─────────────┴──────────────────┤
│           LLM Providers (Ollama/OpenAI/Anthropic/Google)    │
├─────────────────────────────────────────────────────────────┤
│                      LLM-as-Judge                           │
├─────────────────────────────────────────────────────────────┤
│            Compliance (OWASP 2025 + EU AI Act)              │
├─────────────────────────────────────────────────────────────┤
│                    Report Generator                          │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/aegis.git
cd aegis

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -e .

# Configure environment
cp .env.example .env
# Edit .env with your API keys
```

### Basic Usage

```bash
# List providers
aegis providers list

# Test provider connectivity
aegis providers test --provider ollama

# Run prompt injection attacks
aegis attack --type injection --max 5

# Run full security audit
aegis audit --target ollama --model llama3.2 --output ./reports
```

### Python SDK

```python
import asyncio
from aegis.core import create_provider
from aegis.red_team import PromptInjectionAgent

async def main():
    target = create_provider("ollama", model="llama3.2")
    agent = PromptInjectionAgent()
    
    results = await agent.execute(target, max_attacks=5)
    
    for result in results:
        status = "✓" if result.success else "✗"
        print(f"{status} {result.attack_name}")

asyncio.run(main())
```

---

## 📁 Project Structure

```
aegis/
├── aegis/
│   ├── api/              # FastAPI REST endpoints
│   ├── cli.py            # Typer CLI application
│   ├── compliance/       # OWASP & EU AI Act mappers
│   ├── config/           # Pydantic settings
│   ├── core/             # LLM providers
│   │   └── providers/    # Ollama, OpenAI, Anthropic, Google
│   ├── judges/           # LLM-as-Judge evaluation
│   ├── red_team/         # Attack agents
│   │   ├── attacks/
│   │   │   ├── jailbreak/
│   │   │   │   ├── single_turn.py
│   │   │   │   └── multi_turn.py  # Crescendo, TAP, PAIR
│   │   │   ├── prompt_injection.py
│   │   │   └── system_leaker.py
│   │   └── orchestrator.py
│   └── reporting/        # Report generation
├── docs/                 # Documentation
├── reports/              # Generated reports
├── tests/                # Test suite
├── .env.example          # Environment template
└── pyproject.toml        # Project configuration
```

---

## 🔬 Attack Techniques

### Prompt Injection (OWASP LLM01:2025)

- Direct instruction override
- Indirect context manipulation
- Deceptive Delight escalation
- Rolebreaker personas
- Many-shot jailbreaking
- Encoding/obfuscation attacks

### Jailbreak Multi-Turn (SOTA 2025)

| Technique | Reference | Description |
|-----------|-----------|-------------|
| **Crescendo** | Microsoft Research '24 | Gradual escalation across turns |
| **TAP** | Yale/Stanford '23 | Tree exploration with pruning |
| **PAIR** | CMU '23 | Adversarial prompt refinement |

### System Prompt Leakage (OWASP LLM07:2025)

- Direct extraction requests
- Completion attacks
- Diagnostic mode exploitation
- Translation/encoding tricks

---

## 📋 Compliance

### OWASP LLM Top 10 2025

AEGIS maps all findings to the latest OWASP LLM security framework:

| ID | Vulnerability | AEGIS Coverage |
|----|--------------|----------------|
| LLM01 | Prompt Injection | ✅ Full |
| LLM02 | Sensitive Information Disclosure | ✅ Full |
| LLM06 | Excessive Agency | ✅ Full |
| LLM07 | System Prompt Leakage | ✅ Full |

### EU AI Act (Regulation 2024/1689)

Automated compliance checking for High-Risk AI Systems:

- **Article 9**: Risk Management System
- **Article 14**: Human Oversight
- **Article 15**: Accuracy, Robustness and Cybersecurity

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest --cov=aegis --cov-report=html

# Type checking
mypy aegis/

# Linting
ruff check aegis/
```

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [Installation](./docs/INSTALLATION.md) | Setup and configuration guide |
| [Usage Guide](./docs/USAGE.md) | CLI, API, and SDK examples |
| [API Reference](./docs/API.md) | REST endpoint documentation |
| [Attack Catalog](./docs/ATTACKS.md) | Complete technique reference |
| [Architecture](./docs/ARCHITECTURE.md) | System design details |

---

## 🔧 Configuration

Create a `.env` file from the template:

```bash
# LLM Providers
OLLAMA_BASE_URL=http://localhost:11434
OPENAI_API_KEY=sk-your-key-here
ANTHROPIC_API_KEY=sk-ant-your-key-here
GOOGLE_API_KEY=your-google-key-here

# Default Settings
DEFAULT_PROVIDER=ollama
DEFAULT_MODEL=llama3.2

# Judge Settings (for LLM-as-Judge evaluation)
JUDGE_PROVIDER=openai
JUDGE_MODEL=gpt-4o-mini
```

---

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📚 References

### Research Papers

- [Ignore This Title and HackAPrompt](https://arxiv.org/abs/2302.12173) - Prompt Injection
- [Universal and Transferable Adversarial Attacks](https://arxiv.org/abs/2306.05499) - Jailbreaking
- [Many-Shot Jailbreaking](https://www.anthropic.com/research/many-shot-jailbreaking) - Anthropic Research
- [Crescendo Attack](https://arxiv.org/abs/2404.01833) - Microsoft Research
- [Tree of Attacks with Pruning](https://arxiv.org/abs/2312.02119) - Yale/Stanford
- [PAIR: Automatic Jailbreaking](https://arxiv.org/abs/2310.08419) - CMU

### Standards & Frameworks

- [OWASP LLM Top 10 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [EU AI Act](https://artificialintelligenceact.eu/)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚡ Acknowledgments

Built with:
- [FastAPI](https://fastapi.tiangolo.com/) - Modern web framework
- [Typer](https://typer.tiangolo.com/) - CLI framework
- [LangGraph](https://langchain-ai.github.io/langgraph/) - Agent orchestration
- [Pydantic](https://pydantic.dev/) - Data validation
- [Rich](https://rich.readthedocs.io/) - Terminal formatting

---

<div align="center">

**🔴 Remember: With great power comes great responsibility. 🔴**

Made with ❤️ for AI Safety Research

---

**Created by [Giuseppe Spicchiarello](https://github.com/GiuseppeSPk)** 

[![GitHub](https://img.shields.io/badge/GitHub-GiuseppeSPk-black?logo=github)](https://github.com/GiuseppeSPk)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Giuseppe%20Spicchiarello-blue?logo=linkedin)](https://www.linkedin.com/in/giuseppe-spicchiarello-b6b157352/)

</div>
