# VERITY Documentation

Welcome to the VERITY documentation. This guide will help you get started with the Verification of Ethics, Resilience & Integrity for Trusted AI.

## Quick Links

| Document | Description |
|----------|-------------|
| [Installation](./INSTALLATION.md) | How to install and configure VERITY |
| [Usage Guide](./USAGE.md) | CLI, API, and SDK usage examples |
| [API Reference](./API.md) | REST API endpoints documentation |
| [Attack Catalog](./ATTACKS.md) | Complete list of attack techniques |
| [Architecture](./ARCHITECTURE.md) | System design and components |

## What is VERITY?

VERITY (Verification of Ethics, Resilience & Integrity for Trusted AI) is a multi-agent LLM Red/Blue Teaming platform designed for:

- **Security Researchers**: Test LLM safety measures with state-of-the-art attack techniques
- **AI Safety Engineers**: Evaluate robustness against prompt injection and jailbreaking
- **Compliance Officers**: Generate OWASP and EU AI Act compliance reports
- **Red Teams**: Execute comprehensive adversarial testing campaigns

## Key Features

### 🔴 Red Team Capabilities

- **30+ Attack Payloads** across prompt injection, jailbreaking, and system leakage categories
- **Multi-Turn Attacks** including Crescendo, TAP, and PAIR (SOTA 2025)
- **Automated Campaign Orchestration** with configurable attack parameters

### 🔵 Blue Team Analysis

- **LLM-as-Judge** evaluation with structured prompts and confidence scoring
- **Bootstrap Confidence Intervals** for Attack Success Rate (ASR)
- **Detailed Remediation Guidance** for each vulnerability

### 📊 Compliance Reporting

- **OWASP LLM Top 10 2025** complete vulnerability mapping
- **EU AI Act** compliance checking (Articles 9, 14, 15)
- **Professional Reports** in Markdown, HTML, and JSON formats

## Getting Started

```bash
# Install VERITY
pip install -e .

# Configure providers
cp .env.example .env
# Edit .env with your API keys

# Test connectivity
VERITY providers list
VERITY providers test --provider ollama

# Run your first attack
VERITY attack --type injection --max 5
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI / API                            │
├─────────────────────────────────────────────────────────────┤
│                    Red Team Orchestrator                     │
├─────────────┬─────────────┬─────────────┬──────────────────┤
│  Prompt     │  Jailbreak  │  Jailbreak  │    System        │
│  Injection  │  Single     │  Multi-Turn │    Leakage       │
│  Agent      │  Turn       │  (Crescendo │    Agent         │
│             │  Agent      │   TAP/PAIR) │                  │
├─────────────┴─────────────┴─────────────┴──────────────────┤
│                      LLM Providers                          │
│            (Ollama | OpenAI | Anthropic | Google)           │
├─────────────────────────────────────────────────────────────┤
│                      LLM-as-Judge                           │
├─────────────────────────────────────────────────────────────┤
│               Compliance Module + Report Generator          │
│                  (OWASP 2025 | EU AI Act)                   │
└─────────────────────────────────────────────────────────────┘
```

## Support

- **Issues**: [GitHub Issues](https://github.com/GiuseppeSPk/VERITY/issues)
- **Discussions**: [GitHub Discussions](https://github.com/GiuseppeSPk/VERITY/discussions)

## License

AGPL-3.0 License - See [LICENSE](../LICENSE) for details.
