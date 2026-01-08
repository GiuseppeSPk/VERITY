<div align="center">

# 🛡️ VERITY

### Verification of Ethics, Resilience & Integrity for Trusted AI

**Open-Source LLM Red Teaming & Safety Certification Platform**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-red.svg)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010%202025-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Compliant-blue.svg)](https://artificialintelligenceact.eu/)

[Documentation](./docs/README.md) · [Installation](./docs/INSTALLATION.md) · [Usage](./docs/USAGE.md) · [Contributing](./CONTRIBUTING.md)

</div>

---

## 🚀 About VERITY

VERITY is an **open-source** Red Teaming & AI Safety platform designed to audit Large Language Models (LLMs) against adversarial attacks. It automates the entire safety certification lifecycle: from attack execution to judge evaluation and regulatory compliance reporting.

---

## ✨ Features

### 🔴 Red Team Capabilities
- **Prompt Injection**: Instruction override and context manipulation attacks.
- **Jailbreaking (42+ Payloads)**:
  - **Single-Turn**: FlipAttack (98% ASR), PSA (97% ASR), Policy Puppetry, TokenBreak, Time Bandit, Encoding, Framing.
  - **Multi-Turn**: Crescendo, Echo Chamber (90%+ ASR), Deceptive Delight, Skeleton Key, CCA, Bad Likert Judge.
- **System Leakage**: Detection of system prompt extraction vulnerabilities.
- **Providers**: Ollama, OpenAI, Anthropic, Google Gemini.

### 🔵 Blue Team Analysis
- **LLM-as-Judge**: Automated safety scoring (1-10 scale).
- **Bootstrap CI**: Statistical confidence intervals for Attack Success Rate.
- **Detailed Reasoning**: Explainable verdicts for each attack.

### 📊 Compliance & Reporting
- **OWASP LLM Top 10 2025**: Full vulnerability mapping.
- **EU AI Act**: Articles 9, 14, 15 compliance checking.
- **Professional Reports**: Markdown, HTML, and JSON export.

---

## 🏗️ Architecture Overview

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

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/GiuseppeSPk/VERITY.git
cd VERITY

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
verity providers list

# Run prompt injection attacks
verity attack --type injection --max 5

# Run full security audit
verity audit --target ollama --model llama3.1:8b --output ./reports
```

### Testing SOTA Attacks

```bash
# Run the SOTA attack test suite
python test_sota_attacks.py --max-attacks 5

# Test specific technique
python test_sota_attacks.py --technique psa
python test_sota_attacks.py --technique echo_chamber
```

---

## 🔒 Security & Liability

> **This tool is designed for AUTHORIZED SECURITY TESTING ONLY.**

- 🔒 **Authorized Use Only**: Only use VERITY against systems you own or have explicit written permission to test.
- 📜 **Legal Compliance**: You are responsible for complying with all applicable laws and regulations.
- ❌ **No Malicious Use**: Do not use this tool for unauthorized access, harassment, or illegal activities.

**By using VERITY, you agree to use it ethically and legally.**

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

## 📄 License

VERITY is licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).

---

<div align="center">

**Created by [Giuseppe Spicchiarello](https://github.com/GiuseppeSPk)** 

Made with ❤️ for AI Safety Research.

</div>
