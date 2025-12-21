<div align="center">

# 🛡️ VERITY

### Verification of Ethics, Resilience & Integrity for Trusted AI

**Advanced Red Teaming & Safety Certification for Enterprise LLMs**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-red.svg)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010%202025-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Compliant-blue.svg)](https://artificialintelligenceact.eu/)

[Documentation](./docs/README.md) · [Installation](./docs/INSTALLATION.md) · [Usage](./docs/USAGE.md) · [Commercial License](https://verity.ai/pricing)

</div>

---

## 🚀 About VERITY

VERITY is an industry-grade Red Teaming & AI Safety platform designed to audit Large Language Models (LLMs) against adversarial attacks. It automates the entire safety certification lifecycle: from attack execution to judge evaluation and regulatory compliance reporting.

> **VERITY operates on an Open Core model.**
> The Community Edition provides essential tools for security researchers, while VERITY Pro offers state-of-the-art (SOTA) attack payloads and enterprise features.

---

## 💎 Editions & Pricing

| Feature | Community | Pro (€149/mo) | Enterprise |
|---------|:---------:|:-------------:|:----------:|
| **License** | AGPL-3.0 | Commercial | Commercial |
| **Attack Payloads** | 10 (Demo) | 💯 100+ (SOTA) | Custom |
| **Algorithms** | Basic | Crescendo, PAIR, TAP | Advanced + Custom |
| **LLM-as-Judge** | ✅ Standard | ✅ Optimized | ✅ Fine-tuned |
| **Reporting** | Markdown/HTML | + PDF, Whitelabel | + API Integration |
| **Compliance** | Basic | EU AI Act, OWASP | Custom Frameworks |
| **Support** | Community | Email (24h) | Dedicated SLA |

### 🌟 Why Upgrade?
- **Unlock SOTA 2025 Attacks**: Access RoleBreaker (87% ASR), FlipAttack (98% ASR), and Deceptive Delight techniques.
- **Advanced Jailbreaking**: Use multi-turn automated optimization (PAIR, Crescendo) to bypass robust defenses.
- **Commercial Use**: Use VERITY in closed-source proprietary products without AGPL restrictions.

👉 **[Get VERITY Pro License](https://verity.ai/pricing)**

---

## ✨ Features (Community Edition)

### 🔴 Red Team Capabilities
- **Prompt Injection**: Basic instruction override and context manipulation attacks.
- **Jailbreaking**: Single-turn and basic multi-turn iterative testing.
- **System Leakage**: Detection of system prompt extraction vulnerabilities.
- **Providers**: Support for Ollama, OpenAI, Anthropic, Google Gemini.

### 🔵 Blue Team Analysis
- **LLM-as-Judge**: Automated safety scoring (1-10 scale).
- **Bootstrap CI**: Statistical confidence intervals for Attack Success Rate.
- **Detailed Reasoning**: Explainable verdicts for each attack.

### 📊 Compliance & Reporting
- **OWASP LLM Top 10**: Mapping to key vulnerabilities.
- **Professional Reports**: Generate comprehensive Markdown and HTML reports.

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/VERITY.git
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

# Run prompt injection attacks (Community Edition)
verity attack --type injection --max 5

# Run full security audit
verity audit --target ollama --model llama3.2 --output ./reports
```

---

## 🔒 Security & Liability

> **This tool is designed for AUTHORIZED SECURITY TESTING ONLY.**

- 🔒 **Authorized Use Only**: Only use VERITY against systems you own or have explicit written permission to test.
- 📜 **Legal Compliance**: You are responsible for complying with all applicable laws and regulations.
- ❌ **No Malicious Use**: Do not use this tool for unauthorized access, harassment, or illegal activities.

**By using VERITY, you agree to use it ethically and legally.**

---

## 📄 License

**VERITY Community Edition** is licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).
Creating a closed-source service using this code requires releasing your source code.

For proprietary use, please purchase a **Commercial License**.

---

<div align="center">

**Created by [Giuseppe Spicchiarello](https://github.com/GiuseppeSPk)** 

Made with ❤️ for AI Safety Research.

</div>
