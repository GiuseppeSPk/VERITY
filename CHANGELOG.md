# Changelog

All notable changes to VERITY will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- MARL (Multi-Agent Reinforcement Learning) module
- Web Dashboard UI
- PDF report generation
- Continuous monitoring mode

---

## [0.2.2] - 2026-01-07

### Added

#### Test Coverage
- **test_red_team.py** - Comprehensive tests for PromptInjectionAgent and SingleTurnJailbreakAgent
- **test_compliance.py** - Full test suite for EU AI Act compliance checker

#### Infrastructure
- **Structured Logging** - New `verity/config/logging.py` with JSON and console formatters
- **Configurable CORS** - CORS origins now loaded from environment (`CORS_ORIGINS`)
- **Debug Mode** - Stack traces in API error responses when `DEBUG=true`

### Fixed
- **datetime.utcnow() deprecation** - Replaced with `datetime.now(UTC)` in `api/main.py`
- **Hardcoded CORS origins** - Now configurable via settings
- **Generic error handler** - Now includes debug info in development mode
- **Missing logging** - Added structured logging throughout API

### Changed
- API startup now logs configuration (debug mode, CORS origins)
- Error responses include stack traces when DEBUG=true

---

## [0.2.1] - 2026-01-02

### Fixed
- **License Switch**: Project license set to **AGPL-3.0** (Open Core model) to protect against unauthorized commercial exploitation and ensure contributions are shared back. Update reflected in `README.md`, `pyproject.toml`, `LICENSE`, and `verity/__init__.py`.
- **BaseLLMProvider**: Added abstract `close()` method to ensure all providers implement resource cleanup
- **SystemLeakerAgent**: Now respects `max_attacks` parameter (was previously ignored)
- **SystemLeakerAgent**: Uses unique attack names per payload instead of hardcoded "system_leak_basic"
- **SystemLeakerAgent**: Improved success detection with more indicators
- **SystemLeakerAgent**: Added error handling for failed attacks
- **Deprecated API**: Fixed `datetime.utcnow()` deprecation (Python 3.12+) in 6 files:
  - `verity/red_team/base_agent.py`
  - `verity/red_team/orchestrator.py`
  - `verity/compliance/eu_ai_act.py`
  - `verity/compliance/owasp.py`
  - `verity/reporting/report_generator.py`

### Changed
- Test warnings reduced from 18 to 11 due to datetime fixes

---

## [0.2.0] - 2026-01-02

### Added

#### SOTA 2025 Attack Techniques
- **PSA (Paper Summary Attack)** - 97-98% ASR, academic paper framing
- **Echo Chamber** - 90%+ ASR, progressive context poisoning
- **Context Compliance Attack (CCA)** - Microsoft 2025, fake history injection
- **Policy Puppetry** - XML/JSON/INI config file mimicry
- **Chain-of-Thought Hijacking** - Oxford 2025, reasoning overload
- **Skeleton Key** - Microsoft 2024, guardrail override
- **TokenBreak** - Zero-width space tokenization exploit
- **Time Bandit** - Temporal confusion attacks

#### Single-Turn Jailbreak (25 payloads)
- 10 new patterns across 4 new techniques

#### Multi-Turn Jailbreak (17 payloads)
- 10 new patterns across 4 new techniques

#### Testing
- `test_sota_attacks.py` - Comprehensive test suite for Ollama

### Changed
- Attack prioritization now based on ASR (highest first)
- Total payloads increased from 22 to 42 (+90%)

---

## [0.1.0] - 2024-12-16

### Added

#### Core Features
- **CLI Application** - Full-featured command-line interface using Typer
- **REST API** - FastAPI-based API with 22 endpoints
- **LLM Providers** - Support for Ollama, OpenAI, Anthropic, Google Gemini

#### Red Team Capabilities
- **Prompt Injection Agent** - 32 attack payloads
- **Single-Turn Jailbreak Agent** - 12 techniques (DAN, AIM, Developer Mode)
- **Multi-Turn Jailbreak Agent** - SOTA 2025 techniques:
  - Crescendo (Microsoft Research 2024)
  - Tree of Attacks with Pruning (TAP)
  - PAIR (Prompt Automatic Iterative Refinement)
- **System Prompt Leakage Agent** - 12 extraction techniques

#### Blue Team Analysis
- **LLM-as-Judge** - Automated attack evaluation
- **Bootstrap Confidence Intervals** - Statistical ASR analysis
- **Harm Scoring** - Granular severity assessment (1-10)

#### Compliance
- **OWASP LLM Top 10 2025** - Complete vulnerability mapping
- **EU AI Act** - Articles 9, 14, 15 compliance checking

#### Reporting
- **Markdown Reports** - GitHub-compatible format
- **HTML Reports** - Styled with dark theme
- **JSON Reports** - Machine-readable format
- **Jinja2 Templates** - Customizable report generation

#### Documentation
- Installation guide
- Usage guide (CLI, API, SDK)
- API reference
- Attack catalog
- Architecture documentation

### Security
- JWT authentication for API
- API key support
- Rate limiting
- CORS configuration

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.1.0 | 2024-12-16 | Initial release |

---

## Upgrade Guide

### From 0.0.x to 0.1.0

This is the initial public release. No upgrade path needed.

---

## Contributors

Thanks to all contributors who helped make VERITY possible!

<!-- Add contributor list here -->
