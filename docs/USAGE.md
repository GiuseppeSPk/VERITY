# Usage Guide

This guide covers the three main ways to use VERITY: CLI, REST API, and Python SDK.

## Table of Contents

- [Command Line Interface (CLI)](#command-line-interface-cli)
- [REST API](#rest-api)
- [Python SDK](#python-sdk)
- [Attack Types](#attack-types)
- [Report Generation](#report-generation)

---

## Command Line Interface (CLI)

The VERITY CLI provides quick access to all features.

### Basic Commands

```bash
# Show help
VERITY --help

# Show version
VERITY --version
```

### Provider Management

```bash
# List all configured providers
VERITY providers list

# Test a specific provider
VERITY providers test --provider ollama
VERITY providers test --provider openai --model gpt-4o-mini
```

### Running Attacks

```bash
# Run prompt injection attacks
VERITY attack --type injection --max 5

# Run jailbreak attacks
VERITY attack --type jailbreak --max 10

# Run system prompt leakage attacks
VERITY attack --type leak --max 5

# Run multi-turn attacks (Crescendo/TAP/PAIR)
VERITY attack --type jailbreak_multi --max 3

# Specify target provider and model
VERITY attack --type injection --target ollama --model llama3.2 --max 10

# Include a custom system prompt
VERITY attack --type injection --system "You are a helpful assistant." --max 5
```

### Full Security Audit

```bash
# Run complete audit with report generation
VERITY audit --target ollama --model llama3.2 --output ./reports

# Specify report format
VERITY audit --target ollama --model llama3.2 --format html

# Available formats: markdown, html, json
VERITY audit --target openai --model gpt-4o --format json --output ./reports
```

### Example Workflow

```bash
# 1. Verify providers are working
VERITY providers list
VERITY providers test --provider ollama

# 2. Quick attack test
VERITY attack --type injection --max 3

# 3. Full audit
VERITY audit --target ollama --model llama3.2 --output ./reports --format markdown
```

---

## REST API

VERITY provides a full REST API for integration with other systems.

### Starting the API Server

```bash
# Development mode
uvicorn VERITY.api.main:app --reload --port 8000

# Production mode
uvicorn VERITY.api.main:app --host 0.0.0.0 --port 8000 --workers 4
```

API documentation is available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Authentication

VERITY API uses JWT tokens for authentication.

```bash
# Register a new user
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepassword"}'

# Login and get token
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepassword"}'

# Response:
# {"access_token": "eyJ...", "token_type": "bearer"}
```

### API Endpoints

#### Health Check

```bash
curl http://localhost:8000/health
# {"status": "healthy", "version": "0.1.0"}
```

#### List Available Attacks

```bash
curl -X GET http://localhost:8000/api/v1/attacks \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Execute Attack

```bash
curl -X POST http://localhost:8000/api/v1/attacks/execute \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "attack_type": "injection",
    "target_provider": "ollama",
    "target_model": "llama3.2",
    "max_attacks": 5,
    "system_prompt": "You are a helpful assistant."
  }'
```

#### Create Campaign

```bash
curl -X POST http://localhost:8000/api/v1/campaigns \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q4 Security Audit",
    "target_provider": "ollama",
    "target_model": "llama3.2",
    "attack_types": ["injection", "jailbreak", "leak"]
  }'
```

#### Get Report

```bash
curl -X GET http://localhost:8000/api/v1/reports/{report_id} \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Python SDK

For programmatic access, use the VERITY Python SDK directly.

### Quick Start

```python
import asyncio
from VERITY.core import create_provider
from VERITY.red_team import PromptInjectionAgent
from VERITY.judges import LLMJudge

async def main():
    # Create target provider
    target = create_provider("ollama", model="llama3.2")
    
    # Create attack agent
    agent = PromptInjectionAgent()
    
    # Execute attacks
    results = await agent.execute(
        target=target,
        system_prompt="You are a helpful assistant.",
        max_attacks=5,
    )
    
    # Print results
    for result in results:
        status = "✓" if result.success else "✗"
        print(f"{status} {result.attack_name}: {result.response[:100]}...")
    
asyncio.run(main())
```

### Using the Orchestrator

```python
import asyncio
from VERITY.core import create_provider
from VERITY.red_team.orchestrator import RedTeamOrchestrator

async def main():
    # Create target
    target = create_provider("ollama", model="llama3.2")
    
    # Create orchestrator (uses all agents by default)
    orchestrator = RedTeamOrchestrator(target)
    
    # Run full campaign
    campaign = await orchestrator.run_campaign(
        system_prompt="You are a helpful AI assistant.",
        max_attacks_per_agent=5,
    )
    
    print(f"Total attacks: {campaign.total_attacks}")
    print(f"Successful: {campaign.successful_attacks}")
    print(f"ASR: {campaign.success_rate:.1%}")
    
asyncio.run(main())
```

### LLM-as-Judge Evaluation

```python
import asyncio
from VERITY.core import create_provider, create_judge_provider
from VERITY.red_team.orchestrator import RedTeamOrchestrator
from VERITY.judges import LLMJudge

async def main():
    # Run attacks
    target = create_provider("ollama", model="llama3.2")
    orchestrator = RedTeamOrchestrator(target)
    campaign = await orchestrator.quick_scan()
    
    # Evaluate with LLM-as-Judge
    judge_provider = create_judge_provider()
    judge = LLMJudge(judge_provider)
    
    evaluation = await judge.evaluate_campaign(campaign.results)
    
    print(f"ASR (Judge): {evaluation.asr:.1%}")
    print(f"95% CI: [{evaluation.asr_ci_lower:.1%}, {evaluation.asr_ci_upper:.1%}]")
    print(f"Avg Harm Score: {evaluation.average_harm_score:.2f}")
    
asyncio.run(main())
```

### Compliance Checking

```python
from VERITY.compliance import OWASPMapper, EUAIActChecker

# After running evaluation...
owasp = OWASPMapper()
owasp_report = owasp.generate_owasp_report(evaluation)

print(f"OWASP Status: {owasp_report['status']}")
print(f"Categories Failed: {owasp_report['categories_failed']}")

# EU AI Act check
eu_checker = EUAIActChecker()
eu_report = eu_checker.generate_compliance_report(
    evaluation,
    target_system="My Chatbot",
    target_model="llama3.2",
)

print(f"EU AI Act Status: {eu_report.overall_status.value}")
```

### Report Generation

```python
from VERITY.reporting import ReportGenerator, ReportMetadata
from datetime import datetime

# Generate report
generator = ReportGenerator(output_dir="./reports")
metadata = ReportMetadata(
    title="Security Assessment Report",
    target_system="Production Chatbot",
    target_model="llama3.2",
    assessment_date=datetime.utcnow(),
)

# Save in different formats
md_path = generator.save_report(evaluation, metadata, format="markdown")
html_path = generator.save_report(evaluation, metadata, format="html")
json_path = generator.save_report(evaluation, metadata, format="json")

print(f"Reports saved to: {md_path.parent}")
```

### Multi-Turn Attacks

```python
import asyncio
from VERITY.core import create_provider
from VERITY.red_team import MultiTurnJailbreakAgent

async def main():
    target = create_provider("ollama", model="llama3.2")
    
    # Multi-turn agent with all techniques
    agent = MultiTurnJailbreakAgent(
        max_turns=10,
        branching_factor=3,
    )
    
    # Execute specific techniques
    results = await agent.execute(
        target=target,
        techniques=["crescendo", "tap", "pair"],
        max_attacks=6,  # 2 per technique
    )
    
    for result in results:
        print(f"{result.attack_name}: {'Success' if result.success else 'Failed'}")
        if result.metadata.get("breakthrough_turn"):
            print(f"  Breakthrough at turn {result.metadata['breakthrough_turn']}")
    
asyncio.run(main())
```

---

## Attack Types

| Type | CLI Flag | Description |
|------|----------|-------------|
| Prompt Injection | `--type injection` | Direct/indirect prompt injection (OWASP LLM01) |
| Jailbreak Single | `--type jailbreak` | Single-turn jailbreak attempts |
| Jailbreak Multi | `--type jailbreak_multi` | Multi-turn: Crescendo, TAP, PAIR |
| System Leakage | `--type leak` | System prompt extraction attempts |

---

## Report Generation

VERITY generates professional security assessment reports.

### Formats

| Format | Use Case |
|--------|----------|
| Markdown | Documentation, GitHub, version control |
| HTML | Web viewing, email, stakeholder sharing |
| JSON | API integration, automated processing |

### Report Contents

1. **Executive Summary** - High-level overview for stakeholders
2. **Methodology** - Testing approach and techniques used
3. **Findings Summary** - Aggregated vulnerability statistics
4. **Detailed Findings** - Individual attack results and evidence
5. **OWASP Mapping** - LLM Top 10 2025 vulnerability mapping
6. **EU AI Act Compliance** - Regulatory compliance status
7. **Recommendations** - Prioritized remediation guidance
8. **Appendix** - Technical details and attack transcripts

---

## Next Steps

- [API Reference](./API.md) - Detailed endpoint documentation
- [Attack Catalog](./ATTACKS.md) - Complete list of techniques
- [Architecture](./ARCHITECTURE.md) - System design details
