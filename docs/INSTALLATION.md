# Installation Guide

This guide covers the complete installation and configuration of VERITY.

## Prerequisites

### Required

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.12+ | Required for modern type hints |
| pip | Latest | Package manager |

### Optional (Recommended)

| Component | Purpose |
|-----------|---------|
| [Ollama](https://ollama.ai) | Local LLM testing (free, no API key) |
| [OpenAI API](https://openai.com) | LLM-as-Judge evaluation |
| [Anthropic API](https://anthropic.com) | Alternative provider |
| [Google AI](https://ai.google.dev) | Gemini models |

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/GiuseppeSPk/VERITY.git
cd VERITY
```

### 2. Create Virtual Environment

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install VERITY

```bash
# Standard installation
pip install -e .

# With development dependencies
pip install -e ".[dev]"

# With all optional dependencies
pip install -e ".[dev,sandbox,marl]"
```

### 4. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env
```

Edit `.env` with your configuration:

```bash
# .env file

# Ollama (Local LLM - Recommended for testing)
OLLAMA_BASE_URL=http://localhost:11434

# OpenAI (Recommended for LLM-as-Judge)
OPENAI_API_KEY=sk-your-key-here

# Anthropic (Optional)
ANTHROPIC_API_KEY=sk-ant-your-key-here

# Google (Optional)
GOOGLE_API_KEY=your-google-key-here

# Default Settings
DEFAULT_PROVIDER=ollama
DEFAULT_MODEL=llama3.2

# Judge Settings (OpenAI recommended for best results)
JUDGE_PROVIDER=openai
JUDGE_MODEL=gpt-4o-mini
```

## Provider Setup

### Ollama (Recommended for Local Testing)

1. Install Ollama from [ollama.ai](https://ollama.ai)

2. Pull a model:
   ```bash
   ollama pull llama3.2
   ollama pull llama3.2:1b  # Smaller, faster for testing
   ```

3. Verify Ollama is running:
   ```bash
   ollama list
   ```

### OpenAI

1. Get an API key from [platform.openai.com](https://platform.openai.com)
2. Add to `.env`:
   ```bash
   OPENAI_API_KEY=sk-your-key-here
   ```

### Anthropic

1. Get an API key from [console.anthropic.com](https://console.anthropic.com)
2. Add to `.env`:
   ```bash
   ANTHROPIC_API_KEY=sk-ant-your-key-here
   ```

### Google AI

1. Get an API key from [aistudio.google.com](https://aistudio.google.com)
2. Add to `.env`:
   ```bash
   GOOGLE_API_KEY=your-key-here
   ```

## Verify Installation

### Check CLI

```bash
# Show version
VERITY --version

# List providers
VERITY providers list

# Test provider connectivity
VERITY providers test --provider ollama
VERITY providers test --provider openai
```

### Check Python Import

```python
import VERITY
print(VERITY.__version__)

from VERITY.red_team import get_all_agents
agents = get_all_agents()
print(f"Loaded {len(agents)} attack agents")
```

### Run Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest --cov=VERITY --cov-report=html
```

## Troubleshooting

### Common Issues

#### "Module not found: VERITY"

Make sure you installed in editable mode:
```bash
pip install -e .
```

#### "Ollama connection refused"

1. Check if Ollama is running:
   ```bash
   ollama list
   ```

2. Check the base URL in `.env`:
   ```bash
   OLLAMA_BASE_URL=http://localhost:11434
   ```

#### "OpenAI API key invalid"

1. Verify your API key at [platform.openai.com](https://platform.openai.com)
2. Check the key format (should start with `sk-`)
3. Ensure no extra spaces in `.env`

#### "Python version not supported"

VERITY requires Python 3.12+. Check your version:
```bash
python --version
```

### Getting Help

If you encounter issues:

1. Check the [FAQ](./FAQ.md) (coming soon)
2. Search [GitHub Issues](https://github.com/GiuseppeSPk/VERITY/issues)
3. Open a new issue with:
   - Python version
   - Operating system
   - Full error traceback
   - Steps to reproduce

## Next Steps

- [Usage Guide](./USAGE.md) - Learn how to use VERITY
- [API Reference](./API.md) - REST API documentation
- [Attack Catalog](./ATTACKS.md) - Available attack techniques
