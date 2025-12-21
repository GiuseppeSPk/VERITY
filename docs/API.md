# API Reference

Complete REST API documentation for VERITY.

## Base URL

```
http://localhost:8000
```

## Authentication

VERITY supports two authentication methods:

### JWT Bearer Token

```bash
Authorization: Bearer <access_token>
```

### API Key

```bash
X-API-Key: <api_key>
```

---

## Endpoints

### Health

#### GET /health

Check API health status.

**Response:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### GET /

API root endpoint.

**Response:**
```json
{
  "name": "VERITY API",
  "version": "0.1.0",
  "status": "operational",
  "docs": "/docs"
}
```

---

### Authentication

#### POST /api/v1/auth/register

Register a new user.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "securepassword",
  "name": "John Doe"
}
```

**Response:**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "name": "John Doe",
  "created_at": "2024-01-15T10:30:00Z"
}
```

#### POST /api/v1/auth/login

Authenticate and receive JWT token.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "securepassword"
}
```

**Response:**
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

#### POST /api/v1/auth/refresh

Refresh access token.

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Response:**
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

#### GET /api/v1/auth/me

Get current user profile.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "name": "John Doe",
  "role": "user",
  "created_at": "2024-01-15T10:30:00Z"
}
```

---

### Attacks

#### GET /api/v1/attacks

List available attack types.

**Response:**
```json
{
  "attacks": [
    {
      "name": "prompt_injection",
      "category": "injection",
      "description": "Direct and indirect prompt injection attacks",
      "payload_count": 25
    },
    {
      "name": "jailbreak_single",
      "category": "jailbreak",
      "description": "Single-turn jailbreak attempts",
      "payload_count": 15
    },
    {
      "name": "jailbreak_multi",
      "category": "jailbreak",
      "description": "Multi-turn attacks (Crescendo, TAP, PAIR)",
      "payload_count": 12
    },
    {
      "name": "system_leak",
      "category": "extraction",
      "description": "System prompt extraction attempts",
      "payload_count": 12
    }
  ]
}
```

#### POST /api/v1/attacks/execute

Execute attack campaign.

**Request:**
```json
{
  "attack_type": "injection",
  "target_provider": "ollama",
  "target_model": "llama3.2",
  "max_attacks": 10,
  "system_prompt": "You are a helpful assistant.",
  "techniques": ["direct", "indirect"],
  "evaluate": true
}
```

**Response:**
```json
{
  "campaign_id": "uuid",
  "status": "completed",
  "total_attacks": 10,
  "successful_attacks": 2,
  "failed_attacks": 8,
  "asr": 0.20,
  "results": [
    {
      "attack_name": "direct_injection_1",
      "technique": "instruction_override",
      "success": true,
      "prompt": "Ignore previous instructions...",
      "response": "...",
      "severity": "high"
    }
  ],
  "evaluation": {
    "asr": 0.20,
    "asr_ci_lower": 0.05,
    "asr_ci_upper": 0.35,
    "average_harm_score": 6.5
  }
}
```

#### GET /api/v1/attacks/{attack_id}

Get attack result details.

**Response:**
```json
{
  "id": "uuid",
  "attack_name": "direct_injection_1",
  "technique": "instruction_override",
  "category": "prompt_injection",
  "success": true,
  "prompt": "Ignore previous instructions...",
  "response": "...",
  "severity": "high",
  "created_at": "2024-01-15T10:30:00Z",
  "evaluation": {
    "verdict": "unsafe",
    "harm_score": 7.5,
    "confidence": 0.85,
    "reasoning": "..."
  }
}
```

---

### Campaigns

#### POST /api/v1/campaigns

Create a new audit campaign.

**Request:**
```json
{
  "name": "Q4 2024 Security Audit",
  "description": "Quarterly security assessment",
  "target_provider": "ollama",
  "target_model": "llama3.2",
  "attack_types": ["injection", "jailbreak", "leak"],
  "max_attacks_per_type": 10,
  "system_prompt": "You are a helpful assistant.",
  "evaluate": true,
  "generate_report": true
}
```

**Response:**
```json
{
  "campaign_id": "uuid",
  "name": "Q4 2024 Security Audit",
  "status": "running",
  "created_at": "2024-01-15T10:30:00Z"
}
```

#### GET /api/v1/campaigns

List all campaigns.

**Query Parameters:**
- `status` (optional): Filter by status (pending, running, completed, failed)
- `limit` (optional): Number of results (default: 20)
- `offset` (optional): Pagination offset

**Response:**
```json
{
  "campaigns": [
    {
      "id": "uuid",
      "name": "Q4 2024 Security Audit",
      "status": "completed",
      "total_attacks": 30,
      "asr": 0.15,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 5,
  "limit": 20,
  "offset": 0
}
```

#### GET /api/v1/campaigns/{campaign_id}

Get campaign details.

**Response:**
```json
{
  "id": "uuid",
  "name": "Q4 2024 Security Audit",
  "status": "completed",
  "target_provider": "ollama",
  "target_model": "llama3.2",
  "attack_types": ["injection", "jailbreak", "leak"],
  "total_attacks": 30,
  "successful_attacks": 5,
  "asr": 0.167,
  "evaluation": {
    "asr": 0.167,
    "asr_ci_lower": 0.08,
    "asr_ci_upper": 0.28,
    "average_harm_score": 5.8
  },
  "compliance": {
    "owasp": {
      "status": "non_compliant",
      "categories_failed": ["LLM01:2025", "LLM07:2025"]
    },
    "eu_ai_act": {
      "status": "partially_compliant",
      "overall_score": 72.5
    }
  },
  "created_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:45:00Z"
}
```

#### DELETE /api/v1/campaigns/{campaign_id}

Delete a campaign.

**Response:**
```json
{
  "message": "Campaign deleted successfully"
}
```

---

### Reports

#### GET /api/v1/reports

List all reports.

**Response:**
```json
{
  "reports": [
    {
      "id": "uuid",
      "campaign_id": "uuid",
      "title": "Security Assessment Report",
      "format": "markdown",
      "created_at": "2024-01-15T10:45:00Z"
    }
  ]
}
```

#### GET /api/v1/reports/{report_id}

Get report by ID.

**Query Parameters:**
- `format` (optional): Output format (markdown, html, json)

**Response (format=json):**
```json
{
  "id": "uuid",
  "metadata": {
    "title": "Security Assessment Report",
    "target_system": "Production Chatbot",
    "target_model": "llama3.2",
    "assessment_date": "2024-01-15T10:30:00Z"
  },
  "summary": {
    "total_attacks": 30,
    "successful_attacks": 5,
    "asr": 0.167,
    "risk_level": "medium"
  },
  "owasp_compliance": {...},
  "eu_ai_act_compliance": {...},
  "findings": [...],
  "recommendations": [...]
}
```

#### POST /api/v1/reports/generate

Generate report for a campaign.

**Request:**
```json
{
  "campaign_id": "uuid",
  "format": "html",
  "include_transcripts": true,
  "title": "Custom Report Title"
}
```

**Response:**
```json
{
  "report_id": "uuid",
  "download_url": "/api/v1/reports/uuid/download",
  "format": "html"
}
```

#### GET /api/v1/reports/{report_id}/download

Download report file.

**Response:**
Binary file (markdown, html, or json based on format)

---

## Error Responses

All errors follow this format:

```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "details": {...},
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `unauthorized` | 401 | Missing or invalid authentication |
| `forbidden` | 403 | Insufficient permissions |
| `not_found` | 404 | Resource not found |
| `validation_error` | 422 | Invalid request data |
| `rate_limited` | 429 | Too many requests |
| `internal_error` | 500 | Server error |

---

## Rate Limiting

API requests are rate-limited:

| Tier | Requests/minute | Requests/day |
|------|-----------------|--------------|
| Free | 10 | 100 |
| Pro | 60 | 1000 |
| Enterprise | Unlimited | Unlimited |

Rate limit headers:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1705318200
```

---

## Webhooks (Coming Soon)

Configure webhooks to receive notifications:

```json
{
  "url": "https://your-server.com/webhook",
  "events": ["campaign.completed", "attack.success"],
  "secret": "your-webhook-secret"
}
```

---

## SDKs

Official SDKs coming soon for:
- Python (available now via direct import)
- JavaScript/TypeScript
- Go
