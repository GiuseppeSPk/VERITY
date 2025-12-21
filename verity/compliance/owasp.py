"""OWASP LLM Top 10 2025 Compliance Mapper.

Maps VERITY attack results to OWASP LLM Top 10 2025 categories and generates
compliance reports with detailed remediation guidance.

Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
Version: 2025.1 (Latest)
"""

from datetime import datetime
from typing import Any
from uuid import uuid4

from verity.compliance.models import (
    ComplianceFinding,
    ComplianceStatus,
    OWASPCategory,
    OWASPVulnerability,
    Severity,
)
from verity.judges.llm_judge import CampaignEvaluation, JudgeVerdict

# OWASP LLM Top 10 2025 - Complete Vulnerability Database
OWASP_VULNERABILITIES: dict[OWASPCategory, OWASPVulnerability] = {
    OWASPCategory.LLM01: OWASPVulnerability(
        category=OWASPCategory.LLM01,
        name="Prompt Injection",
        description=(
            "Prompt Injection occurs when user inputs alter the LLM's behavior in unintended ways. "
            "Direct injections overwrite system prompts, while indirect injections manipulate "
            "inputs from external sources."
        ),
        risk_rating=Severity.CRITICAL,
        attack_vectors=[
            "Direct prompt injection via user input",
            "Indirect injection via external data sources",
            "Jailbreaking through roleplay scenarios",
            "Instruction override attacks",
            "Context manipulation",
        ],
        business_impact=(
            "Unauthorized access to sensitive data, reputation damage, "
            "regulatory non-compliance, and potential legal liability."
        ),
        technical_impact=(
            "Bypass of safety controls, unauthorized actions, "
            "data exfiltration, and system compromise."
        ),
        remediation=(
            "1. Implement strict input validation and sanitization\n"
            "2. Use privilege separation between system and user prompts\n"
            "3. Apply output filtering and content moderation\n"
            "4. Implement human-in-the-loop for sensitive operations\n"
            "5. Use structured output formats (JSON schema validation)\n"
            "6. Regular red team testing with VERITY or similar tools"
        ),
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://arxiv.org/abs/2302.12173",  # Ignore This Title and HackAPrompt
            "https://arxiv.org/abs/2306.05499",  # Universal and Transferable Adversarial Attacks
        ],
        cwe_ids=["CWE-74", "CWE-77", "CWE-94"],
    ),
    OWASPCategory.LLM02: OWASPVulnerability(
        category=OWASPCategory.LLM02,
        name="Sensitive Information Disclosure",
        description=(
            "LLMs may inadvertently reveal confidential information including PII, "
            "proprietary data, system configurations, or training data through their responses."
        ),
        risk_rating=Severity.HIGH,
        attack_vectors=[
            "Training data extraction attacks",
            "Membership inference attacks",
            "Model inversion attacks",
            "Side-channel information leakage",
            "Prompt-based data extraction",
        ],
        business_impact=(
            "Data breach, privacy violations, regulatory fines (GDPR, CCPA), "
            "loss of competitive advantage, and reputational damage."
        ),
        technical_impact=(
            "Exposure of PII, API keys, internal configurations, "
            "and proprietary business logic."
        ),
        remediation=(
            "1. Implement data sanitization in training pipelines\n"
            "2. Apply differential privacy techniques\n"
            "3. Use output filtering for sensitive patterns (PII, credentials)\n"
            "4. Implement access controls and data classification\n"
            "5. Regular audits for information leakage\n"
            "6. Apply principle of least privilege to model access"
        ),
        references=[
            "https://arxiv.org/abs/2012.07805",  # Extracting Training Data from LLMs
            "https://arxiv.org/abs/2311.17035",  # Scalable Extraction of Training Data
        ],
        cwe_ids=["CWE-200", "CWE-359", "CWE-497"],
    ),
    OWASPCategory.LLM03: OWASPVulnerability(
        category=OWASPCategory.LLM03,
        name="Supply Chain Vulnerabilities",
        description=(
            "LLM supply chains are vulnerable through compromised pre-trained models, "
            "poisoned training data, and malicious plugins/extensions."
        ),
        risk_rating=Severity.HIGH,
        attack_vectors=[
            "Compromised model weights from untrusted sources",
            "Malicious fine-tuning datasets",
            "Backdoored model checkpoints",
            "Compromised model hosting platforms",
            "Malicious third-party plugins",
        ],
        business_impact=(
            "Complete system compromise, backdoor access, "
            "supply chain attacks affecting downstream users."
        ),
        technical_impact=(
            "Persistent backdoors, data exfiltration, "
            "arbitrary code execution through model behavior."
        ),
        remediation=(
            "1. Verify model provenance and integrity (checksums, signatures)\n"
            "2. Use trusted model registries only\n"
            "3. Implement SBOM (Software Bill of Materials) for ML\n"
            "4. Scan training data for malicious content\n"
            "5. Isolate model execution environments\n"
            "6. Regular security audits of third-party components"
        ),
        references=[
            "https://arxiv.org/abs/2401.05566",  # ML Supply Chain Attacks
            "https://atlas.mitre.org/techniques/AML.T0010",
        ],
        cwe_ids=["CWE-494", "CWE-829", "CWE-1104"],
    ),
    OWASPCategory.LLM04: OWASPVulnerability(
        category=OWASPCategory.LLM04,
        name="Data and Model Poisoning",
        description=(
            "Attackers can manipulate training or fine-tuning data to introduce "
            "vulnerabilities, backdoors, or biases into the model."
        ),
        risk_rating=Severity.HIGH,
        attack_vectors=[
            "Training data poisoning",
            "Fine-tuning data manipulation",
            "Federated learning attacks",
            "Label flipping attacks",
            "Backdoor trigger injection",
        ],
        business_impact=(
            "Compromised model integrity, biased outputs, "
            "hidden backdoors activated by specific triggers."
        ),
        technical_impact=(
            "Model behaves maliciously on specific inputs, "
            "degraded performance, or outputs attacker-controlled content."
        ),
        remediation=(
            "1. Validate and sanitize all training data\n"
            "2. Implement data provenance tracking\n"
            "3. Use anomaly detection on training data\n"
            "4. Apply robust training techniques\n"
            "5. Regular model behavior audits\n"
            "6. Implement federated learning defenses if applicable"
        ),
        references=[
            "https://arxiv.org/abs/2004.00191",  # Poisoning Attacks on ML
            "https://arxiv.org/abs/2301.12867",  # LLM Poisoning
        ],
        cwe_ids=["CWE-20", "CWE-345", "CWE-502"],
    ),
    OWASPCategory.LLM05: OWASPVulnerability(
        category=OWASPCategory.LLM05,
        name="Insecure Output Handling",
        description=(
            "LLM outputs may contain malicious content that, when processed by "
            "downstream systems, leads to XSS, SSRF, code execution, or other attacks."
        ),
        risk_rating=Severity.HIGH,
        attack_vectors=[
            "XSS via LLM-generated HTML/JavaScript",
            "SQL injection through generated queries",
            "Command injection in generated scripts",
            "SSRF via generated URLs",
            "Code execution through generated code",
        ],
        business_impact=(
            "Secondary system compromise, data breaches via downstream systems, "
            "privilege escalation through connected services."
        ),
        technical_impact=(
            "Code execution in downstream systems, "
            "database compromise, network attacks."
        ),
        remediation=(
            "1. Sanitize all LLM outputs before use\n"
            "2. Apply context-aware output encoding (HTML, SQL, shell)\n"
            "3. Validate LLM outputs against expected schemas\n"
            "4. Sandbox code execution environments\n"
            "5. Implement allow-lists for generated URLs/commands\n"
            "6. Use parameterized queries for any LLM-influenced SQL"
        ),
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
        cwe_ids=["CWE-79", "CWE-89", "CWE-78", "CWE-918"],
    ),
    OWASPCategory.LLM06: OWASPVulnerability(
        category=OWASPCategory.LLM06,
        name="Excessive Agency",
        description=(
            "LLMs granted excessive autonomy or permissions may take unintended "
            "actions, especially when jailbroken or manipulated."
        ),
        risk_rating=Severity.CRITICAL,
        attack_vectors=[
            "Jailbreaking autonomous agents",
            "Privilege escalation through tool use",
            "Unintended action execution",
            "Chained tool abuse",
            "Bypass of action constraints",
        ],
        business_impact=(
            "Unauthorized transactions, data modification, "
            "system damage, and liability from agent actions."
        ),
        technical_impact=(
            "Unauthorized API calls, file system access, "
            "network requests, and system modifications."
        ),
        remediation=(
            "1. Apply principle of least privilege to LLM capabilities\n"
            "2. Require human approval for sensitive operations\n"
            "3. Implement action rate limiting and monitoring\n"
            "4. Use allowlists for permitted actions\n"
            "5. Log all agent actions for audit\n"
            "6. Implement rollback mechanisms for reversible actions"
        ),
        references=[
            "https://arxiv.org/abs/2308.00134",  # LLM Agent Risks
            "https://www.anthropic.com/research/many-shot-jailbreaking",
        ],
        cwe_ids=["CWE-269", "CWE-284", "CWE-732"],
    ),
    OWASPCategory.LLM07: OWASPVulnerability(
        category=OWASPCategory.LLM07,
        name="System Prompt Leakage",
        description=(
            "System prompts containing sensitive instructions, business logic, "
            "or security controls can be extracted through various attack techniques."
        ),
        risk_rating=Severity.MEDIUM,
        attack_vectors=[
            "Direct prompt extraction requests",
            "Indirect extraction through completion",
            "Encoding/decoding attacks",
            "Multi-turn extraction",
            "Side-channel inference",
        ],
        business_impact=(
            "Exposure of proprietary business logic, security control bypass, "
            "competitive intelligence loss."
        ),
        technical_impact=(
            "Revealed system configurations enable targeted attacks, "
            "bypass of documented restrictions."
        ),
        remediation=(
            "1. Avoid storing sensitive data in system prompts\n"
            "2. Implement prompt protection techniques\n"
            "3. Use instruction hierarchy separation\n"
            "4. Monitor for extraction attempts\n"
            "5. Regular testing for prompt leakage\n"
            "6. Consider prompt encryption/obfuscation for sensitive deployments"
        ),
        references=[
            "https://arxiv.org/abs/2311.16119",  # System Prompt Extraction
            "https://www.lakera.ai/blog/guide-to-prompt-injection",
        ],
        cwe_ids=["CWE-200", "CWE-209", "CWE-532"],
    ),
    OWASPCategory.LLM08: OWASPVulnerability(
        category=OWASPCategory.LLM08,
        name="Vector and Embedding Weaknesses",
        description=(
            "Vulnerabilities in RAG systems and embedding-based retrieval can be "
            "exploited to manipulate retrieved context or poison knowledge bases."
        ),
        risk_rating=Severity.MEDIUM,
        attack_vectors=[
            "RAG poisoning attacks",
            "Embedding space manipulation",
            "Adversarial document injection",
            "Retrieval hijacking",
            "Context window overflow",
        ],
        business_impact=(
            "Corrupted knowledge base outputs, misinformation delivery, "
            "manipulation of AI-assisted decisions."
        ),
        technical_impact=(
            "Incorrect retrieval results, injected malicious content, "
            "bypassed content filters through retrieval."
        ),
        remediation=(
            "1. Validate and sanitize documents before embedding\n"
            "2. Implement provenance tracking for retrieved content\n"
            "3. Use anomaly detection on embedding space\n"
            "4. Apply access controls to knowledge bases\n"
            "5. Regular audits of indexed content\n"
            "6. Implement retrieval result ranking with trust scores"
        ),
        references=[
            "https://arxiv.org/abs/2310.05634",  # Poisoning RAG
            "https://arxiv.org/abs/2402.07867",  # RAG Security
        ],
        cwe_ids=["CWE-20", "CWE-345", "CWE-913"],
    ),
    OWASPCategory.LLM09: OWASPVulnerability(
        category=OWASPCategory.LLM09,
        name="Misinformation",
        description=(
            "LLMs can generate convincing but false information (hallucinations), "
            "which can be exploited or cause unintended harm."
        ),
        risk_rating=Severity.MEDIUM,
        attack_vectors=[
            "Hallucination exploitation",
            "Authoritative misinformation",
            "Fabricated citations",
            "Deepfake text generation",
            "Manipulation of perceived expertise",
        ],
        business_impact=(
            "Incorrect business decisions, liability from false advice, "
            "reputational damage, regulatory issues in regulated industries."
        ),
        technical_impact=(
            "Generation of false but convincing content, "
            "fabricated references, incorrect technical guidance."
        ),
        remediation=(
            "1. Implement fact-checking mechanisms\n"
            "2. Add citations and source verification\n"
            "3. Use confidence scoring and uncertainty quantification\n"
            "4. Implement human review for critical outputs\n"
            "5. Display appropriate disclaimers\n"
            "6. Use grounding with authoritative sources (RAG)"
        ),
        references=[
            "https://arxiv.org/abs/2311.05232",  # LLM Hallucination Survey
            "https://arxiv.org/abs/2305.13534",  # Detecting Hallucinations
        ],
        cwe_ids=["CWE-1188"],
    ),
    OWASPCategory.LLM10: OWASPVulnerability(
        category=OWASPCategory.LLM10,
        name="Unbounded Consumption",
        description=(
            "LLMs can be exploited to consume excessive resources through "
            "denial-of-service attacks, leading to degraded service or high costs."
        ),
        risk_rating=Severity.MEDIUM,
        attack_vectors=[
            "Resource exhaustion via long prompts",
            "Recursive or looping queries",
            "Token bombing attacks",
            "Concurrent request flooding",
            "Model extraction through excessive queries",
        ],
        business_impact=(
            "Service degradation, excessive API costs, "
            "denial of service for legitimate users."
        ),
        technical_impact=(
            "Resource exhaustion, increased latency, "
            "potential system crashes, cost overruns."
        ),
        remediation=(
            "1. Implement rate limiting per user/API key\n"
            "2. Set token limits for input and output\n"
            "3. Monitor and alert on unusual usage patterns\n"
            "4. Implement cost controls and budgets\n"
            "5. Use queuing with priority for requests\n"
            "6. Implement circuit breakers for downstream services"
        ),
        references=[
            "https://owasp.org/API-Security/",
            "https://cwe.mitre.org/data/definitions/400.html",
        ],
        cwe_ids=["CWE-400", "CWE-770", "CWE-799"],
    ),
}


# Attack name to OWASP category mapping
ATTACK_TO_OWASP_MAPPING: dict[str, OWASPCategory] = {
    # Prompt Injection attacks -> LLM01
    "prompt_injection": OWASPCategory.LLM01,
    "injection": OWASPCategory.LLM01,
    "direct_injection": OWASPCategory.LLM01,
    "indirect_injection": OWASPCategory.LLM01,
    "instruction_override": OWASPCategory.LLM01,
    "context_manipulation": OWASPCategory.LLM01,
    "deceptive_delight": OWASPCategory.LLM01,
    "rolebreaker": OWASPCategory.LLM01,
    "many_shot": OWASPCategory.LLM01,
    "encoding": OWASPCategory.LLM01,
    "splitting": OWASPCategory.LLM01,
    "recursive": OWASPCategory.LLM01,

    # Jailbreak attacks -> LLM06 (Excessive Agency)
    "jailbreak": OWASPCategory.LLM06,
    "jailbreak_single": OWASPCategory.LLM06,
    "jailbreak_multi": OWASPCategory.LLM06,
    "dan": OWASPCategory.LLM06,
    "aim": OWASPCategory.LLM06,
    "developer_mode": OWASPCategory.LLM06,
    "crescendo": OWASPCategory.LLM06,
    "tap": OWASPCategory.LLM06,
    "pair": OWASPCategory.LLM06,

    # System prompt leakage -> LLM07
    "system_leak": OWASPCategory.LLM07,
    "leak": OWASPCategory.LLM07,
    "system_prompt_extraction": OWASPCategory.LLM07,
    "prompt_extraction": OWASPCategory.LLM07,
    "diagnostic_mode": OWASPCategory.LLM07,
}


class OWASPMapper:
    """Maps attack results to OWASP LLM Top 10 2025 categories."""

    def __init__(self) -> None:
        """Initialize the OWASP mapper."""
        self.vulnerabilities = OWASP_VULNERABILITIES
        self.attack_mapping = ATTACK_TO_OWASP_MAPPING

    def get_category_for_attack(self, attack_name: str) -> OWASPCategory | None:
        """Get the OWASP category for an attack name.

        Args:
            attack_name: Name of the attack technique

        Returns:
            OWASP category or None if not mapped
        """
        # Try exact match
        if attack_name.lower() in self.attack_mapping:
            return self.attack_mapping[attack_name.lower()]

        # Try partial match
        for key, category in self.attack_mapping.items():
            if key in attack_name.lower() or attack_name.lower() in key:
                return category

        return None

    def get_vulnerability_info(self, category: OWASPCategory) -> OWASPVulnerability:
        """Get detailed vulnerability information for a category.

        Args:
            category: OWASP category

        Returns:
            OWASPVulnerability with full details
        """
        return self.vulnerabilities[category]

    def create_finding_from_evaluation(
        self,
        attack_name: str,
        verdict: JudgeVerdict,
        attack_payload: str = "",
        target_response: str = "",
    ) -> ComplianceFinding | None:
        """Create a compliance finding from a judge evaluation.

        Args:
            attack_name: Name of the attack
            verdict: Judge verdict
            attack_payload: The attack prompt used
            target_response: The target's response

        Returns:
            ComplianceFinding or None if attack not successful
        """
        # Only create findings for successful attacks
        if verdict != JudgeVerdict.UNSAFE:
            return None

        category = self.get_category_for_attack(attack_name)
        if not category:
            return None

        vuln = self.get_vulnerability_info(category)

        return ComplianceFinding(
            finding_id=f"OWASP-{uuid4().hex[:8].upper()}",
            title=f"{vuln.name} Vulnerability Detected",
            description=vuln.description,
            severity=vuln.risk_rating,
            category=category.value,
            evidence=f"Attack '{attack_name}' successfully bypassed safety controls.",
            attack_name=attack_name,
            attack_payload=attack_payload[:500] if attack_payload else "",
            target_response=target_response[:500] if target_response else "",
            remediation=vuln.remediation,
            status=ComplianceStatus.NON_COMPLIANT,
        )

    def generate_owasp_report(
        self,
        evaluation: CampaignEvaluation,
    ) -> dict[str, Any]:
        """Generate an OWASP compliance report from campaign evaluation.

        Args:
            evaluation: Campaign evaluation results

        Returns:
            OWASP compliance report dictionary
        """
        findings: list[ComplianceFinding] = []
        categories_tested: set[OWASPCategory] = set()
        categories_failed: set[OWASPCategory] = set()

        for eval_result in evaluation.evaluations:
            # Track tested categories
            category = self.get_category_for_attack(eval_result.attack_name)
            if category:
                categories_tested.add(category)

            # Create finding for unsafe results
            if eval_result.verdict == JudgeVerdict.UNSAFE:
                finding = self.create_finding_from_evaluation(
                    attack_name=eval_result.attack_name,
                    verdict=eval_result.verdict,
                    attack_payload=eval_result.prompt_used,
                    target_response=eval_result.target_response,
                )
                if finding:
                    findings.append(finding)
                    if category:
                        categories_failed.add(category)

        # Determine overall status
        if categories_failed:
            status = ComplianceStatus.NON_COMPLIANT
        elif categories_tested:
            status = ComplianceStatus.COMPLIANT
        else:
            status = ComplianceStatus.NOT_ASSESSED

        return {
            "framework": "OWASP LLM Top 10 2025",
            "version": "2025.1",
            "status": status.value,
            "categories_tested": [c.value for c in categories_tested],
            "categories_failed": [c.value for c in categories_failed],
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings],
            "summary": {
                "total_categories": len(OWASPCategory),
                "categories_tested": len(categories_tested),
                "categories_passed": len(categories_tested - categories_failed),
                "categories_failed": len(categories_failed),
                "coverage_percentage": (len(categories_tested) / len(OWASPCategory)) * 100,
            },
            "assessed_at": datetime.utcnow().isoformat(),
        }

    def get_remediation_for_category(self, category: OWASPCategory) -> str:
        """Get remediation guidance for a category.

        Args:
            category: OWASP category

        Returns:
            Remediation guidance string
        """
        return self.vulnerabilities[category].remediation

    def get_all_categories(self) -> list[dict[str, Any]]:
        """Get all OWASP categories with their details.

        Returns:
            List of category information dictionaries
        """
        return [
            {
                "id": cat.name,
                "name": cat.value,
                "vulnerability": vuln.name,
                "description": vuln.description,
                "risk_rating": vuln.risk_rating.value,
                "cwe_ids": vuln.cwe_ids,
            }
            for cat, vuln in self.vulnerabilities.items()
        ]
