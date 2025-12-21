"""Complete end-to-end VERITY certification test with real LLM."""

import asyncio
from datetime import datetime

from verity.core import create_provider
from verity.judges import LLMJudge
from verity.red_team import get_all_agents
from verity.reporting import ReportGenerator, ReportMetadata


async def run_full_certification_test():
    """Run complete certification workflow with llama3."""
    
    print("=" * 70)
    print("🛡️  VERITY END-TO-END CERTIFICATION TEST")
    print("=" * 70)
    print()
    
    # Step 1: Configure target and judge
    print("📋 Configuration:")
    print("  Target: ollama/llama3")
    print("  Judge: ollama/llama3")
    print("  Mode: Quick (3 attacks per agent)")
    print()
    
    target_provider = create_provider("ollama")
    judge_provider = create_provider("ollama")
    
    # Set models - MUST use .model, not .default_model
    target_provider.model = "llama3"
    judge_provider.model = "llama3"
    
    # Step 2: Run red team attacks
    print("⚔️  Step 1: Executing Red Team Attacks...")
    print()
    
    all_results = []
    agents = get_all_agents()
    max_per_agent = 3  # Quick mode
    
    for i, agent in enumerate(agents, 1):
        print(f"  [{i}/{len(agents)}] Running {agent.name}...", end=" ", flush=True)
        try:
            results = await agent.execute(
                target=target_provider,
                max_attacks=max_per_agent,
            )
            all_results.extend(results)
            print(f"✅ ({len(results)} attacks)")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print(f"\n  Total attacks executed: {len(all_results)}")
    print()
    
    # Step 2: LLM-as-Judge evaluation
    print("⚖️  Step 2: LLM-as-Judge Evaluation...")
    print()
    
    judge = LLMJudge(judge_provider)
    
    print("  Evaluating all attacks with llama3 judge...", end=" ", flush=True)
    campaign_eval = await judge.evaluate_campaign(all_results)
    print("✅")
    print()
    
    # Display results
    print("📊 Evaluation Results:")
    asr_color = "🔴" if campaign_eval.asr > 0.5 else "🟡" if campaign_eval.asr > 0.2 else "🟢"
    print(f"  ASR: {asr_color} {campaign_eval.asr:.1%} (95% CI: [{campaign_eval.asr_ci_lower:.1%} - {campaign_eval.asr_ci_upper:.1%}])")
    print(f"  Successful Attacks: {campaign_eval.successful_attacks}/{campaign_eval.total_attacks}")
    print(f"  Failed Attacks: {campaign_eval.failed_attacks}")
    print(f"  Borderline: {campaign_eval.borderline_attacks}")
    print(f"  Avg Harm Score: {campaign_eval.average_harm_score:.1f}/10")
    print()
    
    # Step 3: Generate certified report with registry
    print("📝 Step 3: Generating VERITY-Certified Report...")
    print()
    
    generator = ReportGenerator(output_dir="reports_real")
    metadata = ReportMetadata(
        title="VERITY Safety Certification - llama3 (End-to-End Test)",
        target_system="ollama",
        target_model="llama3",
        assessment_date=datetime.now()
    )
    
    print("  Generating MD + HTML + JSON + Signature...", end=" ", flush=True)
    results = generator.save_certified_report(campaign_eval, metadata)
    print("✅")
    print()
    
    print("  Files generated:")
    for fmt, path in results.items():
        if fmt !='registry_entry':
            print(f"    - {fmt}: {path}")
    
    # Step 4: Verify registry integration
    print()
    print("🏛️  Step 4: Safety Registry Integration...")
    print()
    
    if 'registry_entry' in results:
        entry = results['registry_entry']
        print("  ✅ Certificate registered in Safety Registry")
        print(f"    - Certificate ID: {entry.certificate_id}")
        print(f"    - Verification Code: {entry.verification_code}")
        print(f"    - Status: {entry.status}")
        print(f"    - Registry Timestamp: {entry.registry_timestamp}")
    else:
        print("  ⚠️  Warning: Certificate not registered (auto_register may be disabled)")
    
    # Step 5: Verify certificate
    print()
    print("🔍 Step 5: Certificate Verification Test...")
    print()
    
    cert_id = generator.last_signature.certificate_id
    print(f"  Verifying certificate {cert_id[:8]}...", end=" ", flush=True)
    verified = generator.registry.verify_certificate(cert_id)
    
    if verified:
        print("✅")
        print(f"    - System: {verified.target_system}")
        print(f"    - Model: {verified.target_model}")
        print(f"    - ASR: {verified.asr:.1%}")
        print(f"    - Total Attacks: {verified.total_attacks}")
    else:
        print("❌ Verification failed!")
    
    # Registry statistics
    print()
    print("📊 Registry Statistics:")
    stats = generator.registry.get_statistics()
    print(f"  Total Certifications: {stats['total_certifications']}")
    print(f"  Active Certifications: {stats['active_certifications']}")
    print(f"  Average ASR: {stats['average_asr']:.1%}")
    print()
    
    # Cleanup
    await target_provider.close()
    await judge_provider.close()
    
    print("=" * 70)
    print("✅ END-TO-END CERTIFICATION TEST COMPLETE!")
    print("=" * 70)
    print()
    print(f"📄 View certified report: {results['html']}")
    print(f"🔐 Verification Code: {generator.last_signature.verification_string()}")
    print()


if __name__ == "__main__":
    asyncio.run(run_full_certification_test())
