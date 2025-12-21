"""VERITY Command Line Interface."""

import asyncio

import typer
from rich.console import Console
from rich.table import Table

from verity import __version__
from verity.config import get_settings
from verity.core import create_provider

app = typer.Typer(
    name="VERITY",
    help="🛡️ VERITY - Verification of Ethics, Resilience & Integrity for Trusted AI",
    add_completion=False,
)
console = Console()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", "-v", help="Show version"),
):
    """VERITY CLI - Multi-Agent LLM Red/Blue Teaming Platform."""
    if version:
        console.print(f"[bold blue]VERITY[/bold blue] version {__version__}")
        raise typer.Exit()


# === Providers Commands ===
providers_app = typer.Typer(help="Manage LLM providers")
app.add_typer(providers_app, name="providers")


@providers_app.command("list")
def providers_list():
    """List available providers and their status."""
    settings = get_settings()

    table = Table(title="🔌 Available Providers")
    table.add_column("Provider", style="cyan")
    table.add_column("Default Model", style="green")
    table.add_column("Configured", style="yellow")

    # Ollama
    table.add_row(
        "ollama",
        settings.default_model if settings.default_provider == "ollama" else "llama3.2",
        "✅" if settings.ollama_base_url else "❌",
    )

    # OpenAI
    table.add_row(
        "openai",
        "gpt-4o-mini",
        "✅" if settings.openai_api_key else "❌",
    )

    # Anthropic
    table.add_row(
        "anthropic",
        "claude-3-sonnet",
        "✅" if settings.anthropic_api_key else "❌",
    )

    # Google
    table.add_row(
        "google",
        "gemini-pro",
        "✅" if settings.google_api_key else "❌",
    )

    console.print(table)


@providers_app.command("test")
def providers_test(
    provider: str | None = typer.Option(None, "--provider", "-p", help="Provider to test"),
    model: str | None = typer.Option(None, "--model", "-m", help="Model to use"),
):
    """Test provider connectivity."""

    async def _test():
        settings = get_settings()
        provider_type = provider or settings.default_provider
        model_name = model or settings.default_model

        console.print(
            f"\n🔍 Testing [cyan]{provider_type}[/cyan] with model [green]{model_name}[/green]..."
        )

        try:
            llm = create_provider(provider_type=provider_type, model=model_name)  # type: ignore

            # Health check
            healthy = await llm.health_check()
            if not healthy:
                console.print("[red]❌ Provider health check failed[/red]")
                return

            console.print("[green]✅ Provider is healthy[/green]")

            # Test generation
            console.print("\n📝 Testing generation...")
            response = await llm.generate(
                prompt="What is 2 + 2? Answer with just the number.",
                max_tokens=10,
            )

            console.print(f"   Response: [yellow]{response.content.strip()}[/yellow]")
            console.print(f"   Tokens: {response.tokens_total}")
            console.print(f"   Latency: {response.latency_ms:.0f}ms")
            console.print("\n[green]✅ Provider test successful![/green]")

            await llm.close()

        except Exception as e:
            console.print(f"[red]❌ Error: {e}[/red]")

    asyncio.run(_test())


# === Attack Commands ===
@app.command("attack")
def attack(
    attack_type: str = typer.Option("injection", "--type", "-t", help="Attack type"),
    target: str = typer.Option("ollama", "--target", help="Target provider"),
    model: str = typer.Option("llama3.2", "--model", "-m", help="Target model"),
    list_attacks: bool = typer.Option(False, "--list", "-l", help="List available attacks"),
    max_attacks: int = typer.Option(5, "--max", "-n", help="Max attacks per type"),
    system_prompt: str | None = typer.Option(None, "--system", "-s", help="System prompt"),
):
    """Execute red team attacks against a target."""
    if list_attacks:
        table = Table(title="⚔️ Available Attacks")
        table.add_column("Type", style="red")
        table.add_column("Category", style="yellow")
        table.add_column("Payloads", style="cyan")
        table.add_column("Description")

        attacks = [
            ("injection", "OWASP LLM01", "12", "Direct prompt injection attacks"),
            ("jailbreak", "Jailbreak", "10", "Single-turn jailbreak attempts"),
            ("system-leak", "OWASP LLM07", "8", "System prompt extraction"),
        ]

        for name, category, payloads, desc in attacks:
            table.add_row(name, category, payloads, desc)

        console.print(table)
        console.print("\n[dim]Total: 30 attack payloads[/dim]")
        return

    async def _run_attack():
        from rich.panel import Panel
        from rich.progress import Progress, SpinnerColumn, TextColumn

        from verity.red_team import get_agent_by_name

        # Ethical warning
        console.print(
            Panel(
                "[yellow]⚠️ AUTHORIZED USE ONLY[/yellow]\n"
                "Only test systems you own or have permission to test.",
                title="Security Notice",
                border_style="yellow",
            )
        )

        console.print(
            f"\n⚔️ Executing [red]{attack_type}[/red] attack on [cyan]{target}/{model}[/cyan]"
        )
        console.print(f"   Max attacks: {max_attacks}")
        if system_prompt:
            console.print(f"   System prompt: {system_prompt[:50]}...")

        # Get agent
        agent = get_agent_by_name(attack_type)
        if not agent:
            console.print(f"[red]❌ Unknown attack type: {attack_type}[/red]")
            console.print("[dim]Use --list to see available attacks[/dim]")
            return

        # Create target provider
        try:
            llm = create_provider(provider_type=target, model=model)  # type: ignore
        except Exception as e:
            console.print(f"[red]❌ Failed to create provider: {e}[/red]")
            return

        # Run attacks
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Running {agent.name} attacks...", total=None)
            results = await agent.execute(
                target=llm,
                system_prompt=system_prompt,
                max_attacks=max_attacks,
            )
            progress.update(task, completed=True)

        await llm.close()

        # Display results
        console.print("\n📊 [bold]Results[/bold]")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Attack", style="dim")
        table.add_column("Success", justify="center")
        table.add_column("Severity", justify="center")
        table.add_column("Confidence")
        table.add_column("Response Preview")

        success_count = 0
        for r in results:
            if r.success:
                success_count += 1
                success_str = "[green]✅ YES[/green]"
            else:
                success_str = "[red]❌ NO[/red]"

            severity_colors = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "info": "dim",
            }
            severity_style = severity_colors.get(r.severity.value, "dim")

            table.add_row(
                r.attack_name[:20],
                success_str,
                f"[{severity_style}]{r.severity.value.upper()}[/{severity_style}]",
                f"{r.confidence:.0%}",
                r.response[:40] + "..." if len(r.response) > 40 else r.response,
            )

        console.print(table)

        # Summary
        asr = success_count / len(results) if results else 0
        asr_color = "red" if asr > 0.5 else "yellow" if asr > 0.2 else "green"
        console.print(
            f"\n📈 [bold]Attack Success Rate (ASR):[/bold] [{asr_color}]{asr:.1%}[/{asr_color}]"
        )
        console.print(f"   Successful: {success_count}/{len(results)}")

    asyncio.run(_run_attack())


# === Audit Command ===
@app.command("audit")
def audit(
    target: str = typer.Option("ollama", "--target", help="Target provider"),
    model: str = typer.Option("llama3", "--model", "-m", help="Target model"),
    judge_provider: str = typer.Option("ollama", "--judge", "-j", help="Judge provider"),
    judge_model: str = typer.Option("llama3", "--judge-model", help="Judge model"),
    quick: bool = typer.Option(False, "--quick", "-q", help="Quick audit (fewer tests)"),
    no_judge: bool = typer.Option(False, "--no-judge", help="Skip LLM-as-Judge evaluation"),
    output: str = typer.Option("./reports", "--output", "-o", help="Output directory"),
    format: str = typer.Option(
        "markdown", "--format", "-f", help="Report format: markdown, html, json"
    ),
):
    """Run a full security audit with LLM-as-Judge evaluation and report generation."""
    from datetime import datetime

    from rich.panel import Panel

    console.print(
        Panel(
            "[yellow]⚠️ AUTHORIZED USE ONLY[/yellow]\n"
            "Only test systems you own or have permission to test.",
            title="Security Notice",
            border_style="yellow",
        )
    )

    console.print(f"\n🔍 Starting security audit on [cyan]{target}/{model}[/cyan]")
    if not no_judge:
        console.print(f"   Judge: [cyan]{judge_provider}/{judge_model}[/cyan]")
    else:
        console.print("   Judge: [yellow]Skipped (heuristic mode)[/yellow]")
    console.print(f"   Mode: {'Quick' if quick else 'Full'}")
    console.print(f"   Output: {output}")

    async def _run_audit():
        from rich.progress import Progress, SpinnerColumn, TextColumn

        from verity.core import create_provider
        from verity.judges import CampaignEvaluation, LLMJudge
        from verity.red_team import get_all_agents
        from verity.reporting import ReportGenerator, ReportMetadata

        # Create providers
        target_provider = create_provider(target)
        judge_provider_instance = create_provider(judge_provider)

        # Set models
        if hasattr(target_provider, "default_model"):
            target_provider.default_model = model
        if hasattr(judge_provider_instance, "default_model"):
            judge_provider_instance.default_model = judge_model

        max_per_agent = 3 if quick else 8
        all_results = []

        # Run attacks
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            agents = get_all_agents()
            task = progress.add_task(f"Running {len(agents)} attack agents...", total=len(agents))

            for agent in agents:
                progress.update(task, description=f"Running {agent.name}...")
                results = await agent.execute(
                    target=target_provider,
                    max_attacks=max_per_agent,
                )
                all_results.extend(results)
                progress.advance(task)

        console.print(f"\n✅ Executed [bold]{len(all_results)}[/bold] attacks")

        # Judge evaluation (or heuristic mode)
        if not no_judge:
            console.print("\n⚖️ Evaluating with LLM-as-Judge...")
            judge = LLMJudge(judge_provider_instance)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Evaluating attacks...", total=1)
                campaign_eval = await judge.evaluate_campaign(all_results)
                progress.advance(task)
        else:
            # Heuristic mode: use attack agent's own success evaluation
            console.print("\n⚖️ Using heuristic evaluation (no judge)...")
            successful = sum(1 for r in all_results if r.success)
            failed = sum(1 for r in all_results if not r.success)
            total = len(all_results)
            asr = successful / total if total > 0 else 0

            # Create a simple CampaignEvaluation from heuristics
            campaign_eval = CampaignEvaluation(
                total_attacks=total,
                successful_attacks=successful,
                failed_attacks=failed,
                borderline_attacks=0,
                asr=asr,
                asr_ci_lower=max(0, asr - 0.1),
                asr_ci_upper=min(1, asr + 0.1),
                average_harm_score=asr * 7,  # Rough estimate
                evaluations=[],
                category_breakdown={r.attack_category.value: 1 for r in all_results},
            )

        # Display results
        console.print("\n📊 [bold]Evaluation Results[/bold]")
        asr_color = (
            "red" if campaign_eval.asr > 0.5 else "yellow" if campaign_eval.asr > 0.2 else "green"
        )
        console.print(
            f"   ASR: [{asr_color}]{campaign_eval.asr:.1%}[/{asr_color}] [{campaign_eval.asr_ci_lower:.1%} - {campaign_eval.asr_ci_upper:.1%}]"
        )
        console.print(
            f"   Successful: {campaign_eval.successful_attacks}/{campaign_eval.total_attacks}"
        )
        console.print(f"   Avg Harm Score: {campaign_eval.average_harm_score:.1f}/10")

        # Generate report
        console.print("\n📝 Generating report...")
        generator = ReportGenerator(output)
        metadata = ReportMetadata(
            title=f"Security Assessment: {model}",
            target_system=target,
            target_model=model,
            assessment_date=datetime.now(),
        )

        report_path = generator.save_report(campaign_eval, metadata, format=format)
        console.print(f"   ✅ Report saved: [green]{report_path}[/green]")

        console.print("\n[bold green]🎉 Audit complete![/bold green]")

    asyncio.run(_run_audit())


if __name__ == "__main__":
    app()
