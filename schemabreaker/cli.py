"""SchemaBreaker CLI Entrypoint."""

import asyncio
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from schemabreaker.core.models import (
    AttackVector,
    AuditSummary,
    FuzzConfig,
    TestCase,
    TestResult,
)
from schemabreaker.core.loader import (
    load_schema_from_path,
    SchemaInspector,
)
from schemabreaker.core.fuzzer import AdversarialFuzzer
from schemabreaker.core.runner import ValidationRunner
from schemabreaker.core.analyzer import SchemaAnalyzer
from schemabreaker.ui.display import TerminalDashboard
from schemabreaker.ui.export import export_html, export_json, export_markdown
from schemabreaker.demo import DEMO_REGISTRY


console = Console()
dashboard = TerminalDashboard(console)


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx: click.Context):
    """⚡ SchemaBreaker: Automated stress-testing CLI for LLM Structured Outputs."""
    if ctx.invoked_subcommand is None:
        # Default behavior: run demo or show help
        ctx.invoke(demo)


@main.command("run", short_help="Run adversarial stress-test audit on a Pydantic schema or JSON schema.")
@click.option("-s", "--schema", default="ecommerce", help="Path to .py file, .json schema, or demo name ('ecommerce', 'clinical', 'financial').")
@click.option("-m", "--model-name", default=None, help="Pydantic model class name inside the file.")
@click.option("-p", "--system-prompt", default=None, help="Inline system prompt text.")
@click.option("--prompt-file", default=None, help="Path to text file containing system prompt.")
@click.option("-n", "--tests", default=20, type=int, help="Number of adversarial fuzz test runs.")
@click.option("-c", "--concurrency", default=5, type=int, help="Concurrency workers limit.")
@click.option("--target-model", default="gemini-2.5-flash", help="Gemini model to stress test.")
@click.option("--generator-model", default="gemini-2.5-flash", help="Model used for adversarial red-team generation.")
@click.option("--temperature", default=0.2, type=float, help="Sampling temperature for target model.")
@click.option("--mock", is_flag=True, default=False, help="Run in mock simulation mode (no API key required).")
@click.option("--api-key", envvar=["GEMINI_API_KEY", "GOOGLE_API_KEY"], help="Google Gemini API key.")
@click.option("-v", "--vector", multiple=True, type=click.Choice([v.value for v in AttackVector]), help="Filter by specific attack vectors.")
@click.option("--export-json", default=None, help="File path to save JSON audit telemetry.")
@click.option("--export-html", default=None, help="File path to save interactive HTML dashboard.")
@click.option("--export-md", default=None, help="File path to save Markdown summary.")
def run_command(
    schema: str,
    model_name: Optional[str],
    system_prompt: Optional[str],
    prompt_file: Optional[str],
    tests: int,
    concurrency: int,
    target_model: str,
    generator_model: str,
    temperature: float,
    mock: bool,
    api_key: Optional[str],
    vector: tuple,
    export_json: Optional[str],
    export_html: Optional[str],
    export_md: Optional[str],
):
    """Executes full adversarial stress-test audit pipeline."""
    asyncio.run(
        _execute_audit_pipeline(
            schema_path_or_demo=schema,
            model_name=model_name,
            system_prompt_text=system_prompt,
            system_prompt_file=prompt_file,
            tests_count=tests,
            concurrency=concurrency,
            target_model=target_model,
            generator_model=generator_model,
            temperature=temperature,
            mock_mode=mock,
            api_key=api_key,
            selected_vectors=[AttackVector(v) for v in vector] if vector else None,
            export_json_path=export_json,
            export_html_path=export_html,
            export_md_path=export_md,
        )
    )


@main.command("audit", short_help="Alias for 'run'.")
@click.pass_context
def audit_command(ctx: click.Context):
    """Alias for run."""
    ctx.forward(run_command)


@main.command("demo", short_help="Launch instant out-of-the-box demo audit.")
@click.option("--schema", default="ecommerce", type=click.Choice(list(DEMO_REGISTRY.keys())), help="Demo schema to test.")
@click.option("-n", "--tests", default=20, type=int, help="Number of test scenarios.")
@click.option("--live", is_flag=True, help="Force live Gemini API call instead of mock.")
@click.option("--export-html", default=None, help="Save interactive HTML dashboard.")
def demo(schema: str, tests: int, live: bool, export_html: Optional[str]):
    """Runs instant out-of-the-box stress-test audit with pre-packaged schemas."""
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    mock_mode = not live if api_key else True

    asyncio.run(
        _execute_audit_pipeline(
            schema_path_or_demo=schema,
            model_name=None,
            system_prompt_text=None,
            system_prompt_file=None,
            tests_count=tests,
            concurrency=5,
            target_model="gemini-2.5-flash",
            generator_model="gemini-2.5-flash",
            temperature=0.2,
            mock_mode=mock_mode,
            api_key=api_key,
            selected_vectors=None,
            export_json_path=None,
            export_html_path=export_html,
            export_md_path=None,
        )
    )


@main.command("web", short_help="Launch the standalone SchemaBreaker Web Application.")
@click.option("-p", "--port", default=8501, type=int, help="Port to run web app on.")
@click.option("-h", "--host", default="127.0.0.1", help="Host address to bind to.")
@click.option("--reload", is_flag=True, help="Enable auto-reload on code changes.")
def launch_web(port: int, host: str, reload: bool):
    """Starts the standalone FastAPI web application."""
    import uvicorn
    console.print(f"\n[bold cyan]⚡ Launching SchemaBreaker Web UI on [bold white]http://{host}:{port}[/bold white]...[/bold cyan]\n")
    uvicorn.run("web.app:app", host=host, port=port, reload=reload)


@main.command("list-demos", short_help="List all built-in demonstration schemas.")
def list_demos():
    """Lists built-in demo schemas."""
    console.print("\n[bold cyan]📦 Pre-Packaged Demo Schemas:[/bold cyan]\n")
    for key, (cls, prompt, desc) in DEMO_REGISTRY.items():
        console.print(f"  • [bold yellow]{key}[/bold yellow]: [bold white]{cls.__name__}[/bold white]")
        console.print(f"    [dim]{desc}[/dim]\n")


async def _execute_audit_pipeline(
    schema_path_or_demo: str,
    model_name: Optional[str],
    system_prompt_text: Optional[str],
    system_prompt_file: Optional[str],
    tests_count: int,
    concurrency: int,
    target_model: str,
    generator_model: str,
    temperature: float,
    mock_mode: bool,
    api_key: Optional[str],
    selected_vectors: Optional[List[AttackVector]],
    export_json_path: Optional[str],
    export_html_path: Optional[str],
    export_md_path: Optional[str],
):
    """Internal orchestrator for audit workflow."""
    # 1. Load Schema
    try:
        inspector = load_schema_from_path(
            path_or_demo=schema_path_or_demo,
            model_name=model_name,
            system_prompt_path=system_prompt_file,
            system_prompt_text=system_prompt_text,
        )
    except Exception as e:
        console.print(f"[bold red]❌ Failed to load schema:[/bold red] {e}")
        sys.exit(1)

    # 2. Display Banner
    effective_mock = mock_mode or not bool(api_key)
    dashboard.print_banner(
        schema_name=inspector.model_name,
        model_name=target_model,
        test_count=tests_count,
        concurrency=concurrency,
        mock_mode=effective_mock,
    )

    if not api_key and not mock_mode:
        console.print("[dim yellow]ℹ️ No GEMINI_API_KEY found in environment. Defaulting to high-fidelity Mock Simulation mode.[/dim yellow]\n")

    config = FuzzConfig(
        target_model=target_model,
        generator_model=generator_model,
        num_tests=tests_count,
        concurrency=concurrency,
        temperature=temperature,
        mock_mode=effective_mock,
        api_key=api_key,
        attack_vectors=selected_vectors,
    )

    # 3. Generate Adversarial Test Suite
    fuzzer = AdversarialFuzzer(inspector, config)
    with console.status("[bold cyan]Generating adversarial edge cases and attack payloads...[/bold cyan]", spinner="dots"):
        test_suite = await fuzzer.generate_test_suite(tests_count)

    console.print(f"[bold green]✓[/bold green] Synthesized [bold white]{len(test_suite)}[/bold white] targeted adversarial test cases across {len(set(tc.vector for tc in test_suite))} attack vectors.\n")

    # 4. Execute Concurrently with Progress Bar
    results: List[TestResult] = []
    started_at = datetime.now(timezone.utc)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="dim cyan", complete_style="bold cyan"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"[bold white]Fuzz-testing {target_model}...", total=len(test_suite))

        def on_complete(result: TestResult):
            results.append(result)
            progress.update(task, advance=1)

        runner = ValidationRunner(
            inspector=inspector,
            config=config,
            on_test_complete=on_complete,
        )
        await runner.run_suite(test_suite)

    completed_at = datetime.now(timezone.utc)

    # 5. Statistical Telemetry and Health Scoring
    analyzer = SchemaAnalyzer(
        inspector=inspector,
        results=results,
        target_model_name=target_model,
        started_at=started_at,
        completed_at=completed_at,
    )
    summary = analyzer.generate_summary()

    # 6. Render Terminal Dashboard
    dashboard.print_summary_dashboard(summary)

    # 7. Exports
    if export_json_path:
        p = export_json(summary, export_json_path)
        console.print(f"\n[bold green]✓ Saved JSON Telemetry Audit Report:[/bold green] [cyan]{p}[/cyan]")

    if export_html_path:
        p = export_html(summary, export_html_path)
        console.print(f"[bold green]✓ Saved Interactive HTML Dashboard:[/bold green] [cyan]{p}[/cyan]")

    if export_md_path:
        p = export_markdown(summary, export_md_path)
        console.print(f"[bold green]✓ Saved Markdown Audit Report:[/bold green] [cyan]{p}[/cyan]")

    console.print()


if __name__ == "__main__":
    main()
