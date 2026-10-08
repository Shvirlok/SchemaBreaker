"""Rich Terminal UI Dashboard for SchemaBreaker."""

import sys
from typing import List, Optional
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.columns import Columns
from rich.align import Align
from rich import box

from schemabreaker.core.models import (
    AttackVector,
    AuditSummary,
    FailureCategory,
    Recommendation,
    TestResult,
)


class TerminalDashboard:
    """Renders sleek dark-mode terminal dashboards and reports using Rich."""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def print_banner(self, schema_name: str, model_name: str, test_count: int, concurrency: int, mock_mode: bool = False):
        """Displays the stylized ASCII banner and configuration panel."""
        ascii_logo = """
   ███████╗ ██████╗██╗  ██╗███████╗███╗   ███╗ █████╗ ██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗███████╗██████╗ 
   ██╔════╝██╔════╝██║  ██║██╔════╝████╗ ████║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔══██╗
   ███████╗██║     ███████║█████╗  ██╔████╔██║███████║██████╔╝██████╔╝█████╗  ███████║█████╔╝ █████╗  ██████╔╝
   ╚════██║██║     ██╔══██║██╔══╝  ██║╚██╔╝██║██╔══██║██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗
   ███████║╚██████╗██║  ██║███████╗██║ ╚═╝ ██║██║  ██║██████╔╝██████╔╝███████╗██║  ██║██║  ██╗███████╗██║  ██║
   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
        """
        logo_text = Text(ascii_logo, style="bold cyan")
        subtitle = Text("⚡ Automated LLM Structured Output & JSON Schema Stress-Testing Fuzzer ⚡\n", style="bold bright_white")
        
        mode_badge = "[bold yellow]MOCK SIMULATION[/bold yellow]" if mock_mode else "[bold green]LIVE GEMINI API[/bold green]"

        config_table = Table.grid(padding=(0, 2))
        config_table.add_column(style="dim cyan", justify="right")
        config_table.add_column(style="bold white")
        config_table.add_column(style="dim cyan", justify="right")
        config_table.add_column(style="bold white")

        config_table.add_row("Target Schema:", f"[bold magenta]{schema_name}[/bold magenta]", "Target Model:", f"[bold yellow]{model_name}[/bold yellow]")
        config_table.add_row("Fuzz Scenarios:", f"[bold cyan]{test_count}[/bold cyan]", "Concurrency:", f"[bold cyan]{concurrency} workers[/bold cyan]")
        config_table.add_row("Execution Engine:", mode_badge, "Status:", "[bold green]Ready & Running[/bold green]")

        banner_content = Group(
            Align.center(logo_text),
            Align.center(subtitle),
            Panel(config_table, border_style="dim cyan", box=box.ROUNDED, padding=(1, 2))
        )

        self.console.print(Panel(banner_content, border_style="bright_blue", box=box.HEAVY, padding=(0, 1)))
        self.console.print()

    def print_summary_dashboard(self, summary: AuditSummary):
        """Displays the complete executive audit dashboard."""
        self.console.print()
        self._print_kpi_cards(summary)
        self.console.print()
        self._print_vector_table(summary)
        self.console.print()
        self._print_breaking_edge_cases(summary)
        self.console.print()
        self._print_recommendations(summary.recommendations)
        self.console.print()
        self._print_footer(summary)

    def _print_kpi_cards(self, summary: AuditSummary):
        """Prints high-impact KPI summary cards."""
        # Health Score Gauge
        score = summary.health_score
        grade = summary.health_grade
        
        if score >= 90:
            score_color = "bold green"
            gauge_char = "█"
        elif score >= 75:
            score_color = "bold yellow"
            gauge_char = "█"
        elif score >= 60:
            score_color = "bold dark_orange"
            gauge_char = "█"
        else:
            score_color = "bold red"
            gauge_char = "█"

        filled_len = int(score / 10)
        empty_len = 10 - filled_len
        gauge_bar = f"[{score_color}]{gauge_char * filled_len}[/{score_color}][dim white]{'░' * empty_len}[/dim white]"

        health_card = Panel(
            Align.center(
                Group(
                    Text("SCHEMA HEALTH SCORE", style="dim bold white"),
                    Text(f"{score:.1f} / 100", style=score_color),
                    Text(f"Grade: {grade}", style=f"bold {score_color}"),
                    Text(gauge_bar),
                )
            ),
            title="[bold cyan]Contract Integrity[/bold cyan]",
            border_style=score_color.split()[-1],
            box=box.ROUNDED,
            padding=(1, 2)
        )

        pass_rate_color = "bold green" if summary.success_rate >= 90 else ("bold yellow" if summary.success_rate >= 75 else "bold red")
        pass_card = Panel(
            Align.center(
                Group(
                    Text("PASS RATE", style="dim bold white"),
                    Text(f"{summary.success_rate:.1f}%", style=pass_rate_color),
                    Text(f"{summary.passed_tests} Passed / {summary.total_tests} Total", style="dim white"),
                    Text(f"Failed: {summary.failed_tests + summary.error_tests}", style="bold red" if (summary.failed_tests + summary.error_tests) > 0 else "dim green"),
                )
            ),
            title="[bold cyan]Validation Rate[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 2)
        )

        lat_color = "bold green" if summary.p95_latency_ms < 1500 else ("bold yellow" if summary.p95_latency_ms < 3000 else "bold red")
        latency_card = Panel(
            Align.center(
                Group(
                    Text("LATENCY TELEMETRY", style="dim bold white"),
                    Text(f"Avg: {summary.avg_latency_ms:.0f}ms", style="bold white"),
                    Text(f"P50: {summary.p50_latency_ms:.0f}ms", style="dim white"),
                    Text(f"P95: {summary.p95_latency_ms:.0f}ms | P99: {summary.p99_latency_ms:.0f}ms", style=lat_color),
                )
            ),
            title="[bold cyan]Speed & Latency[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 2)
        )

        self.console.print(Columns([health_card, pass_card, latency_card], expand=True))

    def _print_vector_table(self, summary: AuditSummary):
        """Displays breakdown of tests by Attack Vector."""
        table = Table(
            title="🛡️ Attack Vector Resilience Breakdown",
            title_style="bold bright_white",
            header_style="bold cyan",
            box=box.SIMPLE_HEAVY,
            expand=True
        )

        table.add_column("Attack Vector", style="bold white", ratio=4)
        table.add_column("Tests", justify="center", ratio=1)
        table.add_column("Passed", justify="center", style="green", ratio=1)
        table.add_column("Failed", justify="center", style="red", ratio=1)
        table.add_column("Pass Rate", justify="center", ratio=2)
        table.add_column("Avg Latency", justify="right", style="dim white", ratio=2)

        for vec_key, stats in summary.results_by_vector.items():
            rate = stats["success_rate"]
            rate_color = "bold green" if rate >= 90 else ("bold yellow" if rate >= 70 else "bold red")
            
            # Simple mini visual bar
            filled = int(rate / 10)
            bar = f"[{rate_color}]{'█' * filled}[/{rate_color}]{'░' * (10 - filled)}"

            table.add_row(
                f"[bold magenta]{stats['display_name']}[/bold magenta]",
                str(stats["total"]),
                str(stats["passed"]),
                str(stats["failed"]),
                f"{bar} {rate:.1f}%",
                f"{stats['avg_latency_ms']:.0f} ms"
            )

        self.console.print(Panel(table, border_style="dim cyan", box=box.ROUNDED))

    def _print_breaking_edge_cases(self, summary: AuditSummary):
        """Displays detailed audit cards for the breaking edge cases."""
        failed_results = [r for r in summary.results if not r.success]
        
        if not failed_results:
            self.console.print(Panel(
                Align.center(Text("🎉 ZERO SCHEMA FAILURES DETECTED! ALL ADVERSARIAL CASES PASSED! 🎉", style="bold green")),
                border_style="green",
                box=box.ROUNDED
            ))
            return

        self.console.print(Text(f"🚨 Top Breaking Edge Cases ({len(failed_results)} Total Failures)", style="bold bright_red"))

        # Show up to 5 representative failure cases
        for idx, result in enumerate(failed_results[:5], start=1):
            tc = result.test_case
            
            # Vector badge
            badge_color = tc.vector.badge_color
            header = Text()
            header.append(f"[{idx}] {tc.id}: {tc.title} ", style="bold white")
            header.append(f"[{tc.vector.display_name}]", style=badge_color)
            header.append(f" | Category: {result.failure_category.display_name if result.failure_category else 'Unknown'}", style="dim yellow")
            header.append(f" ({result.latency_ms:.0f}ms)", style="dim white")

            # Input content
            input_panel = Panel(
                Text(tc.input_prompt.strip(), style="white"),
                title="[dim cyan]Adversarial Input Payload[/dim cyan]",
                border_style="dim cyan",
                box=box.ROUNDED
            )

            # Raw output snippet
            raw_text = result.raw_output or "<No response content returned>"
            if len(raw_text) > 400:
                raw_text = raw_text[:400] + "... [truncated]"
            
            # Highlight JSON or raw text
            output_renderable = Syntax(raw_text, "json", theme="monokai", word_wrap=True) if raw_text.strip().startswith(("{", "[")) else Text(raw_text, style="dim yellow")
            output_panel = Panel(
                output_renderable,
                title="[dim red]Raw LLM Output (Malformed / Leaked)[/dim red]",
                border_style="dim red",
                box=box.ROUNDED
            )

            # Error details
            err_items = []
            if result.validation_errors:
                for err in result.validation_errors:
                    err_items.append(f"  • [bold red]{err.field_path}[/bold red]: {err.msg} [dim](type: {err.error_type})[/dim]")
                err_text = "\n".join(err_items)
            else:
                err_text = f"  • {result.error_message or 'Unknown error'}"

            error_panel = Panel(
                Text.from_markup(err_text),
                title="[bold red]Pydantic Validation Trace & Field Diffs[/bold red]",
                border_style="red",
                box=box.ROUNDED
            )

            case_group = Group(input_panel, output_panel, error_panel)
            self.console.print(Panel(case_group, title=header, border_style="red", box=box.ROUNDED, padding=(1, 1)))

        if len(failed_results) > 5:
            self.console.print(Text(f"... and {len(failed_results) - 5} more failures. Export full audit report to inspect all cases.", style="dim italic white"))

    def _print_recommendations(self, recommendations: List[Recommendation]):
        """Displays actionable prompt and schema remediation patches."""
        if not recommendations:
            return

        self.console.print(Text("💡 Actionable Remediation & Hardening Recommendations", style="bold bright_cyan"))

        for rec in recommendations:
            sev_color = "bold red" if rec.severity == "CRITICAL" else ("bold yellow" if rec.severity == "HIGH" else "bold green")
            
            content_items = [
                Text.from_markup(f"[bold white]Problem:[/bold white] {rec.problem_statement}"),
                Text.from_markup(f"[bold white]Suggested Fix:[/bold white] {rec.suggested_action}"),
            ]

            if rec.prompt_patch:
                content_items.append(Text("\n[bold cyan]System Prompt Patch:[/bold cyan]"))
                content_items.append(Syntax(rec.prompt_patch, "python", theme="monokai", word_wrap=True))

            if rec.code_patch_pydantic:
                content_items.append(Text("\n[bold magenta]Pydantic Model Patch Diff:[/bold magenta]"))
                content_items.append(Syntax(rec.code_patch_pydantic, "python", theme="monokai", word_wrap=True))

            rec_panel = Panel(
                Group(*content_items),
                title=f"[{sev_color}][{rec.severity}][/{sev_color}] [bold white]{rec.title}[/bold white] [dim]({rec.category})[/dim]",
                border_style="cyan" if rec.severity != "CRITICAL" else "red",
                box=box.ROUNDED,
                padding=(1, 1)
            )
            self.console.print(rec_panel)

    def _print_footer(self, summary: AuditSummary):
        """Displays audit timing and completion metadata."""
        footer_text = Text()
        footer_text.append(f"⏱️ Total Duration: {summary.duration_seconds:.2f}s  |  ", style="dim white")
        footer_text.append(f"Target Schema: {summary.schema_name}  |  ", style="dim magenta")
        footer_text.append(f"Model: {summary.target_model_name}  |  ", style="dim yellow")
        footer_text.append(f"Timestamp: {summary.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}", style="dim cyan")
        
        self.console.print(Align.center(footer_text))
