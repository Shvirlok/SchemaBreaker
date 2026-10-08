"""Audit Report Exporters (JSON, Markdown, Interactive HTML Dashboard)."""

import html
import json
from pathlib import Path
from typing import Optional
from pydantic import BaseModel

from schemabreaker.core.models import AuditSummary


def export_json(summary: AuditSummary, output_path: str) -> str:
    """Exports full audit telemetry and test results to a JSON file."""
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    json_str = summary.model_dump_json(indent=2)
    path.write_text(json_str, encoding="utf-8")
    return str(path)


def export_markdown(summary: AuditSummary, output_path: str) -> str:
    """Exports a GitHub-flavored Markdown report suitable for CI/CD summaries and PR comments."""
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        f"# ⚡ SchemaBreaker Audit Report: `{summary.schema_name}`",
        "",
        f"**Target Model:** `{summary.target_model_name}` | **Health Grade:** **{summary.health_grade}** ({summary.health_score}/100) | **Pass Rate:** **{summary.success_rate}%**",
        f"**Timestamp:** `{summary.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}` | **Duration:** `{summary.duration_seconds}s`",
        "",
        "## 📊 Executive Summary",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| **Total Adversarial Tests** | {summary.total_tests} |",
        f"| **Passed Tests** | {summary.passed_tests} |",
        f"| **Failed Tests** | {summary.failed_tests} |",
        f"| **Runtime Errors / Refusals** | {summary.error_tests} |",
        f"| **Average Latency** | {summary.avg_latency_ms:.1f} ms |",
        f"| **P50 Latency** | {summary.p50_latency_ms:.1f} ms |",
        f"| **P95 Latency** | {summary.p95_latency_ms:.1f} ms |",
        f"| **P99 Latency** | {summary.p99_latency_ms:.1f} ms |",
        "",
        "## 🛡️ Attack Vector Breakdown",
        "",
        "| Attack Vector | Total | Passed | Failed | Pass Rate | Avg Latency |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |",
    ]

    for vec, stats in summary.results_by_vector.items():
        lines.append(
            f"| `{stats['display_name']}` | {stats['total']} | {stats['passed']} | {stats['failed']} | **{stats['success_rate']}%** | {stats['avg_latency_ms']} ms |"
        )

    failed = [r for r in summary.results if not r.success]
    if failed:
        lines.extend([
            "",
            f"## 🚨 Breaking Edge Cases ({len(failed)} Total)",
            "",
        ])
        for idx, r in enumerate(failed[:10], start=1):
            tc = r.test_case
            lines.extend([
                f"### {idx}. [{tc.id}] {tc.title} (`{tc.vector.value}`)",
                f"- **Vulnerability / Trap:** {tc.expected_trap}",
                f"- **Failure Reason:** {r.error_message or 'Validation Failed'}",
                f"- **Latency:** `{r.latency_ms:.1f} ms`",
                "",
                "<details>",
                "<summary><b>View Malicious Input Payload</b></summary>",
                "",
                "```text",
                tc.input_prompt.strip(),
                "```",
                "</details>",
                "",
                "<details>",
                "<summary><b>View Raw LLM Output & Error Details</b></summary>",
                "",
                "```json",
                r.raw_output or "<None>",
                "```",
                "",
            ])
            if r.validation_errors:
                lines.append("**Validation Error Diffs:**")
                for err in r.validation_errors:
                    lines.append(f"- `{err.field_path}`: {err.msg} (`{err.error_type}`)")
            lines.extend(["</details>", ""])

    if summary.recommendations:
        lines.extend([
            "",
            "## 💡 Actionable Remediation Patches",
            "",
        ])
        for rec in summary.recommendations:
            lines.extend([
                f"### [{rec.severity}] {rec.title} ({rec.category})",
                f"- **Problem:** {rec.problem_statement}",
                f"- **Suggested Action:** {rec.suggested_action}",
                "",
            ])
            if rec.prompt_patch:
                lines.extend([
                    "**System Prompt Patch:**",
                    "```python",
                    rec.prompt_patch,
                    "```",
                    "",
                ])
            if rec.code_patch_pydantic:
                lines.extend([
                    "**Pydantic Model Patch:**",
                    "```python",
                    rec.code_patch_pydantic,
                    "```",
                    "",
                ])

    content = "\n".join(lines)
    path.write_text(content, encoding="utf-8")
    return str(path)


def export_html(summary: AuditSummary, output_path: str) -> str:
    """Exports a self-contained, sleek interactive dark-mode HTML dashboard report."""
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    # Encode test results for client-side search and filtering
    results_json = summary.model_dump_json()

    # Pre-render stats
    score = summary.health_score
    grade = summary.health_grade
    score_color = "#10b981" if score >= 90 else ("#f59e0b" if score >= 75 else ("#f97316" if score >= 60 else "#ef4444"))

    html_content = f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SchemaBreaker Audit Report - {html.escape(summary.schema_name)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #090d16;
      --card-bg: rgba(18, 24, 38, 0.75);
      --border: rgba(255, 255, 255, 0.08);
      --border-accent: rgba(56, 189, 248, 0.3);
      --text: #f1f5f9;
      --text-dim: #94a3b8;
      --cyan: #38bdf8;
      --magenta: #ec4899;
      --green: #10b981;
      --yellow: #f59e0b;
      --red: #ef4444;
      --blue: #3b82f6;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Inter', sans-serif;
      background-color: var(--bg);
      background-image: radial-gradient(circle at 15% 15%, rgba(56, 189, 248, 0.07) 0%, transparent 40%),
                        radial-gradient(circle at 85% 85%, rgba(236, 72, 153, 0.05) 0%, transparent 40%);
      color: var(--text);
      line-height: 1.5;
      padding: 2rem 1.5rem;
      min-height: 100vh;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 2rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 2rem;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }}
    .brand-icon {{
      background: linear-gradient(135deg, #38bdf8, #818cf8);
      color: #090d16;
      font-size: 1.5rem;
      font-weight: 800;
      width: 44px;
      height: 44px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 20px rgba(56, 189, 248, 0.4);
    }}
    .brand-title h1 {{ font-size: 1.5rem; font-weight: 800; letter-spacing: -0.02em; }}
    .brand-title p {{ font-size: 0.85rem; color: var(--text-dim); }}
    .meta-badge {{
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border);
      padding: 0.5rem 1rem;
      border-radius: 9999px;
      font-size: 0.85rem;
      font-family: 'JetBrains Mono', monospace;
      color: var(--cyan);
    }}
    .grid-3 {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2rem;
    }}
    .card {{
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 1.5rem;
      box-shadow: 0 10px 30px rgba(0,0,0,0.3);
      position: relative;
      overflow: hidden;
    }}
    .card-title {{
      font-size: 0.8rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-dim);
      margin-bottom: 0.75rem;
    }}
    .score-display {{
      display: flex;
      align-items: baseline;
      gap: 0.5rem;
      margin-bottom: 0.5rem;
    }}
    .score-num {{ font-size: 2.75rem; font-weight: 800; color: {score_color}; }}
    .score-total {{ font-size: 1.25rem; color: var(--text-dim); }}
    .grade-badge {{
      display: inline-block;
      padding: 0.2rem 0.6rem;
      background: {score_color}22;
      border: 1px solid {score_color};
      color: {score_color};
      border-radius: 6px;
      font-weight: 700;
      font-size: 0.85rem;
      margin-left: auto;
    }}
    .progress-bar-bg {{
      height: 8px;
      background: rgba(255,255,255,0.1);
      border-radius: 4px;
      overflow: hidden;
      margin-top: 0.5rem;
    }}
    .progress-bar-fill {{
      height: 100%;
      width: {score}%;
      background: {score_color};
      border-radius: 4px;
    }}
    .stat-row {{
      display: flex;
      justify-content: space-between;
      padding: 0.4rem 0;
      font-size: 0.9rem;
      border-bottom: 1px solid rgba(255,255,255,0.04);
    }}
    .stat-row:last-child {{ border-bottom: none; }}
    .stat-label {{ color: var(--text-dim); }}
    .stat-val {{ font-weight: 600; font-family: 'JetBrains Mono', monospace; }}
    
    .section-title {{
      font-size: 1.25rem;
      font-weight: 700;
      margin: 2.5rem 0 1rem 0;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
    }}
    th, td {{
      padding: 0.9rem 1.2rem;
      text-align: left;
      font-size: 0.9rem;
    }}
    th {{
      background: rgba(255,255,255,0.03);
      color: var(--cyan);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
      border-bottom: 1px solid var(--border);
    }}
    tr:not(:last-child) td {{ border-bottom: 1px solid var(--border); }}
    tr:hover td {{ background: rgba(255,255,255,0.02); }}
    .rate-badge {{
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-weight: 600;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
    }}
    .rate-high {{ background: rgba(16, 185, 129, 0.15); color: #10b981; }}
    .rate-mid {{ background: rgba(245, 158, 11, 0.15); color: #f59e0b; }}
    .rate-low {{ background: rgba(239, 68, 68, 0.15); color: #ef4444; }}

    .failure-card {{
      background: var(--card-bg);
      border: 1px solid rgba(239, 68, 68, 0.25);
      border-radius: 12px;
      padding: 1.25rem;
      margin-bottom: 1rem;
      box-shadow: 0 4px 20px rgba(0,0,0,0.2);
    }}
    .failure-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.75rem;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}
    .failure-title {{ font-weight: 700; font-size: 1rem; }}
    .vector-tag {{
      font-size: 0.75rem;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      background: rgba(236, 72, 153, 0.15);
      color: var(--magenta);
      font-weight: 600;
      font-family: 'JetBrains Mono', monospace;
    }}
    .code-block {{
      background: rgba(0,0,0,0.4);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.75rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      overflow-x: auto;
      margin: 0.5rem 0;
      color: #e2e8f0;
    }}
    .rec-card {{
      background: var(--card-bg);
      border-left: 4px solid var(--cyan);
      border-radius: 0 12px 12px 0;
      padding: 1.25rem;
      margin-bottom: 1rem;
      border-top: 1px solid var(--border);
      border-right: 1px solid var(--border);
      border-bottom: 1px solid var(--border);
    }}
    .rec-card.CRITICAL {{ border-left-color: var(--red); }}
    .rec-card.HIGH {{ border-left-color: var(--yellow); }}
    .rec-title {{ font-weight: 700; font-size: 1rem; margin-bottom: 0.35rem; }}
    .rec-meta {{ font-size: 0.8rem; color: var(--text-dim); margin-bottom: 0.5rem; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <div class="brand-icon">⚡</div>
        <div class="brand-title">
          <h1>SchemaBreaker Audit Report</h1>
          <p>Adversarial Stress-Testing for LLM Structured Outputs</p>
        </div>
      </div>
      <div class="meta-badge">Target: {html.escape(summary.schema_name)} &bull; {html.escape(summary.target_model_name)}</div>
    </header>

    <!-- Top KPI Cards -->
    <div class="grid-3">
      <div class="card">
        <div class="card-title">Schema Health Integrity</div>
        <div class="score-display">
          <div class="score-num">{score:.1f}</div>
          <div class="score-total">/ 100</div>
          <div class="grade-badge">Grade: {grade}</div>
        </div>
        <div class="progress-bar-bg">
          <div class="progress-bar-fill"></div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Test Outcomes</div>
        <div class="stat-row"><span class="stat-label">Total Test Cases:</span><span class="stat-val">{summary.total_tests}</span></div>
        <div class="stat-row"><span class="stat-label">Passed Tests:</span><span class="stat-val" style="color:var(--green)">{summary.passed_tests}</span></div>
        <div class="stat-row"><span class="stat-label">Failed Tests:</span><span class="stat-val" style="color:var(--red)">{summary.failed_tests}</span></div>
        <div class="stat-row"><span class="stat-label">Success Rate:</span><span class="stat-val">{summary.success_rate}%</span></div>
      </div>

      <div class="card">
        <div class="card-title">Latency Telemetry</div>
        <div class="stat-row"><span class="stat-label">Average Latency:</span><span class="stat-val">{summary.avg_latency_ms:.0f} ms</span></div>
        <div class="stat-row"><span class="stat-label">P50 Latency:</span><span class="stat-val">{summary.p50_latency_ms:.0f} ms</span></div>
        <div class="stat-row"><span class="stat-label">P95 Latency:</span><span class="stat-val">{summary.p95_latency_ms:.0f} ms</span></div>
        <div class="stat-row"><span class="stat-label">P99 Latency:</span><span class="stat-val">{summary.p99_latency_ms:.0f} ms</span></div>
      </div>
    </div>

    <!-- Attack Vector Table -->
    <div class="section-title">🛡️ Attack Vector Resilience Breakdown</div>
    <table>
      <thead>
        <tr>
          <th>Attack Vector</th>
          <th>Tests</th>
          <th>Passed</th>
          <th>Failed</th>
          <th>Pass Rate</th>
          <th>Avg Latency</th>
        </tr>
      </thead>
      <tbody>
"""
    for vec, stats in summary.results_by_vector.items():
        rate = stats["success_rate"]
        cls_name = "rate-high" if rate >= 90 else ("rate-mid" if rate >= 70 else "rate-low")
        html_content += f"""        <tr>
          <td><strong>{html.escape(stats['display_name'])}</strong></td>
          <td>{stats['total']}</td>
          <td style="color:var(--green)">{stats['passed']}</td>
          <td style="color:var(--red)">{stats['failed']}</td>
          <td><span class="rate-badge {cls_name}">{rate:.1f}%</span></td>
          <td style="font-family:'JetBrains Mono',monospace">{stats['avg_latency_ms']:.0f} ms</td>
        </tr>
"""

    html_content += """      </tbody>
    </table>
"""

    # Breaking Edge Cases
    failed_results = [r for r in summary.results if not r.success]
    if failed_results:
        html_content += f"""
    <div class="section-title">🚨 Top Breaking Edge Cases ({len(failed_results)} Total)</div>
"""
        for r in failed_results[:8]:
            tc = r.test_case
            err_msg = html.escape(r.error_message or "Validation Failure")
            prompt_escaped = html.escape(tc.input_prompt)
            raw_escaped = html.escape(r.raw_output or "<No response>")

            val_diffs = ""
            if r.validation_errors:
                val_diffs = "<div style='margin-top:0.5rem;font-size:0.85rem;color:#fca5a5;'><b>Field Diffs:</b><br>"
                for err in r.validation_errors:
                    val_diffs += f"&bull; <code>{html.escape(err.field_path)}</code>: {html.escape(err.msg)} (<code>{html.escape(err.error_type)}</code>)<br>"
                val_diffs += "</div>"

            html_content += f"""
    <div class="failure-card">
      <div class="failure-header">
        <div class="failure-title">{html.escape(tc.id)}: {html.escape(tc.title)}</div>
        <div class="vector-tag">{html.escape(tc.vector.display_name)}</div>
      </div>
      <div style="font-size:0.85rem;color:var(--text-dim);margin-bottom:0.5rem;"><strong>Trap:</strong> {html.escape(tc.expected_trap)}</div>
      <div style="font-size:0.85rem;color:var(--red);margin-bottom:0.5rem;"><strong>Error:</strong> {err_msg}</div>
      <div style="font-size:0.8rem;color:var(--cyan);margin-top:0.5rem;"><strong>Malicious Input:</strong></div>
      <div class="code-block">{prompt_escaped}</div>
      <div style="font-size:0.8rem;color:#f87171;margin-top:0.5rem;"><strong>Raw Malformed LLM Output:</strong></div>
      <div class="code-block">{raw_escaped}</div>
      {val_diffs}
    </div>
"""

    # Recommendations
    if summary.recommendations:
        html_content += """
    <div class="section-title">💡 Actionable Hardening Recommendations</div>
"""
        for rec in summary.recommendations:
            code_diff = ""
            if rec.code_patch_pydantic:
                code_diff = f"""<div style="font-size:0.8rem;color:var(--magenta);margin-top:0.5rem;"><strong>Pydantic Code Patch:</strong></div>
<pre class="code-block">{html.escape(rec.code_patch_pydantic)}</pre>"""
            if rec.prompt_patch:
                code_diff += f"""<div style="font-size:0.8rem;color:var(--cyan);margin-top:0.5rem;"><strong>System Prompt Patch:</strong></div>
<pre class="code-block">{html.escape(rec.prompt_patch)}</pre>"""

            html_content += f"""
    <div class="rec-card {rec.severity}">
      <div class="rec-title">[{rec.severity}] {html.escape(rec.title)}</div>
      <div class="rec-meta">Category: {html.escape(rec.category)}</div>
      <p style="font-size:0.9rem;margin-bottom:0.4rem;"><strong>Problem:</strong> {html.escape(rec.problem_statement)}</p>
      <p style="font-size:0.9rem;margin-bottom:0.4rem;"><strong>Fix:</strong> {html.escape(rec.suggested_action)}</p>
      {code_diff}
    </div>
"""

    html_content += f"""
    <footer style="text-align:center;margin-top:3rem;padding-top:1.5rem;border-top:1px solid var(--border);color:var(--text-dim);font-size:0.8rem;">
      Generated by <strong>SchemaBreaker v0.1.0</strong> &bull; {summary.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC')} &bull; Duration: {summary.duration_seconds}s
    </footer>
  </div>
</body>
</html>
"""

    path.write_text(html_content, encoding="utf-8")
    return str(path)
