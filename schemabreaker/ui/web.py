"""Streamlit Web Dashboard for SchemaBreaker."""

import asyncio
import os
from datetime import datetime, timezone
import streamlit as st
import pandas as pd

from schemabreaker.core.models import AttackVector, FuzzConfig
from schemabreaker.core.loader import load_schema_from_code, load_schema_from_path, SchemaInspector
from schemabreaker.core.fuzzer import AdversarialFuzzer
from schemabreaker.core.runner import ValidationRunner
from schemabreaker.core.analyzer import SchemaAnalyzer
from schemabreaker.ui.export import export_html, export_json
from schemabreaker.demo import DEMO_REGISTRY


def run_app():
    st.set_page_config(
        page_title="SchemaBreaker | LLM Structured Output Stress-Tester",
        page_icon="⚡",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Custom styling
    st.markdown("""
    <style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(135deg, #38bdf8, #818cf8, #ec4899);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .kpi-card {
        background: rgba(18, 24, 38, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        padding: 1rem 1.25rem;
        text-align: center;
    }
    .score-badge-a { color: #10b981; font-weight: 800; font-size: 2.2rem; }
    .score-badge-b { color: #f59e0b; font-weight: 800; font-size: 2.2rem; }
    .score-badge-c { color: #ef4444; font-weight: 800; font-size: 2.2rem; }
    </style>
    """, unsafe_allow_html=True)

    st.markdown('<div class="main-title">⚡ SchemaBreaker</div>', unsafe_allow_html=True)
    st.caption("Automated Stress-Testing & Adversarial Fuzzing for LLM Structured Outputs (Pydantic / JSON Schema)")

    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Fuzzing Configuration")

        schema_source = st.radio("Schema Source", ["Built-in Demo", "Custom Pydantic Code", "JSON Schema"])

        target_model = st.selectbox(
            "Target Gemini Model",
            ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-1.5-flash", "gemini-1.5-pro"],
            index=0
        )

        api_key = st.text_input(
            "Gemini API Key",
            type="password",
            value=os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or "",
            help="Optional if using Mock Simulation Mode"
        )

        mock_mode = st.checkbox("Simulate / Mock Run (No API Key needed)", value=not bool(api_key))

        num_tests = st.slider("Number of Fuzz Scenarios", min_value=5, max_value=50, value=20, step=5)
        concurrency = st.slider("Concurrency Workers", min_value=1, max_value=10, value=5, step=1)
        temperature = st.slider("Target Model Temperature", min_value=0.0, max_value=1.0, value=0.2, step=0.1)

        selected_vectors = st.multiselect(
            "Target Attack Vectors",
            options=list(AttackVector),
            default=list(AttackVector),
            format_func=lambda x: x.display_name
        )

    # Main Area: Schema & Prompt Input
    inspector: SchemaInspector

    if schema_source == "Built-in Demo":
        demo_name = st.selectbox(
            "Select Demo Schema",
            list(DEMO_REGISTRY.keys()),
            format_func=lambda x: f"{x.capitalize()} - {DEMO_REGISTRY[x][2]}"
        )
        inspector = load_schema_from_path(demo_name)
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Target Schema Definition")
            st.code(inspector.source_code or inspector.get_summary_text(), language="python")
        with col2:
            st.subheader("Target System Prompt")
            prompt_input = st.text_area("System Prompt", value=inspector.system_prompt, height=220)
            inspector.system_prompt = prompt_input

    elif schema_source == "Custom Pydantic Code":
        sample_code = """from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class Priority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class SupportTicket(BaseModel):
    ticket_id: str = Field(..., pattern=r"^TCK-[0-9]{5}$", description="Formatted as TCK-12345")
    customer_email: str = Field(..., pattern=r"^[^@]+@[^@]+\\.[^@]+$")
    issue_summary: str = Field(..., min_length=10, max_length=200)
    priority: Priority = Field(default=Priority.MEDIUM)
    tags: List[str] = Field(default_factory=list, min_length=1)
    estimated_resolution_hours: float = Field(..., ge=0.5, le=72.0)
    requires_escalation: bool = Field(default=False)
"""
        code_input = st.text_area("Paste Pydantic Python Code", value=sample_code, height=260)
        prompt_input = st.text_area("System Prompt", value="Extract support ticket details from customer communication.", height=100)
        try:
            inspector = load_schema_from_code(code_input, system_prompt=prompt_input)
            st.success(f"✓ Successfully parsed Pydantic Model: `{inspector.model_name}`")
        except Exception as e:
            st.error(f"Error parsing schema code: {e}")
            return
    else:
        sample_json_schema = """{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "UserProfile",
  "type": "object",
  "properties": {
    "username": { "type": "string" },
    "age": { "type": "integer" },
    "is_active": { "type": "boolean" }
  },
  "required": ["username", "age"]
}"""
        json_input = st.text_area("Paste JSON Schema", value=sample_json_schema, height=260)
        prompt_input = st.text_area("System Prompt", value="Parse user profile JSON.", height=100)
        try:
            import json
            from schemabreaker.core.loader import _create_model_from_json_schema
            parsed_json = json.loads(json_input)
            model_cls = _create_model_from_json_schema(parsed_json, "UserProfile")
            inspector = SchemaInspector(model_cls, system_prompt=prompt_input, source_code=json_input)
            st.success("✓ Successfully loaded JSON Schema")
        except Exception as e:
            st.error(f"Error loading JSON Schema: {e}")
            return

    # Fuzz Run Trigger
    st.divider()
    launch_clicked = st.button("🚀 Launch SchemaBreaker Stress-Test", type="primary", use_container_width=True)

    if launch_clicked:
        config = FuzzConfig(
            target_model=target_model,
            num_tests=num_tests,
            concurrency=concurrency,
            temperature=temperature,
            mock_mode=mock_mode,
            api_key=api_key or None,
            attack_vectors=selected_vectors or list(AttackVector),
        )

        with st.status("⚡ Running SchemaBreaker Adversarial Audit...", expanded=True) as status:
            st.write("1. Introspecting schema constraints & enums...")
            fuzzer = AdversarialFuzzer(inspector, config)

            st.write("2. Synthesizing adversarial attack payloads...")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            test_suite = loop.run_until_complete(fuzzer.generate_test_suite(num_tests))

            st.write(f"3. Executing {len(test_suite)} concurrent tests against {target_model}...")
            prog_bar = st.progress(0.0)
            
            completed_count = 0
            def on_complete(result):
                nonlocal completed_count
                completed_count += 1
                prog_bar.progress(min(1.0, completed_count / len(test_suite)))

            started_at = datetime.now(timezone.utc)
            runner = ValidationRunner(inspector, config, on_test_complete=on_complete)
            results = loop.run_until_complete(runner.run_suite(test_suite))
            completed_at = datetime.now(timezone.utc)

            st.write("4. Computing health score and statistical telemetry...")
            analyzer = SchemaAnalyzer(inspector, results, target_model, started_at, completed_at)
            summary = analyzer.generate_summary()
            status.update(label="✅ Stress-Test Audit Complete!", state="complete", expanded=False)

        st.session_state["last_summary"] = summary

    # Render results if available
    if "last_summary" in st.session_state:
        summary = st.session_state["last_summary"]

        st.subheader("📊 Audit Overview")
        k1, k2, k3, k4 = st.columns(4)
        
        with k1:
            st.metric("Health Score", f"{summary.health_score:.1f} / 100", f"Grade: {summary.health_grade}")
        with k2:
            st.metric("Pass Rate", f"{summary.success_rate:.1f}%", f"{summary.passed_tests} / {summary.total_tests} Passed")
        with k3:
            st.metric("Failures Detected", summary.failed_tests + summary.error_tests)
        with k4:
            st.metric("P95 Latency", f"{summary.p95_latency_ms:.0f} ms", f"Avg: {summary.avg_latency_ms:.0f} ms")

        # Attack vector breakdown
        st.subheader("🛡️ Attack Vector Resilience Breakdown")
        df_vectors = []
        for vec_k, stats in summary.results_by_vector.items():
            df_vectors.append({
                "Attack Vector": stats["display_name"],
                "Total Tests": stats["total"],
                "Passed": stats["passed"],
                "Failed": stats["failed"],
                "Pass Rate (%)": stats["success_rate"],
                "Avg Latency (ms)": stats["avg_latency_ms"],
            })
        st.dataframe(pd.DataFrame(df_vectors), use_container_width=True)

        # Breaking Edge Cases
        failed_results = [r for r in summary.results if not r.success]
        st.subheader(f"🚨 Breaking Edge Cases ({len(failed_results)} Total)")
        
        if not failed_results:
            st.success("🎉 All test cases passed! Schema is robust under tested conditions.")
        else:
            for idx, r in enumerate(failed_results, start=1):
                tc = r.test_case
                with st.expander(f"[{idx}] {tc.id}: {tc.title} ({tc.vector.display_name}) - Latency: {r.latency_ms:.0f}ms"):
                    st.markdown(f"**Trap:** {tc.expected_trap}")
                    st.markdown(f"**Failure Category:** `{r.failure_category.value if r.failure_category else 'unknown'}`")
                    st.markdown(f"**Error Message:** `{r.error_message}`")
                    
                    st.markdown("**Malicious Input Payload:**")
                    st.code(tc.input_prompt, language="text")
                    
                    st.markdown("**Raw LLM Output:**")
                    st.code(r.raw_output or "<Empty>", language="json")

                    if r.validation_errors:
                        st.markdown("**Validation Error Diffs:**")
                        for err in r.validation_errors:
                            st.markdown(f"- `{err.field_path}`: {err.msg} (`{err.error_type}`)")

        # Recommendations
        if summary.recommendations:
            st.subheader("💡 Actionable Hardening Recommendations")
            for rec in summary.recommendations:
                with st.container(border=True):
                    st.markdown(f"### [{rec.severity}] {rec.title} *({rec.category})*")
                    st.markdown(f"**Problem:** {rec.problem_statement}")
                    st.markdown(f"**Suggested Action:** {rec.suggested_action}")
                    if rec.prompt_patch:
                        st.markdown("**System Prompt Patch:**")
                        st.code(rec.prompt_patch, language="python")
                    if rec.code_patch_pydantic:
                        st.markdown("**Pydantic Code Patch:**")
                        st.code(rec.code_patch_pydantic, language="python")

        # Download options
        st.divider()
        dcol1, dcol2 = st.columns(2)
        with dcol1:
            json_data = summary.model_dump_json(indent=2)
            st.download_button(
                "📥 Download JSON Audit Report",
                data=json_data,
                file_name=f"schemabreaker_audit_{summary.schema_name}.json",
                mime="application/json",
                use_container_width=True
            )
        with dcol2:
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
                export_html(summary, tmp.name)
                with open(tmp.name, "r", encoding="utf-8") as f:
                    html_data = f.read()
            st.download_button(
                "🌐 Download Interactive HTML Dashboard",
                data=html_data,
                file_name=f"schemabreaker_dashboard_{summary.schema_name}.html",
                mime="text/html",
                use_container_width=True
            )


if __name__ == "__main__":
    run_app()
