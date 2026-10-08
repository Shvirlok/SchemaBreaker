"""Unit tests for Analyzer, Recommender, and Exporters."""

import os
import tempfile
from datetime import datetime, timezone
import pytest
from schemabreaker.core.loader import load_schema_from_path
from schemabreaker.core.models import (
    AttackVector,
    FailureCategory,
    TestCase,
    TestResult,
    ValidationErrorDetail,
)
from schemabreaker.core.analyzer import SchemaAnalyzer
from schemabreaker.ui.export import export_html, export_json, export_markdown


def test_schema_analyzer_scoring():
    inspector = load_schema_from_path("ecommerce")
    
    tc1 = TestCase(id="TC-1", vector=AttackVector.BOUNDARY_STRESS, title="Pass case", description="", input_prompt="", expected_trap="")
    tc2 = TestCase(id="TC-2", vector=AttackVector.ENUM_VIOLATION, title="Fail case", description="", input_prompt="", expected_trap="")

    r1 = TestResult(test_case=tc1, success=True, status_code="PASS", latency_ms=250.0)
    r2 = TestResult(
        test_case=tc2,
        success=False,
        status_code="FAIL",
        latency_ms=300.0,
        failure_category=FailureCategory.ENUM_INVALID,
        error_message="Enum mismatch",
        validation_errors=[ValidationErrorDetail(loc=["status"], msg="Invalid enum value", error_type="enum")]
    )

    t0 = datetime.now(timezone.utc)
    analyzer = SchemaAnalyzer(inspector, [r1, r2], "gemini-2.5-flash", t0, t0)
    summary = analyzer.generate_summary()

    assert summary.total_tests == 2
    assert summary.passed_tests == 1
    assert summary.failed_tests == 1
    assert summary.success_rate == 50.0
    assert 0 <= summary.health_score <= 100
    assert len(summary.recommendations) > 0


def test_report_exporters():
    inspector = load_schema_from_path("clinical")
    tc = TestCase(id="TC-1", vector=AttackVector.UNICODE_STRESS, title="Test", description="", input_prompt="pat info", expected_trap="")
    r = TestResult(test_case=tc, success=True, status_code="PASS", latency_ms=180.0)

    t0 = datetime.now(timezone.utc)
    analyzer = SchemaAnalyzer(inspector, [r], "gemini-2.5-flash", t0, t0)
    summary = analyzer.generate_summary()

    with tempfile.TemporaryDirectory() as tmpdir:
        json_p = os.path.join(tmpdir, "report.json")
        html_p = os.path.join(tmpdir, "report.html")
        md_p = os.path.join(tmpdir, "report.md")

        export_json(summary, json_p)
        export_html(summary, html_p)
        export_markdown(summary, md_p)

        assert os.path.exists(json_p)
        assert os.path.exists(html_p)
        assert os.path.exists(md_p)

        assert "<html" in open(html_p, encoding="utf-8").read()
        assert "# ⚡ SchemaBreaker Audit Report" in open(md_p, encoding="utf-8").read()
