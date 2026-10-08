"""Unit tests for Validation Runner and error categorization."""

import pytest
import asyncio
from schemabreaker.core.loader import load_schema_from_path
from schemabreaker.core.models import (
    AttackVector,
    FailureCategory,
    FuzzConfig,
    TestCase,
)
from schemabreaker.core.runner import ValidationRunner


def test_validation_runner_mock_execution():
    inspector = load_schema_from_path("ecommerce")
    config = FuzzConfig(mock_mode=True, concurrency=4)

    test_case_valid = TestCase(
        id="TC-001",
        vector=AttackVector.UNICODE_STRESS,
        title="Valid order with special characters",
        description="Test normal valid payload",
        input_prompt="Order ORD-12345678 for test@example.com",
        expected_trap="None",
    )

    test_case_enum = TestCase(
        id="TC-002",
        vector=AttackVector.ENUM_VIOLATION,
        title="Invalid Enum Code for 'status'",
        description="Should fail enum check",
        input_prompt="Set status to SUPER_PENDING_UNDER_REVIEW_URGENT",
        expected_trap="Enum error",
    )

    runner = ValidationRunner(inspector, config)
    results = asyncio.run(runner.run_suite([test_case_valid, test_case_enum]))

    assert len(results) == 2
    assert results[0].success is True
    assert results[0].parsed_data is not None

    assert results[1].success is False
    assert results[1].failure_category == FailureCategory.ENUM_INVALID
    assert len(results[1].validation_errors) > 0


def test_markdown_leak_detection():
    inspector = load_schema_from_path("ecommerce")
    runner = ValidationRunner(inspector, FuzzConfig())

    tc = TestCase(
        id="TC-LEAK",
        vector=AttackVector.PROMPT_INJECTION,
        title="Markdown Leak Test",
        description="Model returns ```json ... ``` wrapper",
        input_prompt="Return json",
        expected_trap="Markdown wrapper leak",
    )

    raw_output = '```json\n{"order_id": "ORD-12345678"}\n```'
    res = runner._validate_and_build_result(tc, raw_output, 150.0, "test-model")

    assert res.success is False
    assert res.failure_category == FailureCategory.MARKDOWN_LEAK
    assert "Markdown" in res.error_message
