"""Unit tests for Adversarial Fuzzer."""

import pytest
import asyncio
from schemabreaker.core.loader import load_schema_from_path
from schemabreaker.core.fuzzer import AdversarialFuzzer
from schemabreaker.core.models import AttackVector, FuzzConfig


def test_synthetic_fuzz_generation():
    inspector = load_schema_from_path("ecommerce")
    config = FuzzConfig(mock_mode=True, num_tests=15)
    fuzzer = AdversarialFuzzer(inspector, config)

    test_cases = asyncio.run(fuzzer.generate_test_suite(count=15))
    assert len(test_cases) == 15
    assert all(tc.id.startswith("TC-") for tc in test_cases)
    
    vectors_present = {tc.vector for tc in test_cases}
    assert AttackVector.ENUM_VIOLATION in vectors_present or AttackVector.PROMPT_INJECTION in vectors_present
    assert len(vectors_present) >= 3


def test_vector_filtering():
    inspector = load_schema_from_path("clinical")
    config = FuzzConfig(
        mock_mode=True,
        num_tests=10,
        attack_vectors=[AttackVector.BOUNDARY_STRESS, AttackVector.UNICODE_STRESS]
    )
    fuzzer = AdversarialFuzzer(inspector, config)

    test_cases = asyncio.run(fuzzer.generate_test_suite(count=10))
    assert len(test_cases) == 10
    for tc in test_cases:
        assert tc.vector in (AttackVector.BOUNDARY_STRESS, AttackVector.UNICODE_STRESS)
