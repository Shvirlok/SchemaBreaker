"""Concurrent Execution & Pydantic Validation Runner."""

import asyncio
import json
import random
import re
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, ValidationError

from schemabreaker.core.models import (
    AttackVector,
    FailureCategory,
    FuzzConfig,
    TestCase,
    TestResult,
    ValidationErrorDetail,
)
from schemabreaker.core.loader import SchemaInspector


class ValidationRunner:
    """Orchestrates asynchronous execution of fuzz test cases against Gemini API and validates outputs."""

    def __init__(
        self,
        inspector: SchemaInspector,
        config: Optional[FuzzConfig] = None,
        on_test_start: Optional[Callable[[TestCase], None]] = None,
        on_test_complete: Optional[Callable[[TestResult], None]] = None,
    ):
        self.inspector = inspector
        self.config = config or FuzzConfig()
        self.on_test_start = on_test_start
        self.on_test_complete = on_test_complete
        self.semaphore = asyncio.Semaphore(self.config.concurrency)

    async def run_suite(self, test_cases: List[TestCase]) -> List[TestResult]:
        """Executes all test cases concurrently up to the configured concurrency limit."""
        tasks = [self._execute_single_test(tc) for tc in test_cases]
        results = await asyncio.gather(*tasks)
        return results

    async def _execute_single_test(self, test_case: TestCase) -> TestResult:
        """Executes a single test case with concurrency limiting, timing, and validation."""
        async with self.semaphore:
            if self.on_test_start:
                try:
                    self.on_test_start(test_case)
                except Exception:
                    pass

            start_time = time.perf_counter()

            if self.config.mock_mode or not self.config.api_key:
                result = await self._mock_execute(test_case, start_time)
            else:
                result = await self._live_execute(test_case, start_time)

            if self.on_test_complete:
                try:
                    self.on_test_complete(result)
                except Exception:
                    pass

            return result

    async def _live_execute(self, test_case: TestCase, start_time: float) -> TestResult:
        """Executes request against Google Gemini API using google-genai SDK."""
        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self.config.api_key)

            gen_config = types.GenerateContentConfig(
                system_instruction=self.inspector.system_prompt,
                response_mime_type="application/json",
                response_schema=self.inspector.model_class,
                temperature=self.config.temperature,
            )

            # Fire async generation with timeout
            response_coro = client.aio.models.generate_content(
                model=self.config.target_model,
                contents=test_case.input_prompt,
                config=gen_config,
            )

            response = await asyncio.wait_for(response_coro, timeout=self.config.timeout_seconds)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            raw_text = response.text or ""
            return self._validate_and_build_result(
                test_case=test_case,
                raw_text=raw_text,
                latency_ms=elapsed_ms,
                model_used=self.config.target_model
            )

        except asyncio.TimeoutError:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TestResult(
                test_case=test_case,
                success=False,
                status_code="TIMEOUT",
                latency_ms=elapsed_ms,
                failure_category=FailureCategory.TIMEOUT_LATENCY,
                error_message=f"Request timed out after {self.config.timeout_seconds}s",
                model_used=self.config.target_model,
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            error_str = str(e)

            # Detect safety policy refusals
            if "safety" in error_str.lower() or "blocked" in error_str.lower() or "filter" in error_str.lower():
                return TestResult(
                    test_case=test_case,
                    success=False,
                    status_code="REFUSAL",
                    latency_ms=elapsed_ms,
                    failure_category=FailureCategory.SAFETY_REFUSAL,
                    error_message=f"Safety Filter Refusal: {error_str}",
                    traceback_str=traceback.format_exc(),
                    model_used=self.config.target_model,
                )

            return TestResult(
                test_case=test_case,
                success=False,
                status_code="ERROR",
                latency_ms=elapsed_ms,
                failure_category=FailureCategory.OTHER_ERROR,
                error_message=f"API Execution Error: {error_str}",
                traceback_str=traceback.format_exc(),
                model_used=self.config.target_model,
            )

    def _validate_and_build_result(
        self,
        test_case: TestCase,
        raw_text: str,
        latency_ms: float,
        model_used: str,
    ) -> TestResult:
        """Performs multi-stage schema validation, markdown leak detection, and error categorization."""
        # 1. Check for empty response
        if not raw_text or not raw_text.strip():
            return TestResult(
                test_case=test_case,
                success=False,
                status_code="FAIL",
                latency_ms=latency_ms,
                raw_output=raw_text,
                failure_category=FailureCategory.NULL_VIOLATION,
                error_message="Model returned an empty response string",
                model_used=model_used,
            )

        # 2. Check for markdown codeblock leak (```json ... ```)
        cleaned_text = raw_text.strip()
        has_markdown_leak = False
        if cleaned_text.startswith("```"):
            has_markdown_leak = True
            # Strip fences for downstream json parse attempt
            match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned_text)
            if match:
                cleaned_text = match.group(1).strip()
            else:
                cleaned_text = re.sub(r"^```[a-zA-Z]*\n", "", cleaned_text)
                cleaned_text = re.sub(r"\n```$", "", cleaned_text).strip()

        # 3. Check JSON parseability
        try:
            parsed_dict = json.loads(cleaned_text)
        except json.JSONDecodeError as j_err:
            return TestResult(
                test_case=test_case,
                success=False,
                status_code="FAIL",
                latency_ms=latency_ms,
                raw_output=raw_text,
                failure_category=FailureCategory.JSON_SYNTAX_ERROR,
                error_message=f"Invalid JSON Syntax: {j_err.msg} at line {j_err.lineno}, col {j_err.colno}",
                traceback_str=str(j_err),
                model_used=model_used,
            )

        # If it leaked markdown, flag as markdown leak unless configured to tolerate
        if has_markdown_leak:
            return TestResult(
                test_case=test_case,
                success=False,
                status_code="FAIL",
                latency_ms=latency_ms,
                raw_output=raw_text,
                parsed_data=parsed_dict,
                failure_category=FailureCategory.MARKDOWN_LEAK,
                error_message="Output leaked Markdown code fence delimiters (```json ... ```) instead of raw JSON",
                model_used=model_used,
            )

        # 4. Validate with Pydantic model
        try:
            validated_obj = self.inspector.model_class.model_validate(parsed_dict)
            return TestResult(
                test_case=test_case,
                success=True,
                status_code="PASS",
                latency_ms=latency_ms,
                raw_output=raw_text,
                parsed_data=validated_obj.model_dump(mode="json"),
                model_used=model_used,
            )
        except ValidationError as val_err:
            details: List[ValidationErrorDetail] = []
            is_enum = False
            is_null = False

            for err in val_err.errors():
                err_type = err.get("type", "")
                err_msg = err.get("msg", "")
                loc = list(err.get("loc", []))
                inp = err.get("input", None)

                if "enum" in err_type.lower() or "literal" in err_type.lower():
                    is_enum = True
                if "null" in err_type.lower() or "none" in err_msg.lower() or inp is None:
                    is_null = True

                details.append(ValidationErrorDetail(
                    loc=loc,
                    msg=err_msg,
                    error_type=err_type,
                    input_value=inp,
                ))

            category = FailureCategory.VALIDATION_ERROR
            if is_enum:
                category = FailureCategory.ENUM_INVALID
            elif is_null and any("missing" in d.error_type or d.input_value is None for d in details):
                category = FailureCategory.NULL_VIOLATION

            return TestResult(
                test_case=test_case,
                success=False,
                status_code="FAIL",
                latency_ms=latency_ms,
                raw_output=raw_text,
                parsed_data=parsed_dict,
                failure_category=category,
                error_message=f"Pydantic Validation Failed ({len(details)} error{'s' if len(details) > 1 else ''})",
                validation_errors=details,
                traceback_str=str(val_err),
                model_used=model_used,
            )

    async def _mock_execute(self, test_case: TestCase, start_time: float) -> TestResult:
        """Simulates realistic LLM latency and edge-case validation failure patterns."""
        # Simulate realistic async network / inference delay (120ms - 900ms, with occasional spike)
        simulated_delay = random.uniform(0.12, 0.65)
        if test_case.vector == AttackVector.BOUNDARY_STRESS and "10,000" in test_case.title:
            simulated_delay = random.uniform(1.2, 2.8)  # simulate latency spike on massive payload
        await asyncio.sleep(simulated_delay)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        model_name = self.inspector.model_name

        # E-Commerce Mock Generator
        if model_name == "CustomerOrder":
            return self._mock_ecommerce_result(test_case, elapsed_ms)
        elif model_name == "ClinicalAssessment":
            return self._mock_clinical_result(test_case, elapsed_ms)
        elif model_name == "LoanApplication":
            return self._mock_financial_result(test_case, elapsed_ms)
        else:
            # Generic fallback mock
            return self._mock_generic_result(test_case, elapsed_ms)

    def _mock_ecommerce_result(self, test_case: TestCase, latency_ms: float) -> TestResult:
        """Mock simulation for E-commerce schema."""
        vec = test_case.vector

        if vec == AttackVector.PROMPT_INJECTION and "Ignore Schema" in test_case.title:
            raw = "```markdown\n# Injected Output\nStatus: BYPASSED\n```"
            return self._validate_and_build_result(test_case, raw, latency_ms, "gemini-2.5-flash (mock)")

        if vec == AttackVector.SYNTACTIC_MALFORM and "Triple Backtick" in test_case.title:
            raw = '```json\n{\n  "order_id": "ORD-12345678",\n  "customer_email": "jane@example.com",\n  "status": "PENDING",\n  "currency": "USD",\n  "items": [{"sku": "SKU-9999-AA", "product_name": "Pro Widget", "quantity": 1, "unit_price": 29.99}],\n  "shipping_address": {"street": "123 Main St", "city": "Springfield", "state_province": "IL", "postal_code": "62701", "country_iso": "USA"},\n  "payment": {"method": "CREDIT_CARD", "transaction_id": "TXN-987654321", "is_settled": true},\n  "subtotal": 29.99,\n  "tax_rate": 0.08,\n  "total_amount": 32.39\n}\n```'
            return self._validate_and_build_result(test_case, raw, latency_ms, "gemini-2.5-flash (mock)")

        if vec == AttackVector.ENUM_VIOLATION:
            # Output invalid enum value
            raw = json.dumps({
                "order_id": "ORD-87654321",
                "customer_email": "buyer@domain.com",
                "status": "SUPER_PENDING_UNDER_REVIEW_URGENT",
                "currency": "USD",
                "items": [{"sku": "ITM-100-AB", "product_name": "Gadget", "quantity": 2, "unit_price": 49.99}],
                "shipping_address": {"street": "456 Elm St", "city": "Dallas", "state_province": "TX", "postal_code": "75001", "country_iso": "US"},
                "payment": {"method": "PAYPAL", "transaction_id": "PAY-88887777", "is_settled": True},
                "subtotal": 99.98,
                "tax_rate": 0.0825,
                "total_amount": 108.23
            })
            return self._validate_and_build_result(test_case, raw, latency_ms, "gemini-2.5-flash (mock)")

        if vec == AttackVector.TYPE_CONFUSION and "Spelled-Out" in test_case.title:
            raw = json.dumps({
                "order_id": "ORD-11223344",
                "customer_email": "test@shop.com",
                "status": "PENDING",
                "currency": "USD",
                "items": [{"sku": "PRD-2020-XX", "product_name": "Books", "quantity": "twenty-four", "unit_price": "one thousand four hundred"}],
                "shipping_address": {"street": "789 Pine Ave", "city": "Boston", "state_province": "MA", "postal_code": "02108", "country_iso": "USA"},
                "payment": {"method": "APPLE_PAY", "transaction_id": "APL-12345678", "is_settled": True},
                "subtotal": 1400.0,
                "tax_rate": 0.05,
                "total_amount": 1470.0
            })
            return self._validate_and_build_result(test_case, raw, latency_ms, "gemini-2.5-flash (mock)")

        if vec == AttackVector.BOUNDARY_STRESS and "Negative" in test_case.title:
            raw = json.dumps({
                "order_id": "ORD-55667788",
                "customer_email": "refund@store.com",
                "status": "REFUNDED",
                "currency": "USD",
                "items": [{"sku": "SKU-3333-BB", "product_name": "Return item", "quantity": -50, "unit_price": -99.99}],
                "shipping_address": {"street": "100 Return Way", "city": "Austin", "state_province": "TX", "postal_code": "78701", "country_iso": "USA"},
                "payment": {"method": "CREDIT_CARD", "transaction_id": "REF-99990000", "is_settled": True},
                "subtotal": -4999.5,
                "tax_rate": -0.15,
                "total_amount": -5749.42
            })
            return self._validate_and_build_result(test_case, raw, latency_ms, "gemini-2.5-flash (mock)")

        if vec == AttackVector.BOUNDARY_STRESS and "Empty Array" in test_case.title:
            raw = json.dumps({
                "order_id": "ORD-99001122",
                "customer_email": "zero@shopper.com",
                "status": "CANCELLED",
                "currency": "USD",
                "items": [],
                "shipping_address": {"street": "10 Minimalist Rd", "city": "Seattle", "state_province": "WA", "postal_code": "98101", "country_iso": "USA"},
                "payment": {"method": "DEBIT_CARD", "transaction_id": "DBT-00112233", "is_settled": False},
                "subtotal": 0.0,
                "tax_rate": 0.0,
                "total_amount": 0.0
            })
            return self._validate_and_build_result(test_case, raw, latency_ms, "gemini-2.5-flash (mock)")

        if vec == AttackVector.NULL_INJECTION:
            raw = json.dumps({
                "order_id": None,
                "customer_email": None,
                "status": "PENDING",
                "currency": "USD",
                "items": None,
                "shipping_address": None,
                "payment": {"method": "CREDIT_CARD", "transaction_id": "TXN-00000000", "is_settled": True},
                "subtotal": 0.0,
                "tax_rate": 0.0,
                "total_amount": 0.0
            })
            return self._validate_and_build_result(test_case, raw, latency_ms, "gemini-2.5-flash (mock)")

        # Normal valid output for passed cases
        raw = json.dumps({
            "order_id": f"ORD-{random.randint(10000000, 99999999)}",
            "customer_email": "verified.user@enterprise.org",
            "customer_phone": "+14155552671",
            "status": "PROCESSING",
            "currency": "USD",
            "items": [
                {
                    "sku": "PRD-9988-ZZ",
                    "product_name": "Premium Ergonomic Keyboard",
                    "quantity": 2,
                    "unit_price": 149.99,
                    "discount_amount": 10.0
                }
            ],
            "shipping_address": {
                "street": "742 Evergreen Terrace",
                "city": "Springfield",
                "state_province": "OR",
                "postal_code": "97477",
                "country_iso": "USA"
            },
            "payment": {
                "method": "CREDIT_CARD",
                "last_four": "4242",
                "transaction_id": f"TXN-{random.randint(10000000, 99999999)}",
                "is_settled": True
            },
            "subtotal": 289.98,
            "tax_rate": 0.075,
            "shipping_cost": 15.0,
            "total_amount": 326.73,
            "customer_notes": "Please leave behind the side gate."
        })
        return self._validate_and_build_result(test_case, raw, latency_ms, "gemini-2.5-flash (mock)")

    def _mock_clinical_result(self, test_case: TestCase, latency_ms: float) -> TestResult:
        """Mock simulation for Clinical Assessment schema."""
        vec = test_case.vector
        if vec == AttackVector.BOUNDARY_STRESS and "Negative" in test_case.title:
            raw = json.dumps({
                "patient_id": "PAT-123456",
                "chief_complaint": "Severe dyspnea and chest pressure",
                "triage_level": "RESUSCITATION",
                "vitals": {"heart_rate_bpm": 15, "blood_pressure_systolic": 35, "blood_pressure_diastolic": 15, "temperature_celsius": 25.0, "oxygen_saturation_pct": 40},
                "current_medications": [],
                "allergies": ["Penicillin"],
                "icd10_suspected_codes": ["I21.9"],
                "clinical_notes_summary": "Patient presented with acute cardiac symptoms.",
                "requires_immediate_admission": True
            })
            return self._validate_and_build_result(test_case, raw, latency_ms, "gemini-2.5-flash (mock)")

        raw = json.dumps({
            "patient_id": f"PAT-{random.randint(100000, 999999)}",
            "chief_complaint": "Persistent cough and mild fever for three days",
            "triage_level": "URGENT",
            "vitals": {
                "heart_rate_bpm": 82,
                "blood_pressure_systolic": 120,
                "blood_pressure_diastolic": 78,
                "temperature_celsius": 38.2,
                "oxygen_saturation_pct": 98,
                "respiratory_rate": 18
            },
            "current_medications": [
                {"drug_name": "Amoxicillin", "dosage": "500mg", "frequency": "TID", "route": "oral"}
            ],
            "allergies": ["Sulfa"],
            "icd10_suspected_codes": ["J06.9", "R05"],
            "clinical_notes_summary": "Patient evaluated for acute upper respiratory tract infection. Vitals stable.",
            "follow_up_days": 7,
            "requires_immediate_admission": False
        })
        return self._validate_and_build_result(test_case, raw, latency_ms, "gemini-2.5-flash (mock)")

    def _mock_financial_result(self, test_case: TestCase, latency_ms: float) -> TestResult:
        """Mock simulation for Financial Loan Application schema."""
        raw = json.dumps({
            "application_id": f"APP-{random.randint(1000000, 9999999)}",
            "applicant_name": "Jordan Peterson",
            "credit_score": 745,
            "monthly_gross_income": 9500.0,
            "monthly_debt_obligations": 2400.0,
            "requested_loan_amount": 350000.0,
            "loan_term_months": 360,
            "employment_status": "FULL_TIME",
            "assets": [{"asset_type": "Real Estate", "estimated_value_usd": 120000.0, "is_encumbered": False}],
            "calculated_dti_ratio": 0.252,
            "assigned_risk_tier": "TIER_1_PRIME",
            "underwriter_notes": "Clean credit history, low DTI, stable employment.",
            "auto_approval_granted": True
        })
        return self._validate_and_build_result(test_case, raw, latency_ms, "gemini-2.5-flash (mock)")

    def _mock_generic_result(self, test_case: TestCase, latency_ms: float) -> TestResult:
        """Generic fallback mock for arbitrary schemas."""
        try:
            sample_instance = self.inspector.model_class.model_construct()
            raw = sample_instance.model_dump_json()
        except Exception:
            raw = "{}"
        return self._validate_and_build_result(test_case, raw, latency_ms, "gemini-2.5-flash (mock)")
