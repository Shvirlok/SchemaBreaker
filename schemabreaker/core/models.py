"""Core data models for SchemaBreaker."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AttackVector(str, Enum):
    """Categories of adversarial edge-case attacks."""
    PROMPT_INJECTION = "prompt_injection"
    ENUM_VIOLATION = "enum_violation"
    TYPE_CONFUSION = "type_confusion"
    BOUNDARY_STRESS = "boundary_stress"
    UNICODE_STRESS = "unicode_stress"
    NULL_INJECTION = "null_injection"
    CONTRADICTORY_INTENT = "contradictory_intent"
    SCHEMA_LEAK_INDUCED = "schema_leak_induced"
    SYNTACTIC_MALFORM = "syntactic_malform"

    @property
    def display_name(self) -> str:
        names = {
            AttackVector.PROMPT_INJECTION: "Prompt Injection & Jailbreak",
            AttackVector.ENUM_VIOLATION: "Enum & Allowed Values",
            AttackVector.TYPE_CONFUSION: "Type Confusion & Coercion",
            AttackVector.BOUNDARY_STRESS: "Boundary & Payload Stress",
            AttackVector.UNICODE_STRESS: "Unicode / Control Chars",
            AttackVector.NULL_INJECTION: "Null & Missing Keys",
            AttackVector.CONTRADICTORY_INTENT: "Contradictory Instructions",
            AttackVector.SCHEMA_LEAK_INDUCED: "Schema Confusion / Hallucination",
            AttackVector.SYNTACTIC_MALFORM: "Syntactic Malformation",
        }
        return names.get(self, self.value)

    @property
    def badge_color(self) -> str:
        colors = {
            AttackVector.PROMPT_INJECTION: "bold red",
            AttackVector.ENUM_VIOLATION: "bold yellow",
            AttackVector.TYPE_CONFUSION: "bold magenta",
            AttackVector.BOUNDARY_STRESS: "bold blue",
            AttackVector.UNICODE_STRESS: "bold cyan",
            AttackVector.NULL_INJECTION: "bold dark_orange",
            AttackVector.CONTRADICTORY_INTENT: "bold purple",
            AttackVector.SCHEMA_LEAK_INDUCED: "bold green",
            AttackVector.SYNTACTIC_MALFORM: "bold bright_red",
        }
        return colors.get(self, "white")


class FailureCategory(str, Enum):
    """Categorized root cause of test failures."""
    VALIDATION_ERROR = "pydantic_validation_error"
    MARKDOWN_LEAK = "markdown_leak"
    JSON_SYNTAX_ERROR = "json_syntax_error"
    NULL_VIOLATION = "null_violation"
    ENUM_INVALID = "enum_invalid"
    SAFETY_REFUSAL = "safety_refusal"
    TIMEOUT_LATENCY = "timeout_latency"
    OTHER_ERROR = "other_error"

    @property
    def display_name(self) -> str:
        names = {
            FailureCategory.VALIDATION_ERROR: "Pydantic Validation Error",
            FailureCategory.MARKDOWN_LEAK: "Markdown Code Fence Leak",
            FailureCategory.JSON_SYNTAX_ERROR: "Malformed JSON Syntax",
            FailureCategory.NULL_VIOLATION: "Non-Nullable Null Violation",
            FailureCategory.ENUM_INVALID: "Invalid Enum Member",
            FailureCategory.SAFETY_REFUSAL: "Safety / Policy Refusal",
            FailureCategory.TIMEOUT_LATENCY: "Timeout / Latency Spike",
            FailureCategory.OTHER_ERROR: "Runtime Error",
        }
        return names.get(self, self.value)


class TestCase(BaseModel):
    """An adversarial test scenario generated for fuzz testing."""
    __test__ = False
    id: str = Field(description="Unique test identifier, e.g. TC-001")
    vector: AttackVector = Field(description="Attack vector classification")
    title: str = Field(description="Short human-readable test title")
    description: str = Field(description="Explanation of the vulnerability or edge case probed")
    input_prompt: str = Field(description="The exact adversarial payload sent to the LLM")
    expected_trap: str = Field(description="What validation trap this input is intended to trigger")
    is_synthetic: bool = Field(default=False, description="Whether generated heuristically vs LLM")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context")


class ValidationErrorDetail(BaseModel):
    """Granular detail of a single Pydantic validation failure."""
    loc: List[Any] = Field(description="Field path list, e.g. ['items', 0, 'price']")
    msg: str = Field(description="Pydantic error message")
    error_type: str = Field(description="Pydantic error type, e.g. string_type, missing, enum")
    input_value: Optional[Any] = Field(default=None, description="The erroneous input value")

    @property
    def field_path(self) -> str:
        return ".".join(str(p) for p in self.loc) if self.loc else "root"


class TestResult(BaseModel):
    """Outcome and telemetry of a single fuzz test case execution."""
    __test__ = False
    test_case: TestCase
    success: bool
    status_code: str = Field(description="PASS, FAIL, ERROR, REFUSAL, TIMEOUT")
    latency_ms: float = Field(description="Total roundtrip request duration in milliseconds")
    ttft_ms: Optional[float] = Field(default=None, description="Time to first token in milliseconds")
    raw_output: Optional[str] = Field(default=None, description="Raw text returned by the model")
    parsed_data: Optional[Dict[str, Any]] = Field(default=None, description="Parsed JSON dictionary if valid")
    failure_category: Optional[FailureCategory] = Field(default=None, description="Categorized failure reason")
    error_message: Optional[str] = Field(default=None, description="Primary error message")
    validation_errors: List[ValidationErrorDetail] = Field(default_factory=list, description="Pydantic error list")
    traceback_str: Optional[str] = Field(default=None, description="Error traceback snippet")
    model_used: str = Field(default="gemini-2.5-flash")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Recommendation(BaseModel):
    """Actionable remediation to harden the schema or prompt."""
    id: str
    category: str = Field(description="Schema Constraint, Pydantic Validator, System Prompt, Safety, etc.")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    title: str
    problem_statement: str
    suggested_action: str
    code_patch_pydantic: Optional[str] = None
    prompt_patch: Optional[str] = None


class AuditSummary(BaseModel):
    """Aggregated stress-test audit results, scoring, and telemetry."""
    target_model_name: str
    schema_name: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    error_tests: int
    success_rate: float = Field(description="Percentage 0 - 100")
    health_score: float = Field(description="Composite score 0 - 100")
    health_grade: str = Field(description="A+, A, B, C, D, F")
    avg_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    results_by_vector: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    results_by_category: Dict[str, int] = Field(default_factory=dict)
    recommendations: List[Recommendation] = Field(default_factory=list)
    results: List[TestResult] = Field(default_factory=list)
    started_at: datetime
    completed_at: datetime
    duration_seconds: float


class FuzzConfig(BaseModel):
    """Configuration options for a SchemaBreaker test run."""
    target_model: str = "gemini-2.5-flash"
    generator_model: str = "gemini-2.5-flash"
    num_tests: int = 20
    concurrency: int = 5
    temperature: float = 0.2
    generator_temperature: float = 0.8
    timeout_seconds: float = 30.0
    mock_mode: bool = False
    api_key: Optional[str] = None
    system_prompt: Optional[str] = None
    attack_vectors: Optional[List[AttackVector]] = None
