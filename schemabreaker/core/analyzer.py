"""Statistical analysis and Schema Health Score computation."""

import math
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import numpy as np

from schemabreaker.core.models import (
    AttackVector,
    AuditSummary,
    FailureCategory,
    Recommendation,
    TestResult,
)
from schemabreaker.core.loader import SchemaInspector
from schemabreaker.core.recommender import Recommender


class SchemaAnalyzer:
    """Computes telemetry, statistical percentiles, and Composite Health Score."""

    def __init__(
        self,
        inspector: SchemaInspector,
        results: List[TestResult],
        target_model_name: str,
        started_at: datetime,
        completed_at: datetime,
    ):
        self.inspector = inspector
        self.results = results
        self.target_model_name = target_model_name
        self.started_at = started_at
        self.completed_at = completed_at

    def generate_summary(self) -> AuditSummary:
        """Generates comprehensive audit summary with telemetry and health scoring."""
        total = len(self.results)
        if total == 0:
            return self._empty_summary()

        passed = sum(1 for r in self.results if r.success)
        failed = sum(1 for r in self.results if not r.success and r.status_code == "FAIL")
        errors = sum(1 for r in self.results if r.status_code in ("ERROR", "TIMEOUT", "REFUSAL"))

        success_rate = (passed / total) * 100.0

        # Latency calculations
        latencies = [r.latency_ms for r in self.results if r.latency_ms > 0]
        if latencies:
            latencies.sort()
            avg_lat = float(np.mean(latencies))
            min_lat = float(np.min(latencies))
            max_lat = float(np.max(latencies))
            p50_lat = float(np.percentile(latencies, 50))
            p95_lat = float(np.percentile(latencies, 95))
            p99_lat = float(np.percentile(latencies, 99))
        else:
            avg_lat = min_lat = max_lat = p50_lat = p95_lat = p99_lat = 0.0

        # Breakdown by Attack Vector
        vector_stats: Dict[str, Dict[str, Any]] = {}
        for vec in AttackVector:
            matching = [r for r in self.results if r.test_case.vector == vec]
            if matching:
                vec_passed = sum(1 for r in matching if r.success)
                vec_failed = len(matching) - vec_passed
                vec_rate = (vec_passed / len(matching)) * 100.0
                vec_avg_lat = sum(r.latency_ms for r in matching) / len(matching)
                vector_stats[vec.value] = {
                    "display_name": vec.display_name,
                    "total": len(matching),
                    "passed": vec_passed,
                    "failed": vec_failed,
                    "success_rate": round(vec_rate, 1),
                    "avg_latency_ms": round(vec_avg_lat, 1),
                }

        # Breakdown by Failure Category
        cat_counts: Dict[str, int] = Counter()
        for r in self.results:
            if not r.success and r.failure_category:
                cat_counts[r.failure_category.value] += 1

        # Composite Health Score
        health_score, grade = self._calculate_health_score(
            success_rate=success_rate,
            results=self.results,
            p50=p50_lat,
            p95=p95_lat,
        )

        # Generate Actionable Recommendations
        recommender = Recommender(self.inspector, self.results)
        recommendations = recommender.generate_recommendations()

        duration = (self.completed_at - self.started_at).total_seconds()

        return AuditSummary(
            target_model_name=self.target_model_name,
            schema_name=self.inspector.model_name,
            total_tests=total,
            passed_tests=passed,
            failed_tests=failed,
            error_tests=errors,
            success_rate=round(success_rate, 1),
            health_score=round(health_score, 1),
            health_grade=grade,
            avg_latency_ms=round(avg_lat, 1),
            min_latency_ms=round(min_lat, 1),
            max_latency_ms=round(max_lat, 1),
            p50_latency_ms=round(p50_lat, 1),
            p95_latency_ms=round(p95_lat, 1),
            p99_latency_ms=round(p99_lat, 1),
            results_by_vector=vector_stats,
            results_by_category=dict(cat_counts),
            recommendations=recommendations,
            results=self.results,
            started_at=self.started_at,
            completed_at=self.completed_at,
            duration_seconds=round(duration, 2),
        )

    def _calculate_health_score(
        self,
        success_rate: float,
        results: List[TestResult],
        p50: float,
        p95: float,
    ) -> tuple[float, str]:
        """Calculates 0-100 composite Schema Health Score and assigns letter grade."""
        # 1. Base Success Rate component (40%)
        comp_pass = success_rate * 0.40

        # 2. Failure Severity component (25%)
        # Deduct heavily for syntax crashes, leaks, safety blocks vs soft validation errors
        total_failed = sum(1 for r in results if not r.success)
        if total_failed == 0:
            comp_severity = 25.0
        else:
            cat_weights = {
                FailureCategory.JSON_SYNTAX_ERROR: 1.0,
                FailureCategory.MARKDOWN_LEAK: 0.8,
                FailureCategory.SAFETY_REFUSAL: 0.7,
                FailureCategory.NULL_VIOLATION: 0.5,
                FailureCategory.ENUM_INVALID: 0.4,
                FailureCategory.VALIDATION_ERROR: 0.3,
                FailureCategory.TIMEOUT_LATENCY: 0.9,
                FailureCategory.OTHER_ERROR: 1.0,
            }
            total_penalty_pts = 0.0
            for r in results:
                if not r.success and r.failure_category:
                    w = cat_weights.get(r.failure_category, 0.5)
                    total_penalty_pts += w

            avg_penalty = total_penalty_pts / len(results)
            comp_severity = max(0.0, 25.0 - (avg_penalty * 25.0 * 2.0))

        # 3. Latency Stability component (20%)
        # Healthy if p95 is within 2.5x of p50 and p95 < 2500ms
        if p50 > 0 and p95 > 0:
            tail_ratio = p95 / max(p50, 100.0)
            if tail_ratio <= 1.8 and p95 < 1500:
                comp_lat = 20.0
            elif tail_ratio <= 2.5 and p95 < 3000:
                comp_lat = 16.0
            elif tail_ratio <= 3.5:
                comp_lat = 11.0
            else:
                comp_lat = 5.0
        else:
            comp_lat = 20.0

        # 4. Injection & Adversarial Malice Resistance component (15%)
        security_cases = [
            r for r in results
            if r.test_case.vector in (
                AttackVector.PROMPT_INJECTION,
                AttackVector.SYNTACTIC_MALFORM,
                AttackVector.SCHEMA_LEAK_INDUCED,
            )
        ]
        if security_cases:
            sec_passed = sum(1 for r in security_cases if r.success)
            comp_sec = (sec_passed / len(security_cases)) * 15.0
        else:
            comp_sec = 15.0

        total_score = min(100.0, max(0.0, comp_pass + comp_severity + comp_lat + comp_sec))

        # Grade assignment
        if total_score >= 95.0:
            grade = "A+"
        elif total_score >= 90.0:
            grade = "A"
        elif total_score >= 80.0:
            grade = "B"
        elif total_score >= 70.0:
            grade = "C"
        elif total_score >= 60.0:
            grade = "D"
        else:
            grade = "F"

        return total_score, grade

    def _empty_summary(self) -> AuditSummary:
        now = datetime.now(timezone.utc)
        return AuditSummary(
            target_model_name=self.target_model_name,
            schema_name=self.inspector.model_name,
            total_tests=0,
            passed_tests=0,
            failed_tests=0,
            error_tests=0,
            success_rate=0.0,
            health_score=0.0,
            health_grade="N/A",
            avg_latency_ms=0.0,
            min_latency_ms=0.0,
            max_latency_ms=0.0,
            p50_latency_ms=0.0,
            p95_latency_ms=0.0,
            p99_latency_ms=0.0,
            started_at=now,
            completed_at=now,
            duration_seconds=0.0,
        )
