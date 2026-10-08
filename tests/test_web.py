"""Web API Endpoint Tests."""

from fastapi.testclient import TestClient
from web.app import app


client = TestClient(app)


def test_web_index_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "SchemaBreaker" in response.text
    assert "Target Schema Definition" in response.text
    assert "BREAK MY SCHEMA" in response.text


def test_web_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "SchemaBreaker Web"


def test_web_list_demos():
    response = client.get("/api/demos")
    assert response.status_code == 200
    data = response.json()
    assert "demos" in data
    assert len(data["demos"]) >= 3


def test_web_audit_endpoint_mock():
    sample_code = """
from enum import Enum
from pydantic import BaseModel, Field

class SimpleStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"

class SimpleUser(BaseModel):
    user_id: str = Field(..., pattern=r"^USR-[0-9]{4}$")
    status: SimpleStatus = SimpleStatus.ACTIVE
"""
    payload = {
        "schema_code": sample_code,
        "schema_type": "python",
        "system_prompt": "Extract simple user data.",
        "target_model": "gemini-2.5-flash",
        "num_tests": 5,
        "concurrency": 2,
        "mock_mode": True,
    }

    response = client.post("/api/audit", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_tests"] == 5
    assert "health_score" in data
    assert "results" in data
    assert len(data["results"]) == 5


def test_web_export_html():
    summary_data = {
        "target_model_name": "gemini-2.5-flash",
        "schema_name": "TestModel",
        "total_tests": 1,
        "passed_tests": 1,
        "failed_tests": 0,
        "error_tests": 0,
        "success_rate": 100.0,
        "health_score": 100.0,
        "health_grade": "A+",
        "avg_latency_ms": 150.0,
        "min_latency_ms": 150.0,
        "max_latency_ms": 150.0,
        "p50_latency_ms": 150.0,
        "p95_latency_ms": 150.0,
        "p99_latency_ms": 150.0,
        "results_by_vector": {},
        "results_by_category": {},
        "recommendations": [],
        "results": [],
        "started_at": "2026-10-08T12:00:00Z",
        "completed_at": "2026-10-08T12:00:01Z",
        "duration_seconds": 1.0,
    }

    response = client.post("/api/export/html", json=summary_data)
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "SchemaBreaker Audit Report" in response.text
