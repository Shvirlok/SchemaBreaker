"""Tests for root standalone app.py and /api/run-audit."""

from fastapi.testclient import TestClient
from app import app


client = TestClient(app)


def test_root_index_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "schemabreaker" in response.text.lower()
    assert "schema.py" in response.text
    assert "Run fuzz" in response.text


def test_root_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_api_run_audit_enum_crash():
    enum_crash_code = """
from enum import Enum
from pydantic import BaseModel, Field

class OrderStatus(str, Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    SHIPPED = "SHIPPED"
    DELIVERED = "DELIVERED"
    CANCELLED = "CANCELLED"
    REFUNDED = "REFUNDED"

class CustomerOrder(BaseModel):
    order_id: str = Field(..., pattern=r"^ORD-[0-9]{8}$")
    customer_email: str = Field(...)
    status: OrderStatus = Field(default=OrderStatus.PENDING)
    total_amount: float = Field(..., ge=0.0)
"""
    payload = {
        "schema_definition": enum_crash_code,
        "system_prompt": "Parse orders into CustomerOrder JSON.",
        "iterations": 8,
        "target_model": "gemini-2.5-flash",
        "mock_mode": True,
    }

    response = client.post("/api/run-audit", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_tests"] == 8
    assert "health_score" in data
    assert "recommendations" in data
    assert len(data["results"]) == 8


def test_api_run_audit_markdown_leak():
    markdown_leak_code = """
from enum import Enum
from pydantic import BaseModel, Field

class TicketPriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class SupportTicket(BaseModel):
    ticket_id: str = Field(..., pattern=r"^TCK-[0-9]{5}$")
    customer_email: str = Field(...)
    priority: TicketPriority = Field(default=TicketPriority.MEDIUM)
    issue_description: str = Field(..., min_length=10)
"""
    payload = {
        "schema_definition": markdown_leak_code,
        "system_prompt": "Extract support ticket JSON.",
        "iterations": 6,
        "mock_mode": True,
    }

    response = client.post("/api/run-audit", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_tests"] == 6
    assert "health_score" in data
