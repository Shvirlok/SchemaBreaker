"""Unit tests for Schema and Prompt Loader."""

import json
import pytest
from pydantic import BaseModel, Field
from schemabreaker.core.loader import (
    load_schema_from_path,
    load_schema_from_code,
    _create_model_from_json_schema,
    SchemaInspector,
)
from schemabreaker.demo.ecommerce_schema import CustomerOrder


def test_load_demo_schema():
    inspector = load_schema_from_path("ecommerce")
    assert inspector.model_name == "CustomerOrder"
    assert inspector.model_class == CustomerOrder
    assert "CustomerOrder" in inspector.get_summary_text()
    
    enums_patterns = inspector.get_enums_and_patterns()
    assert "status" in enums_patterns["enums"]
    assert "currency" in enums_patterns["enums"]


def test_load_schema_from_code_string():
    code = """
from pydantic import BaseModel, Field

class TestModel(BaseModel):
    user_id: int = Field(..., gt=0)
    user_name: str = Field(..., min_length=2)

SYSTEM_PROMPT = "Extract test user data."
"""
    inspector = load_schema_from_code(code)
    assert inspector.model_name == "TestModel"
    assert inspector.system_prompt == "Extract test user data."
    
    inst = inspector.model_class(user_id=42, user_name="Alice")
    assert inst.user_id == 42
    assert inst.user_name == "Alice"


def test_create_model_from_json_schema():
    json_schema = {
        "title": "ConfigPayload",
        "type": "object",
        "properties": {
            "api_endpoint": {"type": "string"},
            "retry_count": {"type": "integer"},
            "is_enabled": {"type": "boolean"}
        },
        "required": ["api_endpoint"]
    }
    model_cls = _create_model_from_json_schema(json_schema, "ConfigPayload")
    assert model_cls.__name__ == "ConfigPayload"
    
    # Valid instance
    obj = model_cls(api_endpoint="https://api.test.org", retry_count=3, is_enabled=True)
    assert obj.api_endpoint == "https://api.test.org"
    assert obj.retry_count == 3
