"""Demo schemas registry for SchemaBreaker."""

from typing import Dict, Tuple, Type
from pydantic import BaseModel

from schemabreaker.demo.ecommerce_schema import CustomerOrder, SYSTEM_PROMPT as ECOMMERCE_PROMPT
from schemabreaker.demo.clinical_schema import ClinicalAssessment, SYSTEM_PROMPT as CLINICAL_PROMPT
from schemabreaker.demo.financial_schema import LoanApplication, SYSTEM_PROMPT as FINANCIAL_PROMPT

DEMO_REGISTRY: Dict[str, Tuple[Type[BaseModel], str, str]] = {
    "ecommerce": (
        CustomerOrder,
        ECOMMERCE_PROMPT,
        "E-Commerce Transaction Parser (Nested Items, SKUs, ISO Currency, Address, Strict Enums)"
    ),
    "clinical": (
        ClinicalAssessment,
        CLINICAL_PROMPT,
        "Clinical Note Extraction (Patient Vitals, Medication Dosage, ICD-10 Codes, Triage)"
    ),
    "financial": (
        LoanApplication,
        FINANCIAL_PROMPT,
        "Financial Underwriting (DTI Calculations, Credit Score Bounds, Risk Tiers)"
    ),
}

def get_demo_schema(name: str = "ecommerce") -> Tuple[Type[BaseModel], str, str]:
    """Retrieve demo model class, system prompt, and description."""
    if name not in DEMO_REGISTRY:
        keys = ", ".join(DEMO_REGISTRY.keys())
        raise ValueError(f"Unknown demo schema '{name}'. Available: {keys}")
    return DEMO_REGISTRY[name]
