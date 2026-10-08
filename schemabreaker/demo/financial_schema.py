"""Financial Loan Application Demo Schema."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class EmploymentStatus(str, Enum):
    FULL_TIME = "FULL_TIME"
    PART_TIME = "PART_TIME"
    SELF_EMPLOYED = "SELF_EMPLOYED"
    RETIRED = "RETIRED"
    UNEMPLOYED = "UNEMPLOYED"


class RiskTier(str, Enum):
    TIER_1_PRIME = "TIER_1_PRIME"
    TIER_2_NEAR_PRIME = "TIER_2_NEAR_PRIME"
    TIER_3_SUBPRIME = "TIER_3_SUBPRIME"
    TIER_4_DECLINED = "TIER_4_DECLINED"


class AssetDeclaration(BaseModel):
    asset_type: str = Field(..., description="Real estate, vehicle, investment, cash")
    estimated_value_usd: float = Field(..., ge=0.0, description="Estimated market value in USD")
    is_encumbered: bool = Field(default=False, description="Whether collateral/mortgage exists on asset")


class LoanApplication(BaseModel):
    """Underwriting evaluation for retail mortgage or personal loan."""
    application_id: str = Field(..., pattern=r"^APP-[0-9]{7}$", description="Loan ID formatted as APP-1234567")
    applicant_name: str = Field(..., min_length=2, max_length=100, description="Full legal applicant name")
    credit_score: int = Field(..., ge=300, le=850, description="FICO / VantageScore credit score between 300 and 850")
    monthly_gross_income: float = Field(..., ge=0.0, description="Total pre-tax monthly income in USD")
    monthly_debt_obligations: float = Field(..., ge=0.0, description="Existing monthly debt payments (credit cards, loans)")
    requested_loan_amount: float = Field(..., gt=500.0, le=2000000.0, description="Requested principal amount")
    loan_term_months: int = Field(..., ge=6, le=360, description="Loan repayment duration in months")
    employment_status: EmploymentStatus = Field(..., description="Current employment situation")
    assets: List[AssetDeclaration] = Field(default_factory=list, description="Declared collateral or liquid assets")
    calculated_dti_ratio: float = Field(..., ge=0.0, le=1.5, description="Debt-to-income ratio (debt/income)")
    assigned_risk_tier: RiskTier = Field(..., description="Calculated underwriting risk tier")
    underwriter_notes: Optional[str] = Field(default=None, max_length=500, description="Special underwriting conditions")
    auto_approval_granted: bool = Field(default=False, description="System instant approval flag")


SYSTEM_PROMPT = """You are a financial credit risk automated underwriter.
Given raw borrower disclosures, bank statement transcripts, and application emails, extract the LoanApplication entity.
Calculate the exact DTI ratio (debt / income), assign the appropriate RiskTier, and ensure strict number range validations."""
