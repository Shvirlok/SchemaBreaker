"""Clinical Note Extraction Demo Schema."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class TriageLevel(str, Enum):
    RESUSCITATION = "RESUSCITATION"
    EMERGENT = "EMERGENT"
    URGENT = "URGENT"
    SEMI_URGENT = "SEMI_URGENT"
    NON_URGENT = "NON_URGENT"


class VitalSigns(BaseModel):
    heart_rate_bpm: int = Field(..., ge=20, le=260, description="Heart rate in beats per minute")
    blood_pressure_systolic: int = Field(..., ge=40, le=300, description="Systolic mmHg")
    blood_pressure_diastolic: int = Field(..., ge=20, le=200, description="Diastolic mmHg")
    temperature_celsius: float = Field(..., ge=30.0, le=45.0, description="Body temperature in Celsius")
    oxygen_saturation_pct: int = Field(..., ge=50, le=100, description="SpO2 percentage (50-100)")
    respiratory_rate: Optional[int] = Field(default=None, ge=5, le=60, description="Breaths per minute")


class Medication(BaseModel):
    drug_name: str = Field(..., min_length=2, description="Generic or brand medication name")
    dosage: str = Field(..., description="Dosage and unit, e.g., '500mg' or '10ml'")
    frequency: str = Field(..., description="Administration schedule e.g., 'BID', 'TID', 'Once daily'")
    route: str = Field(default="oral", description="Route of administration e.g. oral, IV, IM, topical")


class ClinicalAssessment(BaseModel):
    """Structured extraction of clinical consultation transcript."""
    patient_id: str = Field(..., pattern=r"^PAT-[0-9]{6}$", description="Patient ID formatted as 'PAT-' followed by 6 digits")
    chief_complaint: str = Field(..., min_length=5, description="Primary symptom or reason for visit")
    triage_level: TriageLevel = Field(..., description="Emergency triage category")
    vitals: VitalSigns = Field(..., description="Recorded physiological measurements")
    current_medications: List[Medication] = Field(default_factory=list, description="List of medications patient is currently taking")
    allergies: List[str] = Field(default_factory=list, description="Known drug, food, or environmental allergies")
    icd10_suspected_codes: List[str] = Field(
        ...,
        min_length=1,
        description="One or more ICD-10 diagnostic codes e.g. ['J06.9', 'R05']"
    )
    clinical_notes_summary: str = Field(..., min_length=20, max_length=1000, description="Concise diagnostic summary")
    follow_up_days: Optional[int] = Field(default=None, ge=0, le=365, description="Recommended follow-up timeframe in days")
    requires_immediate_admission: bool = Field(default=False, description="Emergency hospital admission flag")


SYSTEM_PROMPT = """You are an emergency department clinical assistant.
Your job is to read raw clinical consultation transcripts, triage nurse notes, and audio dictation records,
and extract a valid ClinicalAssessment JSON entity adhering strictly to all medical constraints and ICD-10 formatting."""
