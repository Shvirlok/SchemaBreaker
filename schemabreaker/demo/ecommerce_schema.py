"""E-Commerce Transaction Parser Demo Schema."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class OrderStatus(str, Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    SHIPPED = "SHIPPED"
    DELIVERED = "DELIVERED"
    CANCELLED = "CANCELLED"
    REFUNDED = "REFUNDED"


class CurrencyCode(str, Enum):
    USD = "USD"
    EUR = "EUR"
    GBP = "GBP"
    CAD = "CAD"
    JPY = "JPY"


class PaymentMethod(str, Enum):
    CREDIT_CARD = "CREDIT_CARD"
    DEBIT_CARD = "DEBIT_CARD"
    PAYPAL = "PAYPAL"
    APPLE_PAY = "APPLE_PAY"
    CRYPTO = "CRYPTO"


class Address(BaseModel):
    street: str = Field(..., min_length=3, description="Street address including building number")
    city: str = Field(..., min_length=2, description="City name")
    state_province: str = Field(..., description="Two-letter state/province code or full region name")
    postal_code: str = Field(..., min_length=3, max_length=12, description="ZIP or Postal Code")
    country_iso: str = Field(..., min_length=2, max_length=3, description="ISO 3166-1 alpha-2 or alpha-3 code (e.g., US, GBR)")


class OrderItem(BaseModel):
    sku: str = Field(
        ...,
        pattern=r"^[A-Z0-9]{3,4}-[A-Z0-9]{3,4}-[A-Z0-9]{2,4}$",
        description="Standard SKU code, e.g. 'PRD-1024-XL'"
    )
    product_name: str = Field(..., min_length=1, max_length=150, description="Name of the purchased item")
    quantity: int = Field(..., gt=0, le=1000, description="Positive integer quantity purchased")
    unit_price: float = Field(..., ge=0.0, description="Price per unit in transaction currency")
    discount_amount: float = Field(default=0.0, ge=0.0, description="Discount applied per unit")


class PaymentDetails(BaseModel):
    method: PaymentMethod = Field(..., description="Selected payment method")
    last_four: Optional[str] = Field(
        default=None,
        pattern=r"^\d{4}$",
        description="Last 4 digits of card if card was used"
    )
    transaction_id: str = Field(..., min_length=8, description="Gateway transaction reference")
    is_settled: bool = Field(default=True, description="Whether the payment has settled successfully")


class CustomerOrder(BaseModel):
    """Complete structured order model for e-commerce order ingestion."""
    order_id: str = Field(
        ...,
        pattern=r"^ORD-[0-9]{8}$",
        description="Order identifier formatted as 'ORD-' followed by 8 digits"
    )
    customer_email: str = Field(
        ...,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        description="Customer email address"
    )
    customer_phone: Optional[str] = Field(default=None, description="E.164 phone number if provided")
    status: OrderStatus = Field(default=OrderStatus.PENDING, description="Current lifecycle state of the order")
    currency: CurrencyCode = Field(default=CurrencyCode.USD, description="3-letter ISO currency code")
    items: List[OrderItem] = Field(..., min_length=1, description="List of items in the order (at least 1 required)")
    shipping_address: Address = Field(..., description="Physical delivery destination")
    billing_address: Optional[Address] = Field(default=None, description="Billing address if different from shipping")
    payment: PaymentDetails = Field(..., description="Payment transaction breakdown")
    subtotal: float = Field(..., ge=0.0, description="Sum of unit prices * quantities")
    tax_rate: float = Field(..., ge=0.0, le=0.40, description="Tax rate decimal between 0.0 and 0.40 (e.g. 0.0825 for 8.25%)")
    shipping_cost: float = Field(default=0.0, ge=0.0, description="Shipping fee")
    total_amount: float = Field(..., ge=0.0, description="Grand total charged")
    customer_notes: Optional[str] = Field(default=None, max_length=500, description="Special customer instructions")
    tracking_number: Optional[str] = Field(default=None, description="Carrier tracking code if already shipped")


SYSTEM_PROMPT = """You are an e-commerce order ingestion assistant.
Your task is to parse raw natural language order messages, customer emails, customer support transcripts, or API payloads into a strictly valid CustomerOrder JSON object.
Extract all details accurately. If some optional fields are missing, omit them or set them to null.
Ensure SKU codes, order IDs, tax rates, and prices adhere strictly to the schema constraints."""
