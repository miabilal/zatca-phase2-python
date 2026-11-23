"""Invoice data model + the totals math ZATCA validates (EN 16931 + KSA rules)."""
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import ROUND_HALF_UP, Decimal
from enum import Enum
import uuid as uuidlib

TWO = Decimal("0.01")


def money(value) -> Decimal:
    return Decimal(value).quantize(TWO, rounding=ROUND_HALF_UP)


class InvoiceKind(Enum):
    STANDARD = "01"    # B2B, cleared by ZATCA before it reaches the buyer
    SIMPLIFIED = "02"  # B2C, reported to ZATCA within 24 hours


class DocType(Enum):
    INVOICE = "388"
    DEBIT_NOTE = "383"
    CREDIT_NOTE = "381"


# Seller identification schemes allowed by BR-KSA-08.
SELLER_ID_SCHEMES = {"CRN", "MOM", "MLS", "700", "SAG", "OTH"}
# Buyer identification schemes allowed by BR-KSA-14.
BUYER_ID_SCHEMES = {"TIN", "CRN", "MOM", "MLS", "700", "SAG", "NAT", "GCC", "IQA", "PAS", "OTH"}

# UNTDID 4461 payment means codes ZATCA accepts.
PAYMENT_MEANS = {"10": "cash", "30": "credit", "42": "bank account", "48": "bank card", "1": "not defined"}


def _is_vat(v: str) -> bool:
    return len(v) == 15 and v.isdigit() and v[0] == "3" and v[-1] == "3"


@dataclass
class Address:
    street: str
    building_number: str      # 4 digits (BR-KSA-37)
    district: str             # CitySubdivisionName
    city: str
    postal_zone: str          # 5 digits for SA (BR-KSA-66)
    country: str = "SA"
    additional_number: str | None = None  # PlotIdentification, 4 digits

    def validate(self, who: str) -> None:
        if self.country == "SA":
            if not (len(self.building_number) == 4 and self.building_number.isdigit()):
                raise ValueError(f"{who} building number must be 4 digits")
            if not (len(self.postal_zone) == 5 and self.postal_zone.isdigit()):
                raise ValueError(f"{who} postal code must be 5 digits")
        for name in ("street", "district", "city"):
            if not getattr(self, name):
                raise ValueError(f"{who} address needs {name}")


@dataclass
class Party:
    name: str
    address: Address | None = None
    vat_number: str | None = None
    id_scheme: str | None = None  # e.g. CRN
    id_value: str | None = None


@dataclass(frozen=True)
class TaxCategory:
    code: str                         # S standard, Z zero-rated, E exempt, O out of scope
    percent: Decimal
    exemption_code: str | None = None  # VATEX-SA-...
    exemption_reason: str | None = None

    def validate(self) -> None:
        if self.code not in {"S", "Z", "E", "O"}:
            raise ValueError(f"unknown VAT category {self.code}")
        if self.code == "S":
            if self.percent <= 0 or self.exemption_code:
                raise ValueError("standard-rated (S) needs a positive rate and no exemption")
        else:
            if self.percent != 0:
                raise ValueError(f"category {self.code} must have 0% rate")
            if not (self.exemption_code and self.exemption_code.startswith("VATEX-SA-") and self.exemption_reason):
                raise ValueError(f"category {self.code} needs a VATEX-SA exemption code and reason")


VAT_15 = TaxCategory("S", Decimal("15"))


@dataclass
class Line:
    name: str
    quantity: Decimal
    unit_price: Decimal                 # VAT-exclusive
    tax: TaxCategory = VAT_15
    discount: Decimal = Decimal("0")    # line allowance, VAT-exclusive
    discount_reason: str = "discount"
    unit_code: str = "PCE"

    @property
    def net(self) -> Decimal:
        return money(self.quantity * self.unit_price - self.discount)

    @property
    def vat(self) -> Decimal:
        return money(self.net * self.tax.percent / 100)


@dataclass
class DocumentAllowance:
    amount: Decimal
    reason: str = "discount"
    tax: TaxCategory = VAT_15


@dataclass
class TaxSubtotal:
    category: TaxCategory
    taxable: Decimal
    tax: Decimal


@dataclass
class Totals:
    line_extension: Decimal
    allowance_total: Decimal
    tax_exclusive: Decimal
    tax: Decimal
    tax_inclusive: Decimal
    payable: Decimal
    subtotals: list[TaxSubtotal]


@dataclass
class Invoice:
    number: str
    kind: InvoiceKind
    seller: Party
    lines: list[Line]
    issued_at: datetime                 # KSA local time
    icv: int                            # invoice counter value (KSA-16)
    pih: str                            # previous invoice hash (KSA-13)
    doc_type: DocType = DocType.INVOICE
    buyer: Party | None = None
    uuid: str = field(default_factory=lambda: str(uuidlib.uuid4()))
    supply_date: date | None = None     # KSA-5, mandatory on standard invoices
    payment_means: str = "10"
    billing_reference: str | None = None  # original invoice number, for notes
    note_reason: str | None = None        # KSA-10 reason, for notes
    allowances: list[DocumentAllowance] = field(default_factory=list)
    currency: str = "SAR"

    def totals(self) -> Totals:
        line_ext = sum((l.net for l in self.lines), Decimal("0"))
        allow = sum((money(a.amount) for a in self.allowances), Decimal("0"))

        taxable: dict[TaxCategory, Decimal] = {}
        for l in self.lines:
            taxable[l.tax] = taxable.get(l.tax, Decimal("0")) + l.net
        for a in self.allowances:
            taxable[a.tax] = taxable.get(a.tax, Decimal("0")) - money(a.amount)

        # BR-S-09 / BR-Z-09 ...: category tax = taxable x rate, rounded per category.
        subtotals = [TaxSubtotal(cat, amt, money(amt * cat.percent / 100)) for cat, amt in taxable.items()]
        tax = sum((s.tax for s in subtotals), Decimal("0"))
        excl = line_ext - allow
        incl = excl + tax
        # Prepayments are out of scope: ZATCA requires dedicated prepayment
        # adjustment lines (BR-KSA-73/80), not just a PrepaidAmount.
        return Totals(line_ext, allow, excl, tax, incl, incl, subtotals)

    def validate(self) -> None:
        if self.currency != "SAR":
            raise ValueError("only SAR invoices are supported")
        if not self.lines:
            raise ValueError("invoice needs at least one line")
        if self.icv < 1:
            raise ValueError("ICV must be a positive counter")

        s = self.seller
        if not (s.vat_number and _is_vat(s.vat_number)):
            raise ValueError("seller VAT number must be 15 digits starting and ending with 3")
        if s.id_scheme not in SELLER_ID_SCHEMES or not s.id_value:
            raise ValueError(f"seller needs an identifier with scheme in {sorted(SELLER_ID_SCHEMES)}")
        if s.address is None:
            raise ValueError("seller address is required")
        s.address.validate("seller")

        if self.kind is InvoiceKind.STANDARD:
            b = self.buyer
            if b is None or b.address is None:
                raise ValueError("standard invoices need the buyer's name and address")
            b.address.validate("buyer")
            if b.vat_number is None and not (b.id_scheme in BUYER_ID_SCHEMES and b.id_value):
                raise ValueError("standard invoice buyer needs a VAT number or another identifier")
            if self.supply_date is None:
                raise ValueError("standard invoices need a supply date (KSA-5)")
        if self.buyer and self.buyer.vat_number and not _is_vat(self.buyer.vat_number):
            raise ValueError("buyer VAT number must be 15 digits starting and ending with 3")

        if self.doc_type is not DocType.INVOICE and not (self.billing_reference and self.note_reason):
            raise ValueError("credit/debit notes need the original invoice number and a reason")
        if self.payment_means not in PAYMENT_MEANS:
            raise ValueError(f"payment means must be one of {sorted(PAYMENT_MEANS)}")

        for l in self.lines:
            l.tax.validate()
            if l.quantity <= 0 or l.unit_price < 0 or l.discount < 0 or l.net < 0:
                raise ValueError(f"line '{l.name}' has invalid quantity/price/discount")
        for a in self.allowances:
            a.tax.validate()
        t = self.totals()
        if any(st.taxable < 0 for st in t.subtotals) or t.payable < 0:
            raise ValueError("allowances exceed the invoice amount")
