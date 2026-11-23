"""Fictional seller/buyer used by the demo scripts (ZATCA's published test VAT numbers)."""
from decimal import Decimal

from zatca.models import Address, Party, TaxCategory

SELLER = Party(
    name="Demo Trading Co",
    vat_number="399999999900003",
    id_scheme="CRN",
    id_value="1010010000",
    address=Address(
        street="King Fahd Road",
        building_number="2322",
        additional_number="1234",
        district="Al Olaya",
        city="Riyadh",
        postal_zone="12333",
    ),
)

BUSINESS_BUYER = Party(
    name="Fatoora Samples LTD",
    vat_number="399999999800003",
    address=Address(
        street="Salah Al-Din",
        building_number="1111",
        district="Al-Murooj",
        city="Riyadh",
        postal_zone="12222",
    ),
)

WALK_IN = Party(name="Walk-in customer")

EXEMPT_FINANCIAL = TaxCategory(
    "E", Decimal("0"), "VATEX-SA-29",
    "Financial services mentioned in Article 29 of the VAT Regulations",
)
