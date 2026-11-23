"""Seller / EGS unit details and ZATCA environment settings."""
from dataclasses import dataclass, field
import uuid

# Each ZATCA environment has its own base URL and certificate template name.
ENVIRONMENTS = {
    "sandbox": {
        "base_url": "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal",
        "template": "TSTZATCA-Code-Signing",
    },
    "simulation": {
        "base_url": "https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation",
        "template": "PREZATCA-Code-Signing",
    },
    "production": {
        "base_url": "https://gw-fatoora.zatca.gov.sa/e-invoicing/core",
        "template": "ZATCA-Code-Signing",
    },
}

# The developer portal accepts this fixed OTP; simulation/production need a
# real OTP generated in the taxpayer's Fatoora portal.
SANDBOX_OTP = "123345"


@dataclass
class EGSUnit:
    """One e-invoice generating solution (EGS) unit, e.g. one POS or one backend."""

    vat_number: str = "399999999900003"  # ZATCA's published test VAT number
    organization: str = "Demo Trading Co"
    branch: str = "Riyadh Branch"
    common_name: str = "TST-EGS-399999999900003"
    solution_name: str = "zatca-poc"
    model: str = "1.0"
    egs_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    # 4 flags: standard (B2B), simplified (B2C), future use, future use
    invoice_types: str = "1100"
    location: str = "RRRD2929"  # short national address
    industry: str = "Retail"

    @property
    def serial_number(self) -> str:
        return f"1-{self.solution_name}|2-{self.model}|3-{self.egs_uuid}"

    def validate(self) -> None:
        v = self.vat_number
        if not (len(v) == 15 and v.isdigit() and v[0] == "3" and v[-1] == "3"):
            raise ValueError("VAT number must be 15 digits starting and ending with 3")
        if len(self.invoice_types) != 4 or set(self.invoice_types) - {"0", "1"}:
            raise ValueError("invoice_types must be 4 digits of 0/1, e.g. '1100'")
