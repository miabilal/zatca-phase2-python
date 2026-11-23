"""Build, sign and (optionally) validate a sample simplified (B2C) tax invoice.

Usage: python make_invoice.py [--check]
Needs onboard.py to have run first. Signed XML is written to out/.
"""
import argparse
import base64
import json
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from zoneinfo import ZoneInfo

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from zatca.api import CSID, ZatcaClient
from zatca.chain import InvoiceChain
from zatca.config import ENVIRONMENTS
from demo_data import SELLER, WALK_IN
from zatca.models import DocumentAllowance, Invoice, InvoiceKind, Line
from zatca.qr import decode_qr
from zatca.signing import sign_invoice
from zatca.xml_builder import build_invoice_xml

ROOT = Path(__file__).parent
SECRETS = ROOT / "secrets"
OUT = ROOT / "out"
RIYADH = ZoneInfo("Asia/Riyadh")

QR_NAMES = {1: "seller", 2: "VAT no.", 3: "timestamp", 4: "total", 5: "VAT",
            6: "hash", 7: "signature", 8: "public key", 9: "cert signature"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="validate with ZATCA's compliance API")
    args = parser.parse_args()

    egs = json.loads((SECRETS / "egs.json").read_text())
    csid = CSID.from_dict(json.loads((SECRETS / "compliance_csid.json").read_text()))
    key = load_pem_private_key((SECRETS / "private_key.pem").read_bytes(), password=None)
    cert_b64 = base64.b64decode(csid.binary_security_token).decode()

    with InvoiceChain(SECRETS / "chain.json").reserve() as slot:
        invoice = Invoice(
            number=f"SME{slot.icv:05d}",
            kind=InvoiceKind.SIMPLIFIED,
            seller=SELLER,
            buyer=WALK_IN,
            issued_at=datetime.now(RIYADH).replace(microsecond=0),
            icv=slot.icv,
            pih=slot.pih,
            payment_means="48",  # bank card
            lines=[
                Line("Oud perfume 100ml", Decimal("1"), Decimal("250.00")),
                Line("Hand cream", Decimal("3"), Decimal("19.99"), discount=Decimal("5.00")),
            ],
            allowances=[DocumentAllowance(Decimal("10.00"), reason="coupon")],
        )
        signed = sign_invoice(build_invoice_xml(invoice), key, cert_b64)
        slot.commit(signed.invoice_hash)

    OUT.mkdir(exist_ok=True)
    path = OUT / f"{invoice.number}.xml"
    path.write_bytes(signed.xml)
    t = invoice.totals()
    print(f"{invoice.number}  ICV {invoice.icv}  total {t.tax_inclusive} SAR (VAT {t.tax})")
    print(f"  hash : {signed.invoice_hash}")
    print(f"  file : {path}")
    print("  QR   :")
    for tag, value in decode_qr(signed.qr).items():
        shown = value.decode() if tag <= 5 else f"<{len(value)} bytes>"
        print(f"    {tag} {QR_NAMES[tag]:<15} {shown}")

    if args.check:
        client = ZatcaClient(ENVIRONMENTS[egs["env"]]["base_url"])
        result = client.compliance_check(csid, signed.xml, signed.invoice_hash, signed.uuid)
        print("\nZATCA compliance check:")
        print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
