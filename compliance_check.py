"""Onboarding compliance run: send every document type the EGS is registered for
through ZATCA's compliance check, as required before a production CSID is issued.

For invoice types "1100" that is 6 documents: standard and simplified
invoice, credit note and debit note. They are chained (ICV 1..6, each PIH = the
previous hash) exactly like real invoices.

Usage: python compliance_check.py        (exit code 1 if any document fails)
"""
import json
import sys
from dataclasses import dataclass, replace
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from zoneinfo import ZoneInfo

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from demo_data import BUSINESS_BUYER, EXEMPT_FINANCIAL, SELLER, WALK_IN
from zatca.api import CSID, ZatcaClient
from zatca.chain import INITIAL_PIH
from zatca.config import ENVIRONMENTS
from zatca.models import DocType, DocumentAllowance, Invoice, InvoiceKind, Line
from zatca.signing import sign_invoice
from zatca.xml_builder import build_invoice_xml

ROOT = Path(__file__).parent
SECRETS = ROOT / "secrets"
OUT = ROOT / "out" / "compliance"
D = Decimal


def documents(now: datetime) -> list[Invoice]:
    """The 6 onboarding documents, without ICV/PIH (assigned when chained)."""
    common = dict(seller=SELLER, issued_at=now, icv=0, pih="")
    standard = dict(common, kind=InvoiceKind.STANDARD, buyer=BUSINESS_BUYER,
                    supply_date=now.date(), payment_means="42")
    simplified = dict(common, kind=InvoiceKind.SIMPLIFIED, buyer=WALK_IN, payment_means="48")
    return [
        Invoice(number="STD-INV-1", **standard, lines=[
            Line("Perfume gift sets (carton)", D("10"), D("120.00"), discount=D("50.00")),
            Line("Card processing service", D("1"), D("75.00"), tax=EXEMPT_FINANCIAL),
        ], allowances=[DocumentAllowance(D("25.00"), reason="volume discount")]),
        Invoice(number="STD-CRN-1", **standard, doc_type=DocType.CREDIT_NOTE,
                billing_reference="STD-INV-1", note_reason="2 cartons returned damaged",
                lines=[Line("Perfume gift sets (carton)", D("2"), D("120.00"))]),
        Invoice(number="STD-DBN-1", **standard, doc_type=DocType.DEBIT_NOTE,
                billing_reference="STD-INV-1", note_reason="Shipping charge not invoiced",
                lines=[Line("Freight", D("1"), D("40.00"))]),
        Invoice(number="SIM-INV-1", **simplified, lines=[
            Line("Oud perfume 100ml", D("1"), D("250.00")),
            Line("Hand cream", D("3"), D("19.99"), discount=D("5.00")),
        ], allowances=[DocumentAllowance(D("10.00"), reason="coupon")]),
        Invoice(number="SIM-CRN-1", **simplified, doc_type=DocType.CREDIT_NOTE,
                billing_reference="SIM-INV-1", note_reason="Customer returned hand cream",
                lines=[Line("Hand cream", D("1"), D("19.99"))]),
        Invoice(number="SIM-DBN-1", **simplified, doc_type=DocType.DEBIT_NOTE,
                billing_reference="SIM-INV-1", note_reason="Gift wrapping added after sale",
                lines=[Line("Gift wrapping", D("1"), D("15.00"))]),
    ]


@dataclass
class CheckResult:
    invoice: Invoice
    ok: bool
    status: str
    messages: list[str]


def summarize(result: dict) -> tuple[str, list[str]]:
    v = result.get("validationResults") or {}
    msgs = [f"{m['type']} {m['code']}: {m['message']}"
            for m in (v.get("errorMessages") or []) + (v.get("warningMessages") or [])]
    status = result.get("clearanceStatus") or result.get("reportingStatus") or "-"
    return f"{v.get('status', '?')} / {status}", msgs


def run_checks() -> list[CheckResult]:
    egs = json.loads((SECRETS / "egs.json").read_text())
    csid = CSID.from_dict(json.loads((SECRETS / "compliance_csid.json").read_text()))
    key = load_pem_private_key((SECRETS / "private_key.pem").read_bytes(), password=None)
    client = ZatcaClient(ENVIRONMENTS[egs["env"]]["base_url"])
    OUT.mkdir(parents=True, exist_ok=True)

    now = datetime.now(ZoneInfo("Asia/Riyadh")).replace(microsecond=0)
    pih, results = INITIAL_PIH, []
    for icv, doc in enumerate(documents(now), start=1):
        doc = replace(doc, icv=icv, pih=pih)
        signed = sign_invoice(build_invoice_xml(doc), key, csid.certificate_b64)
        pih = signed.invoice_hash
        (OUT / f"{doc.number}.xml").write_bytes(signed.xml)
        status, msgs = summarize(client.compliance_check(csid, signed.xml, signed.invoice_hash, signed.uuid))
        results.append(CheckResult(doc, status.startswith("PASS"), status, msgs))
    return results


def main() -> int:
    results = run_checks()
    for r in results:
        d = r.invoice
        print(f"{'OK  ' if r.ok else 'FAIL'} {d.number:<10} {d.kind.name.lower():<10} "
              f"{d.doc_type.name.lower().replace('_', ' '):<12} {d.totals().payable:>9} SAR  -> {r.status}")
        for m in r.messages:
            print(f"       {m}")
    print(f"\nSigned XML in {OUT}/")
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
