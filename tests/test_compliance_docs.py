"""The 6 onboarding documents must build, sign and chain offline (the network
check itself is compliance_check.py)."""
from dataclasses import replace
from datetime import datetime
from decimal import Decimal

from lxml import etree

from compliance_check import documents
from zatca.chain import INITIAL_PIH
from zatca.models import DocType, InvoiceKind
from zatca.signing import invoice_hash, sign_invoice
from zatca.xml_builder import NS, build_invoice_xml


def test_all_six_types_covered():
    kinds = {(d.kind, d.doc_type) for d in documents(datetime(2026, 11, 23, 10, 0))}
    assert kinds == {(k, t) for k in InvoiceKind for t in DocType}


def test_standard_invoice_totals_with_exempt_line_and_allowance():
    t = documents(datetime(2026, 11, 23, 10, 0))[0].totals()
    s = {st.category.code: st for st in t.subtotals}
    assert s["S"].taxable == Decimal("1125.00") and s["S"].tax == Decimal("168.75")
    assert s["E"].taxable == Decimal("75.00") and s["E"].tax == Decimal("0.00")
    assert t.payable == Decimal("1368.75")


def test_documents_sign_and_chain(signer):
    key, _, cert_b64 = signer
    pih = INITIAL_PIH
    for icv, doc in enumerate(documents(datetime(2026, 11, 23, 10, 0)), start=1):
        signed = sign_invoice(build_invoice_xml(replace(doc, icv=icv, pih=pih)), key, cert_b64)
        root = etree.fromstring(signed.xml)
        assert root.xpath("cac:AdditionalDocumentReference[cbc:ID='PIH']//cbc:EmbeddedDocumentBinaryObject/text()",
                          namespaces=NS)[0] == pih
        assert invoice_hash(root) == signed.invoice_hash
        pih = signed.invoice_hash
