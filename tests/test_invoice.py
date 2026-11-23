import base64
from datetime import date, datetime
from decimal import Decimal

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from lxml import etree

from zatca.chain import INITIAL_PIH, InvoiceChain
from zatca.csr import generate_private_key
from zatca.models import (Address, DocType, DocumentAllowance, Invoice, InvoiceKind, Line, Party,
                          TaxCategory)
from zatca.qr import decode_qr
from zatca.signing import invoice_hash, sign_invoice
from zatca.xml_builder import NS, build_invoice_xml

D = Decimal
ADDR = Address("King Fahd Road", "2322", "Al Olaya", "Riyadh", "12333", additional_number="1234")
SELLER = Party("Demo Trading Co", ADDR, vat_number="399999999900003", id_scheme="CRN", id_value="1010010000")
BUYER = Party("Buyer Co", ADDR, vat_number="399999999800003")
ZERO = TaxCategory("Z", D("0"), "VATEX-SA-32", "Export of goods")


def make(**kw) -> Invoice:
    base = dict(number="INV1", kind=InvoiceKind.SIMPLIFIED, seller=SELLER, icv=1, pih=INITIAL_PIH,
                issued_at=datetime(2026, 11, 23, 10, 0, 0),
                lines=[Line("Item", D("2"), D("10.00"))])
    base.update(kw)
    return Invoice(**base)


# --- totals -----------------------------------------------------------------

def test_totals_with_line_discount_doc_allowance_and_mixed_categories():
    inv = make(
        lines=[
            Line("Perfume", D("1"), D("250.00")),
            Line("Cream", D("3"), D("19.99"), discount=D("5.00")),  # 59.97 - 5 = 54.97
            Line("Export item", D("1"), D("40.00"), tax=ZERO),
        ],
        allowances=[DocumentAllowance(D("10.00"))],
    )
    t = inv.totals()
    assert t.line_extension == D("344.97")
    assert t.allowance_total == D("10.00")
    assert t.tax_exclusive == D("334.97")
    by_code = {s.category.code: s for s in t.subtotals}
    assert by_code["S"].taxable == D("294.97") and by_code["S"].tax == D("44.25")
    assert by_code["Z"].taxable == D("40.00") and by_code["Z"].tax == D("0.00")
    assert t.tax == D("44.25")
    assert t.tax_inclusive == t.payable == D("379.22")


def test_vat_rounds_half_up_per_category():
    t = make(lines=[Line("A", D("1"), D("0.10"))]).totals()  # 0.015 -> 0.02
    assert t.tax == D("0.02")


# --- validation -------------------------------------------------------------

@pytest.mark.parametrize("kw, msg", [
    (dict(kind=InvoiceKind.STANDARD), "buyer"),
    (dict(kind=InvoiceKind.STANDARD, buyer=BUYER), "supply date"),
    (dict(doc_type=DocType.CREDIT_NOTE), "original invoice"),
    (dict(lines=[Line("X", D("1"), D("5"), tax=TaxCategory("Z", D("0")))]), "VATEX"),
    (dict(lines=[Line("X", D("1"), D("5"), discount=D("6"))]), "invalid"),
    (dict(allowances=[DocumentAllowance(D("100"))]), "exceed"),
    (dict(payment_means="99"), "payment means"),
    (dict(seller=Party("S", ADDR, vat_number="399999999900003")), "identifier"),
])
def test_rejects_invoices_zatca_would_reject(kw, msg):
    with pytest.raises(ValueError, match=msg):
        make(**kw).validate()


def test_standard_credit_note_xml_has_billing_reference_and_reason():
    inv = make(kind=InvoiceKind.STANDARD, buyer=BUYER, supply_date=date(2026, 11, 23),
               doc_type=DocType.CREDIT_NOTE, billing_reference="INV0", note_reason="Item returned")
    root = build_invoice_xml(inv)
    tc = root.find("cbc:InvoiceTypeCode", NS)
    assert (tc.text, tc.get("name")) == ("381", "0100000")
    assert root.findtext("cac:BillingReference/cac:InvoiceDocumentReference/cbc:ID", namespaces=NS) == "INV0"
    assert root.findtext("cac:PaymentMeans/cbc:InstructionNote", namespaces=NS) == "Item returned"
    assert root.findtext("cac:Delivery/cbc:ActualDeliveryDate", namespaces=NS) == "2026-11-23"


def test_top_level_element_order_matches_ubl_schema():
    order = ["UBLExtensions", "ProfileID", "ID", "UUID", "IssueDate", "IssueTime", "InvoiceTypeCode",
             "DocumentCurrencyCode", "TaxCurrencyCode", "BillingReference", "AdditionalDocumentReference",
             "Signature", "AccountingSupplierParty", "AccountingCustomerParty", "Delivery", "PaymentMeans",
             "AllowanceCharge", "TaxTotal", "LegalMonetaryTotal", "InvoiceLine"]
    inv = make(kind=InvoiceKind.STANDARD, buyer=BUYER, supply_date=date(2026, 11, 23),
               doc_type=DocType.DEBIT_NOTE, billing_reference="INV0", note_reason="Price correction",
               allowances=[DocumentAllowance(D("1"))])
    seen = [etree.QName(e).localname for e in build_invoice_xml(inv)]
    positions = [order.index(n) for n in seen]
    assert positions == sorted(positions)


# --- signing ----------------------------------------------------------------

def test_signature_verifies_against_certificate(signer):
    key, cert, cert_b64 = signer
    signed = sign_invoice(build_invoice_xml(make()), key, cert_b64)
    root = etree.fromstring(signed.xml)
    sig = base64.b64decode(root.xpath("//ds:SignatureValue/text()", namespaces=NS)[0])
    # ECDSA over the raw invoice-hash bytes; raises InvalidSignature if wrong
    cert.public_key().verify(sig, base64.b64decode(signed.invoice_hash), ec.ECDSA(hashes.SHA256()))
    assert invoice_hash(root) == signed.invoice_hash
    assert root.xpath("//ds:Reference[@Id='invoiceSignedData']/ds:DigestValue/text()",
                      namespaces=NS)[0] == signed.invoice_hash
    assert root.xpath("//ds:X509SerialNumber/text()", namespaces=NS)[0] == "123456789"


def test_hash_covers_invoice_content_but_not_signature_parts(signer):
    key, _, cert_b64 = signer
    root = build_invoice_xml(make())
    before = invoice_hash(root)
    root.xpath("//ds:SignatureValue", namespaces=NS)[0].text = "anything"
    root.xpath("cac:AdditionalDocumentReference[cbc:ID='QR']//cbc:EmbeddedDocumentBinaryObject",
               namespaces=NS)[0].text = "anything"
    assert invoice_hash(root) == before
    root.find("cbc:ID", NS).text = "INV2"
    assert invoice_hash(root) != before


def test_refuses_certificate_of_another_key(signer):
    _, _, cert_b64 = signer
    with pytest.raises(ValueError, match="does not belong"):
        sign_invoice(build_invoice_xml(make()), generate_private_key(), cert_b64)


def test_simplified_qr_carries_all_nine_tags(signer):
    key, cert, cert_b64 = signer
    signed = sign_invoice(build_invoice_xml(make()), key, cert_b64)
    tags = decode_qr(signed.qr)
    assert sorted(tags) == list(range(1, 10))
    assert tags[1] == b"Demo Trading Co"
    assert tags[2] == b"399999999900003"
    assert tags[3] == b"2026-11-23T10:00:00"
    assert tags[4] == b"23.00" and tags[5] == b"3.00"
    assert tags[6].decode() == signed.invoice_hash
    assert tags[8] == cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert tags[9] == cert.signature


def test_standard_invoice_qr_has_no_tag_9(signer):
    key, _, cert_b64 = signer
    inv = make(kind=InvoiceKind.STANDARD, buyer=BUYER, supply_date=date(2026, 11, 23))
    assert sorted(decode_qr(sign_invoice(build_invoice_xml(inv), key, cert_b64).qr)) == list(range(1, 9))


# --- ICV / PIH chain ----------------------------------------------------------

def test_initial_pih_is_zatcas_constant():
    assert INITIAL_PIH == "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ=="


def test_chain_links_each_invoice_to_the_previous_hash(tmp_path):
    chain = InvoiceChain(tmp_path / "chain.json")
    with chain.reserve() as s1:
        assert (s1.icv, s1.pih) == (1, INITIAL_PIH)
        s1.commit("HASH1")
    with chain.reserve() as s2:
        assert (s2.icv, s2.pih) == (2, "HASH1")
        s2.commit("HASH2")


def test_chain_does_not_advance_when_signing_fails(tmp_path):
    chain = InvoiceChain(tmp_path / "chain.json")
    with pytest.raises(RuntimeError):
        with chain.reserve():
            raise RuntimeError("signing failed")
    with chain.reserve() as s:
        assert (s.icv, s.pih) == (1, INITIAL_PIH)
