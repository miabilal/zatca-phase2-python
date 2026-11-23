"""Phase 2 QR code: base64 of TLV-encoded tags 1-9, read from the invoice itself."""
import base64

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from lxml import etree

from .xml_builder import NS


def tlv(tags: list[bytes]) -> bytes:
    out = bytearray()
    for tag, value in enumerate(tags, start=1):
        if len(value) > 255:
            raise ValueError(f"QR tag {tag} is {len(value)} bytes; TLV length is one byte")
        out += bytes([tag, len(value)]) + value
    return bytes(out)


def _text(root, path) -> str:
    return root.xpath(f"string({path})", namespaces=NS)


def build_qr(root: etree._Element, invoice_hash: str, signature: str, cert: x509.Certificate) -> str:
    seller = "cac:AccountingSupplierParty/cac:Party"
    tags = [
        _text(root, f"{seller}/cac:PartyLegalEntity/cbc:RegistrationName").encode(),             # 1 seller name
        _text(root, f"{seller}/cac:PartyTaxScheme/cbc:CompanyID").encode(),                      # 2 VAT number
        f"{_text(root, 'cbc:IssueDate')}T{_text(root, 'cbc:IssueTime')}".encode(),               # 3 timestamp
        _text(root, "cac:LegalMonetaryTotal/cbc:PayableAmount").encode(),                        # 4 total with VAT (BT-115)
        _text(root, "cac:TaxTotal[not(cac:TaxSubtotal)]/cbc:TaxAmount").encode(),                # 5 VAT total
        invoice_hash.encode(),                                                                   # 6 invoice hash
        signature.encode(),                                                                      # 7 ECDSA signature
        cert.public_key().public_bytes(                                                          # 8 public key
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    ]
    # Tag 9 (the certificate's own signature) is only for simplified invoices;
    # standard ones get ZATCA's QR at clearance.
    if _text(root, "cbc:InvoiceTypeCode/@name").startswith("02"):
        tags.append(cert.signature)                                                          # 9 cert signature
    if not all(tags[:5]):
        raise ValueError("invoice is missing a field the QR needs (seller name, VAT, date, totals)")
    return base64.b64encode(tlv(tags)).decode()


def decode_qr(qr_b64: str) -> dict[int, bytes]:
    data, out, i = base64.b64decode(qr_b64), {}, 0
    while i < len(data):
        tag, length = data[i], data[i + 1]
        out[tag] = data[i + 2 : i + 2 + length]
        i += 2 + length
    return out
