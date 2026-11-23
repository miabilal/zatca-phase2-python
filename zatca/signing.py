"""ZATCA invoice hashing, XAdES signing and QR generation.

Follows ZATCA's "E-Invoice Security Features Implementation Standard":
  1. invoice hash  = base64(sha256(C14N11(invoice minus UBLExtensions, cac:Signature, QR)))
  2. signature     = base64(ECDSA-secp256k1-SHA256 over the raw invoice-hash bytes))
  3. cert hash     = base64(hex(sha256(base64 certificate text)))
  4. signed props  = SigningTime, cert hash, issuer, serial
  5. props hash    = base64(hex(sha256(SignedProperties as the SDK serialises it)))
  6. fill ds:SignedInfo digests, SignatureValue, X509Certificate, then the QR
"""
import base64
import copy
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from lxml import etree

from .qr import build_qr
from .xml_builder import NS

XP = {k: v for k, v in NS.items()}
RIYADH = ZoneInfo("Asia/Riyadh")


@dataclass
class SignedInvoice:
    xml: bytes
    invoice_hash: str
    uuid: str
    qr: str


def _one(root, path):
    found = root.xpath(path, namespaces=XP)
    if len(found) != 1:
        raise ValueError(f"expected exactly one node for {path}, found {len(found)}")
    return found[0]


def _drop_keep_whitespace(el) -> None:
    """Remove an element but keep its tail text, as an XPath node-set filter does."""
    parent, prev = el.getparent(), el.getprevious()
    if el.tail:
        if prev is not None:
            prev.tail = (prev.tail or "") + el.tail
        else:
            parent.text = (parent.text or "") + el.tail
    parent.remove(el)


def invoice_hash(root: etree._Element) -> str:
    doc = copy.deepcopy(root)
    for path in ("ext:UBLExtensions", "cac:Signature", "cac:AdditionalDocumentReference[cbc:ID='QR']"):
        for el in doc.xpath(path, namespaces=XP):
            _drop_keep_whitespace(el)
    # C14N 1.0 and 1.1 only differ on xml:id/xml:base, which UBL invoices never use.
    canonical = etree.tostring(doc, method="c14n", exclusive=False, with_comments=False)
    return base64.b64encode(hashlib.sha256(canonical).digest()).decode()


def _b64_hex_sha256(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).hexdigest().encode()).decode()


_EMPTY_ELEMENT = re.compile(r"<([\w:.-]+)([^<>]*)></\1>")


def signed_properties_hash(signed_props: etree._Element) -> str:
    """Digest of xades:SignedProperties exactly as ZATCA's SDK computes it.

    The SDK hashes dom4j's asXML() of the element, not standard C14N: it is
    exclusive C14N (namespaces declared where first used) but with empty
    elements self-closed, e.g. <ds:DigestMethod .../>. Verified byte-for-byte
    against SDK output in tests/test_sdk_parity.py.
    """
    c14n = etree.tostring(signed_props, method="c14n", exclusive=True, with_comments=False).decode()
    return _b64_hex_sha256(_EMPTY_ELEMENT.sub(r"<\1\2/>", c14n).encode())


def _issuer_name(cert: x509.Certificate) -> str:
    # Java/ZATCA order: most specific RDN first, joined by ", "
    return ", ".join(rdn.rfc4514_string() for rdn in reversed(cert.issuer.rdns))


def sign_invoice(
    root: etree._Element,
    private_key: ec.EllipticCurvePrivateKey,
    certificate_b64: str,
    signing_time: datetime | None = None,
) -> SignedInvoice:
    """Sign a built invoice in place and return the final XML + hash."""
    cert = x509.load_der_x509_certificate(base64.b64decode(certificate_b64))
    if cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ):
        raise ValueError("certificate does not belong to this private key")

    inv_hash = invoice_hash(root)
    signature = base64.b64encode(
        private_key.sign(base64.b64decode(inv_hash), ec.ECDSA(hashes.SHA256()))
    ).decode()

    sp = "ext:UBLExtensions//xades:SignedProperties"
    # KSA local time, no zone suffix: the format ZATCA itself writes when stamping.
    when = (signing_time or datetime.now(RIYADH)).strftime("%Y-%m-%dT%H:%M:%S")
    _one(root, f"{sp}//xades:SigningTime").text = when
    _one(root, f"{sp}//xades:CertDigest/ds:DigestValue").text = _b64_hex_sha256(certificate_b64.encode())
    _one(root, f"{sp}//ds:X509IssuerName").text = _issuer_name(cert)
    _one(root, f"{sp}//ds:X509SerialNumber").text = str(cert.serial_number)

    props_hash = signed_properties_hash(_one(root, sp))

    si = "ext:UBLExtensions//ds:SignedInfo"
    _one(root, f"{si}/ds:Reference[@Id='invoiceSignedData']/ds:DigestValue").text = inv_hash
    _one(root, f"{si}/ds:Reference[@URI='#xadesSignedProperties']/ds:DigestValue").text = props_hash
    _one(root, "ext:UBLExtensions//ds:SignatureValue").text = signature
    _one(root, "ext:UBLExtensions//ds:X509Certificate").text = certificate_b64

    qr = build_qr(root, inv_hash, signature, cert)
    _one(root, "cac:AdditionalDocumentReference[cbc:ID='QR']//cbc:EmbeddedDocumentBinaryObject").text = qr

    # The hash must not move when the excluded parts are filled in.
    if invoice_hash(root) != inv_hash:
        raise AssertionError("invoice hash changed after signing; excluded nodes leaked into the hash")

    xml = b'<?xml version="1.0" encoding="UTF-8"?>\n' + etree.tostring(root, encoding="UTF-8")
    return SignedInvoice(xml=xml, invoice_hash=inv_hash, uuid=_one(root, "cbc:UUID").text, qr=qr)
