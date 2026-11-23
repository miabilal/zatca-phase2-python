"""Byte-for-byte parity with ZATCA's official Java SDK.

tests/fixtures/sdk_signed_invoice.xml is one of our invoices signed by the
ZATCA SDK itself (`fatoora -sign`). Every value the SDK wrote must be
reproduced by our code.
"""
import base64
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from lxml import etree

from zatca.signing import _b64_hex_sha256, _issuer_name, invoice_hash, signed_properties_hash
from zatca.xml_builder import NS

FIXTURE = Path(__file__).parent / "fixtures" / "sdk_signed_invoice.xml"
ROOT = etree.parse(str(FIXTURE)).getroot()


def _x(path):
    return ROOT.xpath(path, namespaces=NS)


CERT_B64 = "".join(_x("//ds:X509Certificate/text()")[0].split())
CERT = x509.load_der_x509_certificate(base64.b64decode(CERT_B64))


def test_invoice_hash_matches_sdk():
    assert invoice_hash(ROOT) == _x("//ds:Reference[@Id='invoiceSignedData']/ds:DigestValue/text()")[0]


def test_signed_properties_hash_matches_sdk():
    sdk = _x("//ds:Reference[@URI='#xadesSignedProperties']/ds:DigestValue/text()")[0]
    assert signed_properties_hash(_x("//xades:SignedProperties")[0]) == sdk


def test_certificate_hash_issuer_and_serial_match_sdk():
    assert _b64_hex_sha256(CERT_B64.encode()) == _x("//xades:CertDigest/ds:DigestValue/text()")[0]
    assert _issuer_name(CERT) == _x("//ds:X509IssuerName/text()")[0]
    assert str(CERT.serial_number) == _x("//ds:X509SerialNumber/text()")[0]


def test_sdk_signature_is_ecdsa_over_invoice_hash_bytes():
    digest = base64.b64decode(invoice_hash(ROOT))
    CERT.public_key().verify(base64.b64decode(_x("//ds:SignatureValue/text()")[0]), digest,
                             ec.ECDSA(hashes.SHA256()))
