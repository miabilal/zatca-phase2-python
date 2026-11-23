"""Private key + CSR generation in the exact shape ZATCA's onboarding API expects."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

from .config import EGSUnit

# Microsoft "certificate template name" extension; ZATCA reads the
# environment from it.
TEMPLATE_NAME_OID = ObjectIdentifier("1.3.6.1.4.1.311.20.2")
REGISTERED_ADDRESS_OID = ObjectIdentifier("2.5.4.26")


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    # ZATCA requires ECDSA on secp256k1.
    return ec.generate_private_key(ec.SECP256K1())


def _printable_string(value: str) -> bytes:
    """DER-encode an ASN.1 PrintableString (tag 0x13)."""
    raw = value.encode("ascii")
    if len(raw) > 127:
        raise ValueError("template name too long for short-form DER length")
    return bytes([0x13, len(raw)]) + raw


def build_csr(key: ec.EllipticCurvePrivateKey, egs: EGSUnit, template: str) -> x509.CertificateSigningRequest:
    egs.validate()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "SA"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, egs.branch),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, egs.organization),
        x509.NameAttribute(NameOID.COMMON_NAME, egs.common_name),
    ])
    egs_details = x509.Name([
        x509.NameAttribute(NameOID.SURNAME, egs.serial_number),
        x509.NameAttribute(NameOID.USER_ID, egs.vat_number),
        x509.NameAttribute(NameOID.TITLE, egs.invoice_types),
        x509.NameAttribute(REGISTERED_ADDRESS_OID, egs.location),
        x509.NameAttribute(NameOID.BUSINESS_CATEGORY, egs.industry),
    ])
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            x509.UnrecognizedExtension(TEMPLATE_NAME_OID, _printable_string(template)),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DirectoryName(egs_details)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )


def key_to_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def csr_to_pem(csr: x509.CertificateSigningRequest) -> bytes:
    return csr.public_bytes(serialization.Encoding.PEM)
