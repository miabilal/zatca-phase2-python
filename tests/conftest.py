import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from zatca.csr import generate_private_key


@pytest.fixture(scope="session")
def signer():
    key = generate_private_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "eInvoicing")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(123456789)
            .not_valid_before(now).not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return key, cert, base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
