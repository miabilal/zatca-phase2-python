from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

from zatca.config import EGSUnit
from zatca.csr import TEMPLATE_NAME_OID, build_csr, generate_private_key


def test_csr_has_zatca_fields():
    egs = EGSUnit(egs_uuid="11111111-2222-3333-4444-555555555555")
    csr = build_csr(generate_private_key(), egs, "TSTZATCA-Code-Signing")

    assert csr.is_signature_valid
    assert isinstance(csr.public_key().curve, ec.SECP256K1)
    assert csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "SA"

    template = csr.extensions.get_extension_for_oid(TEMPLATE_NAME_OID).value.value
    assert template == b"\x13\x15TSTZATCA-Code-Signing"

    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dirname = san.get_values_for_type(x509.DirectoryName)[0]
    assert dirname.get_attributes_for_oid(NameOID.USER_ID)[0].value == "399999999900003"
    assert dirname.get_attributes_for_oid(NameOID.TITLE)[0].value == "1100"
    assert dirname.get_attributes_for_oid(NameOID.SURNAME)[0].value == (
        "1-zatca-poc|2-1.0|3-11111111-2222-3333-4444-555555555555"
    )


@pytest.mark.parametrize("vat", ["39999999990000", "199999999900003", "39999999990000X"])
def test_rejects_bad_vat(vat):
    with pytest.raises(ValueError):
        build_csr(generate_private_key(), EGSUnit(vat_number=vat), "TSTZATCA-Code-Signing")
