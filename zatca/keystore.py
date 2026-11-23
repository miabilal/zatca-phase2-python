"""Loads the EGS key and certificates saved by onboard.py / go_live.py."""
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .api import CSID


def _spki(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


@dataclass
class LiveCredentials:
    env: str
    key: ec.EllipticCurvePrivateKey
    api: CSID                # authenticates reporting/clearance calls
    signing_cert_b64: str    # certificate embedded in the signed XML
    note: str | None = None


def load_live(secrets: Path) -> LiveCredentials:
    egs = json.loads((secrets / "egs.json").read_text())
    key = serialization.load_pem_private_key((secrets / "private_key.pem").read_bytes(), password=None)
    path = secrets / "production_csid.json"
    if not path.exists():
        raise SystemExit("No production CSID yet: run go_live.py first")
    prod = CSID.from_dict(json.loads(path.read_text()))

    if _spki(prod.certificate.public_key()) == _spki(key.public_key()):
        return LiveCredentials(egs["env"], key, prod, prod.certificate_b64)

    # ZATCA's developer portal hands every caller the same sample production
    # certificate, which can't match our key. Only there, sign with our
    # compliance certificate. Anywhere else this is a hard error.
    if egs["env"] != "sandbox":
        raise SystemExit("Production certificate does not match this EGS private key")
    comp = CSID.from_dict(json.loads((secrets / "compliance_csid.json").read_text()))
    return LiveCredentials(egs["env"], key, prod, comp.certificate_b64,
                           note="sandbox: signing with compliance cert (portal issues a sample production cert)")
