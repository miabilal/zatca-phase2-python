"""Onboard an EGS unit: generate key + CSR and obtain a compliance CSID.

Usage: python onboard.py [--env sandbox] [--otp 123345]
Outputs go to secrets/ (git-ignored).
"""
import argparse
import json
from pathlib import Path

from zatca.api import CSID, ZatcaClient
from zatca.config import ENVIRONMENTS, SANDBOX_OTP, EGSUnit
from zatca.csr import build_csr, csr_to_pem, generate_private_key, key_to_pem

SECRETS = Path(__file__).parent / "secrets"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=ENVIRONMENTS, default="sandbox")
    parser.add_argument("--otp", default=None, help="OTP from the Fatoora portal (sandbox uses a fixed one)")
    args = parser.parse_args()

    otp = args.otp or (SANDBOX_OTP if args.env == "sandbox" else None)
    if not otp:
        parser.error("--otp is required outside the sandbox")
    csid = onboard(args.env, otp)
    cert = csid.certificate
    print(f"Compliance CSID issued (requestID {csid.request_id})")
    print(f"  subject : {cert.subject.rfc4514_string()}")
    print(f"  issuer  : {cert.issuer.rfc4514_string()}")
    print(f"  valid   : {cert.not_valid_before_utc:%Y-%m-%d} -> {cert.not_valid_after_utc:%Y-%m-%d}")
    print(f"Saved key, CSR and CSID under {SECRETS}/")


def onboard(env_name: str = "sandbox", otp: str = SANDBOX_OTP) -> CSID:
    """Generate the EGS key + CSR and exchange them for a compliance CSID."""
    env = ENVIRONMENTS[env_name]
    SECRETS.mkdir(mode=0o700, exist_ok=True)
    egs = EGSUnit()
    key = generate_private_key()
    csr_pem = csr_to_pem(build_csr(key, egs, env["template"]))

    key_path = SECRETS / "private_key.pem"
    key_path.write_bytes(key_to_pem(key))
    key_path.chmod(0o600)
    (SECRETS / "csr.pem").write_bytes(csr_pem)
    (SECRETS / "egs.json").write_text(json.dumps(egs.__dict__ | {"env": env_name}, indent=2))

    csid = ZatcaClient(env["base_url"]).compliance_csid(csr_pem, otp)
    csid_path = SECRETS / "compliance_csid.json"
    csid_path.write_text(json.dumps(csid.to_dict(), indent=2))
    csid_path.chmod(0o600)
    return csid


if __name__ == "__main__":
    main()
