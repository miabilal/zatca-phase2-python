"""Final onboarding step: pass the compliance checks, then obtain the production CSID.

Usage: python go_live.py
"""
import json
import sys
from pathlib import Path

import compliance_check
from zatca.api import CSID, ZatcaClient
from zatca.config import ENVIRONMENTS

SECRETS = Path(__file__).parent / "secrets"


class ComplianceFailed(Exception):
    def __init__(self, results):
        super().__init__("compliance checks failed; ZATCA will not issue a production CSID")
        self.results = results


def go_live() -> tuple[list, CSID]:
    """Run the 6 compliance checks; if all pass, request and save the production CSID."""
    results = compliance_check.run_checks()
    if not all(r.ok for r in results):
        raise ComplianceFailed(results)
    egs = json.loads((SECRETS / "egs.json").read_text())
    compliance = CSID.from_dict(json.loads((SECRETS / "compliance_csid.json").read_text()))
    prod = ZatcaClient(ENVIRONMENTS[egs["env"]]["base_url"]).production_csid(compliance)
    path = SECRETS / "production_csid.json"
    path.write_text(json.dumps(prod.to_dict(), indent=2))
    path.chmod(0o600)
    return results, prod


def main() -> int:
    print("Running compliance checks...")
    try:
        results, prod = go_live()
    except ComplianceFailed as e:
        for r in e.results:
            print(f"{'OK  ' if r.ok else 'FAIL'} {r.invoice.number:<10} {r.status}")
            for m in r.messages:
                print(f"       {m}")
        print(e)
        return 1
    for r in results:
        print(f"OK   {r.invoice.number:<10} {r.status}")
    cert = prod.certificate
    print(f"\nProduction CSID issued (requestID {prod.request_id})")
    print(f"  subject : {cert.subject.rfc4514_string()}")
    print(f"  valid   : {cert.not_valid_before_utc:%Y-%m-%d} -> {cert.not_valid_after_utc:%Y-%m-%d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
