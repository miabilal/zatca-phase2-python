"""Issue live invoices through the outbox.

  python issue.py b2c      issue a simplified invoice, report it (queued on failure)
  python issue.py b2b      issue a standard invoice, clear it, save ZATCA's stamped copy
  python issue.py retry    resubmit everything due (run from cron every minute)
  python issue.py status   list invoices and flag B2C ones near the 24h deadline
"""
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from compliance_check import documents
from zatca.api import ZatcaClient
from zatca.chain import InvoiceChain
from zatca.config import ENVIRONMENTS
from zatca.keystore import LiveCredentials, load_live
from zatca.outbox import Outbox, Row
from zatca.signing import sign_invoice
from zatca.xml_builder import build_invoice_xml

ROOT = Path(__file__).parent
SECRETS = ROOT / "secrets"
OUT = ROOT / "out" / "live"


class Live:
    """Everything needed to issue and submit live invoices."""

    def __init__(self):
        self.creds: LiveCredentials = load_live(SECRETS)
        self.client = ZatcaClient(ENVIRONMENTS[self.creds.env]["base_url"])
        self.outbox = Outbox(SECRETS / "outbox.sqlite3")

    def issue_demo(self, kind: str) -> Row:
        """Issue one demo invoice ("b2c" or "b2b"), persist it, then submit it."""
        now = datetime.now(timezone.utc)
        riyadh_now = datetime.now(ZoneInfo("Asia/Riyadh")).replace(microsecond=0)
        template = documents(riyadh_now)[3 if kind == "b2c" else 0]
        with InvoiceChain(SECRETS / "live_chain.json").reserve() as slot:
            prefix = "SIM" if kind == "b2c" else "STD"
            inv = replace(template, number=f"{prefix}-{slot.icv:06d}", icv=slot.icv, pih=slot.pih)
            signed = sign_invoice(build_invoice_xml(inv), self.creds.key, self.creds.signing_cert_b64)
            self.outbox.add(inv, signed, now)   # persisted before any network call
            slot.commit(signed.invoice_hash)
        return self.outbox.process(self.client, self.creds.api, now, uuid=signed.uuid)[0]

    def retry_due(self) -> list[Row]:
        return self.outbox.process(self.client, self.creds.api, datetime.now(timezone.utc))


def show(row: Row) -> None:
    print(f"  {row.number:<14} {row.kind.lower():<10} {row.status:<9} attempts={row.attempts}")
    for w in row.warnings:
        print(f"      warning: {w}")
    if row.last_error:
        print(f"      error  : {row.last_error}")


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    live = Live()

    if cmd in ("b2c", "b2b"):
        if live.creds.note:
            print(f"note: {live.creds.note}")
        row = live.issue_demo(cmd)
        show(row)
        OUT.mkdir(parents=True, exist_ok=True)
        if row.cleared_xml:
            path = OUT / f"{row.number}-cleared.xml"
            path.write_bytes(row.cleared_xml)
            print(f"  ZATCA-stamped invoice for the buyer: {path}")
        else:
            (OUT / f"{row.number}.xml").write_bytes(row.signed_xml)
        return 0 if row.status in ("REPORTED", "CLEARED") else 1

    if cmd == "retry":
        rows = live.retry_due()
        print(f"{len(rows)} invoice(s) submitted")
        for r in rows:
            show(r)
    elif cmd == "status":
        for r in live.outbox.all():
            show(r)
    else:
        print(__doc__)
        return 2

    now = datetime.now(timezone.utc)
    for r in live.outbox.at_risk(now):
        print(f"ALERT: {r.number} still unreported {now - r.issued_at} after issue (24h limit)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
