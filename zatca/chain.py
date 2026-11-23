"""Per-EGS invoice counter (ICV) and previous-invoice-hash (PIH) chain.

Every invoice must carry the next counter and the hash of the invoice issued
just before it. Two invoices signed at the same moment would break the chain,
so the state file is locked from reserving a slot until the new hash is saved.
"""
import base64
import fcntl
import hashlib
import json
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

# ZATCA's defined PIH for the very first invoice: base64 of sha256("0") as hex.
INITIAL_PIH = base64.b64encode(hashlib.sha256(b"0").hexdigest().encode()).decode()


@dataclass
class Slot:
    icv: int
    pih: str
    new_hash: str | None = None

    def commit(self, invoice_hash: str) -> None:
        self.new_hash = invoice_hash


class InvoiceChain:
    def __init__(self, path: Path):
        self.path = Path(path)

    @contextmanager
    def reserve(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.seek(0)
                raw = f.read()
                state = json.loads(raw) if raw.strip() else {"icv": 0, "pih": INITIAL_PIH}
                slot = Slot(icv=state["icv"] + 1, pih=state["pih"])
                yield slot
                if slot.new_hash:  # only advance once the invoice was actually signed
                    f.seek(0)
                    f.truncate()
                    json.dump({"icv": slot.icv, "pih": slot.new_hash}, f)
                    f.flush()
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
