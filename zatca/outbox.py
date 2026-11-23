"""Durable submission queue for signed invoices (SQLite).

- Simplified (B2C): the customer already has the invoice; it must be REPORTED
  within 24 hours, so failures are retried with backoff and flagged before the
  deadline.
- Standard (B2B): must be CLEARED before the buyer receives it; ZATCA's stamped
  copy is stored and is the only version to send. If ZATCA has switched
  clearance off (HTTP 303) the invoice is reported instead.
- Rejections (HTTP 400) are never retried: the data must be fixed and a new
  document issued.
- A row is claimed before sending, so two workers never submit the same invoice.
"""
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .api import CSID, Submission, TransientError, ZatcaClient
from .models import Invoice, InvoiceKind
from .signing import SignedInvoice

BACKOFF = [timedelta(minutes=m) for m in (1, 5, 15, 60, 180)]
CLAIM_LEASE = timedelta(minutes=5)
REPORTING_DEADLINE = timedelta(hours=24)
ALERT_MARGIN = timedelta(hours=4)

SCHEMA = """
CREATE TABLE IF NOT EXISTS invoices (
    uuid            TEXT PRIMARY KEY,
    number          TEXT NOT NULL,
    kind            TEXT NOT NULL,              -- STANDARD | SIMPLIFIED
    invoice_hash    TEXT NOT NULL,
    signed_xml      BLOB NOT NULL,
    issued_at       TEXT NOT NULL,              -- UTC ISO
    status          TEXT NOT NULL,              -- PENDING | REPORTED | CLEARED | REJECTED
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error      TEXT,
    warnings        TEXT,                       -- JSON list
    cleared_xml     BLOB                        -- ZATCA-stamped copy (B2B)
);
CREATE INDEX IF NOT EXISTS invoices_due ON invoices (status, next_attempt_at);
"""


def _utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Row:
    uuid: str
    number: str
    kind: str
    status: str
    attempts: int
    last_error: str | None
    warnings: list[str]
    cleared_xml: bytes | None
    issued_at: datetime
    signed_xml: bytes
    invoice_hash: str


class Outbox:
    def __init__(self, path: Path):
        self.path = path
        self._local = threading.local()
        self.db.executescript(SCHEMA)

    @property
    def db(self) -> sqlite3.Connection:
        """One connection per thread (sqlite3 connections can't be shared across threads)."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, isolation_level=None, timeout=30)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def add(self, invoice: Invoice, signed: SignedInvoice, now: datetime) -> None:
        self.db.execute(
            "INSERT INTO invoices (uuid, number, kind, invoice_hash, signed_xml, issued_at, status, next_attempt_at)"
            " VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?)",
            (signed.uuid, invoice.number, invoice.kind.name, signed.invoice_hash, signed.xml,
             _utc(invoice.issued_at), _utc(now)),
        )

    def get(self, uuid: str) -> Row:
        r = self.db.execute("SELECT * FROM invoices WHERE uuid = ?", (uuid,)).fetchone()
        if r is None:
            raise KeyError(uuid)
        return Row(r["uuid"], r["number"], r["kind"], r["status"], r["attempts"], r["last_error"],
                   json.loads(r["warnings"] or "[]"), r["cleared_xml"], datetime.fromisoformat(r["issued_at"]),
                   r["signed_xml"], r["invoice_hash"])

    def all(self) -> list[Row]:
        return [self.get(r["uuid"]) for r in self.db.execute("SELECT uuid FROM invoices ORDER BY issued_at DESC, rowid DESC")]

    def _claim(self, uuid: str | None, now: datetime) -> list[sqlite3.Row]:
        """Atomically lease due PENDING rows so concurrent workers can't double-send."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            where, args = "status = 'PENDING' AND next_attempt_at <= ?", [_utc(now)]
            if uuid:
                where, args = where + " AND uuid = ?", args + [uuid]
            rows = self.db.execute(f"SELECT * FROM invoices WHERE {where}", args).fetchall()
            for r in rows:
                self.db.execute("UPDATE invoices SET next_attempt_at = ? WHERE uuid = ?",
                                (_utc(now + CLAIM_LEASE), r["uuid"]))
            self.db.execute("COMMIT")
            return rows
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def process(self, client: ZatcaClient, csid: CSID, now: datetime, uuid: str | None = None) -> list[Row]:
        """Submit every due PENDING invoice (or just `uuid`). Returns the rows touched."""
        touched = []
        for r in self._claim(uuid, now):
            args = (r["signed_xml"], r["invoice_hash"], r["uuid"])
            try:
                if r["kind"] == InvoiceKind.STANDARD.name:
                    sub = client.clear(csid, *args)
                    if sub.outcome == "CLEARANCE_OFF":
                        sub = client.report(csid, *args)
                else:
                    sub = client.report(csid, *args)
            except TransientError as e:
                attempts = r["attempts"] + 1
                delay = BACKOFF[min(attempts - 1, len(BACKOFF) - 1)]
                self.db.execute(
                    "UPDATE invoices SET attempts = ?, next_attempt_at = ?, last_error = ? WHERE uuid = ?",
                    (attempts, _utc(now + delay), str(e), r["uuid"]))
            else:
                self._record(r["uuid"], r["attempts"] + 1, sub)
            touched.append(self.get(r["uuid"]))
        return touched

    def _record(self, uuid: str, attempts: int, sub: Submission) -> None:
        if sub.accepted:
            status, error = sub.outcome, None
        elif sub.outcome == "DUPLICATE":
            status, error = "REJECTED", "ZATCA says this invoice was already submitted; check the Fatoora portal"
        else:
            status, error = "REJECTED", "; ".join(sub.errors) or f"HTTP {sub.http_status}: {sub.body}"
        self.db.execute(
            "UPDATE invoices SET status = ?, attempts = ?, last_error = ?, warnings = ?, cleared_xml = ?"
            " WHERE uuid = ?",
            (status, attempts, error, json.dumps(sub.warnings), sub.cleared_xml, uuid))

    def at_risk(self, now: datetime) -> list[Row]:
        """Unreported B2C invoices close to (or past) the 24-hour reporting deadline."""
        cutoff = now - (REPORTING_DEADLINE - ALERT_MARGIN)
        rows = self.db.execute(
            "SELECT uuid FROM invoices WHERE status = 'PENDING' AND kind = 'SIMPLIFIED' AND issued_at <= ?",
            (_utc(cutoff),)).fetchall()
        return [self.get(r["uuid"]) for r in rows]
