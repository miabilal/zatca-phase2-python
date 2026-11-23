"""Outbox behaviour against a scripted fake ZATCA (outages, rejections, 303...)."""
import base64
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from compliance_check import documents
from zatca.api import CSID, Submission, TransientError
from zatca.chain import INITIAL_PIH
from zatca.outbox import Outbox
from zatca.signing import sign_invoice
from zatca.xml_builder import build_invoice_xml

T0 = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
CSID_ = CSID("1", "dG9rZW4=", "secret")
REPORTED = Submission(200, {"reportingStatus": "REPORTED", "validationResults": {}})
CLEARED = Submission(200, {"clearanceStatus": "CLEARED", "validationResults": {},
                           "clearedInvoice": base64.b64encode(b"<stamped/>").decode()})
REJECTED = Submission(400, {"reportingStatus": "NOT_REPORTED", "validationResults": {
    "errorMessages": [{"code": "BR-KSA-37", "message": "building number must be 4 digits"}]}})


class FakeZatca:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def _next(self, kind, uuid):
        self.calls.append((kind, uuid))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    def report(self, csid, xml, h, uuid):
        return self._next("report", uuid)

    def clear(self, csid, xml, h, uuid):
        return self._next("clear", uuid)


@pytest.fixture
def outbox(tmp_path):
    return Outbox(tmp_path / "outbox.sqlite3")


@pytest.fixture
def issue(outbox, signer):
    key, _, cert_b64 = signer

    def _issue(b2b=False, issued_at=T0):
        doc = documents(issued_at.astimezone())[0 if b2b else 3]
        doc = replace(doc, icv=1, pih=INITIAL_PIH, issued_at=issued_at)
        signed = sign_invoice(build_invoice_xml(doc), key, cert_b64)
        outbox.add(doc, signed, issued_at)
        return signed.uuid
    return _issue


def test_b2c_reported_first_time(outbox, issue):
    uuid = issue()
    zatca = FakeZatca(REPORTED)
    [row] = outbox.process(zatca, CSID_, T0)
    assert row.status == "REPORTED" and zatca.calls == [("report", uuid)]


def test_outage_is_retried_with_backoff_then_succeeds(outbox, issue):
    issue()
    zatca = FakeZatca(TransientError("HTTP 503"), TransientError("timeout"), REPORTED)

    assert outbox.process(zatca, CSID_, T0)[0].status == "PENDING"
    assert outbox.process(zatca, CSID_, T0 + timedelta(seconds=30)) == []   # not due yet (1 min)
    assert outbox.process(zatca, CSID_, T0 + timedelta(minutes=1))[0].attempts == 2
    assert outbox.process(zatca, CSID_, T0 + timedelta(minutes=4)) == []    # next is 5 min later
    row = outbox.process(zatca, CSID_, T0 + timedelta(minutes=6))[0]
    assert (row.status, row.attempts) == ("REPORTED", 3)
    assert len(zatca.calls) == 3


def test_rejection_is_recorded_and_never_resent(outbox, issue):
    issue()
    zatca = FakeZatca(REJECTED)
    row = outbox.process(zatca, CSID_, T0)[0]
    assert row.status == "REJECTED" and "BR-KSA-37" in row.last_error
    assert outbox.process(zatca, CSID_, T0 + timedelta(days=1)) == []
    assert len(zatca.calls) == 1


def test_b2b_is_cleared_and_stamped_copy_kept(outbox, issue):
    issue(b2b=True)
    row = outbox.process(FakeZatca(CLEARED), CSID_, T0)[0]
    assert row.status == "CLEARED" and row.cleared_xml == b"<stamped/>"


def test_b2b_falls_back_to_reporting_when_clearance_is_off(outbox, issue):
    uuid = issue(b2b=True)
    zatca = FakeZatca(Submission(303, {}), REPORTED)
    row = outbox.process(zatca, CSID_, T0)[0]
    assert row.status == "REPORTED"
    assert zatca.calls == [("clear", uuid), ("report", uuid)]


def test_accepted_invoice_is_never_submitted_again(outbox, issue):
    issue()
    zatca = FakeZatca(REPORTED)
    outbox.process(zatca, CSID_, T0)
    assert outbox.process(zatca, CSID_, T0 + timedelta(hours=1)) == []


def test_claimed_row_is_not_picked_up_by_a_second_worker(outbox, issue):
    uuid = issue()
    assert [r["uuid"] for r in outbox._claim(None, T0)] == [uuid]
    assert outbox._claim(None, T0 + timedelta(minutes=1)) == []    # leased to worker 1


def test_b2c_close_to_24h_deadline_is_flagged(outbox, issue):
    issue(issued_at=T0)
    assert outbox.at_risk(T0 + timedelta(hours=19)) == []
    assert [r.kind for r in outbox.at_risk(T0 + timedelta(hours=21))] == ["SIMPLIFIED"]


def test_usable_from_several_threads(outbox, issue):
    uuid = issue()
    errors = []

    def read():
        try:
            assert outbox.get(uuid).status == "PENDING"
        except Exception as e:  # pragma: no cover - surfaced below
            errors.append(e)
    threads = [threading.Thread(target=read) for _ in range(5)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert errors == []


def test_unknown_invoice_raises_key_error(outbox):
    with pytest.raises(KeyError):
        outbox.get("no-such-uuid")
