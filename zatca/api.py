"""Thin client for ZATCA's Fatoora e-invoicing API."""
import base64
from dataclasses import dataclass, field

import requests
from cryptography import x509


class ZatcaError(Exception):
    """A response that retrying will not fix (bad credentials, malformed request...)."""

    def __init__(self, status: int, body):
        super().__init__(f"ZATCA returned HTTP {status}: {body}")
        self.status = status
        self.body = body


class TransientError(Exception):
    """Network failure, timeout, rate limit or ZATCA-side 5xx: safe to retry later."""


@dataclass
class CSID:
    """A cryptographic stamp identifier: the certificate ZATCA issued + its API secret."""

    request_id: str
    binary_security_token: str  # base64 of the base64-DER certificate
    secret: str

    @property
    def certificate_b64(self) -> str:
        return base64.b64decode(self.binary_security_token).decode()

    @property
    def certificate(self) -> x509.Certificate:
        return x509.load_der_x509_certificate(base64.b64decode(self.certificate_b64))

    @property
    def basic_auth(self) -> tuple[str, str]:
        return (self.binary_security_token, self.secret)

    def to_dict(self) -> dict:
        return {
            "requestID": self.request_id,
            "binarySecurityToken": self.binary_security_token,
            "secret": self.secret,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CSID":
        return cls(str(d["requestID"]), d["binarySecurityToken"], d["secret"])


@dataclass
class Submission:
    """ZATCA's answer to a reporting or clearance call."""

    http_status: int
    body: dict = field(default_factory=dict)

    @property
    def outcome(self) -> str:
        """REPORTED / CLEARED / NOT_REPORTED / NOT_CLEARED / CLEARANCE_OFF / DUPLICATE"""
        if self.http_status == 303:
            return "CLEARANCE_OFF"
        if self.http_status == 409:
            return "DUPLICATE"
        return self.body.get("clearanceStatus") or self.body.get("reportingStatus") or "UNKNOWN"

    @property
    def accepted(self) -> bool:
        return self.outcome in ("REPORTED", "CLEARED")

    def _messages(self, key: str) -> list[str]:
        v = self.body.get("validationResults") or {}
        return [f"{m['code']}: {m['message']}" for m in v.get(key) or []]

    @property
    def errors(self) -> list[str]:
        return self._messages("errorMessages")

    @property
    def warnings(self) -> list[str]:
        return self._messages("warningMessages")

    @property
    def cleared_xml(self) -> bytes | None:
        """For B2B: ZATCA's stamped copy, the only version the buyer may receive."""
        b64 = self.body.get("clearedInvoice")
        return base64.b64decode(b64) if b64 else None


class ZatcaClient:
    def __init__(self, base_url: str, timeout: float = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, path: str, json: dict, headers: dict | None = None, auth=None,
                 ok: tuple[int, ...] = (200, 202)) -> tuple[int, dict]:
        h = {
            "Accept": "application/json",
            "Accept-Language": "en",
            "Accept-Version": "V2",
            "Content-Type": "application/json",
            **(headers or {}),
        }
        try:
            resp = requests.post(f"{self.base_url}{path}", json=json, headers=h, auth=auth,
                                 timeout=self.timeout, allow_redirects=False)
        except (requests.ConnectionError, requests.Timeout) as e:
            raise TransientError(f"{type(e).__name__}: {e}") from e
        try:
            body = resp.json() if resp.content else {}
        except ValueError:
            body = {"raw": resp.text}
        if resp.status_code == 429 or resp.status_code >= 500:
            raise TransientError(f"HTTP {resp.status_code}: {body}")
        if resp.status_code not in ok:
            raise ZatcaError(resp.status_code, body)
        return resp.status_code, body

    @staticmethod
    def _invoice_body(xml: bytes, invoice_hash: str, uuid: str) -> dict:
        return {"invoiceHash": invoice_hash, "uuid": uuid, "invoice": base64.b64encode(xml).decode()}

    # --- onboarding --------------------------------------------------------

    def compliance_csid(self, csr_pem: bytes, otp: str) -> CSID:
        """Exchange a CSR + OTP for a compliance certificate."""
        _, body = self._request("/compliance", json={"csr": base64.b64encode(csr_pem).decode()},
                                headers={"OTP": otp})
        return CSID(str(body["requestID"]), body["binarySecurityToken"], body["secret"])

    def compliance_check(self, csid: CSID, xml: bytes, invoice_hash: str, uuid: str) -> dict:
        """Run ZATCA's full validator on one document. HTTP 400 carries the
        validation errors, so it is returned rather than raised."""
        _, body = self._request("/compliance/invoices", json=self._invoice_body(xml, invoice_hash, uuid),
                                auth=csid.basic_auth, ok=(200, 202, 400))
        return body

    def production_csid(self, compliance: CSID) -> CSID:
        """Exchange a compliance CSID (after all compliance checks pass) for the production one."""
        _, body = self._request("/production/csids",
                                json={"compliance_request_id": compliance.request_id},
                                auth=compliance.basic_auth)
        return CSID(str(body["requestID"]), body["binarySecurityToken"], body["secret"])

    # --- live invoicing ----------------------------------------------------

    def report(self, csid: CSID, xml: bytes, invoice_hash: str, uuid: str) -> Submission:
        """B2C: report a simplified document (within 24h of issuing it)."""
        status, body = self._request("/invoices/reporting/single",
                                     json=self._invoice_body(xml, invoice_hash, uuid),
                                     headers={"Clearance-Status": "0"}, auth=csid.basic_auth,
                                     ok=(200, 202, 400, 409))
        return Submission(status, body)

    def clear(self, csid: CSID, xml: bytes, invoice_hash: str, uuid: str) -> Submission:
        """B2B: get a standard document cleared before it is shared with the buyer.

        303 means ZATCA has switched clearance off for this taxpayer; the caller
        must then report the invoice instead.
        """
        status, body = self._request("/invoices/clearance/single",
                                     json=self._invoice_body(xml, invoice_hash, uuid),
                                     headers={"Clearance-Status": "1"}, auth=csid.basic_auth,
                                     ok=(200, 202, 303, 400, 409))
        return Submission(status, body)
