"""Local demo dashboard: onboard, run compliance, issue invoices, inspect them.

Usage: python web.py   ->  http://127.0.0.1:8000
"""
import os
from pathlib import Path

import segno
from flask import Flask, Response, abort, flash, redirect, render_template, request, url_for

import compliance_check
import go_live as golive
import onboard as onboarding
from zatca.api import TransientError, ZatcaError
from zatca.reader import read_invoice

ROOT = Path(__file__).parent
SECRETS = ROOT / "secrets"
HOST, PORT = "127.0.0.1", 8000

app = Flask(__name__)
app.secret_key = os.urandom(32)
state = {"live": None, "checks": None}

STATUS = {
    "REPORTED": ("Reported to ZATCA", "ok"),
    "CLEARED": ("Cleared by ZATCA", "ok"),
    "PENDING": ("Waiting to send", "warn"),
    "REJECTED": ("Rejected by ZATCA", "bad"),
}


def live():
    """The issuing service, or None until the device has a production certificate."""
    if state["live"] is None and (SECRETS / "production_csid.json").exists():
        from issue import Live
        state["live"] = Live()
    return state["live"]


def sandbox_cert_warning(text: str) -> bool:
    lv = live()
    return bool(lv and lv.creds.note and text.startswith("certificate-issuer-name"))


app.jinja_env.globals.update(STATUS=STATUS, sandbox_cert_warning=sandbox_cert_warning)


@app.before_request
def same_origin_posts_only():
    if request.method == "POST":
        origin = request.headers.get("Origin")
        if origin and origin not in (f"http://{HOST}:{PORT}", f"http://localhost:{PORT}"):
            abort(403)


def zatca_call(fn, *args):
    try:
        return fn(*args)
    except TransientError as e:
        flash(f"ZATCA could not be reached, please try again ({e})", "bad")
    except ZatcaError as e:
        flash(f"ZATCA refused the request: HTTP {e.status} {e.body}", "bad")
    except golive.ComplianceFailed as e:
        state["checks"] = e.results
        flash("Some compliance checks failed, so ZATCA did not issue a production certificate.", "bad")
    return None


@app.get("/")
def dashboard():
    lv = live()
    rows = []
    if lv:
        for r in lv.outbox.all():
            inv = read_invoice(r.cleared_xml or r.signed_xml)
            rows.append({"row": r, "inv": inv})
    counts = {k: sum(1 for x in rows if x["row"].status == k) for k in STATUS}
    egs = None
    if lv:
        cert = lv.creds.api.certificate
        egs = {"env": lv.creds.env, "note": lv.creds.note,
               "valid_to": f"{cert.not_valid_after_utc:%d %b %Y}"}
    return render_template("dashboard.html", rows=rows, counts=counts, egs=egs,
                           onboarded=(SECRETS / "compliance_csid.json").exists())


@app.post("/setup")
def setup():
    if not (SECRETS / "compliance_csid.json").exists():
        if zatca_call(onboarding.onboard) is None:
            return redirect(url_for("dashboard"))
    result = zatca_call(golive.go_live)
    if result:
        state["checks"], _ = result
        state["live"] = None
        flash("Connected. All 6 compliance checks passed and ZATCA issued the production certificate.", "ok")
        return redirect(url_for("compliance"))
    return redirect(url_for("compliance") if state["checks"] else url_for("dashboard"))


@app.route("/compliance", methods=["GET", "POST"])
def compliance():
    if request.method == "POST":
        state["checks"] = zatca_call(compliance_check.run_checks) or state["checks"]
    if not state["checks"]:
        return redirect(url_for("dashboard"))
    return render_template("compliance.html", checks=state["checks"])


@app.post("/issue/<kind>")
def issue(kind):
    if kind not in ("b2c", "b2b") or not live():
        abort(404)
    row = zatca_call(live().issue_demo, kind)
    if row:
        label, tone = STATUS[row.status]
        flash(f"{row.number}: {label}", tone)
        return redirect(url_for("invoice", uuid=row.uuid))
    return redirect(url_for("dashboard"))


@app.post("/retry")
def retry():
    if not live():
        abort(404)
    rows = zatca_call(live().retry_due)
    if rows is not None:
        flash(f"{len(rows)} waiting invoice(s) sent to ZATCA." if rows else "Nothing is waiting to be sent.", "ok")
    return redirect(url_for("dashboard"))


def _row(uuid):
    if not live():
        abort(404)
    try:
        return live().outbox.get(uuid)
    except KeyError:
        abort(404)


@app.get("/invoice/<uuid>")
def invoice(uuid):
    r = _row(uuid)
    inv = read_invoice(r.cleared_xml or r.signed_xml)
    qr_svg = segno.make(inv["qr"], error="m").svg_inline(scale=3, dark="#111", light="#fff") if inv["qr"] else None
    return render_template("invoice.html", r=r, inv=inv, qr_svg=qr_svg)


@app.get("/invoice/<uuid>/<which>.xml")
def invoice_xml(uuid, which):
    r = _row(uuid)
    data = {"signed": r.signed_xml, "cleared": r.cleared_xml}.get(which)
    if not data:
        abort(404)
    name = f"{r.number}{'-cleared' if which == 'cleared' else ''}.xml"
    return Response(data, mimetype="application/xml",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


if __name__ == "__main__":
    print(f"ZATCA demo running at http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False)
