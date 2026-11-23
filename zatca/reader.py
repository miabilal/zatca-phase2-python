"""Read a signed (or ZATCA-cleared) invoice XML back into display data.

The XML is the source of truth, so the demo UI shows exactly what ZATCA saw.
"""
from lxml import etree

from .models import PAYMENT_MEANS
from .qr import decode_qr
from .xml_builder import NS

DOC_TYPES = {"388": "Tax invoice", "381": "Credit note", "383": "Debit note"}
VAT_CATEGORIES = {"S": "Standard rate", "Z": "Zero rated", "E": "Exempt", "O": "Out of scope"}


def _address(party) -> str:
    def t(p):
        return party.xpath(f"string(cac:PostalAddress/{p})", namespaces=NS)
    parts = [f"{t('cbc:BuildingNumber')} {t('cbc:StreetName')}".strip(), t("cbc:CitySubdivisionName"),
             f"{t('cbc:CityName')} {t('cbc:PostalZone')}".strip()]
    return ", ".join(p for p in parts if p)


def _party(root, path):
    found = root.xpath(path, namespaces=NS)
    if not found:
        return None
    p = found[0]

    def t(x):
        return p.xpath(f"string({x})", namespaces=NS)
    return {
        "name": t("cac:PartyLegalEntity/cbc:RegistrationName"),
        "vat": t("cac:PartyTaxScheme/cbc:CompanyID"),
        "id_scheme": t("cac:PartyIdentification/cbc:ID/@schemeID"),
        "id_value": t("cac:PartyIdentification/cbc:ID"),
        "address": _address(p),
    }


def read_invoice(xml: bytes) -> dict:
    root = etree.fromstring(xml)

    def t(path, node=root):
        return node.xpath(f"string({path})", namespaces=NS)

    lines = []
    for ln in root.xpath("cac:InvoiceLine", namespaces=NS):
        lines.append({
            "name": t("cac:Item/cbc:Name", ln),
            "qty": t("cbc:InvoicedQuantity", ln),
            "price": t("cac:Price/cbc:PriceAmount", ln),
            "discount": t("cac:AllowanceCharge/cbc:Amount", ln),
            "net": t("cbc:LineExtensionAmount", ln),
            "vat_rate": t("cac:Item/cac:ClassifiedTaxCategory/cbc:Percent", ln),
            "vat_code": t("cac:Item/cac:ClassifiedTaxCategory/cbc:ID", ln),
            "vat": t("cac:TaxTotal/cbc:TaxAmount", ln),
            "total": t("cac:TaxTotal/cbc:RoundingAmount", ln),
        })
    subtotals = [{
        "category": VAT_CATEGORIES.get(t("cac:TaxCategory/cbc:ID", s), t("cac:TaxCategory/cbc:ID", s)),
        "rate": t("cac:TaxCategory/cbc:Percent", s),
        "taxable": t("cbc:TaxableAmount", s),
        "tax": t("cbc:TaxAmount", s),
        "reason": t("cac:TaxCategory/cbc:TaxExemptionReason", s),
        "reason_code": t("cac:TaxCategory/cbc:TaxExemptionReasonCode", s),
    } for s in root.xpath("cac:TaxTotal/cac:TaxSubtotal", namespaces=NS)]
    allowances = [{"reason": t("cbc:AllowanceChargeReason", a), "amount": t("cbc:Amount", a)}
                  for a in root.xpath("cac:AllowanceCharge", namespaces=NS)]

    qr = t("cac:AdditionalDocumentReference[cbc:ID='QR']/cac:Attachment/cbc:EmbeddedDocumentBinaryObject")
    code = t("cbc:InvoiceTypeCode")
    subtype = t("cbc:InvoiceTypeCode/@name")[:2]
    pm = t("cac:PaymentMeans/cbc:PaymentMeansCode")
    lmt = "cac:LegalMonetaryTotal/cbc:"
    return {
        "number": t("cbc:ID"),
        "uuid": t("cbc:UUID"),
        "issued": f"{t('cbc:IssueDate')} {t('cbc:IssueTime')}",
        "supply_date": t("cac:Delivery/cbc:ActualDeliveryDate"),
        "doc_type": DOC_TYPES.get(code, code),
        "kind": "Simplified (B2C)" if subtype == "02" else "Standard (B2B)",
        "is_note": code in ("381", "383"),
        "billing_reference": t("cac:BillingReference/cac:InvoiceDocumentReference/cbc:ID"),
        "reason": t("cac:PaymentMeans/cbc:InstructionNote"),
        "payment": PAYMENT_MEANS.get(pm, pm),
        "currency": t("cbc:DocumentCurrencyCode"),
        "seller": _party(root, "cac:AccountingSupplierParty/cac:Party"),
        "buyer": _party(root, "cac:AccountingCustomerParty/cac:Party"),
        "lines": lines,
        "allowances": allowances,
        "subtotals": subtotals,
        "totals": {
            "line_extension": t(lmt + "LineExtensionAmount"),
            "allowance": t(lmt + "AllowanceTotalAmount"),
            "tax_exclusive": t(lmt + "TaxExclusiveAmount"),
            "vat": t("cac:TaxTotal[not(cac:TaxSubtotal)]/cbc:TaxAmount"),
            "payable": t(lmt + "PayableAmount"),
        },
        "icv": t("cac:AdditionalDocumentReference[cbc:ID='ICV']/cbc:UUID"),
        "pih": t("cac:AdditionalDocumentReference[cbc:ID='PIH']/cac:Attachment/cbc:EmbeddedDocumentBinaryObject"),
        "hash": t("//ds:Reference[@Id='invoiceSignedData']/ds:DigestValue"),
        "signing_time": t("//xades:SigningTime"),
        "cert_issuer": t("//ds:X509IssuerName"),
        "qr": qr,
        "qr_tags": len(decode_qr(qr)) if qr else 0,
    }
