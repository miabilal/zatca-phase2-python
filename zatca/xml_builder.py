"""Build the UBL 2.1 invoice XML in the element order the ZATCA schema requires.

The signature block and QR are created as empty slots so the whitespace of the
final document is fixed before hashing; signing.py fills them in.
"""
from lxml import etree

from .models import DocType, Invoice, Party, TaxCategory, money

NS = {
    "inv": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
    "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
    "ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
    "sig": "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2",
    "sac": "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2",
    "sbc": "urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xades": "http://uri.etsi.org/01903/v1.3.2#",
}

C14N11 = "http://www.w3.org/2006/12/xml-c14n11"
XPATH = "http://www.w3.org/TR/1999/REC-xpath-19991116"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
HASH_EXCLUSIONS = (
    "not(//ancestor-or-self::ext:UBLExtensions)",
    "not(//ancestor-or-self::cac:Signature)",
    "not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])",
)


def _q(tag: str) -> str:
    prefix, local = tag.split(":")
    return f"{{{NS[prefix]}}}{local}"


def _el(parent, tag, text=None, nsmap=None, **attrs):
    e = etree.SubElement(parent, _q(tag), nsmap=nsmap)
    for k, v in attrs.items():
        e.set(k, v)
    if text is not None:
        e.text = str(text)
    return e


def _amt(parent, tag, value, currency):
    return _el(parent, tag, f"{money(value):.2f}", currencyID=currency)


def _signature_slot(root):
    exts = _el(root, "ext:UBLExtensions")
    ext = _el(exts, "ext:UBLExtension")
    _el(ext, "ext:ExtensionURI", "urn:oasis:names:specification:ubl:dsig:enveloped:xades")
    content = _el(ext, "ext:ExtensionContent")
    docsigs = _el(content, "sig:UBLDocumentSignatures",
                  nsmap={k: NS[k] for k in ("sig", "sac", "sbc")})
    info = _el(docsigs, "sac:SignatureInformation")
    _el(info, "cbc:ID", "urn:oasis:names:specification:ubl:signature:1")
    _el(info, "sbc:ReferencedSignatureID", "urn:oasis:names:specification:ubl:signature:Invoice")

    sig = _el(info, "ds:Signature", nsmap={"ds": NS["ds"]}, Id="signature")
    si = _el(sig, "ds:SignedInfo")
    _el(si, "ds:CanonicalizationMethod", Algorithm=C14N11)
    _el(si, "ds:SignatureMethod", Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")
    ref = _el(si, "ds:Reference", Id="invoiceSignedData", URI="")
    transforms = _el(ref, "ds:Transforms")
    for xp in HASH_EXCLUSIONS:
        _el(_el(transforms, "ds:Transform", Algorithm=XPATH), "ds:XPath", xp)
    _el(transforms, "ds:Transform", Algorithm=C14N11)
    _el(ref, "ds:DigestMethod", Algorithm=SHA256)
    _el(ref, "ds:DigestValue", "")
    ref2 = _el(si, "ds:Reference", Type="http://www.w3.org/2000/09/xmldsig#SignatureProperties",
               URI="#xadesSignedProperties")
    _el(ref2, "ds:DigestMethod", Algorithm=SHA256)
    _el(ref2, "ds:DigestValue", "")
    _el(sig, "ds:SignatureValue", "")
    _el(_el(_el(sig, "ds:KeyInfo"), "ds:X509Data"), "ds:X509Certificate", "")

    obj = _el(sig, "ds:Object")
    qp = _el(obj, "xades:QualifyingProperties", nsmap={"xades": NS["xades"]}, Target="signature")
    sp = _el(qp, "xades:SignedProperties", Id="xadesSignedProperties")
    ssp = _el(sp, "xades:SignedSignatureProperties")
    _el(ssp, "xades:SigningTime", "")
    cert = _el(_el(ssp, "xades:SigningCertificate"), "xades:Cert")
    digest = _el(cert, "xades:CertDigest")
    _el(digest, "ds:DigestMethod", Algorithm=SHA256)
    _el(digest, "ds:DigestValue", "")
    serial = _el(cert, "xades:IssuerSerial")
    _el(serial, "ds:X509IssuerName", "")
    _el(serial, "ds:X509SerialNumber", "")


def _tax_category(parent, tag, cat: TaxCategory, with_scheme_ids: bool, with_exemption: bool):
    tc = _el(parent, tag)
    if with_scheme_ids:
        _el(tc, "cbc:ID", cat.code, schemeAgencyID="6", schemeID="UN/ECE 5305")
    else:
        _el(tc, "cbc:ID", cat.code)
    _el(tc, "cbc:Percent", f"{cat.percent:.2f}")
    if with_exemption and cat.exemption_code:
        _el(tc, "cbc:TaxExemptionReasonCode", cat.exemption_code)
        _el(tc, "cbc:TaxExemptionReason", cat.exemption_reason)
    scheme = _el(tc, "cac:TaxScheme")
    if with_scheme_ids:
        _el(scheme, "cbc:ID", "VAT", schemeAgencyID="6", schemeID="UN/ECE 5153")
    else:
        _el(scheme, "cbc:ID", "VAT")


def _party(parent, tag, p: Party | None, buyer: bool):
    party = _el(_el(parent, tag), "cac:Party")
    if p is None:
        return
    if p.id_scheme and p.id_value:
        _el(_el(party, "cac:PartyIdentification"), "cbc:ID", p.id_value, schemeID=p.id_scheme)
    if p.address:
        a = p.address
        addr = _el(party, "cac:PostalAddress")
        _el(addr, "cbc:StreetName", a.street)
        _el(addr, "cbc:BuildingNumber", a.building_number)
        if a.additional_number:
            _el(addr, "cbc:PlotIdentification", a.additional_number)
        _el(addr, "cbc:CitySubdivisionName", a.district)
        _el(addr, "cbc:CityName", a.city)
        _el(addr, "cbc:PostalZone", a.postal_zone)
        _el(_el(addr, "cac:Country"), "cbc:IdentificationCode", a.country)
    if p.vat_number or not buyer:
        pts = _el(party, "cac:PartyTaxScheme")
        if p.vat_number:
            _el(pts, "cbc:CompanyID", p.vat_number)
        _el(_el(pts, "cac:TaxScheme"), "cbc:ID", "VAT")
    _el(_el(party, "cac:PartyLegalEntity"), "cbc:RegistrationName", p.name)


def _doc_ref(root, ref_id, *, uuid=None, embedded=None):
    adr = _el(root, "cac:AdditionalDocumentReference")
    _el(adr, "cbc:ID", ref_id)
    if uuid is not None:
        _el(adr, "cbc:UUID", uuid)
    if embedded is not None:
        _el(_el(adr, "cac:Attachment"), "cbc:EmbeddedDocumentBinaryObject", embedded, mimeCode="text/plain")


def build_invoice_xml(inv: Invoice) -> etree._Element:
    inv.validate()
    cur = inv.currency
    t = inv.totals()

    root = etree.Element(_q("inv:Invoice"), nsmap={None: NS["inv"], **{k: NS[k] for k in ("cac", "cbc", "ext")}})
    _signature_slot(root)
    _el(root, "cbc:ProfileID", "reporting:1.0")
    _el(root, "cbc:ID", inv.number)
    _el(root, "cbc:UUID", inv.uuid)
    _el(root, "cbc:IssueDate", inv.issued_at.strftime("%Y-%m-%d"))
    _el(root, "cbc:IssueTime", inv.issued_at.strftime("%H:%M:%S"))
    # name = invoice subtype (01 standard / 02 simplified) + 5 transaction flags
    # (third party, nominal, export, summary, self-billed), all off here.
    _el(root, "cbc:InvoiceTypeCode", inv.doc_type.value, name=f"{inv.kind.value}00000")
    _el(root, "cbc:DocumentCurrencyCode", cur)
    _el(root, "cbc:TaxCurrencyCode", "SAR")
    if inv.doc_type is not DocType.INVOICE:
        _el(_el(_el(root, "cac:BillingReference"), "cac:InvoiceDocumentReference"), "cbc:ID", inv.billing_reference)
    _doc_ref(root, "ICV", uuid=str(inv.icv))
    _doc_ref(root, "PIH", embedded=inv.pih)
    _doc_ref(root, "QR", embedded="")
    sig = _el(root, "cac:Signature")
    _el(sig, "cbc:ID", "urn:oasis:names:specification:ubl:signature:Invoice")
    _el(sig, "cbc:SignatureMethod", "urn:oasis:names:specification:ubl:dsig:enveloped:xades")

    _party(root, "cac:AccountingSupplierParty", inv.seller, buyer=False)
    _party(root, "cac:AccountingCustomerParty", inv.buyer, buyer=True)
    if inv.supply_date:
        _el(_el(root, "cac:Delivery"), "cbc:ActualDeliveryDate", inv.supply_date.isoformat())
    pm = _el(root, "cac:PaymentMeans")
    _el(pm, "cbc:PaymentMeansCode", inv.payment_means)
    if inv.note_reason:
        _el(pm, "cbc:InstructionNote", inv.note_reason)

    for a in inv.allowances:
        ac = _el(root, "cac:AllowanceCharge")
        _el(ac, "cbc:ChargeIndicator", "false")
        _el(ac, "cbc:AllowanceChargeReason", a.reason)
        _amt(ac, "cbc:Amount", a.amount, cur)
        _tax_category(ac, "cac:TaxCategory", a.tax, with_scheme_ids=True, with_exemption=False)

    # KSA: one TaxTotal with the VAT in SAR only, one with the breakdown.
    _amt(_el(root, "cac:TaxTotal"), "cbc:TaxAmount", t.tax, "SAR")
    tt = _el(root, "cac:TaxTotal")
    _amt(tt, "cbc:TaxAmount", t.tax, cur)
    for st in t.subtotals:
        sub = _el(tt, "cac:TaxSubtotal")
        _amt(sub, "cbc:TaxableAmount", st.taxable, cur)
        _amt(sub, "cbc:TaxAmount", st.tax, cur)
        _tax_category(sub, "cac:TaxCategory", st.category, with_scheme_ids=True, with_exemption=True)

    lmt = _el(root, "cac:LegalMonetaryTotal")
    _amt(lmt, "cbc:LineExtensionAmount", t.line_extension, cur)
    _amt(lmt, "cbc:TaxExclusiveAmount", t.tax_exclusive, cur)
    _amt(lmt, "cbc:TaxInclusiveAmount", t.tax_inclusive, cur)
    _amt(lmt, "cbc:AllowanceTotalAmount", t.allowance_total, cur)
    _amt(lmt, "cbc:PayableAmount", t.payable, cur)

    for i, l in enumerate(inv.lines, start=1):
        il = _el(root, "cac:InvoiceLine")
        _el(il, "cbc:ID", i)
        _el(il, "cbc:InvoicedQuantity", f"{l.quantity:f}", unitCode=l.unit_code)
        _amt(il, "cbc:LineExtensionAmount", l.net, cur)
        if l.discount:
            ac = _el(il, "cac:AllowanceCharge")
            _el(ac, "cbc:ChargeIndicator", "false")
            _el(ac, "cbc:AllowanceChargeReason", l.discount_reason)
            _amt(ac, "cbc:Amount", l.discount, cur)
        ltt = _el(il, "cac:TaxTotal")
        _amt(ltt, "cbc:TaxAmount", l.vat, cur)           # KSA-11
        _amt(ltt, "cbc:RoundingAmount", l.net + l.vat, cur)  # KSA-12
        item = _el(il, "cac:Item")
        _el(item, "cbc:Name", l.name)
        _tax_category(item, "cac:ClassifiedTaxCategory", l.tax, with_scheme_ids=False, with_exemption=False)
        _amt(_el(il, "cac:Price"), "cbc:PriceAmount", l.unit_price, cur)

    etree.indent(root, space="    ")
    return root
