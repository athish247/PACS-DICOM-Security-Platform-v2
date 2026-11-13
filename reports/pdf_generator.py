"""
reports/pdf_generator.py
Professional PDF report generator for PACS/DICOM Security Assessment Platform.
Uses ReportLab platypus for structured document generation.
"""

from __future__ import annotations

import io
import os
from collections import Counter, OrderedDict
from datetime import datetime
from typing import Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, inch
from reportlab.platypus import (
    BaseDocTemplate,
    FrameBreak,
    HRFlowable,
    Image,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Frame,
)
from reportlab.platypus.flowables import HRFlowable

from models.findings import AssessmentResult, Finding, Severity

# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------

SEVERITY_COLORS: Dict[str, colors.Color] = {
    Severity.CRITICAL.value: colors.HexColor("#C0392B"),
    Severity.HIGH.value:     colors.HexColor("#E67E22"),
    Severity.MEDIUM.value:   colors.HexColor("#F1C40F"),
    Severity.LOW.value:      colors.HexColor("#F9E79F"),
    Severity.INFORMATIONAL.value: colors.HexColor("#BDC3C7"),
}

SEVERITY_TEXT_COLORS: Dict[str, colors.Color] = {
    Severity.CRITICAL.value: colors.white,
    Severity.HIGH.value:     colors.white,
    Severity.MEDIUM.value:   colors.black,
    Severity.LOW.value:      colors.black,
    Severity.INFORMATIONAL.value: colors.black,
}

BRAND_BLUE = colors.HexColor("#1A3A5C")
BRAND_LIGHT = colors.HexColor("#ECF0F1")
DARK_GREY = colors.HexColor("#2C3E50")


# ---------------------------------------------------------------------------
# Severity ordering for priority sort
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFORMATIONAL.value: 4,
}


# ---------------------------------------------------------------------------
# IP anonymizer
# ---------------------------------------------------------------------------

class _IpAnonymizer:
    """Replaces IP/hostname strings with SYSTEM-N labels deterministically."""

    def __init__(self) -> None:
        self._map: Dict[str, str] = {}
        self._counter = 0

    def anonymize(self, host: str) -> str:
        if host not in self._map:
            self._counter += 1
            self._map[host] = f"SYSTEM-{self._counter}"
        return self._map[host]


# ---------------------------------------------------------------------------
# Style helpers
# ---------------------------------------------------------------------------

def _build_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    styles: Dict[str, ParagraphStyle] = {}

    styles["cover_title"] = ParagraphStyle(
        "cover_title",
        parent=base["Title"],
        fontSize=28,
        textColor=colors.white,
        spaceAfter=12,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    )
    styles["cover_subtitle"] = ParagraphStyle(
        "cover_subtitle",
        parent=base["Normal"],
        fontSize=14,
        textColor=colors.HexColor("#BDC3C7"),
        spaceAfter=8,
        alignment=TA_CENTER,
    )
    styles["cover_meta"] = ParagraphStyle(
        "cover_meta",
        parent=base["Normal"],
        fontSize=11,
        textColor=colors.white,
        spaceAfter=6,
        alignment=TA_CENTER,
    )
    styles["classification"] = ParagraphStyle(
        "classification",
        parent=base["Normal"],
        fontSize=13,
        textColor=colors.white,
        backColor=colors.HexColor("#C0392B"),
        spaceAfter=4,
        spaceBefore=4,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    )
    styles["section_heading"] = ParagraphStyle(
        "section_heading",
        parent=base["Heading1"],
        fontSize=16,
        textColor=BRAND_BLUE,
        spaceAfter=10,
        spaceBefore=14,
        fontName="Helvetica-Bold",
        borderPad=4,
    )
    styles["subsection_heading"] = ParagraphStyle(
        "subsection_heading",
        parent=base["Heading2"],
        fontSize=12,
        textColor=DARK_GREY,
        spaceAfter=6,
        spaceBefore=8,
        fontName="Helvetica-Bold",
    )
    styles["body"] = ParagraphStyle(
        "body",
        parent=base["Normal"],
        fontSize=10,
        textColor=DARK_GREY,
        spaceAfter=4,
        leading=14,
    )
    styles["code"] = ParagraphStyle(
        "code",
        parent=base["Code"],
        fontSize=8,
        textColor=DARK_GREY,
        backColor=colors.HexColor("#F4F6F7"),
        spaceAfter=4,
        leading=12,
        fontName="Courier",
    )
    styles["table_header"] = ParagraphStyle(
        "table_header",
        parent=base["Normal"],
        fontSize=9,
        textColor=colors.white,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    )
    styles["table_cell"] = ParagraphStyle(
        "table_cell",
        parent=base["Normal"],
        fontSize=8,
        textColor=DARK_GREY,
        leading=11,
    )
    styles["severity_badge"] = ParagraphStyle(
        "severity_badge",
        parent=base["Normal"],
        fontSize=8,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    )
    styles["footer"] = ParagraphStyle(
        "footer",
        parent=base["Normal"],
        fontSize=8,
        textColor=colors.grey,
        alignment=TA_CENTER,
    )
    return styles


# ---------------------------------------------------------------------------
# Page decorators
# ---------------------------------------------------------------------------

def _header_footer(canvas, doc):
    """Draw header and footer on every non-cover page."""
    canvas.saveState()
    page_w, page_h = doc.pagesize

    # Classification banner at top
    canvas.setFillColor(colors.HexColor("#C0392B"))
    canvas.rect(0, page_h - 20, page_w, 20, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawCentredString(page_w / 2, page_h - 14, "CONFIDENTIAL — AUTHORIZED USE ONLY")

    # Footer line
    canvas.setStrokeColor(BRAND_BLUE)
    canvas.setLineWidth(0.5)
    canvas.line(2 * cm, 1.8 * cm, page_w - 2 * cm, 1.8 * cm)

    canvas.setFillColor(colors.grey)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(2 * cm, 1.2 * cm, "PACS/DICOM Security Assessment Platform v2.0")
    canvas.drawCentredString(page_w / 2, 1.2 * cm, f"Page {doc.page}")
    canvas.drawRightString(
        page_w - 2 * cm, 1.2 * cm,
        datetime.utcnow().strftime("%Y-%m-%d"),
    )
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_pdf_report(
    result: AssessmentResult,
    output_path: str,
    report_type: str = "full",
    anonymize: bool = False,
) -> str:
    """
    Generate a professional PDF security assessment report.

    Args:
        result:       Populated AssessmentResult.
        output_path:  Destination file path (must end in .pdf).
        report_type:  "full" | "executive" | "technical"
        anonymize:    If True, replace real IPs with SYSTEM-N labels.

    Returns:
        Absolute path of the written PDF.
    """
    anon = _IpAnonymizer() if anonymize else None

    def _host(h: str) -> str:
        return anon.anonymize(h) if anon else h

    styles = _build_styles()
    doc = BaseDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2.5 * cm,
    )

    # Content page template (with header/footer)
    content_frame = Frame(
        doc.leftMargin,
        doc.bottomMargin,
        doc.width,
        doc.height,
        id="content",
    )
    content_template = PageTemplate(
        id="content",
        frames=[content_frame],
        onPage=_header_footer,
    )

    # Cover page template (no header/footer chrome)
    cover_frame = Frame(0, 0, doc.pagesize[0], doc.pagesize[1], id="cover")
    cover_template = PageTemplate(id="cover", frames=[cover_frame])

    doc.addPageTemplates([cover_template, content_template])

    story = []

    # -----------------------------------------------------------------------
    # COVER PAGE
    # -----------------------------------------------------------------------
    story += _build_cover_page(result, styles, _host, report_type)
    story.append(PageBreak())

    # Switch to content template after cover
    from reportlab.platypus.doctemplate import NextPageTemplate
    story.insert(len(story) - 1, NextPageTemplate("content"))

    # -----------------------------------------------------------------------
    # EXECUTIVE SUMMARY
    # -----------------------------------------------------------------------
    if report_type in ("full", "executive"):
        story += _build_executive_summary(result, styles, _host)
        story.append(PageBreak())

    # -----------------------------------------------------------------------
    # SCOPE & METHODOLOGY
    # -----------------------------------------------------------------------
    story += _build_scope_methodology(result, styles, _host)
    story.append(PageBreak())

    # -----------------------------------------------------------------------
    # TECHNICAL FINDINGS
    # -----------------------------------------------------------------------
    if report_type in ("full", "technical"):
        story += _build_findings_table(result, styles, _host)
        story.append(PageBreak())

    # -----------------------------------------------------------------------
    # REMEDIATION PLAN
    # -----------------------------------------------------------------------
    story += _build_remediation_plan(result, styles)
    story.append(PageBreak())

    # -----------------------------------------------------------------------
    # APPENDIX
    # -----------------------------------------------------------------------
    story += _build_appendix(result, styles, _host)

    doc.build(story)
    return os.path.abspath(output_path)


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_cover_page(
    result: AssessmentResult,
    styles: Dict,
    host_fn,
    report_type: str,
) -> list:
    """Return flowables for the cover page."""
    from reportlab.platypus.doctemplate import NextPageTemplate

    page_w, page_h = letter
    story = []

    # Dark background rectangle (drawn via a custom flowable)
    class _CoverBackground:
        def wrap(self, aw, ah):
            return (aw, ah)
        def draw(self):
            pass

    # Classification banner
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("CONFIDENTIAL — AUTHORIZED USE ONLY", styles["classification"]))
    story.append(Spacer(1, 2 * cm))

    # Tool name
    story.append(Paragraph("PACS/DICOM Security Assessment Platform", styles["cover_title"]))
    story.append(Paragraph(f"Security Assessment Report — {report_type.capitalize()}", styles["cover_subtitle"]))
    story.append(Spacer(1, 1 * cm))

    # Separator
    story.append(HRFlowable(width="80%", thickness=2, color=BRAND_BLUE, spaceAfter=20))

    # Assessment metadata table
    target_display = host_fn(result.target.host)
    assessed_on = result.start_time.strftime("%Y-%m-%d %H:%M UTC") if result.start_time else "N/A"
    end_on = result.end_time.strftime("%Y-%m-%d %H:%M UTC") if result.end_time else "N/A"
    duration_secs = (
        int((result.end_time - result.start_time).total_seconds())
        if result.end_time and result.start_time else "N/A"
    )

    meta_data = [
        ["Assessment Target:", target_display],
        ["Target Port:", str(result.target.port)],
        ["Called AE Title:", result.target.called_ae],
        ["Assessment Start:", assessed_on],
        ["Assessment End:", end_on],
        ["Duration:", f"{duration_secs}s" if isinstance(duration_secs, int) else duration_secs],
        ["Assessor:", "Authorized Assessor"],
        ["Report Type:", report_type.capitalize()],
        ["Total Findings:", str(len(result.findings))],
    ]

    meta_table = Table(
        meta_data,
        colWidths=[5 * cm, 10 * cm],
        hAlign="CENTER",
    )
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), BRAND_BLUE),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [BRAND_LIGHT, colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 1.5 * cm))

    # Severity summary badges
    sev_counts = Counter(f.severity.value for f in result.findings)
    badge_data = [["Critical", "High", "Medium", "Low", "Informational"]]
    badge_counts = [
        str(sev_counts.get(Severity.CRITICAL.value, 0)),
        str(sev_counts.get(Severity.HIGH.value, 0)),
        str(sev_counts.get(Severity.MEDIUM.value, 0)),
        str(sev_counts.get(Severity.LOW.value, 0)),
        str(sev_counts.get(Severity.INFORMATIONAL.value, 0)),
    ]
    badge_data.append(badge_counts)

    badge_table = Table(badge_data, colWidths=[3 * cm] * 5, hAlign="CENTER")
    badge_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), SEVERITY_COLORS[Severity.CRITICAL.value]),
        ("BACKGROUND", (1, 0), (1, 0), SEVERITY_COLORS[Severity.HIGH.value]),
        ("BACKGROUND", (2, 0), (2, 0), SEVERITY_COLORS[Severity.MEDIUM.value]),
        ("BACKGROUND", (3, 0), (3, 0), SEVERITY_COLORS[Severity.LOW.value]),
        ("BACKGROUND", (4, 0), (4, 0), SEVERITY_COLORS[Severity.INFORMATIONAL.value]),
        ("TEXTCOLOR", (0, 0), (1, 0), colors.white),
        ("TEXTCOLOR", (2, 0), (-1, 0), colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 18),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(badge_table)
    story.append(Spacer(1, 2 * cm))

    # Footer disclaimer
    disclaimer = (
        "This report contains confidential security findings produced by the PACS/DICOM Security "
        "Assessment Platform for authorized use only. Distribution is restricted to authorized "
        "personnel with a need to know. Unauthorized disclosure is prohibited."
    )
    story.append(Paragraph(disclaimer, styles["body"]))

    return story


def _build_executive_summary(result: AssessmentResult, styles: Dict, host_fn) -> list:
    story = []
    story.append(Paragraph("Executive Summary", styles["section_heading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_BLUE, spaceAfter=10))

    total = len(result.findings)
    sev_counts = Counter(f.severity.value for f in result.findings)
    critical = sev_counts.get(Severity.CRITICAL.value, 0)
    high = sev_counts.get(Severity.HIGH.value, 0)
    medium = sev_counts.get(Severity.MEDIUM.value, 0)
    low = sev_counts.get(Severity.LOW.value, 0)
    info = sev_counts.get(Severity.INFORMATIONAL.value, 0)

    # Overall risk
    if critical > 0:
        overall_risk = "CRITICAL"
        risk_color = SEVERITY_COLORS[Severity.CRITICAL.value]
    elif high > 0:
        overall_risk = "HIGH"
        risk_color = SEVERITY_COLORS[Severity.HIGH.value]
    elif medium > 0:
        overall_risk = "MEDIUM"
        risk_color = SEVERITY_COLORS[Severity.MEDIUM.value]
    elif low > 0:
        overall_risk = "LOW"
        risk_color = SEVERITY_COLORS[Severity.LOW.value]
    else:
        overall_risk = "INFORMATIONAL"
        risk_color = SEVERITY_COLORS[Severity.INFORMATIONAL.value]

    target_display = host_fn(result.target.host)

    # Narrative paragraph
    narrative = (
        f"A security assessment of the DICOM/PACS infrastructure at <b>{target_display}:{result.target.port}</b> "
        f"(AE Title: <i>{result.target.called_ae}</i>) was conducted on "
        f"{result.start_time.strftime('%Y-%m-%d') if result.start_time else 'N/A'}. "
        f"The assessment identified <b>{total} finding(s)</b> across all tested modules: "
        f"{critical} Critical, {high} High, {medium} Medium, {low} Low, and {info} Informational. "
        f"The overall risk posture is rated <b>{overall_risk}</b>. "
    )
    if critical + high > 0:
        narrative += (
            f"Immediate remediation is recommended for all Critical and High findings, "
            f"as these represent significant risks to patient data confidentiality, "
            f"service availability, and regulatory compliance (HIPAA, GDPR)."
        )
    else:
        narrative += (
            "No Critical or High severity findings were identified. "
            "Routine remediation of remaining findings is recommended per standard change management procedures."
        )

    story.append(Paragraph(narrative, styles["body"]))
    story.append(Spacer(1, 0.5 * cm))

    # Findings by severity summary table
    story.append(Paragraph("Findings Summary by Severity", styles["subsection_heading"]))
    sev_data = [
        [Paragraph("Severity", styles["table_header"]),
         Paragraph("Count", styles["table_header"]),
         Paragraph("Risk Impact", styles["table_header"])],
        ["Critical", str(critical), "Immediate action required — potential full compromise"],
        ["High",     str(high),     "Urgent — exploitable without authentication in many cases"],
        ["Medium",   str(medium),   "Elevated risk — remediate within 30 days"],
        ["Low",      str(low),      "Minor risk — remediate within 90 days"],
        ["Informational", str(info), "No immediate risk — review for compliance"],
        ["TOTAL",    str(total),    ""],
    ]
    sev_table = Table(sev_data, colWidths=[4 * cm, 2.5 * cm, 11 * cm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, 1), SEVERITY_COLORS[Severity.CRITICAL.value]),
        ("TEXTCOLOR", (0, 1), (-1, 1), colors.white),
        ("BACKGROUND", (0, 2), (-1, 2), SEVERITY_COLORS[Severity.HIGH.value]),
        ("TEXTCOLOR", (0, 2), (-1, 2), colors.white),
        ("BACKGROUND", (0, 3), (-1, 3), SEVERITY_COLORS[Severity.MEDIUM.value]),
        ("BACKGROUND", (0, 4), (-1, 4), SEVERITY_COLORS[Severity.LOW.value]),
        ("BACKGROUND", (0, 5), (-1, 5), SEVERITY_COLORS[Severity.INFORMATIONAL.value]),
        ("BACKGROUND", (0, 6), (-1, 6), BRAND_LIGHT),
        ("FONTNAME", (0, 6), (-1, 6), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (0, 5), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 0.5 * cm))

    # Top 3 risk areas
    story.append(Paragraph("Top Risk Areas", styles["subsection_heading"]))
    priority_findings = sorted(
        result.findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity.value, 99), f.timestamp),
    )
    top3 = priority_findings[:3]
    if top3:
        for i, f in enumerate(top3, 1):
            sev_color = SEVERITY_COLORS.get(f.severity.value, colors.grey)
            risk_line = (
                f"<b>{i}. [{f.severity.value.upper()}] {f.title}</b> — "
                f"{host_fn(f.host)}:{f.port} ({f.service}). "
                f"{f.evidence[:200]}{'...' if len(f.evidence) > 200 else ''}"
            )
            story.append(Paragraph(risk_line, styles["body"]))
    else:
        story.append(Paragraph("No findings identified during this assessment.", styles["body"]))

    return story


def _build_scope_methodology(result: AssessmentResult, styles: Dict, host_fn) -> list:
    story = []
    story.append(Paragraph("Scope &amp; Methodology", styles["section_heading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_BLUE, spaceAfter=10))

    # Target details table
    story.append(Paragraph("Assessment Target", styles["subsection_heading"]))
    target_data = [
        ["Parameter", "Value"],
        ["Host / IP", host_fn(result.target.host)],
        ["Port", str(result.target.port)],
        ["Called AE Title", result.target.called_ae],
        ["Calling AE Title", result.target.calling_ae],
        ["Connection Timeout", f"{result.target.timeout}s"],
        ["Authorization Confirmed", "Yes" if result.target.authorized else "No"],
        ["Assessment Notes", result.target.notes or "None"],
    ]
    target_table = Table(target_data, colWidths=[5 * cm, 12 * cm])
    target_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 1), (0, -1), BRAND_LIGHT),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (1, 1), (-1, -1), [colors.white, colors.HexColor("#F8F9FA")]),
    ]))
    story.append(target_table)
    story.append(Spacer(1, 0.5 * cm))

    # Timing
    story.append(Paragraph("Assessment Timeline", styles["subsection_heading"]))
    start_str = result.start_time.strftime("%Y-%m-%d %H:%M:%S UTC") if result.start_time else "N/A"
    end_str = result.end_time.strftime("%Y-%m-%d %H:%M:%S UTC") if result.end_time else "In progress"
    duration = "N/A"
    if result.start_time and result.end_time:
        secs = int((result.end_time - result.start_time).total_seconds())
        duration = f"{secs // 60}m {secs % 60}s"

    timeline_data = [
        ["Event", "Timestamp"],
        ["Assessment Start", start_str],
        ["Assessment End", end_str],
        ["Total Duration", duration],
    ]
    timeline_table = Table(timeline_data, colWidths=[5 * cm, 12 * cm])
    timeline_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_LIGHT]),
    ]))
    story.append(timeline_table)
    story.append(Spacer(1, 0.5 * cm))

    # Modules run
    story.append(Paragraph("Modules Executed", styles["subsection_heading"]))
    if result.scan_modules_run:
        for mod in result.scan_modules_run:
            story.append(Paragraph(f"• {mod}", styles["body"]))
    else:
        story.append(Paragraph("No scan module records available.", styles["body"]))

    story.append(Spacer(1, 0.5 * cm))

    # Errors
    if result.errors:
        story.append(Paragraph("Errors / Warnings During Assessment", styles["subsection_heading"]))
        for err in result.errors:
            story.append(Paragraph(f"• {err}", styles["body"]))

    return story


def _build_findings_table(result: AssessmentResult, styles: Dict, host_fn) -> list:
    story = []
    story.append(Paragraph("Technical Findings", styles["section_heading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_BLUE, spaceAfter=10))

    if not result.findings:
        story.append(Paragraph("No findings were identified during this assessment.", styles["body"]))
        return story

    sorted_findings = sorted(
        result.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity.value, 99),
    )

    # Table header
    header = [
        Paragraph("Sev", styles["table_header"]),
        Paragraph("Title", styles["table_header"]),
        Paragraph("Host:Port", styles["table_header"]),
        Paragraph("Service", styles["table_header"]),
        Paragraph("CVE", styles["table_header"]),
        Paragraph("Conf.", styles["table_header"]),
        Paragraph("Evidence (excerpt)", styles["table_header"]),
    ]
    rows = [header]
    row_styles = []

    for idx, f in enumerate(sorted_findings, 1):
        sev_val = f.severity.value
        sev_bg = SEVERITY_COLORS.get(sev_val, colors.grey)
        sev_fg = SEVERITY_TEXT_COLORS.get(sev_val, colors.black)
        evidence_excerpt = f.evidence[:180] + ("..." if len(f.evidence) > 180 else "")
        cve = f.cve_id or "—"
        host_port = f"{host_fn(f.host)}:{f.port}"

        rows.append([
            Paragraph(sev_val, ParagraphStyle(
                f"sev_{idx}",
                parent=styles["severity_badge"],
                textColor=sev_fg,
                backColor=sev_bg,
            )),
            Paragraph(f.title, styles["table_cell"]),
            Paragraph(host_port, styles["table_cell"]),
            Paragraph(f.service, styles["table_cell"]),
            Paragraph(cve, styles["table_cell"]),
            Paragraph(f.confidence.value, styles["table_cell"]),
            Paragraph(evidence_excerpt, styles["table_cell"]),
        ])
        # Alternate row background
        bg = colors.white if idx % 2 == 0 else colors.HexColor("#F8F9FA")
        row_styles.append(("BACKGROUND", (1, idx), (-1, idx), bg))

    col_widths = [1.6 * cm, 4.5 * cm, 3.5 * cm, 2.2 * cm, 2.5 * cm, 1.6 * cm, 7.5 * cm]
    findings_table = Table(rows, colWidths=col_widths, repeatRows=1)
    findings_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 4),
        *row_styles,
    ]))
    story.append(findings_table)
    return story


def _build_remediation_plan(result: AssessmentResult, styles: Dict) -> list:
    story = []
    story.append(Paragraph("Remediation Plan", styles["section_heading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_BLUE, spaceAfter=10))

    if not result.findings:
        story.append(Paragraph("No remediation actions required.", styles["body"]))
        return story

    # Collect unique remediation steps, sorted by severity priority
    seen_remediations: set = set()
    priority_items: List[tuple] = []  # (severity_order, severity_value, title, remediation)

    sorted_findings = sorted(
        result.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity.value, 99),
    )

    for f in sorted_findings:
        if not f.remediation:
            continue
        key = f.remediation.strip().lower()
        if key in seen_remediations:
            continue
        seen_remediations.add(key)
        priority_items.append((
            SEVERITY_ORDER.get(f.severity.value, 99),
            f.severity.value,
            f.title,
            f.remediation,
        ))

    if not priority_items:
        story.append(Paragraph(
            "No explicit remediation steps were recorded for findings in this assessment. "
            "Consult your PACS vendor documentation and applicable DICOM conformance statements.",
            styles["body"],
        ))
        return story

    rem_header = [
        Paragraph("Priority", styles["table_header"]),
        Paragraph("Severity", styles["table_header"]),
        Paragraph("Finding", styles["table_header"]),
        Paragraph("Remediation Action", styles["table_header"]),
    ]
    rows = [rem_header]
    for i, (_, sev, title, rem) in enumerate(priority_items, 1):
        sev_bg = SEVERITY_COLORS.get(sev, colors.grey)
        sev_fg = SEVERITY_TEXT_COLORS.get(sev, colors.black)
        rows.append([
            Paragraph(str(i), styles["table_cell"]),
            Paragraph(sev, ParagraphStyle(
                f"rem_sev_{i}",
                parent=styles["severity_badge"],
                textColor=sev_fg,
                backColor=sev_bg,
            )),
            Paragraph(title, styles["table_cell"]),
            Paragraph(rem, styles["table_cell"]),
        ])

    rem_table = Table(rows, colWidths=[1.5 * cm, 2.5 * cm, 5.5 * cm, 13 * cm])
    rem_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8F9FA")]),
    ]))
    story.append(rem_table)
    return story


def _build_appendix(result: AssessmentResult, styles: Dict, host_fn) -> list:
    story = []
    story.append(Paragraph("Appendix A — Full Evidence", styles["section_heading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_BLUE, spaceAfter=10))

    if result.findings:
        sorted_findings = sorted(
            result.findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity.value, 99),
        )
        for i, f in enumerate(sorted_findings, 1):
            block = KeepTogether([
                Paragraph(
                    f"A{i}. [{f.severity.value}] {f.title}",
                    styles["subsection_heading"],
                ),
                Paragraph(
                    f"<b>Host:</b> {host_fn(f.host)}:{f.port} | "
                    f"<b>Service:</b> {f.service} | "
                    f"<b>Detection:</b> {f.detection_method} | "
                    f"<b>Confidence:</b> {f.confidence.value} | "
                    f"<b>Timestamp:</b> {f.timestamp.isoformat() if f.timestamp else 'N/A'}",
                    styles["body"],
                ),
                Paragraph("<b>Full Evidence:</b>", styles["body"]),
                Paragraph(f.evidence, styles["code"]),
            ])
            story.append(block)
            story.append(Spacer(1, 0.3 * cm))
    else:
        story.append(Paragraph("No findings to append.", styles["body"]))

    # Appendix B — Service discovery data
    story.append(Paragraph("Appendix B — Service Discovery Data", styles["section_heading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_BLUE, spaceAfter=10))

    if result.services_discovered:
        svc_header = [
            Paragraph("Host", styles["table_header"]),
            Paragraph("Port", styles["table_header"]),
            Paragraph("AE Response", styles["table_header"]),
            Paragraph("C-ECHO", styles["table_header"]),
            Paragraph("TLS", styles["table_header"]),
            Paragraph("RTT (ms)", styles["table_header"]),
            Paragraph("Timestamp", styles["table_header"]),
        ]
        rows = [svc_header]
        for svc in result.services_discovered:
            rows.append([
                Paragraph(host_fn(svc.host), styles["table_cell"]),
                Paragraph(str(svc.port), styles["table_cell"]),
                Paragraph(svc.ae_response or "—", styles["table_cell"]),
                Paragraph("✓" if svc.echo_success else "✗", styles["table_cell"]),
                Paragraph("✓" if svc.tls_capable else "✗", styles["table_cell"]),
                Paragraph(f"{svc.response_ms:.1f}" if svc.response_ms else "—", styles["table_cell"]),
                Paragraph(svc.timestamp.strftime("%Y-%m-%d %H:%M") if svc.timestamp else "—", styles["table_cell"]),
            ])
        svc_table = Table(rows, colWidths=[4 * cm, 2 * cm, 4 * cm, 2 * cm, 2 * cm, 2.5 * cm, 5 * cm])
        svc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_LIGHT]),
        ]))
        story.append(svc_table)
    else:
        story.append(Paragraph("No service discovery data recorded.", styles["body"]))

    return story
