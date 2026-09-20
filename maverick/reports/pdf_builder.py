"""
PDF Report Generator for MAVERICK (Module 8).
Constructs a multi-page, executive forensic PDF using ReportLab Platypus.
"""

from __future__ import annotations

import io
from typing import Any, Dict, List, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from maverick.reports.models import ForensicReport


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to compute total page numbers and render running headers/footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[Dict[str, Any]] = []
        self.case_id = "UNKNOWN"

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running header on subsequent pages
        if self._pageNumber > 1:
            self.drawString(40, 755, "MAVERICK // EMAIL THREAT FORENSIC INVESTIGATION REPORT")
            self.drawRightString(612 - 40, 755, f"CASE: {self.case_id}")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(40, 748, 612 - 40, 748)

        # Running footer on all pages
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(40, 42, 612 - 40, 42)
        self.drawString(40, 30, "CONFIDENTIAL // LAW ENFORCEMENT & SOC AUDIT ONLY // MAVERICK PLATFORM")
        self.drawRightString(612 - 40, 30, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


class ForensicPDFBuilder:
    """Builds a forensic PDF document from a ForensicReport model."""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Register custom typography styles for forensic reporting."""
        self.styles.add(
            ParagraphStyle(
                "ReportTitle",
                parent=self.styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=20,
                leading=24,
                textColor=colors.HexColor("#0f172a"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                "SectionHeader",
                parent=self.styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=12,
                leading=16,
                textColor=colors.HexColor("#1e293b"),
                spaceBefore=10,
                spaceAfter=4,
            )
        )
        self.styles.add(
            ParagraphStyle(
                "SubHeader",
                parent=self.styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=10,
                leading=13,
                textColor=colors.HexColor("#334155"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                "TableCell",
                parent=self.styles["Normal"],
                fontName="Helvetica",
                fontSize=8.5,
                leading=11,
                textColor=colors.HexColor("#1e293b"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                "TableCellBold",
                parent=self.styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=8.5,
                leading=11,
                textColor=colors.HexColor("#0f172a"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                "TableCellCode",
                parent=self.styles["Normal"],
                fontName="Courier",
                fontSize=8,
                leading=10,
                textColor=colors.HexColor("#0f172a"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                "VerdictBadge",
                parent=self.styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=14,
                leading=16,
                alignment=1,  # Centered
                textColor=colors.white,
            )
        )
        self.styles.add(
            ParagraphStyle(
                "CaveatText",
                parent=self.styles["Normal"],
                fontName="Helvetica-Oblique",
                fontSize=8,
                leading=10.5,
                textColor=colors.HexColor("#64748b"),
            )
        )

    def _verdict_color(self, verdict: str) -> colors.HexColor:
        """Map categorical verdict to brand hex color."""
        v = verdict.lower()
        if "critical" in v:
            return colors.HexColor("#dc2626")  # red-600
        elif "high" in v:
            return colors.HexColor("#ea580c")  # orange-600
        elif "medium" in v:
            return colors.HexColor("#d97706")  # amber-600
        else:
            return colors.HexColor("#16a34a")  # green-600

    def build_pdf(self, report: ForensicReport) -> bytes:
        """Compile ForensicReport into PDF binary bytes."""
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=40,
            rightMargin=40,
            topMargin=45,
            bottomMargin=50,
        )

        flowables: List[Any] = []

        # 1. Header Banner
        flowables.extend(self._build_header_banner(report))
        flowables.append(Spacer(1, 10))

        # 2. Case Summary & Threat Assessment
        flowables.extend(self._build_case_summary_and_threat(report))
        flowables.append(Spacer(1, 12))

        # 3. Evidence Fusion Breakdown
        flowables.extend(self._build_evidence_fusion_section(report))
        flowables.append(Spacer(1, 12))

        # 4. Machine Learning Phishing Findings
        flowables.extend(self._build_ml_section(report))
        flowables.append(Spacer(1, 12))

        # 5. Email Authentication Analysis (SPF/DKIM/DMARC)
        flowables.extend(self._build_auth_section(report))
        flowables.append(Spacer(1, 12))

        # 6. Header & Body IOC Evidence
        flowables.extend(self._build_ioc_section(report))
        flowables.append(Spacer(1, 12))

        # 7. Geolocation Intelligence
        flowables.extend(self._build_geo_section(report))
        flowables.append(Spacer(1, 12))

        # 8. Attachment Static Forensics
        flowables.extend(self._build_attachment_section(report))
        flowables.append(Spacer(1, 12))

        # 9. Investigation Timeline
        flowables.extend(self._build_timeline_section(report))
        flowables.append(Spacer(1, 12))

        # 10. Recommendations
        flowables.extend(self._build_recommendations_section(report))

        # Build document with custom canvas for page numbers
        def canvas_maker(*args, **kwargs):
            c = NumberedCanvas(*args, **kwargs)
            c.case_id = report.case_metadata.case_id
            return c

        doc.build(flowables, canvasmaker=canvas_maker)
        return buf.getvalue()

    def _build_header_banner(self, report: ForensicReport) -> List[Any]:
        """Construct branded title and metadata banner."""
        title_p = Paragraph("MAVERICK FORENSIC INCIDENT REPORT", self.styles["ReportTitle"])
        subtitle_p = Paragraph(
            f"Case ID: <b>{report.case_metadata.case_id}</b> | Generated: {report.case_metadata.generated_at} | Platform: {report.case_metadata.platform_version}",
            self.styles["TableCell"],
        )
        return [
            title_p,
            Spacer(1, 2),
            subtitle_p,
            Spacer(1, 4),
            HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f172a"), spaceBefore=2, spaceAfter=8),
        ]

    def _build_case_summary_and_threat(self, report: ForensicReport) -> List[Any]:
        """Build Executive Case Summary and Threat Assessment Callout."""
        out: List[Any] = []
        out.append(Paragraph("1. Case Summary & Threat Assessment", self.styles["SectionHeader"]))

        v_color = self._verdict_color(report.threat_assessment.verdict)
        verdict_badge = Paragraph(f"VERDICT: {report.threat_assessment.verdict.upper()}", self.styles["VerdictBadge"])

        score_text = (
            f"<b>Risk Score:</b> {report.threat_assessment.risk_score:.4f} / 1.0000<br/>"
            f"<b>Threat Indicators Flagged:</b> {report.threat_assessment.threat_indicators_count}<br/>"
            f"<b>Summary:</b> {report.threat_assessment.summary}"
        )
        score_p = Paragraph(score_text, self.styles["TableCell"])

        badge_table = Table(
            [[verdict_badge, score_p]],
            colWidths=[1.8 * inch, 5.5 * inch],
        )
        badge_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), v_color),
                ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#f8fafc")),
                ("ALIGN", (0, 0), (0, 0), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ])
        )
        out.append(badge_table)
        out.append(Spacer(1, 6))

        # Email attributes table
        summary = report.case_summary
        to_str = ", ".join(summary.to_addrs) if summary.to_addrs else "Undisclosed"
        summary_data = [
            [Paragraph("<b>Subject:</b>", self.styles["TableCellBold"]), Paragraph(summary.subject or "[No Subject]", self.styles["TableCell"])],
            [Paragraph("<b>From:</b>", self.styles["TableCellBold"]), Paragraph(summary.from_addr or "[Unknown]", self.styles["TableCell"])],
            [Paragraph("<b>To:</b>", self.styles["TableCellBold"]), Paragraph(to_str, self.styles["TableCell"])],
            [Paragraph("<b>Date:</b>", self.styles["TableCellBold"]), Paragraph(summary.date or "[Missing]", self.styles["TableCell"])],
            [Paragraph("<b>Message-ID:</b>", self.styles["TableCellBold"]), Paragraph(summary.message_id or "[Missing]", self.styles["TableCellCode"])],
            [Paragraph("<b>Chain of Custody SHA-256:</b>", self.styles["TableCellBold"]), Paragraph(report.case_metadata.sha256_eml or "N/A", self.styles["TableCellCode"])],
        ]
        sum_table = Table(summary_data, colWidths=[1.8 * inch, 5.5 * inch])
        sum_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ffffff")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        out.append(sum_table)
        return out

    def _build_evidence_fusion_section(self, report: ForensicReport) -> List[Any]:
        """Build Evidence Fusion Dimension Scoring Breakdown."""
        out: List[Any] = []
        out.append(Paragraph("2. Evidence Fusion Scoring Breakdown", self.styles["SectionHeader"]))

        breakdown = report.evidence_fusion.score_breakdown
        fusion_data = [
            [
                Paragraph("<b>Forensic Dimension</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Assigned Weight</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Weighted Score</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Contribution / Status</b>", self.styles["TableCellBold"]),
            ],
            [
                Paragraph("Machine Learning Phishing", self.styles["TableCell"]),
                Paragraph("40% (max 0.40)", self.styles["TableCell"]),
                Paragraph(f"{breakdown.ml_phishing:.4f}", self.styles["TableCellBold"]),
                Paragraph("Lexical vector probability & term attribution", self.styles["TableCell"]),
            ],
            [
                Paragraph("Email Authentication Forensics", self.styles["TableCell"]),
                Paragraph("20% (max 0.20)", self.styles["TableCell"]),
                Paragraph(f"{breakdown.authentication:.4f}", self.styles["TableCellBold"]),
                Paragraph("SPF / DKIM / DMARC status and From: domain alignment", self.styles["TableCell"]),
            ],
            [
                Paragraph("Attachment Static Forensics", self.styles["TableCell"]),
                Paragraph("20% (max 0.20)", self.styles["TableCell"]),
                Paragraph(f"{breakdown.attachments:.4f}", self.styles["TableCellBold"]),
                Paragraph("MIME type magic bytes, VBA macros, and PE headers", self.styles["TableCell"]),
            ],
            [
                Paragraph("IOC & Geolocation Signals", self.styles["TableCell"]),
                Paragraph("20% (max 0.20)", self.styles["TableCell"]),
                Paragraph(f"{breakdown.ioc_geo:.4f}", self.styles["TableCellBold"]),
                Paragraph("Raw IP URLs, high-abuse TLDs, and routing anomalies", self.styles["TableCell"]),
            ],
        ]
        t = Table(fusion_data, colWidths=[2.2 * inch, 1.4 * inch, 1.2 * inch, 2.5 * inch])
        t.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        out.append(t)
        out.append(Spacer(1, 4))

        # Contributing Factors list
        factors = report.evidence_fusion.contributing_factors
        if factors:
            factor_items = "".join([f"&bull; {f}<br/>" for f in factors])
            out.append(Paragraph(f"<b>Key Contributing Factors:</b><br/>{factor_items}", self.styles["TableCell"]))

        return out

    def _build_ml_section(self, report: ForensicReport) -> List[Any]:
        """Build Machine Learning Classification Findings."""
        out: List[Any] = []
        out.append(Paragraph("3. Machine Learning Phishing Classification Findings", self.styles["SectionHeader"]))

        ml = report.ml_findings
        if not ml:
            out.append(Paragraph("No body text available for machine learning inference.", self.styles["TableCell"]))
            return out

        prob = ml.get("phishing_probability", 0.0)
        label = ml.get("predicted_label", "Unknown")
        conf = ml.get("confidence", 0.0)

        ml_summary_data = [
            [
                Paragraph("<b>Phishing Probability:</b>", self.styles["TableCellBold"]),
                Paragraph(f"{prob * 100:.2f}%", self.styles["TableCellBold"]),
                Paragraph("<b>Predicted Label:</b>", self.styles["TableCellBold"]),
                Paragraph(f"<b>{label.upper()}</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Model Confidence:</b>", self.styles["TableCellBold"]),
                Paragraph(f"{conf * 100:.1f}%", self.styles["TableCell"]),
            ]
        ]
        sum_t = Table(ml_summary_data, colWidths=[1.4 * inch, 1.0 * inch, 1.2 * inch, 1.2 * inch, 1.2 * inch, 1.3 * inch])
        sum_t.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        out.append(sum_t)
        out.append(Spacer(1, 4))

        terms = ml.get("top_influential_terms", [])
        if terms:
            terms_data = [
                [
                    Paragraph("<b>Influential Lexical Term</b>", self.styles["TableCellBold"]),
                    Paragraph("<b>Indicator Class</b>", self.styles["TableCellBold"]),
                    Paragraph("<b>Model Feature Weight</b>", self.styles["TableCellBold"]),
                    Paragraph("<b>TF-IDF Weight</b>", self.styles["TableCellBold"]),
                    Paragraph("<b>Directional Impact</b>", self.styles["TableCellBold"]),
                ]
            ]
            for t_item in terms[:6]:
                terms_data.append([
                    Paragraph(t_item.get("term", ""), self.styles["TableCellCode"]),
                    Paragraph(t_item.get("indicator", ""), self.styles["TableCellBold"]),
                    Paragraph(f"{t_item.get('weight', 0.0):.4f}", self.styles["TableCell"]),
                    Paragraph(f"{t_item.get('tfidf', 0.0):.4f}", self.styles["TableCell"]),
                    Paragraph(f"{t_item.get('impact', 0.0):.4f}", self.styles["TableCellBold"]),
                ])
            terms_t = Table(terms_data, colWidths=[2.0 * inch, 1.4 * inch, 1.3 * inch, 1.3 * inch, 1.3 * inch])
            terms_t.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ])
            )
            out.append(terms_t)

        return out

    def _build_auth_section(self, report: ForensicReport) -> List[Any]:
        """Build Email Authentication Forensics Findings."""
        out: List[Any] = []
        out.append(Paragraph("4. Email Authentication Forensics & Domain Alignment", self.styles["SectionHeader"]))

        auth = report.auth_analysis
        if not auth:
            out.append(Paragraph("No authentication headers or results available.", self.styles["TableCell"]))
            return out

        auth_data = [
            [
                Paragraph("<b>Protocol</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Result Status</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Identifier Alignment</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Evaluated Domain(s)</b>", self.styles["TableCellBold"]),
            ],
            [
                Paragraph("SPF", self.styles["TableCellBold"]),
                Paragraph(auth.get("spf", "none").upper(), self.styles["TableCellBold"]),
                Paragraph("ALIGNED" if auth.get("spf_aligned") else "MISALIGNED", self.styles["TableCellBold"]),
                Paragraph(auth.get("spf_domain") or "[None]", self.styles["TableCell"]),
            ],
            [
                Paragraph("DKIM", self.styles["TableCellBold"]),
                Paragraph(auth.get("dkim", "none").upper(), self.styles["TableCellBold"]),
                Paragraph("ALIGNED" if auth.get("dkim_aligned") else "MISALIGNED", self.styles["TableCellBold"]),
                Paragraph(", ".join(auth.get("dkim_domains", [])) or "[None]", self.styles["TableCell"]),
            ],
            [
                Paragraph("DMARC", self.styles["TableCellBold"]),
                Paragraph(auth.get("dmarc", "none").upper(), self.styles["TableCellBold"]),
                Paragraph("PASS" if auth.get("aligned") else "FAIL", self.styles["TableCellBold"]),
                Paragraph(f"From: {auth.get('from_domain') or '[None]'}", self.styles["TableCell"]),
            ],
        ]
        t = Table(auth_data, colWidths=[1.2 * inch, 1.4 * inch, 1.8 * inch, 2.9 * inch])
        t.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        out.append(t)

        notes = auth.get("notes", [])
        if notes:
            note_str = "".join([f"&bull; {n}<br/>" for n in notes[:4]])
            out.append(Spacer(1, 3))
            out.append(Paragraph(f"<b>Authentication Notes:</b><br/>{note_str}", self.styles["TableCell"]))

        return out

    def _build_ioc_section(self, report: ForensicReport) -> List[Any]:
        """Build Indicators of Compromise (IOC) Section."""
        out: List[Any] = []
        out.append(Paragraph("5. Indicators of Compromise (IOCs) & Excluded Subnets", self.styles["SectionHeader"]))

        ioc = report.ioc_evidence
        if not ioc:
            out.append(Paragraph("No network IOCs discovered in email headers or body.", self.styles["TableCell"]))
            return out

        urls = ioc.get("urls", [])
        domains = ioc.get("domains", [])
        emails = ioc.get("emails", [])
        ips = ioc.get("ips", [])
        excluded_ips = ioc.get("excluded_ips", [])

        ioc_data = [
            [Paragraph("<b>Category</b>", self.styles["TableCellBold"]), Paragraph("<b>Forensic IOC Values</b>", self.styles["TableCellBold"])],
            [
                Paragraph("Public IPs", self.styles["TableCellBold"]),
                Paragraph(", ".join([f"{i.get('ip')} ({i.get('source')})" for i in ips]) or "[None]", self.styles["TableCellCode"]),
            ],
            [
                Paragraph("Excluded IPs (RFC 1918)", self.styles["TableCellBold"]),
                Paragraph(", ".join([f"{i.get('ip')} ({i.get('source')})" for i in excluded_ips]) or "[None]", self.styles["TableCellCode"]),
            ],
            [
                Paragraph("Target Domains", self.styles["TableCellBold"]),
                Paragraph(", ".join(domains[:8]) or "[None]", self.styles["TableCellCode"]),
            ],
            [
                Paragraph("Extracted URLs", self.styles["TableCellBold"]),
                Paragraph("<br/>".join(urls[:5]) or "[None]", self.styles["TableCellCode"]),
            ],
            [
                Paragraph("Mentioned Emails", self.styles["TableCellBold"]),
                Paragraph(", ".join(emails[:6]) or "[None]", self.styles["TableCellCode"]),
            ],
        ]
        t = Table(ioc_data, colWidths=[2.0 * inch, 5.3 * inch])
        t.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        out.append(t)
        return out

    def _build_geo_section(self, report: ForensicReport) -> List[Any]:
        """Build Geolocation Intelligence Section."""
        out: List[Any] = []
        out.append(Paragraph("6. Geolocation Intelligence Telemetry", self.styles["SectionHeader"]))

        geo = report.geo_intelligence
        results = geo.get("results", []) if geo else []

        if not results:
            out.append(Paragraph("No public IP geolocation metadata returned.", self.styles["TableCell"]))
            return out

        geo_data = [
            [
                Paragraph("<b>IP Address</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Country</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Region / City</b>", self.styles["TableCellBold"]),
                Paragraph("<b>ASN</b>", self.styles["TableCellBold"]),
                Paragraph("<b>ISP / Organization</b>", self.styles["TableCellBold"]),
            ]
        ]
        for r in results[:6]:
            geo_data.append([
                Paragraph(r.get("ip", ""), self.styles["TableCellCode"]),
                Paragraph(r.get("country") or "[Unknown]", self.styles["TableCell"]),
                Paragraph(f"{r.get('region') or ''}, {r.get('city') or ''}".strip(", "), self.styles["TableCell"]),
                Paragraph(r.get("asn") or "[None]", self.styles["TableCell"]),
                Paragraph(r.get("isp") or "[None]", self.styles["TableCell"]),
            ])

        t = Table(geo_data, colWidths=[1.3 * inch, 1.2 * inch, 1.5 * inch, 1.4 * inch, 1.9 * inch])
        t.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        out.append(t)
        out.append(Spacer(1, 2))
        out.append(Paragraph(
            "<b>EVIDENTIARY DISCLAIMER:</b> IP geolocation data represents inferred enrichment derived from third-party lookup tables (ip-api.com) rather than directly observed header facts. Physical coordinates may represent ISP point-of-presence rather than true sender location.",
            self.styles["CaveatText"],
        ))
        return out

    def _build_attachment_section(self, report: ForensicReport) -> List[Any]:
        """Build Attachment Static Forensics Section."""
        out: List[Any] = []
        out.append(Paragraph("7. Attachment Static Forensics", self.styles["SectionHeader"]))

        att_findings = report.attachment_findings
        attachments = att_findings.get("attachments", []) if att_findings else []

        if not attachments:
            out.append(Paragraph("No email attachments present in message.", self.styles["TableCell"]))
            return out

        att_data = [
            [
                Paragraph("<b>Filename</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Claimed MIME</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Detected Magic Format</b>", self.styles["TableCellBold"]),
                Paragraph("<b>SHA-256 Digest</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Verdict</b>", self.styles["TableCellBold"]),
            ]
        ]
        for a in attachments[:5]:
            v_color = self._verdict_color(a.get("verdict", "clean"))
            v_p = Paragraph(f"<b>{a.get('verdict', 'clean').upper()}</b>", self.styles["TableCellBold"])
            att_data.append([
                Paragraph(a.get("filename", ""), self.styles["TableCellBold"]),
                Paragraph(a.get("claimed_type", ""), self.styles["TableCellCode"]),
                Paragraph(a.get("detected_type", ""), self.styles["TableCell"]),
                Paragraph(a.get("hashes", {}).get("sha256", "")[:32] + "...", self.styles["TableCellCode"]),
                v_p,
            ])

        t = Table(att_data, colWidths=[1.5 * inch, 1.4 * inch, 1.8 * inch, 1.6 * inch, 1.0 * inch])
        t.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        out.append(t)
        return out

    def _build_timeline_section(self, report: ForensicReport) -> List[Any]:
        """Build Chronological Hop-by-Hop Transmission Timeline."""
        out: List[Any] = []
        out.append(Paragraph("8. Investigation Timeline (Received Hop Chain)", self.styles["SectionHeader"]))

        timeline = report.investigation_timeline
        if not timeline:
            out.append(Paragraph("No Received headers parsed in MTA chain.", self.styles["TableCell"]))
            return out

        time_data = [
            [
                Paragraph("<b>Hop #</b>", self.styles["TableCellBold"]),
                Paragraph("<b>From Host / Sender IP</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Receiving MTA</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Hop Timestamp</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Delay</b>", self.styles["TableCellBold"]),
            ]
        ]
        for h in timeline[:8]:
            from_str = f"{h.from_host or ''} ({h.from_ip or ''})".strip(" ()") or "[Unknown]"
            delay_str = f"{h.delay_seconds:.1f}s" if h.delay_seconds is not None else "0.0s"
            time_data.append([
                Paragraph(str(h.hop_index), self.styles["TableCellBold"]),
                Paragraph(from_str, self.styles["TableCellCode"]),
                Paragraph(h.by_host or "[Unknown]", self.styles["TableCellCode"]),
                Paragraph(h.timestamp or "[Unparseable]", self.styles["TableCell"]),
                Paragraph(delay_str, self.styles["TableCell"]),
            ])

        t = Table(time_data, colWidths=[0.6 * inch, 2.4 * inch, 2.0 * inch, 1.5 * inch, 0.8 * inch])
        t.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        out.append(t)
        return out

    def _build_recommendations_section(self, report: ForensicReport) -> List[Any]:
        """Build Prioritized Remediation Recommendations."""
        out: List[Any] = []
        out.append(Paragraph("9. Incident Remediation & Forensic Recommendations", self.styles["SectionHeader"]))

        recs = report.recommendations
        if not recs:
            out.append(Paragraph("No specific remediation recommendations required.", self.styles["TableCell"]))
            return out

        rec_data = [
            [
                Paragraph("<b>Priority</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Category</b>", self.styles["TableCellBold"]),
                Paragraph("<b>Recommended Action & Evidentiary Rationale</b>", self.styles["TableCellBold"]),
            ]
        ]
        for r in recs:
            p_color = colors.HexColor("#dc2626") if r.priority == "CRITICAL" else colors.HexColor("#ea580c") if r.priority == "HIGH" else colors.HexColor("#0f172a")
            action_desc = f"<b>{r.action}</b><br/><i>Rationale:</i> {r.rationale}"
            rec_data.append([
                Paragraph(f"<b>{r.priority}</b>", self.styles["TableCellBold"]),
                Paragraph(r.category, self.styles["TableCellBold"]),
                Paragraph(action_desc, self.styles["TableCell"]),
            ])

        t = Table(rec_data, colWidths=[1.1 * inch, 1.7 * inch, 4.5 * inch])
        t.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        out.append(t)
        return out
