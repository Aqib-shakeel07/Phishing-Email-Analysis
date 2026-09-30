import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, PageBreak
)
from config import REPORT_DIR
from logger import logger


VERDICT_COLORS = {
    "Safe": colors.HexColor("#2e7d32"),
    "Suspicious": colors.HexColor("#f9a825"),
    "Phishing": colors.HexColor("#c62828"),
    "Unknown": colors.HexColor("#616161"),
}


class ReportGenerator:
    def __init__(self, out_dir: str = REPORT_DIR):
        self.out_dir = out_dir
        os.makedirs(self.out_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._register_styles()

    # ---------------- Public ----------------

    def to_json(self, analysis: dict, filename: str | None = None) -> str:
        if not filename:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{ts}.json"
        path = os.path.join(self.out_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._serializable(analysis), f, indent=2, default=str)
        logger.info(f"JSON report saved: {path}")
        return path

    def to_pdf(self, analysis: dict, filename: str | None = None) -> str:
        if not filename:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{ts}.pdf"
        path = os.path.join(self.out_dir, filename)

        doc = SimpleDocTemplate(
            path, pagesize=A4,
            leftMargin=18 * mm, rightMargin=18 * mm,
            topMargin=18 * mm, bottomMargin=18 * mm,
        )
        story = []
        story += self._header_section(analysis)
        story.append(Spacer(1, 8 * mm))
        story += self._summary_section(analysis)
        story.append(Spacer(1, 8 * mm))
        story += self._scores_section(analysis)
        story.append(Spacer(1, 8 * mm))
        story += self._flags_section(analysis)
        story.append(PageBreak())
        story += self._header_details_section(analysis)
        story.append(Spacer(1, 6 * mm))
        story += self._urls_section(analysis)
        story.append(Spacer(1, 6 * mm))
        story += self._attachments_section(analysis)

        doc.build(story)
        logger.info(f"PDF report saved: {path}")
        return path

    # ---------------- Sections ----------------

    def _header_section(self, analysis: dict):
        title = Paragraph("Phishing Email Analysis Report", self.styles["Title"])
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        sub = Paragraph(f"Generated: {ts}", self.styles["SubTitle"])
        return [title, sub]

    def _summary_section(self, analysis: dict):
        verdict = analysis.get("verdict", "Unknown")
        score = analysis.get("final_score", 0)
        subject = analysis.get("subject") or "(no subject)"
        sender = analysis.get("sender") or "(unknown)"

        data = [
            ["Verdict", verdict],
            ["Final Score", f"{score}/100"],
            ["From", sender],
            ["Subject", subject],
        ]
        table = Table(data, colWidths=[35 * mm, 130 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eceff1")),
            ("TEXTCOLOR", (1, 0), (1, 0), VERDICT_COLORS.get(verdict, colors.black)),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return [Paragraph("Summary", self.styles["Heading2"]), table]

    def _scores_section(self, analysis: dict):
        comps = analysis.get("component_scores", {})
        rows = [["Module", "Score"]]
        for k, v in comps.items():
            rows.append([k.capitalize(), f"{round(float(v), 2)}"])
        rows.append(["Final", f"{analysis.get('final_score', 0)}"])

        table = Table(rows, colWidths=[60 * mm, 40 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#eceff1")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ]))
        return [Paragraph("Score Breakdown", self.styles["Heading2"]), table]

    def _flags_section(self, analysis: dict):
        flags = analysis.get("triggered_features", []) or []
        items = [Paragraph("Triggered Features", self.styles["Heading2"])]
        if not flags:
            items.append(Paragraph("No suspicious features detected.", self.styles["Normal"]))
            return items

        rows = [["Module", "Detail"]]
        for f in flags[:60]:
            rows.append([f.get("module", ""), f.get("detail", "")])
        table = Table(rows, colWidths=[25 * mm, 140 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#455a64")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        items.append(table)
        return items

    def _header_details_section(self, analysis: dict):
        rows = [
            ["Field", "Value"],
            ["From", analysis.get("sender") or "-"],
            ["Sender Domain", analysis.get("sender_domain") or "-"],
            ["Reply-To", analysis.get("reply_to") or "-"],
            ["Return-Path", analysis.get("return_path") or "-"],
            ["SPF", str(analysis.get("spf_pass"))],
            ["DKIM", str(analysis.get("dkim_pass"))],
            ["DMARC", str(analysis.get("dmarc_pass"))],
        ]
        table = Table(rows, colWidths=[35 * mm, 130 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ]))
        return [Paragraph("Header Details", self.styles["Heading2"]), table]

    def _urls_section(self, analysis: dict):
        urls = analysis.get("urls_found", []) or []
        items = [Paragraph("URLs Found", self.styles["Heading2"])]
        if not urls:
            items.append(Paragraph("No URLs extracted.", self.styles["Normal"]))
            return items

        rows = [["URL", "Domain", "Score", "Flags"]]
        for u in urls[:40]:
            rows.append([
                Paragraph(str(u.get("url", ""))[:80], self.styles["Small"]),
                str(u.get("domain", "")),
                str(round(float(u.get("score", 0)), 1)),
                Paragraph(", ".join(u.get("flags", []))[:120] or "-", self.styles["Small"]),
            ])
        table = Table(rows, colWidths=[60 * mm, 30 * mm, 15 * mm, 60 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#455a64")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        items.append(table)
        return items

    def _attachments_section(self, analysis: dict):
        atts = analysis.get("attachments", []) or []
        items = [Paragraph("Attachments", self.styles["Heading2"])]
        if not atts:
            items.append(Paragraph("No attachments.", self.styles["Normal"]))
            return items

        rows = [["Filename", "Type", "Size", "Score", "Flags"]]
        for a in atts[:30]:
            rows.append([
                Paragraph(str(a.get("filename", ""))[:60], self.styles["Small"]),
                str(a.get("content_type", ""))[:30],
                str(a.get("size", 0)),
                str(round(float(a.get("score", 0)), 1)),
                Paragraph(", ".join(a.get("flags", []))[:120] or "-", self.styles["Small"]),
            ])
        table = Table(rows, colWidths=[50 * mm, 30 * mm, 15 * mm, 15 * mm, 55 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#455a64")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        items.append(table)
        return items

    # ---------------- Helpers ----------------

    def _register_styles(self):
        self.styles.add(ParagraphStyle(
            name="Small",
            parent=self.styles["Normal"],
            fontSize=7.5,
            leading=9,
        ))

    def _serializable(self, obj):
        if isinstance(obj, dict):
            return {k: self._serializable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._serializable(v) for v in obj]
        if isinstance(obj, datetime):
            return obj.isoformat()
        return obj


def build_full_report(generator: ReportGenerator, analysis: dict) -> dict:
    """Generate both JSON and PDF and return their paths."""
    json_path = generator.to_json(analysis)
    pdf_path = generator.to_pdf(analysis)
    return {"json": json_path, "pdf": pdf_path}