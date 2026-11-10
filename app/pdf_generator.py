"""Spanish PDF Report Generator (Combined Executive First + Technical SOC Level 2 Second).

Generates a single structured, multi-page PDF document in Spanish using fpdf2:
- Parte I: Informe Ejecutivo (Plain language for executive/board audience)
- Parte II: Informe Técnico SOC Nivel 2 (Complete 8-section technical report for security specialists)
"""

from pathlib import Path
from typing import Tuple
from fpdf import FPDF

from app.models import AnalysisResponse, IncidentFinding, RiskLevel


RISK_COLORS: dict[str, Tuple[int, int, int]] = {
    "Crítico": (185, 28, 28),   # Red
    "Alto": (217, 119, 6),      # Orange/Amber
    "Medio": (2, 132, 199),     # Blue
    "Bajo": (22, 163, 74),      # Green
}


def _clean_text(text: str, unicode_enabled: bool = False) -> str:
    """Normalize typography symbols so PDF rendering never fails on any font backend."""
    if not text:
        return ""
    replacements = {
        "—": " - ",
        "–": "-",
        "•": "- ",
        "→": "->",
        "“": '"',
        "”": '"',
        "‘": "'",
        "’": "'",
        "…": "...",
    }
    res = str(text)
    for k, v in replacements.items():
        res = res.replace(k, v)
    if not unicode_enabled:
        return res.encode("latin-1", errors="replace").decode("latin-1")
    return res


class SIEMReportPDF(FPDF):
    """Custom FPDF class with Stockholm SOC Level 2 header, footer, and styling helpers."""

    def __init__(self, report_type_label: str):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.report_type_label = report_type_label
        self.set_auto_page_break(auto=True, margin=16)
        self.unicode_font = False
        self.font_family_name = "Helvetica"
        self.mono_font_name = "Courier"

        # Try loading system DejaVu TTF fonts for full Unicode support if available
        dejavu_dir = Path("/usr/share/fonts/truetype/dejavu")
        if (
            (dejavu_dir / "DejaVuSans.ttf").exists()
            and (dejavu_dir / "DejaVuSans-Bold.ttf").exists()
            and (dejavu_dir / "DejaVuSansMono.ttf").exists()
        ):
            try:
                self.add_font("DejaVu", "", str(dejavu_dir / "DejaVuSans.ttf"))
                self.add_font("DejaVu", "B", str(dejavu_dir / "DejaVuSans-Bold.ttf"))
                self.add_font("DejaVuMono", "", str(dejavu_dir / "DejaVuSansMono.ttf"))
                self.unicode_font = True
                self.font_family_name = "DejaVu"
                self.mono_font_name = "DejaVuMono"
            except Exception:
                self.unicode_font = False

    def txt(self, text: str) -> str:
        return _clean_text(text, self.unicode_font)

    def header(self):
        self.set_fill_color(15, 23, 42)  # Slate-900
        self.rect(0, 0, 210, 14, style="F")
        self.set_xy(10, 3.5)
        self.set_font(self.font_family_name, "B", 8.0)
        self.set_text_color(226, 232, 240)
        self.cell(
            105,
            7,
            self.txt("CONSULTORA DE CIBERSEGURIDAD - ESTOCOLMO, SUECIA | SOC NIVEL 2"),
            align="L",
        )
        self.set_text_color(56, 189, 248)
        self.cell(
            85,
            7,
            self.txt(self.report_type_label),
            align="R",
            new_x="LMARGIN",
            new_y="NEXT",
        )
        self.ln(4)

    def footer(self):
        self.set_y(-12)
        self.set_font(self.font_family_name, "", 7.5)
        self.set_text_color(100, 116, 139)
        self.cell(
            140,
            6,
            self.txt("Confidencial - Sustentado estrictamente en evidencia de registros SIEM (Rigor Analitico)"),
            align="L",
        )
        self.cell(0, 6, self.txt(f"Página {self.page_no()} de {{nb}}"), align="R")

    def section_banner(self, number: str, title: str):
        if self.get_y() > 250:
            self.add_page()
        self.ln(3)
        self.set_fill_color(30, 41, 59)
        self.set_text_color(255, 255, 255)
        self.set_font(self.font_family_name, "B", 11)
        self.cell(0, 8.5, self.txt(f"  {number}. {title.upper()}"), fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(2.5)
        self.set_text_color(15, 23, 42)

    def paragraph(self, text: str, size: float = 9.5, bold: bool = False):
        self.set_font(self.font_family_name, "B" if bold else "", size)
        self.set_text_color(30, 41, 59)
        self.multi_cell(0, 5.2, self.txt(text), new_x="LMARGIN", new_y="NEXT")
        self.ln(1.5)

    def bullet_list(self, items: list[str], size: float = 9.2):
        self.set_font(self.font_family_name, "", size)
        self.set_text_color(30, 41, 59)
        for item in items:
            if self.get_y() > 265:
                self.add_page()
            self.set_x(12)
            self.multi_cell(0, 5, self.txt(f"-  {item}"), new_x="LMARGIN", new_y="NEXT")
            self.ln(1)

    def risk_badge(self, label: str, risk: RiskLevel):
        r, g, b = RISK_COLORS.get(risk, (71, 85, 105))
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font(self.font_family_name, "B", 9)
        self.cell(0, 7.5, self.txt(f"  {label}: {risk.upper()}"), fill=True, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(15, 23, 42)
        self.ln(2)


def _render_executive_content(pdf: SIEMReportPDF, analysis: AnalysisResponse):
    """Render the complete Executive Report section onto the current page of pdf."""
    exec_rep = analysis.executive_report
    m = analysis.metrics

    # Title block
    pdf.set_fill_color(241, 245, 249)
    pdf.rect(10, 18, 190, 28, style="F")
    pdf.set_xy(14, 21)
    pdf.set_font(pdf.font_family_name, "B", 14.5)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, pdf.txt(f"PARTE I — {exec_rep.report_title}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(14)
    pdf.set_font(pdf.font_family_name, "", 9.2)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(0, 5.5, pdf.txt(exec_rep.subtitle), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(14)
    pdf.set_font(pdf.font_family_name, "B", 8.2)
    pdf.cell(
        0,
        5.5,
        pdf.txt(
            f"Archivo Analizado: {analysis.filename}  |  Fecha de Emisión: {analysis.analyzed_at}  |  Motor: {analysis.ai_model_name}"
        ),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(5)

    # Global risk banner
    pdf.risk_badge("NIVEL DE RIESGO GLOBAL PARA LA ORGANIZACIÓN", exec_rep.global_risk_level)

    # KPI Summary Box
    pdf.set_fill_color(248, 250, 252)
    pdf.set_draw_color(203, 213, 225)
    pdf.set_font(pdf.font_family_name, "B", 8.8)
    kpi_line = (
        f"Registros Analizados: {m.total_logs}   |   Incidentes Confirmados: {m.total_incidents} "
        f"({m.critical_incidents_count} Críticos, {m.high_incidents_count} Altos, {m.medium_incidents_count} Medios)   |   "
        f"Datos Exfiltrados: {m.total_exfiltrated_mb} MB"
    )
    pdf.cell(0, 8, pdf.txt(f"  {kpi_line}"), border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # Section 1: Dictamen Ejecutivo
    pdf.section_banner("01", "Dictamen Ejecutivo y Panorama General")
    pdf.paragraph(exec_rep.incident_determination, size=9.8, bold=True)
    pdf.paragraph(exec_rep.executive_overview, size=9.5)

    # Section 2: Impacto en el Negocio
    pdf.section_banner("02", "Impacto Directo en el Negocio (Financiero, Legal y Operativo)")
    pdf.bullet_list(exec_rep.key_business_impacts)

    # Section 3: Resumen de Incidentes en Lenguaje Claro
    pdf.section_banner("03", "Resumen de Incidentes Detectados (En Lenguaje Claro)")
    for item in exec_rep.plain_language_incidents:
        if pdf.get_y() > 235:
            pdf.add_page()
        r, g, b = RISK_COLORS.get(item.risk_level, (71, 85, 105))
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font(pdf.font_family_name, "B", 9.5)
        pdf.cell(
            0,
            7,
            pdf.txt(f"  [{item.incident_id}] {item.title}  —  RIESGO: {item.risk_level.upper()}"),
            fill=True,
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.set_fill_color(248, 250, 252)
        pdf.set_text_color(15, 23, 42)
        pdf.set_font(pdf.font_family_name, "B", 8.8)
        pdf.cell(0, 5.5, pdf.txt("  ¿Qué ocurrió?:"), fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(pdf.font_family_name, "", 8.8)
        pdf.multi_cell(0, 4.8, pdf.txt(f"  {item.what_happened}"), fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font(pdf.font_family_name, "B", 8.8)
        pdf.cell(0, 5.5, pdf.txt("  Riesgo para el Negocio:"), fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(pdf.font_family_name, "", 8.8)
        pdf.multi_cell(0, 4.8, pdf.txt(f"  {item.business_risk}"), fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font(pdf.font_family_name, "B", 8.8)
        pdf.cell(0, 5.5, pdf.txt("  Acción Inmediata Requerida:"), fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(pdf.font_family_name, "", 8.8)
        pdf.multi_cell(0, 4.8, pdf.txt(f"  {item.recommended_decision}"), fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # Section 4: Decisiones Prioritarias de la Dirección
    pdf.section_banner("04", "Decisiones Prioritarias para la Alta Dirección")
    pdf.bullet_list(exec_rep.priority_decisions)

    # Section 5: Recomendaciones Estratégicas e Inversión
    pdf.section_banner("05", "Recomendaciones Estratégicas de Ciberseguridad")
    pdf.bullet_list(exec_rep.investment_recommendations)


def _render_technical_content(pdf: SIEMReportPDF, analysis: AnalysisResponse):
    """Render the complete Technical SOC Level 2 Report section onto the current page of pdf."""
    tech = analysis.technical_report
    m = analysis.metrics

    # Title Block
    pdf.set_fill_color(241, 245, 249)
    pdf.rect(10, 18, 190, 28, style="F")
    pdf.set_xy(14, 21)
    pdf.set_font(pdf.font_family_name, "B", 13.5)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, pdf.txt(f"PARTE II — {tech.report_title}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(14)
    pdf.set_font(pdf.font_family_name, "", 9)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(0, 5.5, pdf.txt(tech.subtitle), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(14)
    pdf.set_font(pdf.font_family_name, "B", 8.2)
    pdf.cell(
        0,
        5.5,
        pdf.txt(
            f"Evidencia: {analysis.filename} ({m.total_logs} logs) | Ventana: {m.time_range_start} - {m.time_range_end}"
        ),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(5)

    pdf.risk_badge("CLASIFICACIÓN DE CRITICIDAD GLOBAL DEL INCIDENTE", tech.global_risk_level)

    # 1. Resumen Ejecutivo
    pdf.section_banner("01", "Resumen Ejecutivo Técnico")
    pdf.paragraph(tech.resumen_ejecutivo)
    pdf.paragraph(f"Nota de Rigor Analítico: {tech.nota_rigor_analitico}", size=8.5, bold=True)

    # 2. Hallazgos Identificados (Overview & Correlation Matrix)
    pdf.section_banner("02", "Hallazgos Identificados y Matriz de Correlación")
    pdf.paragraph(tech.hallazgos_resumen)

    # Summary Table of Incidents
    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font(pdf.font_family_name, "B", 8)
    pdf.cell(16, 6.5, pdf.txt("ID"), border=1, fill=True)
    pdf.cell(22, 6.5, pdf.txt("Criticidad"), border=1, fill=True)
    pdf.cell(35, 6.5, pdf.txt("Ventana Temporal"), border=1, fill=True)
    pdf.cell(18, 6.5, pdf.txt("Eventos"), border=1, fill=True)
    pdf.cell(99, 6.5, pdf.txt("Activos / Cuentas / IPs Clave"), border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font(pdf.font_family_name, "", 7.8)
    pdf.set_text_color(15, 23, 42)
    for inc in analysis.incidents:
        tw = f"{inc.time_start[11:19]} - {inc.time_end[11:19]}" if len(inc.time_start) >= 19 else inc.time_start
        scope_str = f"Hosts: {', '.join(inc.affected_hosts[:3])} | Users: {', '.join(inc.compromised_users[:2])}"
        pdf.cell(16, 6, pdf.txt(inc.incident_id), border=1)
        pdf.cell(22, 6, pdf.txt(inc.risk_level), border=1)
        pdf.cell(35, 6, pdf.txt(tw[:19]), border=1)
        pdf.cell(18, 6, pdf.txt(f"{inc.total_events} ({inc.hidden_informational_count} Info)"), border=1)
        pdf.cell(99, 6, pdf.txt(scope_str[:62]), border=1, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # Sections 3, 4, 5, 7 Detailed per Incident Finding
    pdf.section_banner(
        "03-07",
        "Detalle Técnico por Hallazgo: Explicación, Evidencias en Logs, Criticidad, Impacto y Plan de Acción",
    )

    for inc in analysis.incidents:
        _render_technical_incident_block(pdf, inc)

    # Section 6: Posible impacto global en la organización
    pdf.section_banner("06", "Evaluación Global de Impacto en la Organización (CIA Triad)")
    pdf.paragraph(tech.impacto_organizacion_global)

    # Section 8: Recomendaciones generales de seguridad
    pdf.section_banner("08", "Recomendaciones Generales de Seguridad y Arquitectura SOC")
    pdf.bullet_list(tech.recomendaciones_generales)


def generate_combined_pdf(analysis: AnalysisResponse) -> bytes:
    """
    Generate a single Spanish PDF file containing:
    1. Executive Report first (Parte I: Informe Ejecutivo para Alta Dirección)
    2. Technical Report second (Parte II: Informe Técnico Forense SOC Nivel 2)
    """
    pdf = SIEMReportPDF("PARTE I: INFORME EJECUTIVO (ALTA DIRECCIÓN)")
    pdf.alias_nb_pages()

    # Part I: Executive Report
    pdf.add_page()
    _render_executive_content(pdf, analysis)

    # Part II: Technical SOC L2 Report (starts on a clean page with updated running header)
    pdf.report_type_label = "PARTE II: INFORME TÉCNICO FORENSE (SOC NIVEL 2)"
    pdf.add_page()
    _render_technical_content(pdf, analysis)

    return bytes(pdf.output())


def _render_technical_incident_block(pdf: SIEMReportPDF, inc: IncidentFinding):
    """Render complete technical detail, strict log evidence, justification, and action plan for one incident."""
    if pdf.get_y() > 210:
        pdf.add_page()

    r, g, b = RISK_COLORS.get(inc.risk_level, (71, 85, 105))
    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font(pdf.font_family_name, "B", 9.8)
    pdf.cell(
        0,
        7.5,
        pdf.txt(f"  [{inc.incident_id}] {inc.title}   |   CRITICIDAD: {inc.risk_level.upper()}"),
        fill=True,
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(1.5)

    # Metadata bar
    pdf.set_font(pdf.font_family_name, "B", 8.2)
    pdf.set_text_color(51, 65, 85)
    pdf.multi_cell(
        0,
        4.6,
        pdf.txt(
            f"Categorías Detectadas: {', '.join(inc.categories)}   |   "
            f"Ventana: {inc.time_start} a {inc.time_end}   |   "
            f"Total Eventos Correlacionados: {inc.total_events} "
            f"(Eventos 'Informational' ocultos descubiertos: {inc.hidden_informational_count})\n"
            f"Sistemas Afectados: {', '.join(inc.affected_hosts)}   |   "
            f"Cuentas: {', '.join(inc.compromised_users)}   |   "
            f"IPs Involucradas: {', '.join(inc.attacker_ips)}\n"
            f"MITRE ATT&CK: {'; '.join(inc.mitre_tactics)}"
        ),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(1.5)

    # Criticidad y Justificación
    pdf.set_font(pdf.font_family_name, "B", 9)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 5.2, pdf.txt("Criticidad y Justificación Estricta:"), new_x="LMARGIN", new_y="NEXT")
    pdf.paragraph(inc.justification, size=8.8)

    # Explicación Técnica
    pdf.set_font(pdf.font_family_name, "B", 9)
    pdf.cell(0, 5.2, pdf.txt("Explicación Técnica del Hallazgo y Cadena de Correlación:"), new_x="LMARGIN", new_y="NEXT")
    pdf.paragraph(inc.technical_explanation, size=8.8)

    # Posible impacto en la organización
    pdf.set_font(pdf.font_family_name, "B", 9)
    pdf.cell(0, 5.2, pdf.txt("Posible Impacto en la Organización e Indicadores de Compromiso (IoCs):"), new_x="LMARGIN", new_y="NEXT")
    pdf.paragraph(inc.organizational_impact, size=8.8)
    pdf.bullet_list(inc.key_iocs, size=8.4)

    # Evidencias encontradas en los logs
    if pdf.get_y() > 235:
        pdf.add_page()
    pdf.set_font(pdf.font_family_name, "B", 8.8)
    pdf.set_text_color(15, 23, 42)
    sample_ids_str = ", ".join(inc.evidence_log_ids[:12])
    if len(inc.evidence_log_ids) > 12:
        sample_ids_str += f" ... (+{len(inc.evidence_log_ids) - 12} registros adicionales)"
    pdf.cell(
        0,
        5.5,
        pdf.txt(f"Evidencias Encontradas en los Logs (Log_IDs: {sample_ids_str}):"),
        new_x="LMARGIN",
        new_y="NEXT",
    )

    pdf.set_fill_color(241, 245, 249)
    pdf.set_font(pdf.mono_font_name, "", 7.0)
    pdf.set_text_color(15, 23, 42)
    for ev in inc.evidence_logs[:10]:
        if pdf.get_y() > 268:
            pdf.add_page()
            pdf.set_font(pdf.mono_font_name, "", 7.0)
        cmd_part = f" | Cmd/URI: {ev.process_command_line}" if ev.process_command_line else ""
        elev_tag = " [INFO->ELEVADO]" if ev.elevated_from_informational else ""
        line = (
            f"{ev.log_id} | {ev.timestamp} | {ev.hostname} | Evt:{ev.event_id} | "
            f"Usr:{ev.user} | {ev.source_ip}->{ev.destination or '-'} | "
            f"{ev.event_description}{cmd_part} | {ev.result} ({ev.severity}{elev_tag})"
        )
        pdf.multi_cell(0, 4.0, pdf.txt(line), fill=True, border=0, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # Plan de Acción: Investigar, Contener y Remediar
    if pdf.get_y() > 235:
        pdf.add_page()
    pdf.set_font(pdf.font_family_name, "B", 9)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 5.5, pdf.txt("Plan de Acción SOC Nivel 2 (Investigar, Contener y Remediar):"), new_x="LMARGIN", new_y="NEXT")

    pdf.set_font(pdf.font_family_name, "B", 8.5)
    pdf.set_text_color(3, 105, 161)
    pdf.cell(0, 4.8, pdf.txt("Fase 1 - Investigar:"), new_x="LMARGIN", new_y="NEXT")
    pdf.bullet_list(inc.action_plan.investigar, size=8.4)

    pdf.set_font(pdf.font_family_name, "B", 8.5)
    pdf.set_text_color(185, 28, 28)
    pdf.cell(0, 4.8, pdf.txt("Fase 2 - Contener:"), new_x="LMARGIN", new_y="NEXT")
    pdf.bullet_list(inc.action_plan.contener, size=8.4)

    pdf.set_font(pdf.font_family_name, "B", 8.5)
    pdf.set_text_color(21, 128, 61)
    pdf.cell(0, 4.8, pdf.txt("Fase 3 - Remediar:"), new_x="LMARGIN", new_y="NEXT")
    pdf.bullet_list(inc.action_plan.remediar, size=8.4)

    pdf.ln(3)
    pdf.set_draw_color(203, 213, 225)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)
