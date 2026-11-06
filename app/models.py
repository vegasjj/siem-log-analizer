"""Pydantic data models for SIEM Log Analyzer (SOC Level 2)."""

from typing import Dict, List, Literal, Optional
from pydantic import BaseModel, Field


RiskLevel = Literal["Crítico", "Alto", "Medio", "Bajo"]


class LogEntry(BaseModel):
    """Represents a single normalized SIEM log record from the Excel export."""

    row_number: int = Field(..., description="1-based row number in the Excel sheet")
    log_id: str = Field(..., description="Unique event identifier, e.g., EVT-00001")
    timestamp: str = Field(..., description="Timestamp string YYYY-MM-DD HH:MM:SS")
    hostname: str = Field(..., description="System hostname, e.g., DC-01, APP-SRV01")
    event_id: str = Field(..., description="Windows Event ID or log type, e.g., 4625, PROXY_ACCESS")
    user: str = Field(..., description="Domain/local user or service account")
    source_ip: str = Field(..., description="Origin IP address")
    destination: str = Field(..., description="Target host, share, or IP:port")
    log_source: str = Field(..., description="Telemetry source: Security, System, Proxy, IIS, PowerShell, Firewall")
    event_description: str = Field(..., description="Description or summary of the event")
    process_command_line: str = Field(default="", description="Command line, URI, or detail string")
    result: str = Field(..., description="Event result: Success, Failure, Allowed, HTTP status")
    severity: str = Field(..., description="Original SIEM severity: Informational, Warning, Medium, High")

    # Enriched fields populated by the correlation engine
    is_suspicious: bool = Field(default=False, description="True if correlated into a security finding")
    elevated_from_informational: bool = Field(
        default=False,
        description="True if raw severity was Informational but event is part of an attack chain",
    )
    correlated_incident_id: Optional[str] = Field(
        default=None, description="ID of the correlated incident (e.g., INC-01)"
    )
    detection_category: Optional[str] = Field(
        default=None, description="Primary detection category assigned by correlation engine"
    )


class ActionPlan(BaseModel):
    """Structured 3-phase incident response action plan required by SOC L2 spec."""

    investigar: List[str] = Field(..., description="Steps to investigate and scope the incident")
    contener: List[str] = Field(..., description="Immediate containment measures")
    remediar: List[str] = Field(..., description="Long-term remediation and hardening actions")


class IncidentFinding(BaseModel):
    """Represents a correlated multi-event security incident or anomaly cluster."""

    incident_id: str = Field(..., description="Unique incident identifier, e.g., INC-01")
    title: str = Field(..., description="Spanish title of the correlated incident")
    executive_title: str = Field(..., description="Plain-language title for executive audience")
    categories: List[str] = Field(
        ...,
        description="Applicable detection categories (Fuerza bruta, Inicios sospechosos, Escalamiento, Comandos y procesos, Movimiento lateral, Otras anomalías)",
    )
    risk_level: RiskLevel = Field(..., description="Criticality: Crítico, Alto, Medio, Bajo")
    justification: str = Field(..., description="Strict evidence-based justification for risk level")
    mitre_tactics: List[str] = Field(default_factory=list, description="MITRE ATT&CK tactics & techniques")
    time_start: str = Field(..., description="Start timestamp of correlated incident")
    time_end: str = Field(..., description="End timestamp of correlated incident")
    affected_hosts: List[str] = Field(default_factory=list, description="List of affected hostnames")
    compromised_users: List[str] = Field(default_factory=list, description="List of involved user/service accounts")
    attacker_ips: List[str] = Field(default_factory=list, description="Origin or destination external/internal IPs")
    total_events: int = Field(..., description="Number of correlated log events")
    hidden_informational_count: int = Field(
        default=0,
        description="Count of raw Informational events uncovered via multi-event correlation",
    )
    summary_plain_language: str = Field(
        ..., description="Non-technical explanation for the executive audience"
    )
    business_impact: str = Field(
        ..., description="Business, financial, legal, or operational impact in plain language"
    )
    technical_explanation: str = Field(
        ..., description="Detailed SOC Level 2 technical explanation of the attack chain"
    )
    organizational_impact: str = Field(
        ..., description="Detailed technical and organizational impact assessment"
    )
    key_iocs: List[str] = Field(default_factory=list, description="Key Indicators of Compromise (IoCs)")
    evidence_log_ids: List[str] = Field(
        default_factory=list, description="All Log_IDs supporting this incident"
    )
    evidence_logs: List[LogEntry] = Field(
        default_factory=list, description="Representative/complete LogEntry records as strict evidence"
    )
    action_plan: ActionPlan = Field(..., description="Investigar, Contener y Remediar action plan")


class ExecutiveIncidentItem(BaseModel):
    """Plain-language incident summary item for the Executive Report."""

    incident_id: str
    title: str
    risk_level: RiskLevel
    what_happened: str
    business_risk: str
    recommended_decision: str


class ExecutiveReportData(BaseModel):
    """Complete Spanish report structure tailored for an Executive / Board audience."""

    report_title: str = "Informe Ejecutivo de Ciberseguridad — Análisis de Incidentes SIEM"
    subtitle: str = "Evaluación de Riesgo Organizacional, Impacto al Negocio y Decisiones Estratégicas"
    consultancy_location: str = "Consultora de Ciberseguridad — Estocolmo, Suecia (SOC Nivel 2)"
    global_risk_level: RiskLevel
    incident_determination: str = Field(
        ..., description="Clear statement on whether there was one or multiple security incidents"
    )
    executive_overview: str = Field(
        ..., description="Plain-language executive summary without excessive technical jargon"
    )
    key_business_impacts: List[str] = Field(
        ..., description="Key financial, legal, operational, and reputational impacts identified"
    )
    plain_language_incidents: List[ExecutiveIncidentItem] = Field(
        ..., description="Simplified breakdown of each correlated incident for leadership"
    )
    priority_decisions: List[str] = Field(
        ..., description="Immediate strategic and governance decisions required from leadership"
    )
    investment_recommendations: List[str] = Field(
        ..., description="High-level security roadmap and resource recommendations"
    )


class TechnicalReportData(BaseModel):
    """Complete Spanish report structure tailored for a Security-Savvy / SOC L2 audience (Slide 4)."""

    report_title: str = "Informe Técnico de Análisis Forense y Correlación SIEM — SOC Nivel 2"
    subtitle: str = "Investigación de Indicadores de Compromiso (IoC), Correlación de Eventos y Plan de Respuesta"
    consultancy_location: str = "Consultora de Ciberseguridad — Estocolmo, Suecia (SOC Nivel 2)"
    global_risk_level: RiskLevel
    resumen_ejecutivo: str = Field(..., description="Section 1: Resumen ejecutivo")
    hallazgos_resumen: str = Field(..., description="Section 2: Overview of identified findings and correlation")
    impacto_organizacion_global: str = Field(
        ..., description="Section 6: Global organizational and infrastructure impact"
    )
    recomendaciones_generales: List[str] = Field(
        ..., description="Section 8: Recomendaciones generales de seguridad"
    )
    nota_rigor_analitico: str = Field(
        default="Todas las conclusiones, líneas de tiempo e indicadores de compromiso (IoC) de este informe están sustentados estrictamente en los registros de eventos (Log_ID) contenidos en el archivo exportado del SIEM, sin extrapolar ni inventar hallazgos fuera de la evidencia.",
        description="Explicit analytical rigor statement",
    )


class DashboardMetrics(BaseModel):
    """Aggregated statistics and chart datasets for the interactive web dashboard."""

    total_logs: int
    suspicious_logs_count: int
    hidden_informational_detected: int
    total_incidents: int
    critical_incidents_count: int
    high_incidents_count: int
    medium_incidents_count: int
    low_incidents_count: int
    compromised_hosts_count: int
    compromised_accounts_count: int
    external_attacker_ips_count: int
    total_exfiltrated_bytes: int
    total_exfiltrated_mb: float
    time_range_start: str
    time_range_end: str

    # Chart series
    incidents_by_risk: Dict[str, int]
    events_by_raw_severity: Dict[str, int]
    events_by_category: Dict[str, int]
    events_by_log_source: Dict[str, int]
    timeline_buckets: List[Dict[str, object]]
    top_affected_hosts: Dict[str, int]
    top_suspicious_ips: Dict[str, int]
    top_targeted_users: Dict[str, int]


class AIConfigRequest(BaseModel):
    """Optional runtime Microsoft Foundry configuration passed from the UI."""

    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    deployment_name: Optional[str] = None
    api_version: Optional[str] = None
    use_ai: bool = True


class AnalysisResponse(BaseModel):
    """Full response returned by the SIEM Log Analyzer pipeline."""

    filename: str
    analyzed_at: str
    ai_mode_used: str = Field(
        ..., description="Indicates whether Microsoft Foundry GPT enrichment or Deterministic Engine was used"
    )
    ai_model_name: str = Field(default="Motor Determinista SOC L2", description="Model identifier")
    metrics: DashboardMetrics
    incidents: List[IncidentFinding]
    executive_report: ExecutiveReportData
    technical_report: TechnicalReportData
    logs: List[LogEntry]
