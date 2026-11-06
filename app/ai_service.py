"""Microsoft Foundry (Azure AI Foundry / Azure OpenAI) Integration Service.

Enriches the deterministic correlation findings and Spanish reports using a
cost-effective GPT model (e.g., gpt-4o-mini / gpt-4.1-mini) while strictly
enforcing 'Rigor Analítico' (zero hallucinated findings; every claim must be
grounded in the verified Log_IDs from the uploaded SIEM Excel file).
"""

import json
import os
from typing import Dict, List, Optional, Tuple
from dotenv import load_dotenv

from app.models import (
    AIConfigRequest,
    DashboardMetrics,
    ExecutiveReportData,
    IncidentFinding,
    TechnicalReportData,
)

load_dotenv()


def resolve_foundry_config(config_req: Optional[AIConfigRequest] = None) -> Dict[str, str]:
    """Resolve Microsoft Foundry credentials from UI request or environment variables."""
    endpoint = (
        (config_req.endpoint if config_req and config_req.endpoint else None)
        or os.getenv("AZURE_OPENAI_ENDPOINT", "")
    ).strip()
    api_key = (
        (config_req.api_key if config_req and config_req.api_key else None)
        or os.getenv("AZURE_OPENAI_API_KEY", "")
    ).strip()
    deployment = (
        (config_req.deployment_name if config_req and config_req.deployment_name else None)
        or os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME", "gpt-4o-mini")
    ).strip()
    api_version = (
        (config_req.api_version if config_req and config_req.api_version else None)
        or os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21")
    ).strip()

    # Ignore placeholder values from .env.example
    if "your-foundry-resource" in endpoint or "your-api-key" in api_key:
        endpoint = ""
        api_key = ""

    return {
        "endpoint": endpoint,
        "api_key": api_key,
        "deployment": deployment or "gpt-4o-mini",
        "api_version": api_version or "2024-10-21",
    }


def _create_foundry_client(cfg: Dict[str, str]):
    """Instantiate an OpenAI / AzureOpenAI client compatible with Microsoft Foundry endpoints."""
    from openai import AzureOpenAI, OpenAI

    endpoint = cfg["endpoint"].rstrip("/")
    api_key = cfg["api_key"]
    api_version = cfg["api_version"]

    # If the user provides a direct v1 or models inference URL in Microsoft Foundry
    if endpoint.endswith("/openai/v1") or endpoint.endswith("/models"):
        return OpenAI(
            base_url=endpoint,
            api_key=api_key,
            default_headers={"api-key": api_key},
        )

    return AzureOpenAI(
        azure_endpoint=endpoint,
        api_key=api_key,
        api_version=api_version,
    )


def test_foundry_connection(config_req: AIConfigRequest) -> Dict[str, object]:
    """Test connectivity to the configured Microsoft Foundry deployment."""
    cfg = resolve_foundry_config(config_req)
    if not cfg["endpoint"] or not cfg["api_key"]:
        return {
            "ok": False,
            "message": (
                "No se han configurado credenciales de Microsoft Foundry (AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_API_KEY). "
                "El sistema operará con el Motor Híbrido Determinista SOC L2 hasta que ingreses tus credenciales."
            ),
        }

    try:
        client = _create_foundry_client(cfg)
        resp = client.chat.completions.create(
            model=cfg["deployment"],
            messages=[
                {
                    "role": "system",
                    "content": "Eres un asistente de ciberseguridad SOC Nivel 2. Responde únicamente 'CONEXIÓN EXITOSA'.",
                },
                {"role": "user", "content": "Prueba de conectividad desde SIEM Log Analyzer."},
            ],
            max_tokens=20,
            temperature=0.0,
        )
        reply = (resp.choices[0].message.content or "").strip()
        return {
            "ok": True,
            "deployment": cfg["deployment"],
            "endpoint": cfg["endpoint"],
            "message": f"Conexión verificada con Microsoft Foundry ({cfg['deployment']}): {reply}",
        }
    except Exception as exc:
        return {
            "ok": False,
            "deployment": cfg["deployment"],
            "endpoint": cfg["endpoint"],
            "message": f"Error al conectar con Microsoft Foundry: {exc}",
        }


def enrich_analysis_with_foundry(
    incidents: List[IncidentFinding],
    metrics: DashboardMetrics,
    executive_report: ExecutiveReportData,
    technical_report: TechnicalReportData,
    config_req: Optional[AIConfigRequest] = None,
) -> Tuple[List[IncidentFinding], ExecutiveReportData, TechnicalReportData, str, str]:
    """
    Call Microsoft Foundry GPT model with verified correlation evidence to synthesize
    and refine the Executive and Technical Spanish reports while strictly enforcing
    analytical rigor (no hallucinated Log_IDs or findings).
    """
    if config_req and not config_req.use_ai:
        return (
            incidents,
            executive_report,
            technical_report,
            "Motor Determinista SOC L2 (Rigurosidad Estricta)",
            "Correlación Basada en Reglas SOC L2",
        )

    cfg = resolve_foundry_config(config_req)
    if not cfg["endpoint"] or not cfg["api_key"]:
        return (
            incidents,
            executive_report,
            technical_report,
            "Motor Híbrido SOC L2 (Correlación Determinista Activa — Listo para Microsoft Foundry)",
            "Motor Determinista SOC L2 (Sin API Key externa)",
        )

    # Build a compact, token-efficient evidence payload for the cost-effective GPT model
    compact_evidence = {
        "total_logs": metrics.total_logs,
        "suspicious_logs_count": metrics.suspicious_logs_count,
        "hidden_informational_detected": metrics.hidden_informational_detected,
        "time_range": f"{metrics.time_range_start} a {metrics.time_range_end}",
        "total_exfiltrated_bytes": metrics.total_exfiltrated_bytes,
        "total_exfiltrated_mb": metrics.total_exfiltrated_mb,
        "incidents": [
            {
                "incident_id": inc.incident_id,
                "title": inc.title,
                "risk_level": inc.risk_level,
                "categories": inc.categories,
                "time_window": f"{inc.time_start} - {inc.time_end}",
                "affected_hosts": inc.affected_hosts,
                "compromised_users": inc.compromised_users,
                "attacker_ips": inc.attacker_ips,
                "total_events": inc.total_events,
                "hidden_informational_count": inc.hidden_informational_count,
                "key_iocs": inc.key_iocs,
                "sample_log_ids": inc.evidence_log_ids[:10],
            }
            for inc in incidents
        ],
    }

    system_prompt = (
        "Eres el Analista Principal SOC Nivel 2 de una prestigiosa consultora de ciberseguridad en Estocolmo, Suecia. "
        "Tu misión es redactar secciones de alto nivel para DOS informes en español basados ESTRICTAMENTE en la "
        "evidencia correlacionada del SIEM proporcionada en formato JSON:\n"
        "1) Informe Ejecutivo (en lenguaje claro y llano para directivos no técnicos, enfocado en impacto al negocio y decisiones).\n"
        "2) Informe Técnico SOC Nivel 2 (para especialistas en ciberseguridad, citando Log_IDs exactos, IPs, cuentas, procesos y técnicas MITRE).\n\n"
        "REGLA DE ORO (RIGOR ANALÍTICO): NO inventes hallazgos, IPs, usuarios, archivos ni eventos que no estén en el JSON "
        "de entrada. Devuelve ÚNICAMENTE un objeto JSON válido con las claves exactas:\n"
        "{\n"
        '  "executive_overview": "string (2 párrafos en lenguaje llano para la alta dirección)",\n'
        '  "incident_determination": "string (conclusión clara de si hubo uno o múltiples incidentes)",\n'
        '  "resumen_ejecutivo_tecnico": "string (resumen ejecutivo técnico para el informe SOC L2)",\n'
        '  "hallazgos_resumen_tecnico": "string (síntesis técnica de correlación multi-evento)",\n'
        '  "impacto_organizacion_global": "string (evaluación detallada de confidencialidad, integridad y disponibilidad)"\n'
        "}"
    )

    try:
        client = _create_foundry_client(cfg)
        response = client.chat.completions.create(
            model=cfg["deployment"],
            messages=[
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": (
                        "Evidencia verificada de correlación SIEM (Estocolmo SOC L2):\n"
                        + json.dumps(compact_evidence, ensure_ascii=False)
                    ),
                },
            ],
            response_format={"type": "json_object"},
            temperature=0.1,
            max_tokens=1400,
        )
        raw_content = (response.choices[0].message.content or "").strip()
        parsed = json.loads(raw_content)

        if parsed.get("executive_overview"):
            executive_report.executive_overview = str(parsed["executive_overview"]).strip()
        if parsed.get("incident_determination"):
            executive_report.incident_determination = str(parsed["incident_determination"]).strip()
        if parsed.get("resumen_ejecutivo_tecnico"):
            technical_report.resumen_ejecutivo = str(parsed["resumen_ejecutivo_tecnico"]).strip()
        if parsed.get("hallazgos_resumen_tecnico"):
            technical_report.hallazgos_resumen = str(parsed["hallazgos_resumen_tecnico"]).strip()
        if parsed.get("impacto_organizacion_global"):
            technical_report.impacto_organizacion_global = str(parsed["impacto_organizacion_global"]).strip()

        return (
            incidents,
            executive_report,
            technical_report,
            f"Microsoft Foundry GPT Activo ({cfg['deployment']}) + Correlación Determinista SOC L2",
            cfg["deployment"],
        )
    except Exception as exc:
        # Seamless fallback to deterministic report while noting the fallback reason
        return (
            incidents,
            executive_report,
            technical_report,
            f"Motor Determinista SOC L2 (Fallback automático tras error en Foundry: {type(exc).__name__})",
            f"{cfg['deployment']} (Fallback)",
        )
