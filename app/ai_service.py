"""AI-Driven SIEM Log Correlation, Dashboard Categorization & Report Generator.

Uses Microsoft Foundry (Azure AI Foundry / Azure OpenAI GPT) to dynamically analyze
any uploaded SIEM Excel dataset, correlate events into security incidents, classify
risks (Crítico, Alto, Medio, Bajo), populate dashboard categories, and generate both
Executive and Technical reports in Spanish.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from dotenv import load_dotenv

from app.analyzer import (
    REQUIRED_CATEGORIES,
    build_dashboard_metrics,
    build_fallback_reports,
    extract_candidate_signals,
    group_candidates_generically,
)
from app.models import (
    AIConfigRequest,
    ActionPlan,
    DashboardMetrics,
    ExecutiveIncidentItem,
    ExecutiveReportData,
    IncidentFinding,
    LogEntry,
    RiskLevel,
    TechnicalReportData,
)

load_dotenv()
logger = logging.getLogger(__name__)


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


def _chat_completion_flexible(
    client: Any,
    model: str,
    messages: List[Dict[str, str]],
    max_completion_tokens: int = 16000,
    json_mode: bool = True,
):
    """
    Invoke chat.completions.create with automatic compatibility for both standard
    GPT models (gpt-4o-mini, gpt-4.1-mini) and reasoning models (gpt-5-mini, o4-mini, o3-mini)
    that may reject custom temperature or require large max_completion_tokens budgets.
    """
    kwargs: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_completion_tokens": max_completion_tokens,
    }
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    # First attempt: without custom temperature if model looks like a reasoning model, else temperature=0.1
    is_reasoning_model = any(
        prefix in model.lower() for prefix in ("o1", "o3", "o4", "gpt-5")
    )
    if not is_reasoning_model:
        kwargs["temperature"] = 0.1

    try:
        return client.chat.completions.create(**kwargs)
    except Exception as first_err:
        err_str = str(first_err).lower()
        # Retry without temperature if the model rejects temperature!=1
        if "temperature" in err_str and "temperature" in kwargs:
            kwargs.pop("temperature", None)
            return client.chat.completions.create(**kwargs)
        # Retry without response_format if the endpoint doesn't support json_object mode
        if "response_format" in err_str and "response_format" in kwargs:
            kwargs.pop("response_format", None)
            return client.chat.completions.create(**kwargs)
        raise


def _extract_and_parse_json(raw_text: str) -> Dict[str, Any]:
    """
    Cleanly parse JSON from an LLM response:
    1. Strips markdown code fences (```json ... ```).
    2. Extracts the outermost {...} JSON object.
    3. Attempts lightweight bracket repair if output was slightly truncated.
    """
    if not raw_text or not raw_text.strip():
        raise ValueError("El modelo de Microsoft Foundry devolvió una respuesta vacía (verifica el límite de tokens).")

    cleaned = raw_text.strip()

    # Strip ```json ... ``` fences if present
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    cleaned = cleaned.strip()

    # Extract from first '{' to last '}'
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidate = cleaned[first_brace : last_brace + 1]
    elif first_brace != -1:
        candidate = cleaned[first_brace:]
    else:
        candidate = cleaned

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        # Attempt control-character sanitization inside strings
        sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", candidate)
        try:
            return json.loads(sanitized)
        except json.JSONDecodeError:
            # Attempt closing truncated JSON structures if finish_reason=='length' occurred
            repaired = _attempt_json_truncation_repair(sanitized)
            return json.loads(repaired)


def _attempt_json_truncation_repair(text: str) -> str:
    """Best-effort closure of open quotes, brackets, and braces on truncated JSON."""
    s = text.rstrip()
    # Trim trailing incomplete key/value after last comma
    last_comma = s.rfind(",")
    if last_comma > len(s) - 120 and last_comma != -1:
        s = s[:last_comma]

    # Count open braces/brackets outside strings
    in_str = False
    escape = False
    stack: List[str] = []
    for ch in s:
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if not in_str:
            if ch in "{[":
                stack.append("}" if ch == "{" else "]")
            elif ch in "}]" and stack and stack[-1] == ch:
                stack.pop()

    if in_str:
        s += '"'
    while stack:
        s += stack.pop()
    return s


def test_foundry_connection(config_req: AIConfigRequest) -> Dict[str, object]:
    """Test connectivity to the configured Microsoft Foundry deployment."""
    cfg = resolve_foundry_config(config_req)
    if not cfg["endpoint"] or not cfg["api_key"]:
        return {
            "ok": False,
            "message": (
                "No se han configurado credenciales de Microsoft Foundry (Endpoint / API Key). "
                "Ingresa tu Endpoint y API Key para que el modelo GPT genere el análisis dinámicamente."
            ),
        }

    try:
        client = _create_foundry_client(cfg)
        resp = _chat_completion_flexible(
            client=client,
            model=cfg["deployment"],
            messages=[
                {
                    "role": "system",
                    "content": "Eres un analista SOC Nivel 2. Responde únicamente 'CONEXIÓN EXITOSA'.",
                },
                {"role": "user", "content": "Prueba de conectividad."},
            ],
            max_completion_tokens=500,
            json_mode=False,
        )
        reply = (resp.choices[0].message.content or "").strip() or "OK"
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


def run_dynamic_siem_analysis(
    logs: List[LogEntry],
    config_req: Optional[AIConfigRequest] = None,
) -> Tuple[List[IncidentFinding], DashboardMetrics, ExecutiveReportData, TechnicalReportData, str, str]:
    """
    Main dynamic analysis pipeline:
    1. Extracts candidate signals generically from the uploaded logs (no hardcoded dataset values).
    2. Calls Microsoft Foundry GPT to correlate incidents, classify risks, and generate
       both Executive and Technical reports in Spanish strictly grounded in the uploaded Log_IDs.
    3. Computes dynamic DashboardMetrics from the resulting incidents and logs.
    """
    candidate_logs, summary_stats = extract_candidate_signals(logs)
    cfg = resolve_foundry_config(config_req)
    use_ai = True if config_req is None else config_req.use_ai

    if use_ai and cfg["endpoint"] and cfg["api_key"]:
        try:
            incidents, exec_report, tech_report = _call_foundry_full_correlation(
                logs, candidate_logs, summary_stats, cfg
            )
            metrics = build_dashboard_metrics(logs, incidents)
            return (
                incidents,
                metrics,
                exec_report,
                tech_report,
                f"Análisis Generado por IA — Microsoft Foundry ({cfg['deployment']})",
                cfg["deployment"],
            )
        except Exception as exc:
            logger.exception("Error calling Microsoft Foundry AI service: %s", exc)
            incidents = group_candidates_generically(logs, candidate_logs)
            metrics = build_dashboard_metrics(logs, incidents)
            exec_report, tech_report = build_fallback_reports(incidents, metrics)
            return (
                incidents,
                metrics,
                exec_report,
                tech_report,
                f"Agrupación Heurística Genérica (Error en llamada a Microsoft Foundry: {type(exc).__name__}: {exc})",
                f"{cfg['deployment']} (Fallback)",
            )

    incidents = group_candidates_generically(logs, candidate_logs)
    metrics = build_dashboard_metrics(logs, incidents)
    exec_report, tech_report = build_fallback_reports(incidents, metrics)
    return (
        incidents,
        metrics,
        exec_report,
        tech_report,
        "Motor Heurístico Genérico (Configura Microsoft Foundry IA para análisis profundo con GPT)",
        "Heurística Genérica (Sin API Key)",
    )


def _call_foundry_full_correlation(
    all_logs: List[LogEntry],
    candidate_logs: List[LogEntry],
    summary_stats: Dict[str, object],
    cfg: Dict[str, str],
) -> Tuple[List[IncidentFinding], ExecutiveReportData, TechnicalReportData]:
    """
    Send the extracted candidate logs and statistical summary from the uploaded file to
    Microsoft Foundry GPT and parse its complete correlated incidents + dual Spanish reports.
    """
    log_by_id = {l.log_id: l for l in all_logs}

    # Pre-group candidate logs generically so we can pass compact cluster summaries + sample logs
    # to the LLM and avoid forcing the LLM to output hundreds of repetitive Log_ID strings.
    pre_clusters = group_candidates_generically(all_logs, candidate_logs)
    compact_clusters = [
        {
            "cluster_hint_id": c.incident_id,
            "time_start": c.time_start,
            "time_end": c.time_end,
            "total_events_in_cluster": c.total_events,
            "hidden_informational_count": c.hidden_informational_count,
            "affected_hosts": c.affected_hosts,
            "users": c.compromised_users,
            "ips": c.attacker_ips,
            "sample_log_ids": c.evidence_log_ids[:10],
            "sample_events": [
                f"{e.log_id}|{e.timestamp}|{e.hostname}|{e.event_id}|{e.user}|"
                f"{e.source_ip}->{e.destination}|{e.event_description}|{e.process_command_line}|{e.result}|{e.severity}"
                for e in c.evidence_logs[:8]
            ],
        }
        for c in pre_clusters
    ]

    # Map cluster_hint_id -> full evidence_log_ids so when the LLM references a cluster or any of its Log_IDs,
    # we can attach the complete set of underlying LogEntries without bloating LLM output tokens!
    cluster_full_ids = {c.incident_id: c.evidence_log_ids for c in pre_clusters}

    system_prompt = (
        "Eres un Analista Principal SOC Nivel 2 en una consultora de ciberseguridad en Estocolmo, Suecia. "
        "Acabas de recibir los registros sospechosos y estadísticas de un archivo Excel SIEM subido por el usuario. "
        "Tu tarea es correlacionar los eventos en incidentes de seguridad reales, clasificar su criticidad "
        "(Crítico, Alto, Medio, Bajo) con justificación estricta, y redactar DOS informes completos en español: "
        "uno para una audiencia ejecutiva (lenguaje claro/llano) y otro para una audiencia técnica de ciberseguridad.\n\n"
        "CATEGORÍAS DE DETECCIÓN PERMITIDAS (usa únicamente estas cadenas exactas en 'categories'):\n"
        '- "Fuerza bruta"\n'
        '- "Inicios sospechosos"\n'
        '- "Escalamiento"\n'
        '- "Comandos y procesos"\n'
        '- "Movimiento lateral"\n'
        '- "Otras anomalías"\n\n'
        "REGLA ESTRICTA DE RIGOR ANALÍTICO:\n"
        "- NO inventes hallazgos, IPs, usuarios, comandos ni Log_IDs.\n"
        "- En 'evidence_log_ids' incluye entre 3 y 10 Log_IDs representativos reales de ese incidente (no necesitas listar decenas de IDs repetidos para ahorrar tokens).\n"
        "- Devuelve ÚNICAMENTE un objeto JSON válido con la siguiente estructura exacta:\n"
        "{\n"
        '  "global_risk_level": "Crítico" | "Alto" | "Medio" | "Bajo",\n'
        '  "incidents": [\n'
        "    {\n"
        '      "incident_id": "INC-01",\n'
        '      "source_cluster_ids": ["INC-01"],\n'
        '      "title": "Título técnico en español",\n'
        '      "executive_title": "Título en lenguaje claro para directivos",\n'
        '      "categories": ["Fuerza bruta"],\n'
        '      "risk_level": "Crítico" | "Alto" | "Medio" | "Bajo",\n'
        '      "justification": "Justificación basada estrictamente en los Log_IDs y métricas",\n'
        '      "mitre_tactics": ["Txxxx - Nombre"],\n'
        '      "time_start": "YYYY-MM-DD HH:MM:SS",\n'
        '      "time_end": "YYYY-MM-DD HH:MM:SS",\n'
        '      "affected_hosts": ["HOST1"],\n'
        '      "compromised_users": ["USER1"],\n'
        '      "attacker_ips": ["IP1"],\n'
        '      "summary_plain_language": "Explicación en lenguaje sencillo sin jerga técnica",\n'
        '      "business_impact": "Impacto financiero, legal u operativo para el negocio",\n'
        '      "technical_explanation": "Explicación técnica detallada paso a paso citando Log_IDs",\n'
        '      "organizational_impact": "Impacto técnico en confidencialidad, integridad y disponibilidad",\n'
        '      "key_iocs": ["IoC 1", "IoC 2"],\n'
        '      "evidence_log_ids": ["EVT-00001"],\n'
        '      "action_plan": {\n'
        '        "investigar": ["Paso 1...", "Paso 2..."],\n'
        '        "contener": ["Paso 1...", "Paso 2..."],\n'
        '        "remediar": ["Paso 1...", "Paso 2..."]\n'
        "      }\n"
        "    }\n"
        "  ],\n"
        '  "executive_report": {\n'
        '    "incident_determination": "Conclusión ejecutiva clara de si hubo uno o múltiples incidentes",\n'
        '    "executive_overview": "Resumen ejecutivo en lenguaje claro (2 párrafos)",\n'
        '    "key_business_impacts": ["Impacto 1...", "Impacto 2..."],\n'
        '    "priority_decisions": ["Decisión 1...", "Decisión 2..."],\n'
        '    "investment_recommendations": ["Recomendación 1...", "Recomendación 2..."]\n'
        "  },\n"
        '  "technical_report": {\n'
        '    "resumen_ejecutivo": "Resumen ejecutivo técnico SOC Nivel 2",\n'
        '    "hallazgos_resumen": "Síntesis técnica de correlación multi-evento",\n'
        '    "impacto_organizacion_global": "Análisis técnico global de impacto en la organización",\n'
        '    "recomendaciones_generales": ["Recomendación técnica 1...", "Recomendación técnica 2..."]\n'
        "  }\n"
        "}"
    )

    user_payload = {
        "dataset_statistics": summary_stats,
        "detected_anomaly_clusters": compact_clusters,
    }

    client = _create_foundry_client(cfg)
    response = _chat_completion_flexible(
        client=client,
        model=cfg["deployment"],
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
        max_completion_tokens=16000,
        json_mode=True,
    )

    raw_json = (response.choices[0].message.content or "").strip()
    parsed = _extract_and_parse_json(raw_json)

    # Reset log correlation markers and apply what the AI correlated
    for l in all_logs:
        l.is_suspicious = False
        l.correlated_incident_id = None

    incidents: List[IncidentFinding] = []
    valid_risks = {"Crítico", "Alto", "Medio", "Bajo"}

    for idx, raw_inc in enumerate(parsed.get("incidents", []), start=1):
        inc_id = str(raw_inc.get("incident_id") or f"INC-{idx:02d}")
        raw_risk = str(raw_inc.get("risk_level", "Medio"))
        risk_level: RiskLevel = raw_risk if raw_risk in valid_risks else "Medio"  # type: ignore

        raw_cats = [c for c in raw_inc.get("categories", []) if c in REQUIRED_CATEGORIES]
        if not raw_cats:
            raw_cats = ["Otras anomalías"]

        # Combine explicit evidence_log_ids returned by AI + full cluster IDs from source_cluster_ids
        combined_ids: List[str] = []
        seen_lids = set()
        for lid in raw_inc.get("evidence_log_ids", []):
            if lid in log_by_id and lid not in seen_lids:
                seen_lids.add(lid)
                combined_ids.append(lid)

        for cid in raw_inc.get("source_cluster_ids", []):
            for lid in cluster_full_ids.get(cid, []):
                if lid in log_by_id and lid not in seen_lids:
                    seen_lids.add(lid)
                    combined_ids.append(lid)

        # Also check if any pre-cluster shares an evidence_log_id with combined_ids
        for cid, cid_logs in cluster_full_ids.items():
            if any(lid in seen_lids for lid in cid_logs):
                for lid in cid_logs:
                    if lid in log_by_id and lid not in seen_lids:
                        seen_lids.add(lid)
                        combined_ids.append(lid)

        matched_logs: List[LogEntry] = []
        for lid in combined_ids:
            log_obj = log_by_id[lid]
            log_obj.is_suspicious = True
            if log_obj.severity.lower() in ("informational", "info"):
                log_obj.elevated_from_informational = True
            log_obj.correlated_incident_id = inc_id
            log_obj.detection_category = raw_cats[0]
            matched_logs.append(log_obj)

        matched_logs.sort(key=lambda x: x.row_number)
        combined_ids = [x.log_id for x in matched_logs]

        hidden_cnt = sum(1 for l in matched_logs if l.elevated_from_informational)
        ap_raw = raw_inc.get("action_plan") or {}

        # Select representative evidence logs (first 6 + last 3 + any elevated Informational logs)
        elevated_in_inc = [x for x in matched_logs if x.elevated_from_informational]
        rep_candidates = matched_logs[:6] + elevated_in_inc + (matched_logs[-3:] if len(matched_logs) > 6 else [])
        seen_rep = set()
        rep_logs = [x for x in rep_candidates if not (x.log_id in seen_rep or seen_rep.add(x.log_id))][:12]

        incidents.append(
            IncidentFinding(
                incident_id=inc_id,
                title=str(raw_inc.get("title") or f"Incidente {inc_id}"),
                executive_title=str(raw_inc.get("executive_title") or raw_inc.get("title") or inc_id),
                categories=raw_cats,
                risk_level=risk_level,
                justification=str(raw_inc.get("justification") or "Sustentado en registros correlacionados."),
                mitre_tactics=[str(x) for x in raw_inc.get("mitre_tactics", [])],
                time_start=str(raw_inc.get("time_start") or (matched_logs[0].timestamp if matched_logs else "")),
                time_end=str(raw_inc.get("time_end") or (matched_logs[-1].timestamp if matched_logs else "")),
                affected_hosts=[str(x) for x in raw_inc.get("affected_hosts", [])],
                compromised_users=[str(x) for x in raw_inc.get("compromised_users", [])],
                attacker_ips=[str(x) for x in raw_inc.get("attacker_ips", [])],
                total_events=len(matched_logs) if matched_logs else len(combined_ids),
                hidden_informational_count=hidden_cnt,
                summary_plain_language=str(raw_inc.get("summary_plain_language") or ""),
                business_impact=str(raw_inc.get("business_impact") or ""),
                technical_explanation=str(raw_inc.get("technical_explanation") or ""),
                organizational_impact=str(raw_inc.get("organizational_impact") or ""),
                key_iocs=[str(x) for x in raw_inc.get("key_iocs", [])],
                evidence_log_ids=combined_ids,
                evidence_logs=rep_logs,
                action_plan=ActionPlan(
                    investigar=[str(x) for x in ap_raw.get("investigar", ["Investigar registros asociados."])],
                    contener=[str(x) for x in ap_raw.get("contener", ["Aislar activos afectados."])],
                    remediar=[str(x) for x in ap_raw.get("remediar", ["Aplicar controles preventivos."])],
                ),
            )
        )

    global_risk_str = str(parsed.get("global_risk_level", "Alto"))
    global_risk: RiskLevel = global_risk_str if global_risk_str in valid_risks else "Alto"  # type: ignore

    exec_raw = parsed.get("executive_report") or {}
    tech_raw = parsed.get("technical_report") or {}

    exec_items = [
        ExecutiveIncidentItem(
            incident_id=inc.incident_id,
            title=inc.executive_title,
            risk_level=inc.risk_level,
            what_happened=inc.summary_plain_language,
            business_risk=inc.business_impact,
            recommended_decision=(
                inc.action_plan.contener[0] if inc.action_plan.contener else "Contener incidente."
            ),
        )
        for inc in incidents
    ]

    exec_report = ExecutiveReportData(
        global_risk_level=global_risk,
        incident_determination=str(exec_raw.get("incident_determination") or ""),
        executive_overview=str(exec_raw.get("executive_overview") or ""),
        key_business_impacts=[str(x) for x in exec_raw.get("key_business_impacts", [])],
        plain_language_incidents=exec_items,
        priority_decisions=[str(x) for x in exec_raw.get("priority_decisions", [])],
        investment_recommendations=[str(x) for x in exec_raw.get("investment_recommendations", [])],
    )

    tech_report = TechnicalReportData(
        global_risk_level=global_risk,
        resumen_ejecutivo=str(tech_raw.get("resumen_ejecutivo") or ""),
        hallazgos_resumen=str(tech_raw.get("hallazgos_resumen") or ""),
        impacto_organizacion_global=str(tech_raw.get("impacto_organizacion_global") or ""),
        recomendaciones_generales=[str(x) for x in tech_raw.get("recomendaciones_generales", [])],
    )

    return incidents, exec_report, tech_report
