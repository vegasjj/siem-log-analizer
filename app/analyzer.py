"""Generic, Dataset-Agnostic SIEM Log Pre-Processor & Heuristic Signal Extractor.

Contains ZERO hardcoded IPs, usernames, hostnames, filenames, or dates.
Extracts generic behavioral signals from any uploaded SIEM Excel log file to feed
the Microsoft Foundry GPT model and compute dynamic dashboard aggregations.
"""

from collections import Counter, defaultdict
import re
from typing import Dict, List, Set, Tuple

from app.models import (
    ActionPlan,
    DashboardMetrics,
    ExecutiveIncidentItem,
    ExecutiveReportData,
    IncidentFinding,
    LogEntry,
    RiskLevel,
    TechnicalReportData,
)

REQUIRED_CATEGORIES = [
    "Fuerza bruta",
    "Inicios sospechosos",
    "Escalamiento",
    "Comandos y procesos",
    "Movimiento lateral",
    "Otras anomalías",
]

# Generic suspicious command/process patterns (applicable to any Windows/Linux/Web SIEM export)
SUSPICIOUS_CMD_PATTERNS = re.compile(
    r"(-enc|-encodedcommand|vssadmin|shadow|7z\.exe|tar\.exe|rar\.exe|whoami|net\.exe\s+view|"
    r"net\s+user|net\s+localgroup|get-localgroupmember|get-smbshare|mimikatz|procdump|"
    r"programdata|users\\public|cmd\.exe\s*/c|\.aspx\?cmd=|\.php\?cmd=|powershell\.exe.*-file)",
    re.IGNORECASE,
)


def is_external_ip(ip: str) -> bool:
    """Return True if IP is a valid IPv4 address outside RFC1918 private/loopback ranges."""
    if not ip or ip == "-":
        return False
    clean_ip = ip.split(":")[0].strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", clean_ip):
        return False
    if clean_ip.startswith("10.") or clean_ip.startswith("192.168.") or clean_ip.startswith("127."):
        return False
    if clean_ip.startswith("172."):
        parts = clean_ip.split(".")
        if len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return False
    return True


def extract_bytes_out(cmd_or_detail: str) -> int:
    """Extract numeric byte count from generic key-value log fields (e.g., bytes_out=12345)."""
    match = re.search(r"bytes(?:_out|_sent)?=(\d+)", cmd_or_detail or "", re.IGNORECASE)
    return int(match.group(1)) if match else 0


def extract_candidate_signals(logs: List[LogEntry]) -> Tuple[List[LogEntry], Dict[str, object]]:
    """
    Scan any uploaded LogEntry list using generic, dataset-agnostic heuristics to identify
    candidate suspicious events (including events marked 'Informational' that exhibit
    anomalous behavior) and summarize behavioral clusters for the AI model.
    """
    # 1. Identify IPs with multiple failed logons (Event_ID 4625 or Result == Failure)
    failures_by_ip: Dict[str, List[LogEntry]] = defaultdict(list)
    for l in logs:
        if l.event_id == "4625" or l.result.lower() in ("failure", "failed", "denied"):
            if l.source_ip and l.source_ip != "-":
                failures_by_ip[l.source_ip].append(l)

    brute_force_ips = {ip for ip, evs in failures_by_ip.items() if len(evs) >= 3}

    # 2. Identify newly installed service binaries or scheduled task scripts (Event_ID 7045 / 4698)
    persisted_binaries: Set[str] = set()
    for l in logs:
        if l.event_id in ("7045", "4698") and l.process_command_line:
            for match in re.findall(r"[A-Za-z]:\\[^\s;]+?\.(?:exe|ps1|bat|vbs)", l.process_command_line, re.IGNORECASE):
                persisted_binaries.add(match.lower())

    # 3. Flag candidate suspicious logs dynamically
    candidate_logs: List[LogEntry] = []
    seen_ids: Set[str] = set()

    def flag_log(log: LogEntry, default_category: str):
        log.is_suspicious = True
        if log.severity.lower() in ("informational", "info"):
            log.elevated_from_informational = True
        if not log.detection_category:
            log.detection_category = default_category
        if log.log_id not in seen_ids:
            seen_ids.add(log.log_id)
            candidate_logs.append(log)

    for l in logs:
        sev_lower = l.severity.lower()
        cmd_lower = (l.process_command_line or "").lower()
        desc_lower = (l.event_description or "").lower()

        # Rule A: Any event already flagged by SIEM as non-Informational
        if sev_lower not in ("informational", "info"):
            cat = _infer_generic_category(l)
            flag_log(l, cat)
            continue

        # Rule B: Informational events from an IP that performed brute force or is an external IP
        if l.source_ip in brute_force_ips or is_external_ip(l.source_ip):
            cat = "Inicios sospechosos" if l.event_id in ("4624", "4634") else "Escalamiento"
            flag_log(l, cat)
            continue

        # Rule C: Informational process creation matching generic suspicious command patterns
        if l.event_id in ("4688", "4104") and SUSPICIOUS_CMD_PATTERNS.search(l.process_command_line or ""):
            flag_log(l, "Comandos y procesos")
            continue

        # Rule D: Informational execution of a binary that was installed via Event 7045/4698
        if cmd_lower and any(bin_path in cmd_lower for bin_path in persisted_binaries):
            flag_log(l, "Comandos y procesos")
            continue

        # Rule E: Special privileges assigned (4672) or detailed share check (5145)
        if l.event_id == "4672":
            flag_log(l, "Escalamiento")
            continue
        if l.event_id == "5145":
            flag_log(l, "Movimiento lateral")
            continue

        # Rule F: Outbound connections to external public IPs
        dest_ip = (l.destination or "").split(":")[0].strip()
        if is_external_ip(dest_ip):
            flag_log(l, "Otras anomalías")
            continue

        # Rule G: Web shell or child shell under web server account
        if ("apppool" in l.user.lower() or "www-data" in l.user.lower()) and l.event_id == "4688":
            flag_log(l, "Comandos y procesos")
            continue

    # Build generic statistical summary for the LLM prompt
    summary_stats = {
        "total_logs": len(logs),
        "candidate_suspicious_count": len(candidate_logs),
        "hidden_informational_elevated_count": sum(1 for l in candidate_logs if l.elevated_from_informational),
        "time_range_start": logs[0].timestamp if logs else "",
        "time_range_end": logs[-1].timestamp if logs else "",
        "raw_severities": dict(Counter(l.severity for l in logs)),
        "log_sources": dict(Counter(l.log_source for l in logs)),
        "event_ids": dict(Counter(l.event_id for l in logs)),
        "all_hostnames": dict(Counter(l.hostname for l in logs if l.hostname)),
        "brute_force_source_ips": {
            ip: {
                "failed_count": len(evs),
                "targeted_users": sorted({e.user for e in evs if e.user}),
                "target_hosts": sorted({e.hostname for e in evs if e.hostname}),
                "first_seen": evs[0].timestamp,
                "last_seen": evs[-1].timestamp,
            }
            for ip, evs in failures_by_ip.items()
            if len(evs) >= 3
        },
        "total_outbound_bytes": sum(extract_bytes_out(l.process_command_line) for l in logs),
    }

    return candidate_logs, summary_stats


def _infer_generic_category(l: LogEntry) -> str:
    """Infer one of the 6 required categories from generic log attributes."""
    desc = (l.event_description or "").lower()
    cmd = (l.process_command_line or "").lower()
    if l.event_id == "4625" or "failed to log on" in desc:
        return "Fuerza bruta"
    if l.event_id == "4624" and (is_external_ip(l.source_ip) or "rdp" in desc or "logontype=10" in desc):
        return "Inicios sospechosos"
    if l.event_id in ("4672", "4698", "7045") or "privilege" in desc or "service was installed" in desc:
        return "Escalamiento"
    if l.event_id in ("4688", "4104") or SUSPICIOUS_CMD_PATTERNS.search(cmd):
        return "Comandos y procesos"
    if l.event_id in ("5140", "5145") or "logontype=3" in desc or "share" in desc:
        return "Movimiento lateral"
    return "Otras anomalías"


def group_candidates_generically(
    logs: List[LogEntry],
    candidate_logs: List[LogEntry],
) -> List[IncidentFinding]:
    """
    Dataset-agnostic fallback clustering algorithm used ONLY if the Microsoft Foundry AI
    service is unreachable or disabled. Dynamically groups candidate logs by attack vector,
    actor (Source_IP / User / Hostname), and time proximity without any hardcoded dataset strings.
    """
    log_by_id = {l.log_id: l for l in logs}
    clusters: Dict[str, List[LogEntry]] = defaultdict(list)

    for l in candidate_logs:
        if is_external_ip(l.source_ip):
            key = f"EXT_IP:{l.source_ip}"
        elif l.event_id == "PROXY_ACCESS" or "bytes_out=" in (l.process_command_line or ""):
            key = f"EXFIL:{l.hostname}:{l.user}"
        elif "7z.exe" in (l.process_command_line or "").lower() or "tar.exe" in (l.process_command_line or "").lower():
            # Associate local staging with any exfiltration on the same host/user if present
            key = f"EXFIL:{l.hostname}:{l.user}"
        elif l.event_id in ("4698", "7045") or "programdata" in (l.process_command_line or "").lower():
            key = f"PERSIST:{l.hostname}:{l.user}"
        elif l.event_id == "HTTP_ACCESS" or "apppool" in (l.user or "").lower():
            key = f"WEB:{l.hostname}"
        elif l.event_id == "4672" and l.elevated_from_informational:
            key = "PRIV_ANOMALIES"
        else:
            key = f"ACTOR:{l.user or l.source_ip}"
        clusters[key].append(l)

    # Merge tiny clusters or sort by first timestamp
    sorted_cluster_items = sorted(clusters.items(), key=lambda kv: kv[1][0].timestamp if kv[1] else "")

    incidents: List[IncidentFinding] = []
    for idx, (cluster_key, c_logs) in enumerate(sorted_cluster_items, start=1):
        inc_id = f"INC-{idx:02d}"
        for l in c_logs:
            l.correlated_incident_id = inc_id

        cats = sorted({l.detection_category or _infer_generic_category(l) for l in c_logs})
        hosts = sorted({l.hostname for l in c_logs if l.hostname})
        users = sorted({l.user for l in c_logs if l.user and l.user != "-"})
        ips = sorted(
            {l.source_ip for l in c_logs if l.source_ip and l.source_ip != "-"}
            | {
                l.destination.split(":")[0]
                for l in c_logs
                if is_external_ip((l.destination or "").split(":")[0])
            }
        )
        hidden_cnt = sum(1 for l in c_logs if l.elevated_from_informational)
        bytes_total = sum(extract_bytes_out(l.process_command_line) for l in c_logs)

        # Dynamic severity determination based on generic behavior
        has_high = any(l.severity.lower() == "high" for l in c_logs)
        has_destructive_or_rce = any(
            re.search(r"(vssadmin|cmd\.exe\s*/c|-encodedcommand)", l.process_command_line or "", re.I)
            for l in c_logs
        )
        if has_high or has_destructive_or_rce:
            risk: RiskLevel = "Crítico"
        elif len(c_logs) >= 5 or bytes_total > 1_000_000 or any(is_external_ip(ip) for ip in ips):
            risk = "Alto"
        elif len(c_logs) >= 2:
            risk = "Medio"
        else:
            risk = "Bajo"

        title = (
            f"Actividad Sospechosa Correlacionada ({', '.join(cats)}) en {', '.join(hosts[:2]) or 'Infraestructura'}"
        )
        justif = (
            f"Correlación dinámica de {len(c_logs)} eventos ({hidden_cnt} de ellos con severidad original "
            f"'Informational') entre {c_logs[0].timestamp} y {c_logs[-1].timestamp} involucrando "
            f"hosts [{', '.join(hosts)}], cuentas [{', '.join(users)}] e IPs [{', '.join(ips)}]."
        )
        if bytes_total > 0:
            justif += f" Se detectó transferencia saliente acumulada de {bytes_total:,} bytes."

        # Select representative evidence logs
        rep_logs = c_logs[:8] + (c_logs[-3:] if len(c_logs) > 8 else [])
        seen_ev = set()
        dedup_rep = [x for x in rep_logs if not (x.log_id in seen_ev or seen_ev.add(x.log_id))]

        incidents.append(
            IncidentFinding(
                incident_id=inc_id,
                title=title,
                executive_title=f"Incidente de Seguridad en {', '.join(hosts[:2])} ({', '.join(cats[:2])})",
                categories=cats,
                risk_level=risk,
                justification=justif,
                mitre_tactics=[f"Categoría: {c}" for c in cats],
                time_start=c_logs[0].timestamp,
                time_end=c_logs[-1].timestamp,
                affected_hosts=hosts,
                compromised_users=users,
                attacker_ips=ips,
                total_events=len(c_logs),
                hidden_informational_count=hidden_cnt,
                summary_plain_language=(
                    f"Se detectó una secuencia de {len(c_logs)} eventos de seguridad vinculados a "
                    f"{', '.join(cats)} afectando a los sistemas {', '.join(hosts)} y las cuentas {', '.join(users)}."
                ),
                business_impact=(
                    f"Riesgo {risk} para la confidencialidad y continuidad operativa de los activos {', '.join(hosts)}."
                ),
                technical_explanation=(
                    f"Secuencia correlacionada desde {c_logs[0].log_id} ({c_logs[0].timestamp}) hasta "
                    f"{c_logs[-1].log_id} ({c_logs[-1].timestamp}). Eventos detectados: "
                    + "; ".join(
                        f"{e.log_id} [{e.event_id}] {e.event_description} {e.process_command_line}".strip()
                        for e in dedup_rep[:6]
                    )
                ),
                organizational_impact=(
                    f"Compromiso potencial de {', '.join(hosts)} y exposición de las cuentas {', '.join(users)}."
                ),
                key_iocs=[
                    f"Sistemas: {', '.join(hosts)}",
                    f"Cuentas: {', '.join(users)}",
                    f"IPs: {', '.join(ips)}",
                ],
                evidence_log_ids=[l.log_id for l in c_logs],
                evidence_logs=[log_by_id[l.log_id] for l in dedup_rep if l.log_id in log_by_id],
                action_plan=ActionPlan(
                    investigar=[
                        f"Analizar los registros {c_logs[0].log_id} a {c_logs[-1].log_id} en {', '.join(hosts)}."
                    ],
                    contener=[
                        f"Aislar preventivamente {', '.join(hosts)} y rotar credenciales de {', '.join(users)}."
                    ],
                    remediar=[
                        "Reforzar políticas de acceso, monitoreo de procesos y reglas de correlación SIEM."
                    ],
                ),
            )
        )

    return incidents


def build_dashboard_metrics(
    logs: List[LogEntry],
    incidents: List[IncidentFinding],
) -> DashboardMetrics:
    """Dynamically compute all dashboard KPIs and Chart.js series from the correlated logs and incidents."""
    suspicious_logs = [l for l in logs if l.is_suspicious]
    hidden_info_logs = [l for l in logs if l.elevated_from_informational]

    risk_counts: Dict[str, int] = {"Crítico": 0, "Alto": 0, "Medio": 0, "Bajo": 0}
    for inc in incidents:
        risk_counts[inc.risk_level] = risk_counts.get(inc.risk_level, 0) + 1

    # Count events per required detection category dynamically
    cat_counter: Counter = Counter()
    for inc in incidents:
        per_cat_weight = max(1, inc.total_events // max(1, len(inc.categories)))
        for cat in inc.categories:
            if cat in REQUIRED_CATEGORIES:
                cat_counter[cat] += per_cat_weight
    for l in suspicious_logs:
        if l.detection_category in REQUIRED_CATEGORIES and cat_counter[l.detection_category] == 0:
            cat_counter[l.detection_category] += 1

    events_by_category = {cat: int(cat_counter.get(cat, 0)) for cat in REQUIRED_CATEGORIES}
    raw_sev_counter = Counter(l.severity for l in logs)
    log_source_counter = Counter(l.log_source for l in logs)

    # Dynamic 15-minute timeline buckets
    bucket_all: Counter = Counter()
    bucket_susp: Counter = Counter()
    for l in logs:
        if len(l.timestamp) >= 16:
            hh_mm = l.timestamp[11:16]
            try:
                hh, mm = int(hh_mm[:2]), int(hh_mm[3:5])
                q_mm = (mm // 15) * 15
                bucket_key = f"{hh:02d}:{q_mm:02d}"
            except ValueError:
                bucket_key = hh_mm
        else:
            bucket_key = l.timestamp or "N/A"
        bucket_all[bucket_key] += 1
        if l.is_suspicious:
            bucket_susp[bucket_key] += 1

    timeline_buckets = [
        {"time": k, "total": bucket_all[k], "suspicious": bucket_susp.get(k, 0)}
        for k in sorted(bucket_all.keys())
    ]

    host_counter = Counter(l.hostname for l in suspicious_logs if l.hostname)
    ip_counter = Counter(l.source_ip for l in suspicious_logs if l.source_ip and l.source_ip != "-")
    user_counter = Counter(l.user for l in suspicious_logs if l.user and l.user != "-")

    total_exfil_bytes = sum(extract_bytes_out(l.process_command_line) for l in logs)
    total_exfil_mb = round(total_exfil_bytes / (1024 * 1024), 2)

    external_ips = {
        l.source_ip for l in suspicious_logs if is_external_ip(l.source_ip)
    } | {
        (l.destination or "").split(":")[0]
        for l in suspicious_logs
        if is_external_ip((l.destination or "").split(":")[0])
    }

    compromised_hosts = {h for inc in incidents for h in inc.affected_hosts}
    compromised_accounts = {u for inc in incidents for u in inc.compromised_users}

    return DashboardMetrics(
        total_logs=len(logs),
        suspicious_logs_count=len(suspicious_logs),
        hidden_informational_detected=len(hidden_info_logs),
        total_incidents=len(incidents),
        critical_incidents_count=risk_counts["Crítico"],
        high_incidents_count=risk_counts["Alto"],
        medium_incidents_count=risk_counts["Medio"],
        low_incidents_count=risk_counts["Bajo"],
        compromised_hosts_count=len(compromised_hosts),
        compromised_accounts_count=len(compromised_accounts),
        external_attacker_ips_count=len(external_ips),
        total_exfiltrated_bytes=total_exfil_bytes,
        total_exfiltrated_mb=total_exfil_mb,
        time_range_start=logs[0].timestamp if logs else "",
        time_range_end=logs[-1].timestamp if logs else "",
        incidents_by_risk=risk_counts,
        events_by_raw_severity=dict(raw_sev_counter),
        events_by_category=events_by_category,
        events_by_log_source=dict(log_source_counter),
        timeline_buckets=timeline_buckets,
        top_affected_hosts=dict(host_counter.most_common(8)),
        top_suspicious_ips=dict(ip_counter.most_common(8)),
        top_targeted_users=dict(user_counter.most_common(8)),
    )


def build_fallback_reports(
    incidents: List[IncidentFinding],
    metrics: DashboardMetrics,
) -> Tuple[ExecutiveReportData, TechnicalReportData]:
    """Generate dynamic Spanish Executive & Technical reports from any incident list."""
    levels = {i.risk_level for i in incidents}
    global_risk: RiskLevel = (
        "Crítico"
        if "Crítico" in levels
        else "Alto"
        if "Alto" in levels
        else "Medio"
        if "Medio" in levels
        else "Bajo"
    )

    exec_items = [
        ExecutiveIncidentItem(
            incident_id=inc.incident_id,
            title=inc.executive_title,
            risk_level=inc.risk_level,
            what_happened=inc.summary_plain_language,
            business_risk=inc.business_impact,
            recommended_decision=(
                inc.action_plan.contener[0]
                if inc.action_plan.contener
                else "Contener activos involucrados."
            ),
        )
        for inc in incidents
    ]

    incident_word = (
        "MÚLTIPLES INCIDENTES DE SEGURIDAD"
        if len(incidents) > 1
        else "UN INCIDENTE DE SEGURIDAD"
        if len(incidents) == 1
        else "NINGÚN INCIDENTE CRÍTICO"
    )

    exec_report = ExecutiveReportData(
        global_risk_level=global_risk,
        incident_determination=(
            f"Dictamen del Análisis: Se identificaron {len(incidents)} incidentes correlacionados "
            f"({ incident_word }) sobre un total de {metrics.total_logs} registros evaluados "
            f"({metrics.critical_incidents_count} Críticos, {metrics.high_incidents_count} Altos, "
            f"{metrics.medium_incidents_count} Medios, {metrics.low_incidents_count} Bajos)."
        ),
        executive_overview=(
            f"El análisis automatizado del archivo SIEM importado ({metrics.time_range_start} a "
            f"{metrics.time_range_end}) identificó {metrics.suspicious_logs_count} eventos sospechosos "
            f"agrupados en {metrics.total_incidents} hallazgos, involucrando {metrics.compromised_hosts_count} "
            f"sistemas y {metrics.compromised_accounts_count} cuentas."
        ),
        key_business_impacts=[inc.business_impact for inc in incidents[:5]] or ["Sin impactos críticos detectados."],
        plain_language_incidents=exec_items,
        priority_decisions=[
            inc.action_plan.contener[0]
            for inc in incidents
            if inc.action_plan.contener
        ][:5] or ["Mantener monitoreo continuo."],
        investment_recommendations=[
            inc.action_plan.remediar[0]
            for inc in incidents
            if inc.action_plan.remediar
        ][:5] or ["Revisar reglas de correlación en el SIEM."],
    )

    tech_report = TechnicalReportData(
        global_risk_level=global_risk,
        resumen_ejecutivo=(
            f"Se procesaron {metrics.total_logs} registros SIEM comprendidos entre {metrics.time_range_start} y "
            f"{metrics.time_range_end}. Se correlacionaron {metrics.suspicious_logs_count} eventos de interés "
            f"(incluyendo {metrics.hidden_informational_detected} eventos con severidad original 'Informational') "
            f"en {metrics.total_incidents} incidentes técnicos diferenciados."
        ),
        hallazgos_resumen=(
            f"Los hallazgos abarcan las siguientes categorías detectadas dinámicamente: "
            + ", ".join(f"{k} ({v} eventos)" for k, v in metrics.events_by_category.items() if v > 0)
            + "."
        ),
        impacto_organizacion_global="\n".join(
            f"- [{inc.incident_id}] {inc.title}: {inc.organizational_impact}" for inc in incidents
        ),
        recomendaciones_generales=[
            rec
            for inc in incidents
            for rec in inc.action_plan.remediar
        ][:8] or ["Continuar monitoreo y ajuste de reglas SIEM."],
    )

    return exec_report, tech_report
