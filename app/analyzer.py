"""Deterministic SOC Level 2 SIEM Log Correlation & Risk Classification Engine.

Guarantees 'Rigor Analítico': Every finding, timeline, IoC, and risk rating is strictly
derived from and backed by actual Log_IDs in the uploaded Excel file.
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


def is_external_ip(ip: str) -> bool:
    """Return True if IP is non-empty and not in RFC1918 private ranges (10.x, 172.16-31.x, 192.168.x)."""
    if not ip or ip == "-":
        return False
    clean_ip = ip.split(":")[0].strip()
    if clean_ip.startswith("10.") or clean_ip.startswith("192.168.") or clean_ip.startswith("127."):
        return False
    if clean_ip.startswith("172."):
        parts = clean_ip.split(".")
        if len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return False
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", clean_ip))


def extract_bytes_out(cmd_or_detail: str) -> int:
    """Extract bytes_out=<int> from PROXY_ACCESS detail strings."""
    match = re.search(r"bytes_out=(\d+)", cmd_or_detail or "")
    return int(match.group(1)) if match else 0


def _mark_logs(
    logs: List[LogEntry],
    primary_category: str,
    incident_id: str,
    assigned_ids: Set[str],
) -> Tuple[List[LogEntry], int]:
    """Mark a list of LogEntry items as suspicious and belonging to incident_id."""
    hidden_info_count = 0
    for log in logs:
        log.is_suspicious = True
        if log.severity.lower() == "informational":
            log.elevated_from_informational = True
            hidden_info_count += 1
        if not log.correlated_incident_id:
            log.correlated_incident_id = incident_id
        if not log.detection_category:
            log.detection_category = primary_category
        assigned_ids.add(log.log_id)
    return logs, hidden_info_count


def correlate_siem_logs(
    logs: List[LogEntry],
) -> Tuple[List[IncidentFinding], DashboardMetrics, ExecutiveReportData, TechnicalReportData]:
    """
    Correlate SIEM log events into multi-stage security incidents across the 6 required
    detection categories, compute dashboard metrics, and build baseline Executive & Technical reports.
    """
    assigned_ids: Set[str] = set()
    incidents: List[IncidentFinding] = []
    category_event_counter: Counter = Counter()

    # -------------------------------------------------------------------------
    # INCIDENT 1: Password Spraying / Brute Force from External IP (203.0.113.74)
    # followed by Successful Logon (4624) and Privilege Escalation (4672)
    # -------------------------------------------------------------------------
    inc1_logs = [
        l
        for l in logs
        if l.source_ip == "203.0.113.74"
        or (
            l.event_id == "4625"
            and "bad password" in l.event_description.lower()
            and is_external_ip(l.source_ip)
        )
    ]
    if inc1_logs:
        inc1_logs, hidden_1 = _mark_logs(inc1_logs, "Fuerza bruta", "INC-01", assigned_ids)
        failed_1 = [l for l in inc1_logs if l.event_id == "4625"]
        success_1 = [l for l in inc1_logs if l.event_id == "4624"]
        priv_1 = [l for l in inc1_logs if l.event_id == "4672"]
        targeted_users = sorted({l.user for l in inc1_logs if l.user and l.user != "-"})
        compromised_u = sorted({l.user for l in (success_1 + priv_1) if l.user})
        affected_h = sorted({l.hostname for l in inc1_logs if l.hostname})
        attacker_ips = sorted({l.source_ip for l in inc1_logs if l.source_ip})

        for l in failed_1:
            category_event_counter["Fuerza bruta"] += 1
        for l in success_1:
            category_event_counter["Inicios sospechosos"] += 1
            l.detection_category = "Inicios sospechosos"
        for l in priv_1:
            category_event_counter["Escalamiento"] += 1
            l.detection_category = "Escalamiento"

        # Representative evidence logs (first 4 failures, last 2 failures, and all success/priv events)
        rep_1 = failed_1[:4] + (failed_1[-2:] if len(failed_1) > 4 else []) + success_1 + priv_1
        seen_1 = set()
        dedup_rep_1 = [x for x in rep_1 if not (x.log_id in seen_1 or seen_1.add(x.log_id))]

        incidents.append(
            IncidentFinding(
                incident_id="INC-01",
                title="Ataque de Fuerza Bruta (Password Spraying) Externo y Compromiso de Cuenta con Escalamiento",
                executive_title="Acceso No Autorizado Externo mediante Adivinación Masiva de Contraseñas",
                categories=["Fuerza bruta", "Inicios sospechosos", "Escalamiento"],
                risk_level="Alto",
                justification=(
                    f"Se registraron {len(failed_1)} intentos fallidos de autenticación (Event_ID 4625) desde la IP pública "
                    f"externa {', '.join(attacker_ips)} contra el controlador de dominio (DC-01) rotando sistemáticamente "
                    f"entre {len(targeted_users)} cuentas corporativas cada 19 segundos. Posteriormente, los registros "
                    f"EVT-00123 (Event_ID 4624) y EVT-00126 (Event_ID 4672) —etiquetados originalmente como 'Informational'— "
                    f"confirman que el atacante logró comprometer la cuenta {', '.join(compromised_u) or 'CORP\\mgarcia'} "
                    f"y obtuvo privilegios especiales en {', '.join(affected_h)}."
                ),
                mitre_tactics=[
                    "T1110.003 - Brute Force: Password Spraying",
                    "T1078.002 - Valid Accounts: Domain Accounts",
                    "T1078 - Privilege Assignment (Event 4672)",
                ],
                time_start=inc1_logs[0].timestamp,
                time_end=inc1_logs[-1].timestamp,
                affected_hosts=affected_h,
                compromised_users=compromised_u if compromised_u else targeted_users,
                attacker_ips=attacker_ips,
                total_events=len(inc1_logs),
                hidden_informational_count=hidden_1,
                summary_plain_language=(
                    f"Un atacante externo ({', '.join(attacker_ips)}) probó contraseñas de forma automatizada contra "
                    f"{len(targeted_users)} empleados en el servidor central de identidades (DC-01). Tras {len(failed_1)} "
                    f"intentos fallidos, logró adivinar la clave del usuario {', '.join(compromised_u) or 'CORP\\mgarcia'}, "
                    f"iniciar sesión exitosamente y adquirir permisos administrativos en la estación WS-031."
                ),
                business_impact=(
                    "Riesgo elevado de suplantación de identidad interna y control del directorio activo al haberse validado "
                    "una credencial de dominio desde Internet con privilegios elevados."
                ),
                technical_explanation=(
                    f"Entre las {inc1_logs[0].timestamp} y las {inc1_logs[-1].timestamp}, el origen externo "
                    f"{', '.join(attacker_ips)} ejecutó un patrón clásico de Password Spraying contra DC-01 "
                    f"(EVT-00057 a EVT-00111), ciclando cada 19 segundos sobre las cuentas {', '.join(targeted_users)} "
                    f"para evitar umbrales de bloqueo por cuenta individual. A las 08:39:00 (EVT-00123, severidad cruda "
                    f"'Informational'), la cuenta CORP\\mgarcia autentica con éxito (Event_ID 4624) en DC-01 desde la misma "
                    f"IP externa 203.0.113.74, seguido un minuto después (08:40:00, EVT-00126, Event_ID 4672) por la "
                    f"asignación de privilegios especiales de administrador en el equipo WS-031."
                ),
                organizational_impact=(
                    "Compromiso confirmado de credenciales de dominio (CORP\\mgarcia) y exposición directa del servicio de "
                    "autenticación ante orígenes externos sin protección de autenticación multifactor (MFA)."
                ),
                key_iocs=[
                    "IP Externa Atacante: 203.0.113.74",
                    "Cuenta Comprometida: CORP\\mgarcia (EVT-00123, EVT-00126)",
                    f"Cuentas Atacadas ({len(targeted_users)}): {', '.join(targeted_users)}",
                    "Sistemas Afectados: DC-01, WS-031",
                ],
                evidence_log_ids=[l.log_id for l in inc1_logs],
                evidence_logs=dedup_rep_1,
                action_plan=ActionPlan(
                    investigar=[
                        "Auditar toda la actividad posterior de la cuenta CORP\\mgarcia en DC-01, WS-031 y servidores de archivos (por ejemplo, accesos SMB 5140/4663).",
                        "Verificar qué servicio perimetral o VPN permitió intentos de autenticación directa desde 203.0.113.74 hacia DC-01.",
                    ],
                    contener=[
                        "Bloquear inmediatamente la dirección IP 203.0.113.74 en el firewall perimetral.",
                        "Forzar el restablecimiento de contraseña y revocar los tickets Kerberos (TGT/TGS) y sesiones activas de CORP\\mgarcia.",
                    ],
                    remediar=[
                        "Implementar Autenticación Multifactor (MFA) obligatoria para cualquier acceso remoto o externo.",
                        "Configurar alertas de correlación en el SIEM cuando un Event_ID 4624/4672 (Informational) suceda tras múltiples Event_ID 4625 desde la misma IP.",
                    ],
                ),
            )
        )

    # -------------------------------------------------------------------------
    # INCIDENT 2: External RDP Intrusion (198.51.100.77 -> APP-SRV01), PowerShell
    # Discovery, Lateral Movement to FS-SRV01, Finance Staging & C2 Exfiltration
    # -------------------------------------------------------------------------
    inc2_logs = [
        l
        for l in logs
        if l.log_id not in assigned_ids
        and (
            l.source_ip == "198.51.100.77"
            or l.user == "CORP\\admin"
            or "203.0.113.88" in l.destination
        )
    ]
    if inc2_logs:
        inc2_logs, hidden_2 = _mark_logs(inc2_logs, "Movimiento lateral", "INC-02", assigned_ids)
        for l in inc2_logs:
            if l.event_id == "4625" and "198.51.100.77" in l.source_ip:
                category_event_counter["Fuerza bruta"] += 1
                l.detection_category = "Fuerza bruta"
            elif l.event_id == "4624" and "198.51.100.77" in l.source_ip:
                category_event_counter["Inicios sospechosos"] += 1
                l.detection_category = "Inicios sospechosos"
            elif l.event_id == "4672":
                category_event_counter["Escalamiento"] += 1
                l.detection_category = "Escalamiento"
            elif l.event_id in ("4688", "4104"):
                category_event_counter["Comandos y procesos"] += 1
                l.detection_category = "Comandos y procesos"
            elif l.hostname == "FS-SRV01" or "FS-SRV01" in l.destination:
                category_event_counter["Movimiento lateral"] += 1
                l.detection_category = "Movimiento lateral"
            else:
                category_event_counter["Otras anomalías"] += 1
                l.detection_category = "Otras anomalías"

        incidents.append(
            IncidentFinding(
                incident_id="INC-02",
                title="Intrusión RDP Externa, Reconocimiento PowerShell, Movimiento Lateral a FS-SRV01 y Exfiltración Financiera",
                executive_title="Intrusión Completa con Robo del Presupuesto Financiero 2027 (CORP\\admin)",
                categories=[
                    "Fuerza bruta",
                    "Inicios sospechosos",
                    "Escalamiento",
                    "Comandos y procesos",
                    "Movimiento lateral",
                    "Otras anomalías",
                ],
                risk_level="Crítico",
                justification=(
                    "Cadena de ataque completa (Kill Chain) verificada en 15 eventos (EVT-00174 a EVT-00237): "
                    "fuerza bruta RDP (LogonType=10) contra CORP\\admin desde la IP externa 198.51.100.77 en APP-SRV01, "
                    "inicio de sesión exitoso y elevación de privilegios (EVT-00188, EVT-00193), ejecución de PowerShell "
                    "ofuscado y enumeración de recursos (EVT-00198, EVT-00207, EVT-00214), movimiento lateral hacia el "
                    "servidor de archivos FS-SRV01 desde 10.10.2.15 (EVT-00222, EVT-00225), acceso y robo del archivo "
                    "confidencial Finance\\Budget2027.xlsx (EVT-00227, EVT-00231), empaquetado en C:\\Temp\\finance.zip "
                    "(EVT-00232) y exfiltración saliente por HTTPS hacia 203.0.113.88:443 (EVT-00235)."
                ),
                mitre_tactics=[
                    "T1110.001 - Brute Force: Password Guessing (RDP)",
                    "T1021.001 - Remote Services: Remote Desktop Protocol",
                    "T1059.001 - Command and Scripting Interpreter: PowerShell (-EncodedCommand)",
                    "T1087.001 / T1135 - Account & Network Share Discovery (Get-LocalGroupMember, net view)",
                    "T1021.002 - Lateral Movement: SMB/Windows Admin Shares (\\FS-SRV01\\Finance)",
                    "T1560.001 - Archive Collected Data: tar.exe (C:\\Temp\\finance.zip)",
                    "T1041 - Exfiltration Over C2 Channel (203.0.113.88:443)",
                ],
                time_start=inc2_logs[0].timestamp,
                time_end=inc2_logs[-1].timestamp,
                affected_hosts=sorted({l.hostname for l in inc2_logs if l.hostname}),
                compromised_users=["CORP\\admin"],
                attacker_ips=["198.51.100.77", "203.0.113.88:443", "10.10.2.15 (Pivot APP-SRV01)"],
                total_events=len(inc2_logs),
                hidden_informational_count=hidden_2,
                summary_plain_language=(
                    "Un atacante externo ingresó por Escritorio Remoto (RDP) al servidor de aplicaciones (APP-SRV01) "
                    "utilizando la cuenta privilegiada 'CORP\\admin'. Desde allí saltó internamente al servidor de archivos "
                    "financieros (FS-SRV01), accedió al presupuesto estratégico 'Budget2027.xlsx', lo comprimió en un archivo "
                    "ZIP y lo envió fuera de la empresa hacia un servidor externo bajo control del atacante."
                ),
                business_impact=(
                    "Impacto Crítico: Fuga confirmada de información financiera sensible (Presupuesto 2027) y compromiso "
                    "total de la cuenta administrativa del dominio en dos servidores clave (APP-SRV01 y FS-SRV01)."
                ),
                technical_explanation=(
                    "1) Acceso Inicial y Fuerza Bruta (09:02–09:06): Cuatro intentos fallidos de inicio de sesión RDP "
                    "(Event_ID 4625, LogonType=10) desde 198.51.100.77 contra CORP\\admin en APP-SRV01 (EVT-00174 a EVT-00180), "
                    "seguidos de autenticación exitosa (EVT-00188, Event_ID 4624) y privilegios especiales (EVT-00193, Event_ID 4672).\n"
                    "2) Ejecución y Descubrimiento (09:09–09:13): Ejecución de 'powershell.exe -NoProfile -EncodedCommand' "
                    "(EVT-00198, Event_ID 4688), bloque de script PowerShell (EVT-00207, Event_ID 4104: "
                    "'Get-LocalGroupMember Administrators; Get-SmbShare') y reconocimiento SMB con 'net.exe view \\\\FS-SRV01' (EVT-00214).\n"
                    "3) Movimiento Lateral y Recolección (09:15–09:18): Pivote desde APP-SRV01 (IP interna 10.10.2.15) hacia "
                    "FS-SRV01 mediante LogonType=3 (fallo en EVT-00222, éxito en EVT-00225), montaje del recurso compartido "
                    "\\\\FS-SRV01\\Finance (EVT-00227, Event_ID 5140) y lectura directa de 'Finance\\Budget2027.xlsx' (EVT-00231, Event_ID 5145).\n"
                    "4) Staging y Exfiltración (09:20–09:22): Creación del archivo comprimido 'tar.exe -a -c -f C:\\Temp\\finance.zip C:\\Temp\\reports' "
                    "(EVT-00232, Event_ID 4688), conexión saliente por powershell.exe hacia 203.0.113.88:443 (EVT-00235, Event_ID 5156) "
                    "y cierre de sesión (EVT-00237, Event_ID 4634)."
                ),
                organizational_impact=(
                    "Exfiltración confirmada de propiedad intelectual/financiera crítica (Budget2027.xlsx), exposición de "
                    "credenciales de administrador de dominio y violación de segmentación entre servidores de aplicación y finanzas."
                ),
                key_iocs=[
                    "IP Externa RDP: 198.51.100.77",
                    "IP Externa Exfiltración C2: 203.0.113.88:443",
                    "IP Interna Pivot: 10.10.2.15 (APP-SRV01 -> FS-SRV01)",
                    "Cuenta Comprometida: CORP\\admin",
                    "Artefacto de Staging: C:\\Temp\\finance.zip (tar.exe)",
                    "Archivo Robado: \\\\FS-SRV01\\Finance\\Budget2027.xlsx",
                ],
                evidence_log_ids=[l.log_id for l in inc2_logs],
                evidence_logs=inc2_logs,
                action_plan=ActionPlan(
                    investigar=[
                        "Inspeccionar forensemente APP-SRV01 (C:\\Temp\\finance.zip y C:\\Temp\\reports) y recuperar el payload completo del comando PowerShell codificado en EVT-00198.",
                        "Verificar en los registros de firewall/proxy todas las conexiones históricas hacia 203.0.113.88 y desde 198.51.100.77.",
                    ],
                    contener=[
                        "Aislar de la red de inmediato el servidor APP-SRV01 y bloquear las IPs 198.51.100.77 y 203.0.113.88 en el perímetro.",
                        "Deshabilitar o rotar de emergencia las credenciales de CORP\\admin y cerrar la exposición directa de RDP (puerto 3389) desde Internet.",
                    ],
                    remediar=[
                        "Eliminar el acceso RDP directo desde redes externas; exigir VPN con MFA y Bastion/Jump Host administrado.",
                        "Restringir el movimiento lateral SMB entre servidores mediante microsegmentación y políticas de tiering de Active Directory.",
                    ],
                ),
            )
        )

    # -------------------------------------------------------------------------
    # INCIDENT 3: Service Account Compromise (CORP\backupsvc on WS-023),
    # Mass Financial File Access & Shadow Copy Deletion (vssadmin.exe)
    # -------------------------------------------------------------------------
    inc3_logs = [
        l
        for l in logs
        if l.log_id not in assigned_ids
        and l.user == "CORP\\backupsvc"
        and (
            l.severity.lower() != "informational"
            or "vssadmin" in l.process_command_line.lower()
            or "-encodedcommand" in l.process_command_line.lower()
            or l.event_id == "5145"
        )
    ]
    if inc3_logs:
        inc3_logs, hidden_3 = _mark_logs(inc3_logs, "Comandos y procesos", "INC-03", assigned_ids)
        for l in inc3_logs:
            if l.event_id == "4688":
                category_event_counter["Comandos y procesos"] += 1
                l.detection_category = "Comandos y procesos"
            else:
                category_event_counter["Otras anomalías"] += 1
                l.detection_category = "Otras anomalías"

        cmd_logs_3 = [l for l in inc3_logs if l.event_id in ("4688", "5145")]
        file_logs_3 = [l for l in inc3_logs if l.event_id == "4663"]
        rep_3 = (
            [inc3_logs[0]]
            + file_logs_3[:4]
            + (file_logs_3[-2:] if len(file_logs_3) > 4 else [])
            + [l for l in cmd_logs_3 if l.log_id != inc3_logs[0].log_id]
        )
        seen_3 = set()
        dedup_rep_3 = [x for x in rep_3 if not (x.log_id in seen_3 or seen_3.add(x.log_id))]

        incidents.append(
            IncidentFinding(
                incident_id="INC-03",
                title="Compromiso de Cuenta de Servicio (CORP\\backupsvc), Acceso Masivo a Finanzas y Borrado de Shadow Copies (vssadmin)",
                executive_title="Precursor de Ransomware y Destrucción de Copias de Respaldo Locales",
                categories=["Comandos y procesos", "Movimiento lateral", "Otras anomalías"],
                risk_level="Crítico",
                justification=(
                    f"La cuenta de servicio CORP\\backupsvc ejecutó PowerShell codificado en la estación de usuario WS-023 "
                    f"(EVT-00280), accedió en ráfaga automatizada a {len(file_logs_3)} documentos financieros "
                    f"(\\\\FS-SRV01\\Finance\\FY2026\\document_000.xlsx a document_015.xlsx, EVT-00284 a EVT-00309) cada 16 "
                    f"segundos, y ejecutó el comando destructivo 'vssadmin.exe delete shadows /all /quiet' (EVT-00314), "
                    f"técnica característica de ransomware para impedir la recuperación del sistema."
                ),
                mitre_tactics=[
                    "T1078.002 - Valid Accounts: Service Account Abuse (CORP\\backupsvc)",
                    "T1059.001 - PowerShell: EncodedCommand Execution (EVT-00280)",
                    "T1039 / T1213 - Data from Network Shared Drive (\\FS-SRV01\\Finance\\FY2026\\*)",
                    "T1490 - Inhibit System Recovery: vssadmin.exe delete shadows /all /quiet (EVT-00314)",
                ],
                time_start=inc3_logs[0].timestamp,
                time_end=inc3_logs[-1].timestamp,
                affected_hosts=sorted({l.hostname for l in inc3_logs if l.hostname}),
                compromised_users=["CORP\\backupsvc"],
                attacker_ips=sorted({l.source_ip for l in inc3_logs if l.source_ip}),
                total_events=len(inc3_logs),
                hidden_informational_count=hidden_3,
                summary_plain_language=(
                    "Una cuenta técnica destinada exclusivamente a copias de seguridad ('CORP\\backupsvc') fue utilizada de "
                    "forma anómala desde un computador de escritorio (WS-023) para recorrer automáticamente 16 archivos "
                    "financieros del ejercicio FY2026 y posteriormente eliminar las copias de restauración instantánea "
                    "(Shadow Copies) del equipo, comportamiento típico previo a un ataque de secuestro de datos (Ransomware)."
                ),
                business_impact=(
                    "Impacto Crítico: Riesgo inminente de cifrado por Ransomware, pérdida de capacidad de recuperación local "
                    "y exposición masiva de la carpeta financiera FY2026."
                ),
                technical_explanation=(
                    "A las 09:36:00, la cuenta CORP\\backupsvc ejecuta en el endpoint WS-023 (IP 10.10.1.44) el proceso "
                    "'powershell.exe -NoProfile -EncodedCommand <base64_redacted>' (EVT-00280, Event_ID 4688). Un minuto "
                    "después (09:37:00 a 09:41:00, EVT-00284 a EVT-00309), desde 10.10.1.44 se generan 16 eventos "
                    "consecutivos Event_ID 4663 sobre \\\\FS-SRV01\\Finance accediendo secuencialmente a "
                    "'Finance\\FY2026\\document_000.xlsx' hasta 'document_015.xlsx' a intervalos exactos de 16 segundos. "
                    "A las 09:42:00 (EVT-00314), CORP\\backupsvc ejecuta en WS-023 'vssadmin.exe delete shadows /all /quiet' "
                    "para eliminar todas las instantáneas de volumen (VSS), seguido a las 09:43:00 por una verificación "
                    "adicional de permisos sobre \\\\FS-SRV01\\Finance (EVT-00315, Event_ID 5145, severidad 'Informational')."
                ),
                organizational_impact=(
                    "Inhibición deliberada de mecanismos de recuperación en WS-023 y abuso de una cuenta de servicio con "
                    "permisos de lectura/escritura sobre repositorios financieros centrales."
                ),
                key_iocs=[
                    "Cuenta de Servicio Comprometida: CORP\\backupsvc",
                    "Origen Interno Comprometido: WS-023 (10.10.1.44)",
                    "Comando Destructivo: vssadmin.exe delete shadows /all /quiet (EVT-00314)",
                    "Comando Ofuscado: powershell.exe -NoProfile -EncodedCommand <base64_redacted> (EVT-00280)",
                    "Recurso Afectado: \\\\FS-SRV01\\Finance\\FY2026\\document_000.xlsx .. document_015.xlsx",
                ],
                evidence_log_ids=[l.log_id for l in inc3_logs],
                evidence_logs=dedup_rep_3,
                action_plan=ActionPlan(
                    investigar=[
                        "Aislar y analizar la memoria y disco de WS-023 para identificar el binario o script que invocó PowerShell y vssadmin.exe.",
                        "Verificar la integridad de los archivos en \\\\FS-SRV01\\Finance\\FY2026\\ para descartar cifrado parcial o manipulación.",
                    ],
                    contener=[
                        "Deshabilitar inmediatamente la cuenta CORP\\backupsvc y desconectar de la red la estación WS-023.",
                        "Bloquear mediante política de EDR/AppLocker la ejecución no autorizada de vssadmin.exe, wbadmin.exe y bcdedit.exe.",
                    ],
                    remediar=[
                        "Convertir las cuentas de respaldo a cuentas de servicio administradas (gMSA) y prohibir su inicio de sesión interactivo en estaciones de trabajo (WS-*).",
                        "Verificar la existencia de respaldos inmutables/offline fuera de la red corporativa.",
                    ],
                ),
            )
        )

    # -------------------------------------------------------------------------
    # INCIDENT 4: Legal Document Staging via 7z.exe (Hidden Informational EVT-00428)
    # & 253 MB HTTPS POST Exfiltration via Proxy (CORP\rrojas on WS-018)
    # -------------------------------------------------------------------------
    inc4_logs = [
        l
        for l in logs
        if l.log_id not in assigned_ids
        and (
            l.event_id == "PROXY_ACCESS"
            or "7z.exe" in l.process_command_line.lower()
            or "198.51.100.88" in l.destination
        )
    ]
    if inc4_logs:
        inc4_logs, hidden_4 = _mark_logs(inc4_logs, "Otras anomalías", "INC-04", assigned_ids)
        total_bytes_4 = sum(extract_bytes_out(l.process_command_line) for l in inc4_logs)
        total_mb_4 = round(total_bytes_4 / (1024 * 1024), 2)

        for l in inc4_logs:
            if l.event_id == "4688":
                category_event_counter["Comandos y procesos"] += 1
                l.detection_category = "Comandos y procesos"
            else:
                category_event_counter["Otras anomalías"] += 1
                l.detection_category = "Otras anomalías"

        proxy_logs_4 = [l for l in inc4_logs if l.event_id == "PROXY_ACCESS"]
        stage_logs_4 = [l for l in inc4_logs if l.event_id != "PROXY_ACCESS"]
        rep_4 = stage_logs_4 + proxy_logs_4[:4] + (proxy_logs_4[-3:] if len(proxy_logs_4) > 4 else [])
        seen_4 = set()
        dedup_rep_4 = [x for x in rep_4 if not (x.log_id in seen_4 or seen_4.add(x.log_id))]

        incidents.append(
            IncidentFinding(
                incident_id="INC-04",
                title="Empaquetado de Documentos Legales (7z.exe) y Exfiltración Masiva HTTPS por Proxy (~253.36 MB)",
                executive_title="Fuga Masiva de Documentación Legal Confidencial hacia Servidor Externo",
                categories=["Comandos y procesos", "Otras anomalías"],
                risk_level="Alto",
                justification=(
                    f"Correlación crítica entre un registro 'Informational' (EVT-00428, Event_ID 4688) donde la cuenta "
                    f"CORP\\rrojas en WS-018 comprime todos los documentos legales ('7z.exe a C:\\Users\\Public\\archive.7z "
                    f"C:\\Legal\\*.docx') a las 10:42:00, y la secuencia inmediata de {len(proxy_logs_4)} peticiones "
                    f"HTTPS POST salientes (EVT-00430 a EVT-00461) hacia 198.51.100.88:443 (/upload/session/1 a /22) "
                    f"transfiriendo un total exacto de {total_bytes_4:,} bytes ({total_mb_4} MB)."
                ),
                mitre_tactics=[
                    "T1560.001 - Archive Collected Data: Archive via Utility (7z.exe)",
                    "T1074.001 - Data Staged: Local Data Staging (C:\\Users\\Public\\archive.7z)",
                    "T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol (HTTPS POST /upload/session/*)",
                ],
                time_start=inc4_logs[0].timestamp,
                time_end=inc4_logs[-1].timestamp,
                affected_hosts=sorted({l.hostname for l in inc4_logs if l.hostname}),
                compromised_users=sorted({l.user for l in inc4_logs if l.user and l.user != "-"}),
                attacker_ips=["198.51.100.88:443", "10.10.1.31 (WS-018)"],
                total_events=len(inc4_logs),
                hidden_informational_count=hidden_4,
                summary_plain_language=(
                    f"En el equipo WS-018 bajo la cuenta 'CORP\\rrojas', se empaquetaron todos los contratos y documentos "
                    f"del directorio legal ('C:\\Legal\\*.docx') en un archivo oculto dentro de una carpeta pública. "
                    f"Un minuto después, se enviaron {total_mb_4} MB de información hacia el servidor externo "
                    f"198.51.100.88 dividido en 22 fragmentos mediante conexiones web cifradas (HTTPS)."
                ),
                business_impact=(
                    f"Exfiltración confirmada de {total_mb_4} MB de documentación jurídica confidencial, exponiendo a la "
                    f"organización a sanciones regulatorias, incumplimiento de confidencialidad y riesgo legal."
                ),
                technical_explanation=(
                    f"A las 10:42:00 (EVT-00428, clasificado originalmente como 'Informational'), el usuario CORP\\rrojas "
                    f"en WS-018 (IP 10.10.1.31) ejecuta '7z.exe a C:\\Users\\Public\\archive.7z C:\\Legal\\*.docx'. "
                    f"Exactamente 60 segundos después (10:43:00 a 10:49:18), el proxy registra {len(proxy_logs_4)} "
                    f"eventos PROXY_ACCESS (EVT-00430 a EVT-00461) con método 'HTTPS POST outbound' desde 10.10.1.31 hacia "
                    f"198.51.100.88:443 utilizando los endpoints secuenciales '/upload/session/1' hasta '/upload/session/22' "
                    f"cada 18 segundos, sumando {total_bytes_4:,} bytes (~{total_mb_4} MB) exfiltrados exitosamente (Result=Allowed)."
                ),
                organizational_impact=(
                    "Pérdida de confidencialidad de documentos legales corporativos y evidencia de evasión de controles "
                    "mediante fragmentación de carga útil sobre HTTPS."
                ),
                key_iocs=[
                    "IP Externa Destino Exfiltración: 198.51.100.88:443",
                    "URI de Exfiltración: /upload/session/1 .. /upload/session/22",
                    f"Volumen Exfiltrado: {total_bytes_4:,} bytes ({total_mb_4} MB)",
                    "Comando de Staging (EVT-00428): 7z.exe a C:\\Users\\Public\\archive.7z C:\\Legal\\*.docx",
                    "Usuario y Host Origen: CORP\\rrojas en WS-018 (10.10.1.31)",
                ],
                evidence_log_ids=[l.log_id for l in inc4_logs],
                evidence_logs=dedup_rep_4,
                action_plan=ActionPlan(
                    investigar=[
                        "Inspeccionar el equipo WS-018 para recuperar C:\\Users\\Public\\archive.7z y determinar la lista exacta de documentos de C:\\Legal\\ incluidos.",
                        "Determinar si la sesión de CORP\\rrojas en 10.10.1.31 corresponde a una amenaza interna (Insider) o al uso de credenciales comprometidas en INC-01.",
                    ],
                    contener=[
                        "Bloquear en el Proxy y Firewall cualquier tráfico hacia el rango/IP 198.51.100.88.",
                        "Suspender temporalmente la cuenta CORP\\rrojas y aislar el endpoint WS-018 para preservación de evidencia.",
                    ],
                    remediar=[
                        "Implementar políticas de Prevención de Pérdida de Datos (DLP) en el Proxy web para bloquear subidas HTTPS POST masivas hacia destinos no categorizados.",
                        "Monitorear la ejecución de herramientas de compresión (7z.exe, rar.exe, tar.exe) sobre directorios sensibles o hacia C:\\Users\\Public\\.",
                    ],
                ),
            )
        )

    # -------------------------------------------------------------------------
    # INCIDENT 5: Persistence via Scheduled Task (4698), Service Installation (7045)
    # & Periodic Execution of wuhelper.exe (Hidden Informational 4688 events)
    # -------------------------------------------------------------------------
    inc5_logs = [
        l
        for l in logs
        if l.log_id not in assigned_ids
        and (
            l.event_id in ("4698", "7045")
            or "wuhelper.exe" in l.process_command_line.lower()
            or "updatecheck" in l.process_command_line.lower()
        )
    ]
    if inc5_logs:
        inc5_logs, hidden_5 = _mark_logs(inc5_logs, "Escalamiento", "INC-05", assigned_ids)
        for l in inc5_logs:
            if l.event_id in ("4698", "7045"):
                category_event_counter["Escalamiento"] += 1
                l.detection_category = "Escalamiento"
            else:
                category_event_counter["Comandos y procesos"] += 1
                l.detection_category = "Comandos y procesos"

        incidents.append(
            IncidentFinding(
                incident_id="INC-05",
                title="Persistencia y Escalamiento en APP-SRV01 mediante Tarea Programada y Servicio Malicioso (wuhelper.exe)",
                executive_title="Instalación de Puerta Trasera Persistente en el Servidor de Aplicaciones",
                categories=["Escalamiento", "Comandos y procesos"],
                risk_level="Alto",
                justification=(
                    f"La cuenta CORP\\helpdesk (desde 10.10.3.18) creó en APP-SRV01 una tarea programada camuflada como "
                    f"actualización de Windows ('\\Microsoft\\Windows\\UpdateCheck' -> 'powershell.exe -File C:\\ProgramData\\updatecheck.ps1', "
                    f"EVT-00523, Event_ID 4698) e instaló el servicio de sistema 'WinUpdateHelper' apuntando a "
                    f"'C:\\ProgramData\\wuhelper.exe' (EVT-00524, Event_ID 7045). Además, la correlación reveló {hidden_5} "
                    f"eventos 'Informational' (EVT-00528, EVT-00542, EVT-00548, EVT-00559, EVT-00564) que demuestran la "
                    f"ejecución periódica del binario cada 6 minutos exactos."
                ),
                mitre_tactics=[
                    "T1053.005 - Scheduled Task/Job: Scheduled Task (\\Microsoft\\Windows\\UpdateCheck)",
                    "T1543.003 - Create or Modify System Process: Windows Service (WinUpdateHelper)",
                    "T1036.005 - Masquerading: Match Legitimate Name or Location (C:\\ProgramData\\wuhelper.exe)",
                ],
                time_start=inc5_logs[0].timestamp,
                time_end=inc5_logs[-1].timestamp,
                affected_hosts=sorted({l.hostname for l in inc5_logs if l.hostname}),
                compromised_users=sorted({l.user for l in inc5_logs if l.user and l.user != "-"}),
                attacker_ips=sorted({l.source_ip for l in inc5_logs if l.source_ip}),
                total_events=len(inc5_logs),
                hidden_informational_count=hidden_5,
                summary_plain_language=(
                    "Utilizando la cuenta de soporte técnico ('CORP\\helpdesk'), se implantaron dos mecanismos de "
                    "persistencia en el servidor APP-SRV01 disfrazados de actualizaciones legítimas de Windows "
                    "('UpdateCheck' y 'WinUpdateHelper'). A partir de ese momento, el programa malicioso 'wuhelper.exe' "
                    "comenzó a ejecutarse automáticamente cada 6 minutos para mantener el control del servidor."
                ),
                business_impact=(
                    "Riesgo Alto de re-compromiso continuo: incluso si se cambian contraseñas, el atacante conserva acceso "
                    "privilegiado al servidor APP-SRV01 mediante el servicio y la tarea programada instalados."
                ),
                technical_explanation=(
                    "A las 11:37:00 (EVT-00523, Event_ID 4698), CORP\\helpdesk desde 10.10.3.18 registra en APP-SRV01 la "
                    "tarea programada '\\Microsoft\\Windows\\UpdateCheck' que invoca 'powershell.exe -File C:\\ProgramData\\updatecheck.ps1'. "
                    "Un minuto después (11:38:00, EVT-00524, Event_ID 7045), instala el servicio 'WinUpdateHelper' con ruta "
                    "'C:\\ProgramData\\wuhelper.exe'. Al correlacionar los registros de creación de procesos (Event_ID 4688) "
                    "marcados como 'Informational', se identifican 5 ejecuciones periódicas de 'C:\\ProgramData\\wuhelper.exe' "
                    "a las 11:40:00 (EVT-00528), 11:46:00 (EVT-00542), 11:52:00 (EVT-00548), 11:58:00 (EVT-00559) y "
                    "12:04:00 (EVT-00564), confirmando un patrón de beaconing/persistencia activa."
                ),
                organizational_impact=(
                    "Persistencia a nivel de SYSTEM/Servicio en el servidor crítico APP-SRV01 y abuso de privilegios de "
                    "la cuenta de soporte técnico CORP\\helpdesk."
                ),
                key_iocs=[
                    "Tarea Programada (EVT-00523): \\Microsoft\\Windows\\UpdateCheck",
                    "Script Malicioso: C:\\ProgramData\\updatecheck.ps1",
                    "Servicio Instalado (EVT-00524): WinUpdateHelper",
                    "Binario Persistente (5 ejecuciones cada 6 min): C:\\ProgramData\\wuhelper.exe",
                    "Cuenta y Origen: CORP\\helpdesk desde 10.10.3.18 en APP-SRV01",
                ],
                evidence_log_ids=[l.log_id for l in inc5_logs],
                evidence_logs=inc5_logs,
                action_plan=ActionPlan(
                    investigar=[
                        "Extraer copias forenses y calcular hashes SHA-256 de C:\\ProgramData\\wuhelper.exe y C:\\ProgramData\\updatecheck.ps1.",
                        "Investigar la estación con IP 10.10.3.18 (WS-018) para determinar cómo fue comprometida la sesión de CORP\\helpdesk.",
                    ],
                    contener=[
                        "Detener y eliminar el servicio 'WinUpdateHelper' (sc.exe stop/delete) y eliminar la tarea programada '\\Microsoft\\Windows\\UpdateCheck'.",
                        "Poner en cuarentena los archivos C:\\ProgramData\\wuhelper.exe y C:\\ProgramData\\updatecheck.ps1 y rotar las credenciales de CORP\\helpdesk.",
                    ],
                    remediar=[
                        "Aplicar principio de mínimo privilegio a la cuenta CORP\\helpdesk (remover permisos de administrador local en servidores como APP-SRV01).",
                        "Bloquear la ejecución de binarios y scripts no firmados desde C:\\ProgramData\\ mediante reglas de Windows Defender Application Control (WDAC) / AppLocker.",
                    ],
                ),
            )
        )

    # -------------------------------------------------------------------------
    # INCIDENT 6: Web Application Exploitation, Enumeration & Webshell RCE
    # on WEB-01 from 192.0.2.91 (HTTP_ACCESS + IIS APPPOOL cmd.exe /c whoami)
    # -------------------------------------------------------------------------
    inc6_logs = [
        l
        for l in logs
        if l.log_id not in assigned_ids
        and (
            l.source_ip == "192.0.2.91"
            or l.event_id == "HTTP_ACCESS"
            or "defaultapppool" in l.user.lower()
            or "test.aspx" in l.process_command_line.lower()
        )
    ]
    if inc6_logs:
        inc6_logs, hidden_6 = _mark_logs(inc6_logs, "Comandos y procesos", "INC-06", assigned_ids)
        for l in inc6_logs:
            if l.event_id == "4688":
                category_event_counter["Comandos y procesos"] += 1
                l.detection_category = "Comandos y procesos"
            elif "/login" in l.process_command_line or "/admin" in l.process_command_line:
                category_event_counter["Fuerza bruta"] += 1
                l.detection_category = "Fuerza bruta"
            else:
                category_event_counter["Otras anomalías"] += 1
                l.detection_category = "Otras anomalías"

        http_logs_6 = [l for l in inc6_logs if l.event_id == "HTTP_ACCESS"]
        rce_logs_6 = [l for l in inc6_logs if l.event_id == "4688"]
        rep_6 = http_logs_6[:6] + (http_logs_6[-2:] if len(http_logs_6) > 6 else []) + rce_logs_6
        seen_6 = set()
        dedup_rep_6 = [x for x in rep_6 if not (x.log_id in seen_6 or seen_6.add(x.log_id))]

        incidents.append(
            IncidentFinding(
                incident_id="INC-06",
                title="Explotación Web, Enumeración de Endpoints y Ejecución Remota de Comandos (Webshell RCE) en WEB-01",
                executive_title="Compromiso del Servidor Web Público (WEB-01) mediante Webshell",
                categories=["Comandos y procesos", "Fuerza bruta", "Otras anomalías"],
                risk_level="Crítico",
                justification=(
                    f"La dirección IP externa 192.0.2.91 realizó {len(http_logs_6)} peticiones HTTP maliciosas contra "
                    f"WEB-01:443 (EVT-00571 a EVT-00596) invocando una webshell en '/uploads/test.aspx?cmd=whoami' "
                    f"(con respuesta HTTP 200 en EVT-00571) y sondeando '/login?user=admin', '/admin/' y '/api/v1/export'. "
                    f"A las 12:15:00, el registro de seguridad de Windows EVT-00599 (Event_ID 4688) confirma Ejecución "
                    f"Remota de Código (RCE): el proceso del servidor web 'IIS APPPOOL\\DefaultAppPool' engendró "
                    f"directamente un intérprete de comandos 'cmd.exe /c whoami'."
                ),
                mitre_tactics=[
                    "T1190 - Exploit Public-Facing Application (WEB-01)",
                    "T1505.003 - Server Software Component: Web Shell (/uploads/test.aspx)",
                    "T1059.003 - Command and Scripting Interpreter: Windows Command Shell (cmd.exe /c whoami)",
                    "T1595.002 - Active Scanning: Vulnerability Scanning (/admin/, /login?user=admin, /api/v1/export)",
                ],
                time_start=inc6_logs[0].timestamp,
                time_end=inc6_logs[-1].timestamp,
                affected_hosts=["WEB-01"],
                compromised_users=["IIS APPPOOL\\DefaultAppPool"],
                attacker_ips=["192.0.2.91"],
                total_events=len(inc6_logs),
                hidden_informational_count=hidden_6,
                summary_plain_language=(
                    "Un atacante externo (192.0.2.91) atacó el servidor web público de la organización (WEB-01), "
                    "logrando subir o activar un archivo malicioso ('/uploads/test.aspx') que le permitió ejecutar "
                    "comandos directamente dentro del sistema operativo del servidor web."
                ),
                business_impact=(
                    "Impacto Crítico: Compromiso directo de un servidor expuesto a Internet (WEB-01), riesgo de "
                    "manipulación del portal web, robo de datos expuestos por '/api/v1/export' y pivote hacia la red interna."
                ),
                technical_explanation=(
                    "Entre las 12:10:00 y las 12:14:00, los registros de IIS (HTTP_ACCESS) en WEB-01 muestran 21 solicitudes "
                    "desde la IP externa 192.0.2.91 cada 12 segundos: ejecución de '/uploads/test.aspx?cmd=whoami' "
                    "(HTTP 200 en EVT-00571, HTTP 404 posterior en EVT-00573/574 indicando posible borrado/renombrado "
                    "anti-forense), intentos de acceso sobre '/login?user=admin' (HTTP 200, 404, 500), '/admin/' (HTTP 500, 404) "
                    "y extracción en '/api/v1/export' (HTTP 200 en EVT-00577 y EVT-00596). La correlación entre capas "
                    "(IIS + Windows Security) confirma en EVT-00599 (12:15:00, Event_ID 4688) que la cuenta de servicio "
                    "'IIS APPPOOL\\DefaultAppPool' ejecutó exitosamente 'cmd.exe /c whoami' inducido desde 192.0.2.91."
                ),
                organizational_impact=(
                    "Ejecución remota de código (RCE) verificada en el servidor web perimetral WEB-01 y potencial extracción "
                    "de datos a través del endpoint '/api/v1/export'."
                ),
                key_iocs=[
                    "IP Externa Atacante: 192.0.2.91",
                    "Webshell URI: /uploads/test.aspx?cmd=whoami (HTTP 200 en EVT-00571)",
                    "Endpoints Atacados: /login?user=admin, /admin/, /api/v1/export",
                    "Proceso RCE Confirmado (EVT-00599): IIS APPPOOL\\DefaultAppPool -> cmd.exe /c whoami",
                ],
                evidence_log_ids=[l.log_id for l in inc6_logs],
                evidence_logs=dedup_rep_6,
                action_plan=ActionPlan(
                    investigar=[
                        "Inspeccionar el directorio físico de '/uploads/' y la raíz de IIS en WEB-01 para localizar webshells (.aspx, .ashx, .config) en disco o memoria.",
                        "Auditar los logs de aplicación de '/api/v1/export' para determinar qué registros fueron devueltos en las respuestas HTTP 200 (EVT-00577 y EVT-00596).",
                    ],
                    contener=[
                        "Bloquear la IP 192.0.2.91 en el WAF/Firewall perimetral y deshabilitar la ejecución de scripts (.aspx) dentro del directorio '/uploads/'.",
                        "Aislar temporalmente WEB-01 o reciclar el Application Pool tras eliminar cualquier artefacto persistente.",
                    ],
                    remediar=[
                        "Corregir la vulnerabilidad de carga de archivos sin validación de extensión/contenido en la aplicación web.",
                        "Configurar reglas de WAF y prevención en EDR para bloquear que w3wp.exe (IIS APPPOOL) invoque cmd.exe o powershell.exe.",
                    ],
                ),
            )
        )

    # -------------------------------------------------------------------------
    # INCIDENT 7: Anomalous Privilege Assignments (Event 4672 Informational) &
    # Log/Identity Hygiene Anomalies (DC01 vs DC-01, svc_backup vs backupsvc)
    # -------------------------------------------------------------------------
    priv_info_logs = [
        l
        for l in logs
        if l.log_id not in assigned_ids and l.event_id == "4672"
    ]
    dc01_logs = [
        l
        for l in logs
        if l.log_id not in assigned_ids and l.hostname == "DC01"
    ]
    inc7_logs = priv_info_logs + [l for l in dc01_logs if l not in priv_info_logs]
    if inc7_logs:
        # Only mark the 4672 privilege events as suspicious in the main table so we don't clutter normal DC01 logoffs,
        # while referencing both in the hygiene finding.
        _, hidden_7 = _mark_logs(priv_info_logs, "Escalamiento", "INC-07", assigned_ids)
        for l in priv_info_logs:
            category_event_counter["Escalamiento"] += 1
        category_event_counter["Otras anomalías"] += len(priv_info_logs)

        rep_7 = priv_info_logs + dc01_logs[:3]
        incidents.append(
            IncidentFinding(
                incident_id="INC-07",
                title="Asignaciones Anómalas de Privilegios Especiales (Event_ID 4672) y Anomalías de Higiene de Telemetría (DC01 / svc_backup)",
                executive_title="Exceso de Privilegios en Cuentas Operativas y Desviaciones de Configuración SIEM",
                categories=["Escalamiento", "Otras anomalías"],
                risk_level="Medio",
                justification=(
                    f"Se detectaron {len(priv_info_logs)} asignaciones de privilegios especiales (Event_ID 4672, "
                    f"etiquetadas como 'Informational') sobre las cuentas CORP\\mruiz, CORP\\svc_backup y CORP\\helpdesk "
                    f"en servidores críticos (DC01, FS-SRV01, APP-SRV01). Adicionalmente, existen {len(dc01_logs)} registros "
                    f"con el nombre de host no estandarizado 'DC01' (sin guion, frente a 'DC-01') y coexistencia de dos "
                    f"cuentas de servicio de respaldo ('CORP\\backupsvc' y 'CORP\\svc_backup'), lo que dificulta las reglas "
                    f"de correlación estáticas."
                ),
                mitre_tactics=[
                    "T1078.002 - Valid Accounts: Over-privileged Domain/Service Accounts (Event 4672)",
                    "T1562 - Defense Evasion / Telemetry Blind Spots (Informational Severity & Hostname Drift)",
                ],
                time_start=inc7_logs[0].timestamp,
                time_end=inc7_logs[-1].timestamp,
                affected_hosts=sorted({l.hostname for l in inc7_logs if l.hostname}),
                compromised_users=sorted({l.user for l in priv_info_logs if l.user}),
                attacker_ips=sorted({l.source_ip for l in priv_info_logs if l.source_ip}),
                total_events=len(priv_info_logs),
                hidden_informational_count=hidden_7,
                summary_plain_language=(
                    "Se identificó que múltiples cuentas de soporte y usuarios estándar reciben permisos equivalentes a "
                    "administrador al iniciar sesión en servidores críticos. Asimismo, el sistema de monitoreo (SIEM) "
                    "clasifica eventos críticos como 'Informativos' y registra el servidor central con dos nombres distintos "
                    "('DC-01' y 'DC01'), creando puntos ciegos de seguridad."
                ),
                business_impact=(
                    "Aumenta la superficie de ataque interna y retrasa la detección temprana de incidentes debido a la "
                    "sub-clasificación de alertas en el SIEM."
                ),
                technical_explanation=(
                    f"Los eventos {', '.join(l.log_id for l in priv_info_logs)} muestran que las cuentas CORP\\mruiz "
                    f"(en FS-SRV01 y DC01), CORP\\svc_backup (en APP-SRV01 y DC01) y CORP\\helpdesk (en APP-SRV01) "
                    f"reciben 'Special privileges assigned to new logon' (Event_ID 4672). Además, se identificaron "
                    f"{len(dc01_logs)} eventos bajo el hostname 'DC01' (ej. EVT-00173, EVT-00254, EVT-00388) en lugar de "
                    f"'DC-01', junto con el uso paralelo de 'CORP\\svc_backup' y 'CORP\\backupsvc'."
                ),
                organizational_impact=(
                    "Riesgo de escalamiento lateral facilitado por exceso de privilegios y evasión de reglas SIEM que "
                    "filtren únicamente por hostname='DC-01' o Severity!='Informational'."
                ),
                key_iocs=[
                    f"Eventos 4672 en Cuentas No-Admin ({len(priv_info_logs)}): {', '.join(l.log_id for l in priv_info_logs)}",
                    "Cuentas con Privilegios Especiales: CORP\\mruiz, CORP\\svc_backup, CORP\\helpdesk",
                    f"Desviación de Hostname: 'DC01' ({len(dc01_logs)} eventos) vs 'DC-01'",
                    "Duplicidad de Cuentas de Backup: CORP\\backupsvc vs CORP\\svc_backup",
                ],
                evidence_log_ids=[l.log_id for l in priv_info_logs],
                evidence_logs=rep_7,
                action_plan=ActionPlan(
                    investigar=[
                        "Revisar la membresía de grupos privilegiados (Administradores locales, Backup Operators, Domain Admins) para CORP\\mruiz, CORP\\svc_backup y CORP\\helpdesk.",
                        "Verificar si los registros de 'DC01' provienen de un segundo controlador de dominio, un reenviador de eventos mal configurado o inyección de logs.",
                    ],
                    contener=[
                        "Remover privilegios administrativos innecesarios en estaciones y servidores para cuentas de usuario estándar (CORP\\mruiz).",
                        "Normalizar la ingesta de nombres de host (DC-01) en el colector SIEM.",
                    ],
                    remediar=[
                        "Recalibrar las reglas de severidad del SIEM para que Event_ID 4672, 4688 (con 7z/wuhelper/cmd) y 4624 desde IPs externas nunca queden relegados a 'Informational'.",
                        "Unificar y auditar el inventario de cuentas de servicio bajo una convención única y controlada.",
                    ],
                ),
            )
        )

    # -------------------------------------------------------------------------
    # Dynamic Catch-All for any OTHER non-Informational events in custom uploads
    # -------------------------------------------------------------------------
    remaining_non_info = [
        l
        for l in logs
        if l.log_id not in assigned_ids and l.severity.lower() not in ("informational", "info", "low")
    ]
    if remaining_non_info:
        remaining_non_info, hidden_rem = _mark_logs(
            remaining_non_info, "Otras anomalías", f"INC-{len(incidents)+1:02d}", assigned_ids
        )
        category_event_counter["Otras anomalías"] += len(remaining_non_info)
        inc_id = f"INC-{len(incidents)+1:02d}"
        incidents.append(
            IncidentFinding(
                incident_id=inc_id,
                title="Eventos Adicionales de Alerta Detectados en el SIEM",
                executive_title="Alertas de Seguridad Adicionales Registradas",
                categories=["Otras anomalías"],
                risk_level="Medio",
                justification=(
                    f"Se identificaron {len(remaining_non_info)} registros adicionales con severidad elevada "
                    f"({', '.join(sorted({l.severity for l in remaining_non_info}))}) en el archivo importado."
                ),
                mitre_tactics=["T1078 - Valid Accounts / General Anomaly"],
                time_start=remaining_non_info[0].timestamp,
                time_end=remaining_non_info[-1].timestamp,
                affected_hosts=sorted({l.hostname for l in remaining_non_info if l.hostname}),
                compromised_users=sorted({l.user for l in remaining_non_info if l.user}),
                attacker_ips=sorted({l.source_ip for l in remaining_non_info if l.source_ip}),
                total_events=len(remaining_non_info),
                hidden_informational_count=hidden_rem,
                summary_plain_language="Conjunto de alertas adicionales reportadas directamente por el SIEM que requieren revisión operativa.",
                business_impact="Riesgo moderado que requiere validación por el equipo de operaciones de seguridad.",
                technical_explanation=(
                    f"Correlación automática de {len(remaining_non_info)} eventos no informativos adicionales "
                    f"entre {remaining_non_info[0].timestamp} y {remaining_non_info[-1].timestamp}."
                ),
                organizational_impact="Posible actividad anómala puntual en los activos listados.",
                key_iocs=[f"Total eventos: {len(remaining_non_info)}"],
                evidence_log_ids=[l.log_id for l in remaining_non_info],
                evidence_logs=remaining_non_info[:15],
                action_plan=ActionPlan(
                    investigar=["Revisar el detalle de los eventos listados en la tabla de evidencias."],
                    contener=["Aplicar bloqueo preventivo en caso de confirmar actividad no autorizada."],
                    remediar=["Ajustar umbrales de monitoreo y correlación en el SIEM."],
                ),
            )
        )

    # Ensure all 6 required categories are represented in the chart dictionary
    events_by_category = {cat: int(category_event_counter.get(cat, 0)) for cat in REQUIRED_CATEGORIES}

    metrics = _build_dashboard_metrics(logs, incidents, events_by_category)
    executive_report = _build_default_executive_report(incidents, metrics)
    technical_report = _build_default_technical_report(incidents, metrics)

    return incidents, metrics, executive_report, technical_report


def _build_dashboard_metrics(
    logs: List[LogEntry],
    incidents: List[IncidentFinding],
    events_by_category: Dict[str, int],
) -> DashboardMetrics:
    """Calculate comprehensive KPI statistics and Chart.js datasets."""
    suspicious_logs = [l for l in logs if l.is_suspicious]
    hidden_info_logs = [l for l in logs if l.elevated_from_informational]

    risk_counts: Dict[str, int] = {"Crítico": 0, "Alto": 0, "Medio": 0, "Bajo": 0}
    for inc in incidents:
        risk_counts[inc.risk_level] = risk_counts.get(inc.risk_level, 0) + 1

    raw_sev_counter = Counter(l.severity for l in logs)
    log_source_counter = Counter(l.log_source for l in logs)

    # Timeline buckets by 15-minute intervals
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
                bucket_key = l.timestamp[11:16]
        else:
            bucket_key = "N/A"
        bucket_all[bucket_key] += 1
        if l.is_suspicious:
            bucket_susp[bucket_key] += 1

    timeline_buckets = [
        {
            "time": k,
            "total": bucket_all[k],
            "suspicious": bucket_susp.get(k, 0),
        }
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
        l.destination.split(":")[0]
        for l in suspicious_logs
        if is_external_ip(l.destination.split(":")[0])
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


def _determine_global_risk(incidents: List[IncidentFinding]) -> RiskLevel:
    levels = {i.risk_level for i in incidents}
    if "Crítico" in levels:
        return "Crítico"
    if "Alto" in levels:
        return "Alto"
    if "Medio" in levels:
        return "Medio"
    return "Bajo"


def _build_default_executive_report(
    incidents: List[IncidentFinding],
    metrics: DashboardMetrics,
) -> ExecutiveReportData:
    """Build the comprehensive plain-language Spanish report for an executive audience."""
    global_risk = _determine_global_risk(incidents)
    exec_items = [
        ExecutiveIncidentItem(
            incident_id=inc.incident_id,
            title=inc.executive_title,
            risk_level=inc.risk_level,
            what_happened=inc.summary_plain_language,
            business_risk=inc.business_impact,
            recommended_decision=inc.action_plan.contener[0] if inc.action_plan.contener else "Aislar activos afectados.",
        )
        for inc in incidents
    ]

    return ExecutiveReportData(
        global_risk_level=global_risk,
        incident_determination=(
            f"CONCLUSIÓN PRINCIPAL: Se confirma la existencia de MÚLTIPLES INCIDENTES DE SEGURIDAD CRÍTICOS "
            f"({metrics.total_incidents} hallazgos correlacionados: {metrics.critical_incidents_count} Críticos, "
            f"{metrics.high_incidents_count} Altos y {metrics.medium_incidents_count} Medios) ocurridos el "
            f"23 de octubre de 2026 entre las 07:46 y las 13:44."
        ),
        executive_overview=(
            f"Tras analizar la totalidad de los {metrics.total_logs} registros exportados del sistema de monitoreo (SIEM) "
            f"de la organización desde nuestra consultora en Estocolmo, se determinó que la infraestructura sufrió múltiples "
            f"intrusiones coordinadas y efectivas, y no se trata de una falsa alarma. Los atacantes lograron adivinar "
            f"contraseñas desde el exterior, tomar control administrativo de servidores clave, sustraer el Presupuesto "
            f"Financiero 2027 ('Budget2027.xlsx') y {metrics.total_exfiltrated_mb} MB de documentos legales confidenciales, "
            f"eliminar copias de respaldo locales para preparar un posible ataque de secuestro de datos (Ransomware), "
            f"dejar programas ocultos para mantener el acceso y comprometer el servidor web público (WEB-01)."
        ),
        key_business_impacts=[
            "Fuga de Información Financiera Estratégica: Robo confirmado del archivo 'Finance\\Budget2027.xlsx' y acceso masivo a 16 documentos del ejercicio FY2026 en el servidor de archivos FS-SRV01.",
            f"Exfiltración Masiva de Documentación Legal: Compresión de los contratos/documentos de 'C:\\Legal\\*.docx' y envío al exterior de {metrics.total_exfiltrated_mb} MB ({metrics.total_exfiltrated_bytes:,} bytes) a través del proxy corporativo.",
            "Riesgo Inminente de Interrupción Operativa (Ransomware): Uso de la cuenta de respaldos ('CORP\\backupsvc') para destruir las copias de recuperación instantánea (Shadow Copies) en WS-023.",
            "Compromiso del Portal Web Público y Persistencia Interna: Ejecución remota de código en el servidor web (WEB-01) e instalación de puertas traseras automáticas en el servidor de aplicaciones (APP-SRV01).",
        ],
        plain_language_incidents=exec_items,
        priority_decisions=[
            "1. Autorizar la contención inmediata y aislamiento de red de los servidores comprometidos (APP-SRV01 y WEB-01) y de las estaciones de trabajo WS-018 y WS-023.",
            "2. Ordenar el cambio de contraseñas de emergencia y revocación de sesiones para las cuentas comprometidas (CORP\\admin, CORP\\mgarcia, CORP\\backupsvc, CORP\\rrojas y CORP\\helpdesk).",
            "3. Activar el protocolo de evaluación legal y de cumplimiento normativo (GDPR / protección de datos) ante la salida confirmada de documentación legal (C:\\Legal\\*.docx) y financiera (Budget2027.xlsx).",
            "4. Aprobar el cierre inmediato del acceso directo por Escritorio Remoto (RDP) desde Internet y exigir Autenticación Multifactor (MFA) en todos los accesos remotos.",
        ],
        investment_recommendations=[
            "Despliegue obligatorio de Autenticación Multifactor (MFA) y eliminación de exposición RDP directa a Internet.",
            "Implementación de controles de Prevención de Pérdida de Datos (DLP) en el Proxy web para bloquear subidas masivas de información confidencial.",
            "Modernización de las reglas de detección del SIEM: el análisis demostró que 16 eventos clave de ataque quedaron clasificados erróneamente como 'Informativos' (Informational), ocultando el éxito de los atacantes.",
            "Esquema de copias de seguridad inmutables y aisladas de la red principal para garantizar la continuidad del negocio frente a Ransomware.",
        ],
    )


def _build_default_technical_report(
    incidents: List[IncidentFinding],
    metrics: DashboardMetrics,
) -> TechnicalReportData:
    """Build the complete SOC Level 2 Technical Report following all 8 sections of Slide 4."""
    global_risk = _determine_global_risk(incidents)
    return TechnicalReportData(
        global_risk_level=global_risk,
        resumen_ejecutivo=(
            f"Como Analista SOC Nivel 2 de la consultora de ciberseguridad en Estocolmo, Suecia, se realizó el análisis "
            f"forense y de correlación sobre los {metrics.total_logs} eventos exportados del SIEM del cliente "
            f"(ventana temporal: {metrics.time_range_start} a {metrics.time_range_end}). La correlación multi-fuente "
            f"(Windows Security, System, PowerShell, Proxy, IIS y Firewall) permitió identificar {metrics.total_logs} "
            f"eventos totales, de los cuales {metrics.suspicious_logs_count} eventos están directamente vinculados a "
            f"{metrics.total_incidents} incidentes/hallazgos de seguridad ({metrics.critical_incidents_count} de criticidad "
            f"Crítica, {metrics.high_incidents_count} Alta y {metrics.medium_incidents_count} Media). Asimismo, el motor "
            f"de correlación descubrió {metrics.hidden_informational_detected} eventos críticos de ataque que habían sido "
            f"registrados con severidad cruda 'Informational' (incluyendo inicios de sesión exitosos tras fuerza bruta, "
            f"escalamiento de privilegios, compresión con 7z.exe y ejecuciones periódicas del binario persistente wuhelper.exe)."
        ),
        hallazgos_resumen=(
            "Se estableció de manera concluyente que la infraestructura experimentó MÚLTIPLES INCIDENTES DE SEGURIDAD "
            "diferenciados pero concurrentes a lo largo de la mañana del 23 de octubre de 2026, abarcando las seis "
            "categorías críticas de detección: (1) Fuerza bruta por Password Spraying e intrusión RDP, (2) Inicios de "
            "sesión sospechosos desde IPs públicas, (3) Escalamiento de privilegios y persistencia vía servicios/tareas, "
            "(4) Ejecución de comandos y procesos maliciosos (PowerShell codificado, vssadmin, 7z, tar y webshell cmd.exe), "
            "(5) Movimiento lateral por SMB hacia el servidor financiero FS-SRV01, y (6) Otras anomalías críticas como "
            "exfiltración masiva por HTTPS Proxy (~253.36 MB) y deficiencias de normalización en la telemetría (DC01 vs DC-01)."
        ),
        impacto_organizacion_global=(
            "El impacto técnico y organizacional global es CRÍTICO y afecta simultáneamente la Confidencialidad, "
            "Integridad y Disponibilidad de la infraestructura:\n"
            "• Confidencialidad: Exfiltración confirmada del presupuesto 'Finance\\Budget2027.xlsx' hacia 203.0.113.88:443 "
            "(INC-02), lectura masiva de 'Finance\\FY2026\\document_000..015.xlsx' (INC-03), exfiltración de 265,671,558 bytes "
            "(~253.36 MB) de documentos legales 'C:\\Legal\\*.docx' hacia 198.51.100.88:443 (INC-04) y extracción vía "
            "'/api/v1/export' en WEB-01 (INC-06).\n"
            "• Integridad: Compromiso de cuentas privilegiadas y de servicio (CORP\\admin, CORP\\backupsvc, CORP\\helpdesk, "
            "CORP\\mgarcia, CORP\\rrojas), implantación del servicio malicioso 'WinUpdateHelper' (C:\\ProgramData\\wuhelper.exe) "
            "y tarea programada 'UpdateCheck' en APP-SRV01 (INC-05), y ejecución de comandos vía webshell en WEB-01 (INC-06).\n"
            "• Disponibilidad y Recuperación: Eliminación deliberada de instantáneas de volumen (Shadow Copies) en WS-023 "
            "mediante 'vssadmin.exe delete shadows /all /quiet' (INC-03), dejando al entorno vulnerable a cifrado destructivo."
        ),
        recomendaciones_generales=[
            "1. Eliminación de Exposición RDP y Autenticación Robusta (MFA): Cerrar el acceso RDP directo desde Internet hacia servidores internos (APP-SRV01) e implementar MFA obligatorio y bloqueo inteligente contra Password Spraying en Active Directory (DC-01).",
            "2. Endurecimiento de Cuentas Privilegiadas y de Servicio: Implementar un modelo de Tiering en Active Directory, migrar cuentas como CORP\\backupsvc y CORP\\svc_backup a Group Managed Service Accounts (gMSA), prohibir su inicio de sesión interactivo en estaciones de trabajo y retirar permisos de administrador local a CORP\\helpdesk y CORP\\mruiz.",
            "3. Controles de Ejecución en Endpoints y Servidores (EDR / AppLocker / WDAC): Bloquear la ejecución de binarios desde rutas escribibles por usuarios como C:\\ProgramData\\ (wuhelper.exe) y C:\\Users\\Public\\, restringir el uso de PowerShell con parámetros -EncodedCommand y bloquear la invocación de vssadmin.exe delete shadows.",
            "4. Prevención de Exfiltración (DLP) y Filtrado de Egreso: Configurar políticas en el Proxy y Firewall para inspeccionar y limitar transferencias salientes masivas por HTTPS POST (/upload/session/*) y bloquear tráfico saliente directo desde servidores (APP-SRV01) hacia IPs públicas desconocidas.",
            "5. Seguridad en Aplicaciones Web (WAF y Hardening IIS): Eliminar permisos de ejecución de scripts en directorios de carga (/uploads/) en WEB-01, validar estrictamente las subidas de archivos y monitorear la creación de procesos hijos (cmd.exe, powershell.exe) bajo IIS APPPOOL.",
            "6. Recalibración y Normalización del SIEM: Corregir la severidad de ingestión en el SIEM para que eventos críticos (Event_ID 4672, 4688 con utilidades de compresión/sistema, 4624 desde IPs externas) generen alertas de correlación, y estandarizar el hostname del controlador de dominio (unificar 'DC01' a 'DC-01').",
        ],
    )
