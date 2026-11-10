"""Automated test suite for Dynamic SIEM Log Analyzer (SOC Level 2)."""

from io import BytesIO
from fastapi.testclient import TestClient
import openpyxl

from app.ai_service import _extract_and_parse_json, run_dynamic_siem_analysis
from app.analyzer import REQUIRED_CATEGORIES
from app.excel_parser import parse_siem_excel_bytes
import app.main as main_mod
from app.main import app


client = TestClient(app)


def _build_synthetic_siem_xlsx() -> bytes:
    """Create an in-memory multi-incident SIEM Excel file covering all 6 required detection categories."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "SIEM Export"
    ws.append([
        "Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP",
        "Destination", "Log_Source", "Event_Description", "Process_CommandLine", "Result", "Severity",
    ])
    # 1. Brute Force + Suspicious Logon + Privilege Escalation (including hidden Informational events)
    ws.append(["LOG-0001", "2027-05-10 08:00:01", "DC-CORE", "4625", "ACME\\jdoe", "45.33.32.156", "DC-CORE", "Security", "An account failed to log on", "", "Failure", "Warning"])
    ws.append(["LOG-0002", "2027-05-10 08:00:10", "DC-CORE", "4625", "ACME\\jdoe", "45.33.32.156", "DC-CORE", "Security", "An account failed to log on", "", "Failure", "Warning"])
    ws.append(["LOG-0003", "2027-05-10 08:00:20", "DC-CORE", "4625", "ACME\\jdoe", "45.33.32.156", "DC-CORE", "Security", "An account failed to log on", "", "Failure", "Warning"])
    ws.append(["LOG-0004", "2027-05-10 08:00:35", "DC-CORE", "4624", "ACME\\jdoe", "45.33.32.156", "DC-CORE", "Security", "An account was successfully logged on (LogonType=10; RDP)", "", "Success", "Informational"])
    ws.append(["LOG-0005", "2027-05-10 08:00:40", "DC-CORE", "4672", "ACME\\jdoe", "45.33.32.156", "DC-CORE", "Security", "Special privileges assigned to new logon", "", "Success", "Informational"])
    # 2. Suspicious Commands & Processes + Lateral Movement + Outbound Exfiltration
    ws.append(["LOG-0006", "2027-05-10 08:05:00", "APP-NODE1", "4688", "ACME\\jdoe", "10.20.1.15", "", "Security", "A new process has been created", "powershell.exe -EncodedCommand ZABpAHIA", "Success", "High"])
    ws.append(["LOG-0007", "2027-05-10 08:06:00", "FILE-SRV1", "5145", "ACME\\jdoe", "10.20.1.15", "\\\\FILE-SRV1\\Payroll", "Security", "Detailed file share access", "", "Success", "Informational"])
    ws.append(["LOG-0008", "2027-05-10 08:07:00", "WS-101", "4688", "ACME\\jdoe", "10.20.1.50", "", "Security", "A new process has been created", "7z.exe a C:\\Users\\Public\\dump.7z C:\\Payroll\\*.xlsx", "Success", "Informational"])
    ws.append(["LOG-0009", "2027-05-10 08:08:00", "WS-101", "PROXY_ACCESS", "ACME\\jdoe", "10.20.1.50", "198.51.100.200:443", "Proxy", "HTTPS POST outbound", "bytes_out=15728640 uri=/upload/chunk/1", "Allowed", "Warning"])

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()


def test_json_extractor_handles_fences_and_truncation():
    """Verify _extract_and_parse_json handles markdown code blocks and slightly truncated JSON."""
    fenced = '```json\n{"global_risk_level": "Crítico", "incidents": []}\n```'
    parsed = _extract_and_parse_json(fenced)
    assert parsed["global_risk_level"] == "Crítico"

    truncated = '{"global_risk_level": "Alto", "incidents": [{"incident_id": "INC-01", "title": "Ataque'
    repaired = _extract_and_parse_json(truncated)
    assert repaired["global_risk_level"] == "Alto"


def test_nothing_generated_before_file_upload():
    """Verify the app does not generate any PDF reports before an Excel file is uploaded."""
    main_mod._LATEST_ANALYSIS = None
    pdf_resp = client.get("/api/reports/pdf")
    assert pdf_resp.status_code == 400


def test_dynamic_analysis_and_unified_pdf_export():
    """Verify uploading a new Excel dataset dynamically generates the dashboard, categories, and unified PDF."""
    xlsx_bytes = _build_synthetic_siem_xlsx()
    logs = parse_siem_excel_bytes(xlsx_bytes, filename="synthetic_siem.xlsx")
    incidents, metrics, exec_rep, tech_rep, _, _ = run_dynamic_siem_analysis(logs)

    assert metrics.total_logs == 9
    assert len(incidents) >= 2

    detected_categories = {cat for inc in incidents for cat in inc.categories}
    for req_cat in REQUIRED_CATEGORIES:
        assert req_cat in detected_categories, f"Missing required category: {req_cat}"

    # Verify hidden Informational attack events were elevated dynamically
    elevated_ids = {l.log_id for l in logs if l.elevated_from_informational}
    assert {"LOG-0004", "LOG-0005", "LOG-0007", "LOG-0008"}.issubset(elevated_ids)

    # Verify upload endpoint and unified PDF download (Executive first + Technical second)
    up_resp = client.post(
        "/api/analyze",
        files={"file": ("synthetic_siem.xlsx", BytesIO(xlsx_bytes), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        data={"use_ai": "false"},
    )
    assert up_resp.status_code == 200
    data = up_resp.json()
    assert data["filename"] == "synthetic_siem.xlsx"
    assert data["metrics"]["total_logs"] == 9
    assert "DC-CORE" in data["metrics"]["top_affected_hosts"]
    assert "45.33.32.156" in data["metrics"]["top_suspicious_ips"]

    combined_pdf = client.get("/api/reports/pdf")
    assert combined_pdf.status_code == 200
    assert combined_pdf.headers["content-type"] == "application/pdf"
    assert "Informe_SIEM_Ejecutivo_y_Tecnico_SOC_L2_ES.pdf" in combined_pdf.headers.get("content-disposition", "")
    assert combined_pdf.content.startswith(b"%PDF-")
    assert len(combined_pdf.content) > 4000
