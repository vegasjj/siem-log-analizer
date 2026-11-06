"""Automated test suite for Dynamic SIEM Log Analyzer (SOC Level 2)."""

from io import BytesIO
from fastapi.testclient import TestClient
import openpyxl

from app.ai_service import _extract_and_parse_json, run_dynamic_siem_analysis
from app.analyzer import REQUIRED_CATEGORIES
from app.excel_parser import get_sample_excel_path, parse_siem_excel_bytes
import app.main as main_mod
from app.main import app


client = TestClient(app)


def test_json_extractor_handles_fences_and_truncation():
    """Verify _extract_and_parse_json handles markdown code blocks and slightly truncated JSON."""
    fenced = '```json\n{"global_risk_level": "Crítico", "incidents": []}\n```'
    parsed = _extract_and_parse_json(fenced)
    assert parsed["global_risk_level"] == "Crítico"

    truncated = '{"global_risk_level": "Alto", "incidents": [{"incident_id": "INC-01", "title": "Ataque'
    repaired = _extract_and_parse_json(truncated)
    assert repaired["global_risk_level"] == "Alto"



def test_nothing_generated_before_file_upload():
    """Verify the app does not generate any reports before a file is uploaded."""
    main_mod._LATEST_ANALYSIS = None
    exec_resp = client.get("/api/reports/pdf/executive")
    assert exec_resp.status_code == 400
    tech_resp = client.get("/api/reports/pdf/technical")
    assert tech_resp.status_code == 400


def test_dynamic_analysis_on_brand_new_dataset():
    """Verify a completely new, unseen Excel dataset dynamically generates dashboards and PDFs."""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "SIEM Export"
    ws.append([
        "Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP",
        "Destination", "Log_Source", "Event_Description", "Process_CommandLine", "Result", "Severity"
    ])
    # Brand-new unseen IPs (45.33.32.156), users (ACME\jdoe), hosts (PROD-DB99)
    ws.append(["LOG-9001", "2027-05-10 14:00:01", "PROD-DB99", "4625", "ACME\\jdoe", "45.33.32.156", "PROD-DB99", "Security", "Failed logon", "", "Failure", "Warning"])
    ws.append(["LOG-9002", "2027-05-10 14:00:10", "PROD-DB99", "4625", "ACME\\jdoe", "45.33.32.156", "PROD-DB99", "Security", "Failed logon", "", "Failure", "Warning"])
    ws.append(["LOG-9003", "2027-05-10 14:00:20", "PROD-DB99", "4625", "ACME\\jdoe", "45.33.32.156", "PROD-DB99", "Security", "Failed logon", "", "Failure", "Warning"])
    ws.append(["LOG-9004", "2027-05-10 14:00:35", "PROD-DB99", "4624", "ACME\\jdoe", "45.33.32.156", "PROD-DB99", "Security", "Successful logon", "", "Success", "Informational"])
    ws.append(["LOG-9005", "2027-05-10 14:01:00", "PROD-DB99", "4688", "ACME\\jdoe", "45.33.32.156", "", "Security", "Process created", "powershell.exe -EncodedCommand ZABpAHIA", "Success", "High"])

    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)

    up_resp = client.post(
        "/api/analyze",
        files={"file": ("unseen_acme_logs.xlsx", buf, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        data={"use_ai": "false"},
    )
    assert up_resp.status_code == 200
    data = up_resp.json()
    assert data["filename"] == "unseen_acme_logs.xlsx"
    assert data["metrics"]["total_logs"] == 5
    assert data["metrics"]["total_incidents"] >= 1
    assert "PROD-DB99" in data["metrics"]["top_affected_hosts"]
    assert "45.33.32.156" in data["metrics"]["top_suspicious_ips"]

    # Verify PDF generation works for the brand-new dataset
    exec_pdf = client.get("/api/reports/pdf/executive")
    assert exec_pdf.status_code == 200
    assert exec_pdf.content.startswith(b"%PDF-")


def test_dynamic_analysis_on_sample_excel_without_hardcoding():
    """Verify the generic engine also correlates all categories and hidden Informational logs on the case study file."""
    sample_path, sample_name = get_sample_excel_path()
    logs = parse_siem_excel_bytes(sample_path.read_bytes(), filename=sample_name)
    incidents, metrics, exec_rep, tech_rep, _, _ = run_dynamic_siem_analysis(logs)

    assert metrics.total_logs == 715
    assert len(incidents) >= 5

    detected_categories = {cat for inc in incidents for cat in inc.categories}
    for req_cat in REQUIRED_CATEGORIES:
        assert req_cat in detected_categories, f"Missing required category: {req_cat}"

    # Verify hidden Informational attack events were elevated generically
    elevated_ids = {l.log_id for l in logs if l.elevated_from_informational}
    for expected_hidden in ["EVT-00123", "EVT-00126", "EVT-00428", "EVT-00528"]:
        assert expected_hidden in elevated_ids

    # Test upload endpoint and PDF generation
    with sample_path.open("rb") as f:
        resp = client.post(
            "/api/analyze",
            files={"file": (sample_name, f, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
            data={"use_ai": "false"},
        )
    assert resp.status_code == 200

    # Verify unified PDF generation (Executive first + Technical second)
    combined_pdf = client.get("/api/reports/pdf")
    assert combined_pdf.status_code == 200
    assert combined_pdf.headers["content-type"] == "application/pdf"
    assert "Informe_SIEM_Ejecutivo_y_Tecnico_SOC_L2_ES.pdf" in combined_pdf.headers.get("content-disposition", "")
    assert combined_pdf.content.startswith(b"%PDF-")
    assert len(combined_pdf.content) > 6000

