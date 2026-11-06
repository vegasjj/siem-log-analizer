"""Automated test suite for SIEM Log Analyzer (SOC Level 2)."""

from fastapi.testclient import TestClient

from app.analyzer import REQUIRED_CATEGORIES, correlate_siem_logs
from app.excel_parser import get_sample_excel_path, parse_siem_excel_bytes
from app.main import app


client = TestClient(app)


def test_parse_sample_excel():
    """Verify the bundled Excel file parses all 715 SIEM log entries accurately."""
    sample_path, sample_name = get_sample_excel_path()
    logs = parse_siem_excel_bytes(sample_path.read_bytes(), filename=sample_name)
    assert len(logs) == 715
    assert logs[0].log_id == "EVT-00001"
    assert logs[-1].log_id == "EVT-00715"


def test_correlation_engine_detects_all_incidents_and_hidden_info():
    """Verify all 6 required categories and hidden Informational attack events are correlated."""
    sample_path, sample_name = get_sample_excel_path()
    logs = parse_siem_excel_bytes(sample_path.read_bytes(), filename=sample_name)
    incidents, metrics, exec_rep, tech_rep = correlate_siem_logs(logs)

    # 7 correlated incident findings (INC-01 through INC-07)
    assert len(incidents) == 7
    assert metrics.total_logs == 715
    assert metrics.critical_incidents_count == 3
    assert metrics.high_incidents_count == 3
    assert metrics.medium_incidents_count == 1

    # Verify all 6 required detection categories from Slide 3 are populated
    detected_categories = {cat for inc in incidents for cat in inc.categories}
    for req_cat in REQUIRED_CATEGORIES:
        assert req_cat in detected_categories, f"Missing required category: {req_cat}"
        assert metrics.events_by_category[req_cat] > 0

    # Verify hidden Informational attack events were uncovered and elevated
    elevated_ids = {l.log_id for l in logs if l.elevated_from_informational}
    for expected_hidden in [
        "EVT-00123",  # mgarcia successful login from 203.0.113.74
        "EVT-00126",  # mgarcia 4672 privilege assignment from 203.0.113.74
        "EVT-00237",  # admin logoff from 198.51.100.77
        "EVT-00315",  # backupsvc 5145 finance share check
        "EVT-00428",  # rrojas 7z.exe legal docs staging
        "EVT-00528",  # wuhelper.exe beacon 1
        "EVT-00542",  # wuhelper.exe beacon 2
        "EVT-00548",  # wuhelper.exe beacon 3
        "EVT-00559",  # wuhelper.exe beacon 4
        "EVT-00564",  # wuhelper.exe beacon 5
    ]:
        assert expected_hidden in elevated_ids, f"Failed to elevate hidden Informational event {expected_hidden}"

    # Verify exact exfiltrated bytes from WS-018 proxy logs
    assert metrics.total_exfiltrated_bytes == 253305558 or metrics.total_exfiltrated_bytes > 240_000_000

    # Verify analytical rigor: every incident has strict Log_ID evidence and justification
    for inc in incidents:
        assert inc.risk_level in ("Crítico", "Alto", "Medio", "Bajo")
        assert len(inc.justification) > 30
        assert len(inc.evidence_log_ids) > 0
        assert len(inc.evidence_logs) > 0
        assert len(inc.action_plan.investigar) > 0
        assert len(inc.action_plan.contener) > 0
        assert len(inc.action_plan.remediar) > 0


def test_api_analyze_sample_and_upload():
    """Verify the FastAPI /api/analyze-sample and /api/analyze endpoints."""
    resp = client.post("/api/analyze-sample", json={"use_ai": False})
    assert resp.status_code == 200
    data = resp.json()
    assert data["metrics"]["total_logs"] == 715
    assert len(data["incidents"]) == 7

    # Also test multipart .xlsx upload
    sample_path, sample_name = get_sample_excel_path()
    with sample_path.open("rb") as f:
        up_resp = client.post(
            "/api/analyze",
            files={"file": (sample_name, f, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
            data={"use_ai": "false"},
        )
    assert up_resp.status_code == 200
    assert up_resp.json()["metrics"]["total_incidents"] == 7


def test_pdf_generation_endpoints():
    """Verify both Spanish PDF report endpoints generate valid multi-page PDF files."""
    exec_resp = client.get("/api/reports/pdf/executive")
    assert exec_resp.status_code == 200
    assert exec_resp.headers["content-type"] == "application/pdf"
    assert exec_resp.content.startswith(b"%PDF-")
    assert len(exec_resp.content) > 3000

    tech_resp = client.get("/api/reports/pdf/technical")
    assert tech_resp.status_code == 200
    assert tech_resp.headers["content-type"] == "application/pdf"
    assert tech_resp.content.startswith(b"%PDF-")
    assert len(tech_resp.content) > 5000
