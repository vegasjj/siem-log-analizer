"""FastAPI Web Application Server for SIEM Log Analyzer (SOC Level 2)."""

from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from app.ai_service import (
    enrich_analysis_with_foundry,
    resolve_foundry_config,
    test_foundry_connection,
)
from app.analyzer import correlate_siem_logs
from app.excel_parser import get_sample_excel_path, parse_siem_excel_bytes
from app.models import AIConfigRequest, AnalysisResponse
from app.pdf_generator import generate_executive_pdf, generate_technical_pdf

app = FastAPI(
    title="SIEM Log Analyzer — SOC Nivel 2 (Estocolmo)",
    description=(
        "Plataforma web de análisis forense y correlación de registros SIEM con "
        "IA integrada (Microsoft Foundry GPT) y generación dual de informes en PDF (Español)."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# In-memory store of the most recent analysis for instant GET/POST PDF downloads
_LATEST_ANALYSIS: Optional[AnalysisResponse] = None


def _run_full_pipeline(
    file_bytes: bytes,
    filename: str,
    ai_config: Optional[AIConfigRequest] = None,
) -> AnalysisResponse:
    """Execute Excel parsing, deterministic correlation, and Microsoft Foundry GPT enrichment."""
    global _LATEST_ANALYSIS

    logs = parse_siem_excel_bytes(file_bytes, filename=filename)
    incidents, metrics, exec_report, tech_report = correlate_siem_logs(logs)
    incidents, exec_report, tech_report, ai_mode, ai_model = enrich_analysis_with_foundry(
        incidents, metrics, exec_report, tech_report, config_req=ai_config
    )

    analyzed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result = AnalysisResponse(
        filename=filename,
        analyzed_at=analyzed_at,
        ai_mode_used=ai_mode,
        ai_model_name=ai_model,
        metrics=metrics,
        incidents=incidents,
        executive_report=exec_report,
        technical_report=tech_report,
        logs=logs,
    )
    _LATEST_ANALYSIS = result
    return result


@app.get("/", include_in_schema=False)
async def serve_index():
    """Serve the main SIEM Log Analyzer Single Page Application."""
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Interfaz web index.html no encontrada.")
    return FileResponse(str(index_file))


@app.get("/api/ai-config/status")
async def get_ai_config_status():
    """Return current Microsoft Foundry configuration status (without exposing raw API keys)."""
    cfg = resolve_foundry_config()
    has_creds = bool(cfg["endpoint"] and cfg["api_key"])
    return {
        "configured": has_creds,
        "endpoint": cfg["endpoint"],
        "deployment_name": cfg["deployment"],
        "api_version": cfg["api_version"],
    }


@app.post("/api/ai-config/test")
async def api_test_ai_config(config_req: AIConfigRequest):
    """Test connection to a Microsoft Foundry GPT deployment."""
    return test_foundry_connection(config_req)


@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_uploaded_excel(
    file: UploadFile = File(...),
    endpoint: Optional[str] = Form(default=None),
    api_key: Optional[str] = Form(default=None),
    deployment_name: Optional[str] = Form(default=None),
    api_version: Optional[str] = Form(default=None),
    use_ai: bool = Form(default=True),
):
    """Upload and analyze a SIEM .xlsx file."""
    filename = file.filename or "siem_export.xlsx"
    if not filename.lower().endswith(".xlsx"):
        raise HTTPException(
            status_code=400,
            detail="Formato de archivo no válido. Por favor suba un archivo Excel (.xlsx).",
        )
    try:
        file_bytes = await file.read()
        ai_cfg = AIConfigRequest(
            endpoint=endpoint,
            api_key=api_key,
            deployment_name=deployment_name,
            api_version=api_version,
            use_ai=use_ai,
        )
        return _run_full_pipeline(file_bytes, filename, ai_config=ai_cfg)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve)) from ve
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Error al procesar el archivo Excel: {exc}"
        ) from exc


@app.post("/api/analyze-sample", response_model=AnalysisResponse)
async def analyze_sample_excel(config_req: Optional[AIConfigRequest] = None):
    """Load and analyze the bundled SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx file."""
    try:
        sample_path, sample_name = get_sample_excel_path()
        file_bytes = sample_path.read_bytes()
        return _run_full_pipeline(file_bytes, sample_name, ai_config=config_req)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Error al analizar el archivo del caso de estudio: {exc}",
        ) from exc


def _get_or_create_analysis(payload: Optional[AnalysisResponse] = None) -> AnalysisResponse:
    global _LATEST_ANALYSIS
    if payload is not None:
        return payload
    if _LATEST_ANALYSIS is not None:
        return _LATEST_ANALYSIS
    sample_path, sample_name = get_sample_excel_path()
    return _run_full_pipeline(sample_path.read_bytes(), sample_name)


@app.post("/api/reports/pdf/executive")
async def download_executive_pdf_post(payload: Optional[AnalysisResponse] = None):
    """Generate and download the Spanish Executive Report in PDF format."""
    analysis = _get_or_create_analysis(payload)
    pdf_bytes = generate_executive_pdf(analysis)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="Informe_Ejecutivo_SOC_L2_ES.pdf"'
        },
    )


@app.get("/api/reports/pdf/executive")
async def download_executive_pdf_get():
    """GET endpoint for direct browser download of the Spanish Executive Report PDF."""
    analysis = _get_or_create_analysis(None)
    pdf_bytes = generate_executive_pdf(analysis)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="Informe_Ejecutivo_SOC_L2_ES.pdf"'
        },
    )


@app.post("/api/reports/pdf/technical")
async def download_technical_pdf_post(payload: Optional[AnalysisResponse] = None):
    """Generate and download the Spanish Technical SOC L2 Report in PDF format."""
    analysis = _get_or_create_analysis(payload)
    pdf_bytes = generate_technical_pdf(analysis)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="Informe_Tecnico_SOC_L2_ES.pdf"'
        },
    )


@app.get("/api/reports/pdf/technical")
async def download_technical_pdf_get():
    """GET endpoint for direct browser download of the Spanish Technical SOC L2 Report PDF."""
    analysis = _get_or_create_analysis(None)
    pdf_bytes = generate_technical_pdf(analysis)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="Informe_Tecnico_SOC_L2_ES.pdf"'
        },
    )
