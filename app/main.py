"""FastAPI Web Application Server for SIEM Log Analyzer (SOC Level 2).

Waits for user file upload before generating any analysis, dashboards, or reports.
Exports both reports (Executive first, Technical second) into a single Spanish PDF file.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from app.ai_service import (
    resolve_foundry_config,
    run_dynamic_siem_analysis,
    test_foundry_connection,
)
from app.excel_parser import parse_siem_excel_bytes
from app.models import AIConfigRequest, AnalysisResponse
from app.pdf_generator import generate_combined_pdf

app = FastAPI(
    title="SIEM Log Analyzer — SOC Nivel 2 (Estocolmo)",
    description=(
        "Plataforma web de análisis dinámico de registros SIEM con "
        "IA integrada (Microsoft Foundry GPT) y exportación de informes (Ejecutivo + Técnico) en un único PDF (Español)."
    ),
    version="2.1.0",
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

# Stores the latest analysis ONLY after a file has been uploaded by the user
_LATEST_ANALYSIS: Optional[AnalysisResponse] = None


def _run_full_pipeline(
    file_bytes: bytes,
    filename: str,
    ai_config: Optional[AIConfigRequest] = None,
) -> AnalysisResponse:
    """Execute Excel parsing and dynamic AI-driven correlation, dashboard & report generation."""
    global _LATEST_ANALYSIS

    logs = parse_siem_excel_bytes(file_bytes, filename=filename)
    incidents, metrics, exec_report, tech_report, ai_mode, ai_model = run_dynamic_siem_analysis(
        logs, config_req=ai_config
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
    """Return current Microsoft Foundry configuration status."""
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
    """Upload and dynamically analyze any SIEM .xlsx file."""
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


def _require_existing_analysis(payload: Optional[AnalysisResponse] = None) -> AnalysisResponse:
    """Require that a file has already been uploaded and analyzed before generating PDFs."""
    if payload is not None:
        return payload
    if _LATEST_ANALYSIS is not None:
        return _LATEST_ANALYSIS
    raise HTTPException(
        status_code=400,
        detail="Primero debe subir y analizar un archivo Excel (.xlsx) antes de generar el informe PDF.",
    )


@app.post("/api/reports/pdf")
async def download_combined_pdf_post(payload: Optional[AnalysisResponse] = None):
    """Generate and download the unified Spanish PDF (Executive Report first + Technical Report second)."""
    analysis = _require_existing_analysis(payload)
    pdf_bytes = generate_combined_pdf(analysis)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="Informe_SIEM_Ejecutivo_y_Tecnico_SOC_L2_ES.pdf"'
        },
    )


@app.get("/api/reports/pdf")
async def download_combined_pdf_get():
    """GET endpoint for direct download of the unified Spanish PDF (Executive first + Technical second)."""
    analysis = _require_existing_analysis(None)
    pdf_bytes = generate_combined_pdf(analysis)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="Informe_SIEM_Ejecutivo_y_Tecnico_SOC_L2_ES.pdf"'
        },
    )


@app.post("/api/reports/pdf/executive")
async def download_executive_pdf_post(payload: Optional[AnalysisResponse] = None):
    """Alias endpoint returning the unified Spanish PDF."""
    return await download_combined_pdf_post(payload)


@app.get("/api/reports/pdf/executive")
async def download_executive_pdf_get():
    """Alias endpoint returning the unified Spanish PDF."""
    return await download_combined_pdf_get()


@app.post("/api/reports/pdf/technical")
async def download_technical_pdf_post(payload: Optional[AnalysisResponse] = None):
    """Alias endpoint returning the unified Spanish PDF."""
    return await download_combined_pdf_post(payload)


@app.get("/api/reports/pdf/technical")
async def download_technical_pdf_get():
    """Alias endpoint returning the unified Spanish PDF."""
    return await download_combined_pdf_get()
