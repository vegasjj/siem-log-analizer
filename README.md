# SIEM Log Analyzer — SOC Nivel 2 (Estocolmo, Suecia)

Aplicación web de análisis forense y correlación de registros SIEM exportados en formato Excel (`.xlsx`), diseñada para el escenario de **Analista SOC Nivel 2** en una consultora de ciberseguridad en Estocolmo, Suecia.

## Características Principales

1. **Carga y Exploración de Archivos Excel (`.xlsx`)**:
   - Importación mediante arrastrar y soltar (*Drag & Drop*) o carga instantánea del archivo del caso de estudio (`SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx`).
   - Explorador interactivo de los `715` registros con búsqueda en tiempo real y filtros por incidente, severidad, host y eventos ocultos bajo severidad `Informational`.
2. **Motor Híbrido de Análisis de Seguridad (Correlación Determinista + Microsoft Foundry GPT)**:
   - Detecta y correlaciona automáticamente las **6 categorías requeridas**:
     - **Fuerza bruta** (*Password Spraying* externo contra `DC-01` e intrusión RDP contra `APP-SRV01`)
     - **Inicios sospechosos** (Autenticaciones exitosas desde IPs públicas `203.0.113.74` y `198.51.100.77`)
     - **Escalamiento** (`Event_ID 4672`, creación de tarea programada `4698` e instalación de servicio `7045`)
     - **Comandos y procesos** (PowerShell `-EncodedCommand`, `vssadmin.exe delete shadows /all /quiet`, `7z.exe`, `tar.exe`, `wuhelper.exe` y webshell `cmd.exe /c whoami`)
     - **Movimiento lateral** (Pivote SMB `LogonType=3` desde `APP-SRV01` hacia `\\FS-SRV01\Finance`)
     - **Otras anomalías** (Exfiltración masiva de `253.36 MB` por Proxy HTTPS hacia `198.51.100.88:443`, exfiltración C2 hacia `203.0.113.88:443`, acceso secuencial a `FY2026\document_000..015.xlsx` y desviación de hostname `DC01` vs `DC-01`)
   - **Rigor Analítico Garantizado**: Ningún hallazgo es inventado; cada conclusión está sustentada estrictamente en los `Log_ID` del archivo proporcionado.
3. **Dashboard Interactivo**:
   - Indicadores clave (KPIs) y gráficos interactivos con Chart.js por criticidad, línea de tiempo cada 15 minutos, categorías de detección y sistemas afectados.
4. **Clasificación de Riesgos**:
   - Clasificación en **Crítico**, **Alto**, **Medio** o **Bajo** con justificación técnica estricta y mapeo MITRE ATT&CK.
5. **Dos Informes en Español + Descarga en PDF**:
   - **Informe Ejecutivo (`Informe_Ejecutivo_SOC_L2_ES.pdf`)**: Redactado en lenguaje claro y llano para la Alta Dirección, enfocado en impacto de negocio y toma de decisiones.
   - **Informe Técnico SOC Nivel 2 (`Informe_Tecnico_SOC_L2_ES.pdf`)**: Documento estructurado con las 8 secciones requeridas (Resumen ejecutivo, Hallazgos identificados, Explicación técnica de cada hallazgo, Evidencias encontradas en los logs, Criticidad y justificación, Posible impacto en la organización, Plan de acción: investigar, contener y remediar, y Recomendaciones generales de seguridad).

---

## Configuración de Microsoft Foundry (Azure AI Foundry / Azure OpenAI)

Puedes configurar tus credenciales de **Microsoft Foundry** copiando `.env.example` a `.env` o directamente desde el botón **"⚙️ Microsoft Foundry IA"** en la interfaz web:

```ini
AZURE_OPENAI_ENDPOINT="https://tu-recurso.openai.azure.com/"
AZURE_OPENAI_API_KEY="tu-api-key"
AZURE_OPENAI_DEPLOYMENT_NAME="gpt-4o-mini"
AZURE_OPENAI_API_VERSION="2024-10-21"
```

---

## Ejecución de la Aplicación

```bash
# 1. Activar el entorno virtual e iniciar el servidor FastAPI
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Luego abre en tu navegador: **`http://localhost:8000`**

## Ejecución de Pruebas Automatizadas

```bash
.venv/bin/pytest -v tests/test_siem_analyzer.py
```
