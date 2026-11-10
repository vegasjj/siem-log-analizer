# SIEM Log Analyzer — SOC Nivel 2 (Estocolmo, Suecia)

Aplicación web para el análisis dinámico de registros SIEM exportados en formato Excel (`.xlsx`), diseñada para el escenario de **Analista SOC Nivel 2** en una consultora de ciberseguridad en Estocolmo, Suecia.

La aplicación inicia en un estado limpio esperando la carga de un archivo `.xlsx`. Una vez subido el archivo, utiliza **IA integrada (Microsoft Foundry / Azure OpenAI GPT)** junto con extracción heurística agnóstica de señales para correlacionar incidentes, construir dinámicamente un dashboard interactivo y generar dos informes en español (**Ejecutivo** y **Técnico SOC Nivel 2**) exportables en un **único archivo PDF**.

---

## Características Principales

1. **Flujo Dinámico Basado en Carga de Archivos (`.xlsx`)**:
   - No pre-genera ni precarga ningún dato antes de que el usuario suba un archivo.
   - Importación mediante arrastrar y soltar (*Drag & Drop*) o selector de archivos para cualquier exportación SIEM que cumpla con las columnas estándar (`Log_ID`, `Timestamp`, `Hostname`, `Event_ID`, `User`, `Source_IP`, `Destination`, `Log_Source`, `Event_Description`, `Process_CommandLine`, `Result`, `Severity`).
   - Explorador interactivo de registros con búsqueda en tiempo real, paginación y filtros por incidente, severidad cruda, sistema (`Hostname`) y eventos ocultos bajo severidad `Informational`.

2. **Análisis de Seguridad y Correlación con IA (Microsoft Foundry GPT)**:
   - Detecta y correlaciona dinámicamente eventos en las **6 categorías requeridas**:
     - **Fuerza bruta**: Intentos fallidos repetidos de autenticación (`Event_ID 4625`, *Password Spraying*, fuerza bruta RDP/Web).
     - **Inicios sospechosos**: Sesiones anómalas por dirección IP pública/externa, protocolo (`LogonType=10`) o patrón posterior a fuerza bruta.
     - **Escalamiento**: Asignación de privilegios especiales (`Event_ID 4672`), creación de tareas programadas (`4698`) e instalación de servicios (`7045`).
     - **Comandos y procesos**: Ejecución sospechosa (`Event_ID 4688` / `4104`) como PowerShell codificado (`-EncodedCommand`), borrado de copias de sombra (`vssadmin`), utilidades de compresión (`7z.exe`, `tar.exe`), binarios persistentes en `C:\ProgramData` o shells invocadas por servidores web (`cmd.exe /c`).
     - **Movimiento lateral**: Saltos entre sistemas de la red y acceso a recursos compartidos (`LogonType=3`, `Event_ID 5140` / `5145`).
     - **Otras anomalías**: Exfiltración de datos saliente (`PROXY_ACCESS` HTTPS POST, conexiones salientes a IPs externas) y anomalías de configuración/telemetría.
   - **Rigor Analítico**: Cada hallazgo y conclusión se sustenta estrictamente en los `Log_ID` reales presentes en el archivo Excel subido, sin inventar eventos.

3. **Dashboard Dinámico e Interactivo (Chart.js)**:
   - Tarjetas KPI calculadas dinámicamente (Total de logs, Incidentes correlacionados, Eventos sospechosos, Eventos `Informational` ocultos descubiertos, Activos/Cuentas afectadas y Volumen exfiltrado).
   - Gráficos interactivos de distribución por criticidad (`Crítico`, `Alto`, `Medio`, `Bajo`), línea de tiempo en intervalos de 15 minutos, detecciones por las 6 categorías requeridas y sistemas más afectados.

4. **Vista Previa Separada de Informes y Exportación en un Único PDF en Español**:
   - **Previsualización en Pantalla**: Pestañas independientes para alternar entre el **Informe Ejecutivo** (lenguaje claro y llano para la Alta Dirección) y el **Informe Técnico SOC Nivel 2** (con las 8 secciones técnicas requeridas: *Resumen ejecutivo, Hallazgos identificados, Explicación técnica de cada hallazgo, Evidencias encontradas en los logs, Criticidad y justificación, Posible impacto en la organización, Plan de acción: investigar, contener y remediar, y Recomendaciones generales de seguridad*).
   - **Descarga en PDF Único (`Informe_SIEM_Ejecutivo_y_Tecnico_SOC_L2_ES.pdf`)**: Exporta ambos informes en un solo documento PDF en español con **Parte I: Informe Ejecutivo** primero y **Parte II: Informe Técnico Forense SOC Nivel 2** segundo.

---

## Estructura del Proyecto

```text
proyecto_final_soc2/
├── app/
│   ├── __init__.py
│   ├── main.py            # Servidor FastAPI y endpoints REST (/api/analyze, /api/reports/pdf)
│   ├── models.py          # Esquemas Pydantic (LogEntry, IncidentFinding, Reportes y Métricas)
│   ├── excel_parser.py    # Lector y validador de archivos Excel (.xlsx)
│   ├── analyzer.py        # Extractor heurístico agnóstico de señales y calculador de métricas
│   ├── ai_service.py      # Integración con Microsoft Foundry (Azure OpenAI GPT) y parser JSON
│   ├── pdf_generator.py   # Generador del PDF unificado en español (Parte I Ejecutivo + Parte II Técnico)
│   └── static/
│       ├── index.html     # Interfaz web SPA (Tailwind CSS + Chart.js)
│       ├── app.js         # Lógica de cliente, gráficos dinámicos, filtros y descarga PDF
│       └── styles.css     # Estilos del tema oscuro SOC Nivel 2
├── tests/
│   └── test_siem_analyzer.py  # Suite de pruebas automatizadas (pytest)
├── .env.example           # Plantilla de variables de entorno para Microsoft Foundry
├── pytest.ini             # Configuración de pytest
├── requirements.txt       # Dependencias de Python
└── README.md
```

---

## Configuración de Microsoft Foundry (Azure AI Foundry / Azure OpenAI)

1. Copia el archivo de ejemplo `.env.example` a `.env`:
   ```bash
   cp .env.example .env
   ```
2. Configura tus credenciales en `.env` (o ingrésalas directamente desde el botón **"⚙️ Configurar Microsoft Foundry IA"** en la barra superior de la aplicación web):
   ```ini
   AZURE_OPENAI_ENDPOINT="https://tu-recurso.openai.azure.com/"
   AZURE_OPENAI_API_KEY="tu-api-key"
   AZURE_OPENAI_DEPLOYMENT_NAME="gpt-4o-mini"
   AZURE_OPENAI_API_VERSION="2024-10-21"
   ```

---

## Instalación y Ejecución

```bash
# 1. Activar el entorno virtual
source .venv/bin/activate

# 2. Instalar dependencias (si aún no están instaladas)
pip install -r requirements.txt

# 3. Iniciar el servidor web FastAPI
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Abre en tu navegador: **`http://localhost:8000`**

---

## Ejecución de Pruebas Automatizadas

```bash
.venv/bin/pytest -v
```
