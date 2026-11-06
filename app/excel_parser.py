"""Excel (.xlsx) ingestion and normalization module for SIEM exports."""

from io import BytesIO
from pathlib import Path
import re
from typing import List, Tuple
import xml.etree.ElementTree as ET
import zipfile

from app.models import LogEntry

EXPECTED_COLUMNS = [
    "Log_ID",
    "Timestamp",
    "Hostname",
    "Event_ID",
    "User",
    "Source_IP",
    "Destination",
    "Log_Source",
    "Event_Description",
    "Process_CommandLine",
    "Result",
    "Severity",
]


def parse_siem_excel_bytes(file_bytes: bytes, filename: str = "upload.xlsx") -> List[LogEntry]:
    """
    Parse an uploaded .xlsx SIEM log file into normalized LogEntry objects.
    Uses openpyxl when available and includes a fast, zero-dependency XML/zip fallback.
    """
    rows: List[List[str]] = []
    try:
        import openpyxl  # type: ignore

        wb = openpyxl.load_workbook(BytesIO(file_bytes), read_only=True, data_only=True)
        sheet_name = "SIEM Export" if "SIEM Export" in wb.sheetnames else wb.sheetnames[0]
        ws = wb[sheet_name]
        for row in ws.iter_rows(values_only=True):
            rows.append(["" if cell is None else str(cell).strip() for cell in row])
        wb.close()
    except Exception:
        rows = _parse_xlsx_via_xml(file_bytes)

    if not rows or len(rows) < 2:
        raise ValueError(f"El archivo Excel '{filename}' no contiene registros de eventos válidos.")

    headers = [h.strip() for h in rows[0]]
    col_index = _map_column_indices(headers)

    entries: List[LogEntry] = []
    for idx, raw_row in enumerate(rows[1:], start=1):
        if not any(raw_row):
            continue

        def get_col(name: str) -> str:
            c_idx = col_index.get(name)
            if c_idx is None or c_idx >= len(raw_row):
                return ""
            val = raw_row[c_idx]
            return "" if val is None else str(val).strip()

        log_id = get_col("Log_ID") or f"EVT-{idx:05d}"
        entries.append(
            LogEntry(
                row_number=idx,
                log_id=log_id,
                timestamp=get_col("Timestamp"),
                hostname=get_col("Hostname"),
                event_id=get_col("Event_ID"),
                user=get_col("User"),
                source_ip=get_col("Source_IP"),
                destination=get_col("Destination"),
                log_source=get_col("Log_Source"),
                event_description=get_col("Event_Description"),
                process_command_line=get_col("Process_CommandLine"),
                result=get_col("Result"),
                severity=get_col("Severity") or "Informational",
            )
        )

    if not entries:
        raise ValueError(f"No se encontraron filas de logs en el archivo '{filename}'.")

    return entries


def _map_column_indices(headers: List[str]) -> dict:
    """Map canonical SIEM column names to their 0-based column index."""
    normalized_map = {h.lower().replace(" ", "_"): i for i, h in enumerate(headers)}
    col_index = {}
    for expected in EXPECTED_COLUMNS:
        key = expected.lower()
        if key in normalized_map:
            col_index[expected] = normalized_map[key]
        else:
            raise ValueError(
                f"Columna requerida '{expected}' no encontrada en el archivo Excel. "
                f"Columnas detectadas: {', '.join(headers)}"
            )
    return col_index


def _col_letters_to_index(col_letters: str) -> int:
    """Convert Excel column letters (A, B, ..., L) to 0-based index."""
    result = 0
    for ch in col_letters:
        result = result * 26 + (ord(ch.upper()) - ord("A") + 1)
    return result - 1


def _parse_xlsx_via_xml(file_bytes: bytes) -> List[List[str]]:
    """Fallback parser using standard library zipfile + xml.etree.ElementTree."""
    with zipfile.ZipFile(BytesIO(file_bytes)) as z:
        ns = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        shared_strings: List[str] = []
        if "xl/sharedStrings.xml" in z.namelist():
            ss_root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            shared_strings = ["".join(si.itertext()) for si in ss_root.findall("s:si", ns)]

        sheet_xml = z.read("xl/worksheets/sheet1.xml")
        sheet_root = ET.fromstring(sheet_xml)
        parsed_rows: List[List[str]] = []
        for row_elem in sheet_root.findall(".//s:row", ns):
            cells_dict = {}
            max_idx = 0
            for c_elem in row_elem.findall("s:c", ns):
                ref = c_elem.attrib.get("r", "A1")
                col_letters = re.sub(r"[0-9]", "", ref)
                c_idx = _col_letters_to_index(col_letters)
                max_idx = max(max_idx, c_idx)
                c_type = c_elem.attrib.get("t")
                v_elem = c_elem.find("s:v", ns)
                val = v_elem.text if v_elem is not None and v_elem.text is not None else ""
                if c_type == "s" and val != "":
                    val = shared_strings[int(val)]
                cells_dict[c_idx] = val.strip()
            row_list = [cells_dict.get(i, "") for i in range(max(max_idx + 1, 12))]
            parsed_rows.append(row_list)
        return parsed_rows


def get_sample_excel_path() -> Tuple[Path, str]:
    """Locate the bundled sample SIEM Excel file."""
    base_dir = Path(__file__).resolve().parent.parent
    candidates = [
        base_dir / "plans" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx",
        base_dir / "app" / "sample_data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx",
    ]
    for path in candidates:
        if path.exists():
            return path, path.name
    raise FileNotFoundError(
        "No se encontró el archivo de muestra SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
    )
