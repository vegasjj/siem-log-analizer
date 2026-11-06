/**
 * SIEM Log Analyzer — SOC Level 2 Frontend Controller
 * Starts in a clean empty state waiting for the user to upload an .xlsx file.
 * Once uploaded, uses AI (Microsoft Foundry GPT) to dynamically generate the
 * dashboard, correlated incidents, and dual Spanish PDF reports.
 */

let currentAnalysis = null;
let filteredLogs = [];
let currentLogPage = 1;
const LOGS_PER_PAGE = 50;

// Chart.js instances
let chartRisk = null;
let chartTimeline = null;
let chartCategories = null;
let chartHosts = null;

// Microsoft Foundry runtime config
const aiConfig = {
  endpoint: localStorage.getItem("foundry_endpoint") || "",
  api_key: localStorage.getItem("foundry_api_key") || "",
  deployment_name: localStorage.getItem("foundry_deployment") || "gpt-4o-mini",
  api_version: localStorage.getItem("foundry_api_version") || "2024-10-21",
  use_ai: localStorage.getItem("foundry_use_ai") !== "false",
};

document.addEventListener("DOMContentLoaded", () => {
  initNavigationTabs();
  initUploadHandlers();
  initIncidentFilters();
  initLogExplorerHandlers();
  initReportTabHandlers();
  initAiModalHandlers();
  checkBackendAiStatus();
});

async function checkBackendAiStatus() {
  try {
    const resp = await fetch("/api/ai-config/status");
    if (!resp.ok) return;
    const status = await resp.json();
    const dot = document.getElementById("aiStatusDot");
    const txt = document.getElementById("aiStatusText");
    if (status.configured || (aiConfig.endpoint && aiConfig.api_key)) {
      dot.className = "w-2 h-2 rounded-full bg-emerald-400 animate-pulse";
      txt.textContent = `Microsoft Foundry IA Listo (${aiConfig.deployment_name || status.deployment_name}) — Esperando archivo`;
    } else {
      dot.className = "w-2 h-2 rounded-full bg-amber-400";
      txt.textContent = "Esperando archivo .xlsx (Configura Microsoft Foundry IA)";
    }
  } catch (_) {
    // Ignore status check error on boot
  }
}

/* =========================================================================
 * NAVIGATION TABS
 * ========================================================================= */
function initNavigationTabs() {
  document.querySelectorAll(".nav-tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      switchMainTab(btn.getAttribute("data-tab"));
    });
  });
}

function switchMainTab(tabId) {
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.add("hidden");
  });
  const target = document.getElementById(tabId);
  if (target) target.classList.remove("hidden");

  document.querySelectorAll(".nav-tab-btn").forEach((btn) => {
    if (btn.getAttribute("data-tab") === tabId) {
      btn.className =
        "nav-tab-btn px-4 py-2 rounded-lg text-sm font-semibold bg-sky-600 text-white transition";
    } else {
      btn.className =
        "nav-tab-btn px-4 py-2 rounded-lg text-sm font-semibold bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition";
    }
  });
}

/* =========================================================================
 * UPLOAD HANDLERS (WAITS FOR USER UPLOAD)
 * ========================================================================= */
function initUploadHandlers() {
  const dropZone = document.getElementById("dropZone");
  const fileInput = document.getElementById("fileInput");
  const fileLabel = document.getElementById("selectedFileLabel");
  const btnUpload = document.getElementById("btnUploadAnalyze");

  dropZone.addEventListener("click", () => fileInput.click());

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dropzone-active");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("dropzone-active");
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dropzone-active");
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      fileLabel.textContent = `Archivo seleccionado: ${fileInput.files[0].name}`;
      uploadAndAnalyzeFile(fileInput.files[0]);
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files && fileInput.files.length > 0) {
      fileLabel.textContent = `Archivo seleccionado: ${fileInput.files[0].name}`;
    }
  });

  btnUpload.addEventListener("click", () => {
    if (!fileInput.files || fileInput.files.length === 0) {
      showError("Por favor seleccione primero un archivo Excel (.xlsx) para iniciar el análisis.");
      return;
    }
    uploadAndAnalyzeFile(fileInput.files[0]);
  });
}

async function uploadAndAnalyzeFile(file) {
  setLoading(true);
  hideError();
  try {
    const formData = new FormData();
    formData.append("file", file);
    if (aiConfig.endpoint) formData.append("endpoint", aiConfig.endpoint);
    if (aiConfig.api_key) formData.append("api_key", aiConfig.api_key);
    if (aiConfig.deployment_name) formData.append("deployment_name", aiConfig.deployment_name);
    if (aiConfig.api_version) formData.append("api_version", aiConfig.api_version);
    formData.append("use_ai", String(aiConfig.use_ai));

    const resp = await fetch("/api/analyze", {
      method: "POST",
      body: formData,
    });
    if (!resp.ok) {
      const errData = await resp.json().catch(() => ({}));
      throw new Error(errData.detail || `Error HTTP ${resp.status}`);
    }
    const data = await resp.json();
    renderFullAnalysis(data);
  } catch (err) {
    showError(err.message || "Error al procesar el archivo Excel.");
  } finally {
    setLoading(false);
  }
}

/* =========================================================================
 * MASTER RENDER PIPELINE (CALLED ONLY AFTER FILE UPLOAD)
 * ========================================================================= */
function renderFullAnalysis(data) {
  currentAnalysis = data;

  // Hide empty state and reveal the dynamic workspace
  document.getElementById("emptyStateBanner").classList.add("hidden");
  document.getElementById("analysisResultsWorkspace").classList.remove("hidden");

  // Update AI Status Badge
  const aiStatusDot = document.getElementById("aiStatusDot");
  const aiStatusText = document.getElementById("aiStatusText");
  aiStatusDot.className = "w-2 h-2 rounded-full bg-emerald-400 animate-pulse";
  aiStatusText.textContent = data.ai_mode_used;

  // Update Tab Counters
  document.getElementById("navIncidentCount").textContent = data.metrics.total_incidents;
  document.getElementById("navLogCount").textContent = data.metrics.total_logs;

  renderDashboardKPIs(data.metrics);
  renderDashboardCharts(data.metrics);
  renderDashboardIncidentTable(data.incidents);
  renderIncidentCards(data.incidents);
  populateLogFilters(data);
  applyLogFilters();
  renderExecutiveReportPreview(data);
  renderTechnicalReportPreview(data);
}

/* =========================================================================
 * DASHBOARD KPIs & CHARTS
 * ========================================================================= */
function renderDashboardKPIs(m) {
  document.getElementById("kpiTotalLogs").textContent = m.total_logs.toLocaleString("es-ES");
  const startStr = m.time_range_start ? m.time_range_start.slice(0, 16) : "";
  const endStr = m.time_range_end ? m.time_range_end.slice(11, 16) : "";
  document.getElementById("kpiTimeWindow").textContent = `${startStr} – ${endStr}`;

  document.getElementById("kpiTotalIncidents").textContent = m.total_incidents;
  document.getElementById("kpiIncidentBreakdown").textContent =
    `${m.critical_incidents_count} Críticos • ${m.high_incidents_count} Altos • ${m.medium_incidents_count} Medios`;

  document.getElementById("kpiSuspiciousLogs").textContent = m.suspicious_logs_count;
  document.getElementById("kpiHiddenInfo").textContent = m.hidden_informational_detected;
  document.getElementById("kpiAssetsAccounts").textContent =
    `${m.compromised_hosts_count} Hosts / ${m.compromised_accounts_count} Cuentas`;
  document.getElementById("kpiExternalIps").textContent =
    `${m.external_attacker_ips_count} IPs externas detectadas`;
  document.getElementById("kpiExfilMb").textContent = `${m.total_exfiltrated_mb} MB`;
  document.getElementById("kpiExfilBytes").textContent =
    `${m.total_exfiltrated_bytes.toLocaleString("es-ES")} bytes salientes`;
}

function renderDashboardCharts(m) {
  const ctxRisk = document.getElementById("chartRiskDistribution").getContext("2d");
  if (chartRisk) chartRisk.destroy();
  chartRisk = new Chart(ctxRisk, {
    type: "doughnut",
    data: {
      labels: ["Crítico", "Alto", "Medio", "Bajo"],
      datasets: [
        {
          data: [
            m.incidents_by_risk["Crítico"] || 0,
            m.incidents_by_risk["Alto"] || 0,
            m.incidents_by_risk["Medio"] || 0,
            m.incidents_by_risk["Bajo"] || 0,
          ],
          backgroundColor: ["#ef4444", "#f59e0b", "#0ea5e9", "#22c55e"],
          borderColor: "#0f172a",
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: { color: "#cbd5e1", font: { size: 11 } },
        },
      },
    },
  });

  const ctxTime = document.getElementById("chartTimeline").getContext("2d");
  if (chartTimeline) chartTimeline.destroy();
  const labelsTime = m.timeline_buckets.map((b) => b.time);
  const dataTotal = m.timeline_buckets.map((b) => b.total);
  const dataSusp = m.timeline_buckets.map((b) => b.suspicious);

  chartTimeline = new Chart(ctxTime, {
    type: "line",
    data: {
      labels: labelsTime,
      datasets: [
        {
          label: "Eventos Sospechosos Correlacionados",
          data: dataSusp,
          borderColor: "#ef4444",
          backgroundColor: "rgba(239, 68, 68, 0.25)",
          fill: true,
          tension: 0.3,
          pointRadius: 3,
        },
        {
          label: "Volumen Total de Logs SIEM",
          data: dataTotal,
          borderColor: "#38bdf8",
          backgroundColor: "rgba(56, 189, 248, 0.08)",
          fill: true,
          tension: 0.3,
          pointRadius: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { color: "#1e293b" } },
        y: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { color: "#1e293b" }, beginAtZero: true },
      },
      plugins: {
        legend: { labels: { color: "#cbd5e1", font: { size: 11 } } },
      },
    },
  });

  const ctxCat = document.getElementById("chartCategories").getContext("2d");
  if (chartCategories) chartCategories.destroy();
  const catLabels = Object.keys(m.events_by_category);
  const catValues = Object.values(m.events_by_category);

  chartCategories = new Chart(ctxCat, {
    type: "bar",
    data: {
      labels: catLabels,
      datasets: [
        {
          label: "Eventos Correlacionados",
          data: catValues,
          backgroundColor: [
            "#f43f5e",
            "#fb923c",
            "#a855f7",
            "#eab308",
            "#38bdf8",
            "#10b981",
          ],
          borderRadius: 6,
        },
      ],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" }, beginAtZero: true },
        y: { ticks: { color: "#e2e8f0", font: { size: 11, weight: "600" } }, grid: { display: false } },
      },
      plugins: {
        legend: { display: false },
      },
    },
  });

  const ctxHosts = document.getElementById("chartAffectedHosts").getContext("2d");
  if (chartHosts) chartHosts.destroy();
  const hostLabels = Object.keys(m.top_affected_hosts);
  const hostValues = Object.values(m.top_affected_hosts);

  chartHosts = new Chart(ctxHosts, {
    type: "bar",
    data: {
      labels: hostLabels,
      datasets: [
        {
          label: "Eventos Sospechosos en el Sistema",
          data: hostValues,
          backgroundColor: "#38bdf8",
          borderRadius: 6,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: "#e2e8f0" }, grid: { display: false } },
        y: { ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" }, beginAtZero: true },
      },
      plugins: {
        legend: { display: false },
      },
    },
  });
}

function renderDashboardIncidentTable(incidents) {
  const tbody = document.getElementById("dashboardIncidentTableBody");
  tbody.innerHTML = "";

  incidents.forEach((inc) => {
    const tr = document.createElement("tr");
    tr.className = "hover:bg-slate-800/50 transition";
    tr.innerHTML = `
      <td class="py-3 px-3 font-mono font-bold text-sky-400">${escapeHtml(inc.incident_id)}</td>
      <td class="py-3 px-3">
        <div class="font-semibold text-white">${escapeHtml(inc.title)}</div>
        <div class="text-xs text-slate-400 mt-0.5">${inc.categories.map((c) => `<span class="inline-block mr-1.5 text-sky-300">#${escapeHtml(c)}</span>`).join("")}</div>
      </td>
      <td class="py-3 px-3">${getRiskBadgeHtml(inc.risk_level)}</td>
      <td class="py-3 px-3 font-mono text-xs text-slate-300">${escapeHtml(inc.time_start)} – ${escapeHtml(inc.time_end)}</td>
      <td class="py-3 px-3 text-xs text-slate-300">
        <div><strong>Hosts:</strong> ${escapeHtml(inc.affected_hosts.join(", "))}</div>
        <div class="text-slate-400"><strong>Cuentas:</strong> ${escapeHtml(inc.compromised_users.slice(0, 3).join(", "))}</div>
      </td>
      <td class="py-3 px-3 font-mono text-xs">
        <span class="font-bold text-white">${inc.total_events}</span>
        ${inc.hidden_informational_count > 0 ? `<span class="ml-1 px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 text-[10px]">+${inc.hidden_informational_count} Info Ocultos</span>` : ""}
      </td>
      <td class="py-3 px-3 text-right">
        <button onclick="jumpToIncident('${inc.incident_id}')" class="px-2.5 py-1 rounded bg-sky-600/20 hover:bg-sky-600/40 text-sky-300 border border-sky-500/30 text-xs font-semibold">
          Inspeccionar
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function jumpToIncident(incidentId) {
  switchMainTab("tab-incidents");
  const el = document.getElementById(`card-${incidentId}`);
  if (el) {
    el.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

/* =========================================================================
 * TAB 2: INCIDENT CARDS & RISK CLASSIFICATION
 * ========================================================================= */
function initIncidentFilters() {
  document.getElementById("filterIncidentRisk").addEventListener("change", () => {
    if (currentAnalysis) {
      renderIncidentCards(currentAnalysis.incidents);
    }
  });
}

function renderIncidentCards(incidents) {
  const container = document.getElementById("incidentsContainer");
  const riskFilter = document.getElementById("filterIncidentRisk").value;
  container.innerHTML = "";

  const filtered = incidents.filter(
    (inc) => riskFilter === "ALL" || inc.risk_level === riskFilter
  );

  filtered.forEach((inc) => {
    const card = document.createElement("div");
    card.id = `card-${inc.incident_id}`;
    card.className =
      "bg-slate-900 border border-slate-800 rounded-2xl p-5 sm:p-6 space-y-4 shadow-lg";

    const evidenceRowsHtml = inc.evidence_logs
      .map(
        (ev) => `
        <tr class="border-b border-slate-800/60 ${ev.elevated_from_informational ? "log-row-elevated" : ""}">
          <td class="py-1.5 px-2 font-bold text-sky-300">${escapeHtml(ev.log_id)}</td>
          <td class="py-1.5 px-2 text-slate-300">${escapeHtml(ev.timestamp)}</td>
          <td class="py-1.5 px-2 text-white">${escapeHtml(ev.hostname)}</td>
          <td class="py-1.5 px-2 text-amber-300">${escapeHtml(ev.event_id)}</td>
          <td class="py-1.5 px-2 text-slate-200">${escapeHtml(ev.user)}</td>
          <td class="py-1.5 px-2 text-slate-300">${escapeHtml(ev.source_ip)} → ${escapeHtml(ev.destination || "-")}</td>
          <td class="py-1.5 px-2 text-slate-200">${escapeHtml(ev.event_description)} ${ev.process_command_line ? `<code class="text-rose-300 bg-rose-950/60 px-1 rounded">${escapeHtml(ev.process_command_line)}</code>` : ""}</td>
          <td class="py-1.5 px-2">
            ${escapeHtml(ev.severity)}
            ${ev.elevated_from_informational ? `<span class="ml-1 px-1 rounded bg-amber-500/30 text-amber-200 text-[10px]">OCULTO</span>` : ""}
          </td>
        </tr>`
      )
      .join("");

    card.innerHTML = `
      <div class="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800 pb-4">
        <div class="space-y-1">
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-mono text-sm font-bold px-2.5 py-0.5 rounded bg-slate-800 text-sky-400 border border-slate-700">${escapeHtml(inc.incident_id)}</span>
            ${getRiskBadgeHtml(inc.risk_level)}
            <span class="text-xs font-mono text-slate-400">🕒 ${escapeHtml(inc.time_start)} — ${escapeHtml(inc.time_end)}</span>
            <span class="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">${inc.total_events} eventos correlacionados</span>
            ${inc.hidden_informational_count > 0 ? `<span class="text-xs px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">⚠️ ${inc.hidden_informational_count} eventos 'Informational' descubiertos</span>` : ""}
          </div>
          <h3 class="text-base sm:text-lg font-bold text-white pt-1">${escapeHtml(inc.title)}</h3>
          <div class="flex flex-wrap gap-1.5 pt-1">
            ${inc.categories.map((cat) => `<span class="text-[11px] px-2 py-0.5 rounded-full bg-sky-500/15 text-sky-300 border border-sky-500/30 font-medium">${escapeHtml(cat)}</span>`).join("")}
            ${inc.mitre_tactics.map((t) => `<span class="text-[11px] px-2 py-0.5 rounded-full bg-purple-500/15 text-purple-300 border border-purple-500/30 font-mono">${escapeHtml(t)}</span>`).join("")}
          </div>
        </div>

        <button onclick="filterLogsByIncident('${inc.incident_id}')"
          class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-sky-300 border border-slate-700 text-xs font-semibold transition">
          🔍 Ver registros en Explorador
        </button>
      </div>

      <div class="rounded-xl bg-slate-950/90 border border-slate-800 p-4 space-y-1.5">
        <div class="text-xs font-bold uppercase tracking-wider text-amber-400">
          Clasificación de Riesgo (${escapeHtml(inc.risk_level)}) — Justificación Estricta
        </div>
        <p class="text-xs sm:text-sm text-slate-200 leading-relaxed">${escapeHtml(inc.justification)}</p>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div class="rounded-xl bg-slate-950/60 border border-slate-800/80 p-4 space-y-2">
          <div class="text-xs font-bold uppercase tracking-wider text-sky-400">Explicación Técnica Forense (SOC Nivel 2)</div>
          <p class="text-xs text-slate-300 whitespace-pre-line leading-relaxed">${escapeHtml(inc.technical_explanation)}</p>
        </div>

        <div class="rounded-xl bg-slate-950/60 border border-slate-800/80 p-4 space-y-3">
          <div>
            <div class="text-xs font-bold uppercase tracking-wider text-emerald-400">Resumen Ejecutivo (Lenguaje Claro e Impacto)</div>
            <p class="text-xs text-slate-300 mt-1 leading-relaxed">${escapeHtml(inc.summary_plain_language)}</p>
            <p class="text-xs text-amber-200/90 mt-1.5 font-medium">${escapeHtml(inc.business_impact)}</p>
          </div>
          <div>
            <div class="text-xs font-bold uppercase tracking-wider text-purple-400 mb-1">Indicadores de Compromiso (IoCs Extraídos)</div>
            <ul class="space-y-1 text-xs font-mono text-slate-300">
              ${inc.key_iocs.map((ioc) => `<li>• ${escapeHtml(ioc)}</li>`).join("")}
            </ul>
          </div>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div class="rounded-xl bg-sky-950/25 border border-sky-500/30 p-3.5">
          <div class="text-xs font-bold text-sky-300 uppercase mb-1.5">1. Investigar</div>
          <ul class="space-y-1 text-xs text-slate-300 list-disc list-inside">
            ${inc.action_plan.investigar.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}
          </ul>
        </div>
        <div class="rounded-xl bg-rose-950/25 border border-rose-500/30 p-3.5">
          <div class="text-xs font-bold text-rose-300 uppercase mb-1.5">2. Contener</div>
          <ul class="space-y-1 text-xs text-slate-300 list-disc list-inside">
            ${inc.action_plan.contener.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}
          </ul>
        </div>
        <div class="rounded-xl bg-emerald-950/25 border border-emerald-500/30 p-3.5">
          <div class="text-xs font-bold text-emerald-300 uppercase mb-1.5">3. Remediar</div>
          <ul class="space-y-1 text-xs text-slate-300 list-disc list-inside">
            ${inc.action_plan.remediar.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}
          </ul>
        </div>
      </div>

      <div class="space-y-2">
        <div class="flex items-center justify-between">
          <span class="text-xs font-bold uppercase tracking-wider text-slate-400">
            Evidencias Encontradas en los Logs (${inc.evidence_logs.length} de ${inc.total_events} registros mostrados)
          </span>
          <span class="text-[11px] font-mono text-slate-400">
            Log_IDs: ${escapeHtml(inc.evidence_log_ids.slice(0, 8).join(", "))}${inc.evidence_log_ids.length > 8 ? ` (+${inc.evidence_log_ids.length - 8} más)` : ""}
          </span>
        </div>
        <div class="overflow-x-auto border border-slate-800 rounded-lg">
          <table class="w-full text-left border-collapse font-mono text-[11px]">
            <thead>
              <tr class="bg-slate-950 text-slate-400 border-b border-slate-800">
                <th class="py-1.5 px-2">Log_ID</th>
                <th class="py-1.5 px-2">Timestamp</th>
                <th class="py-1.5 px-2">Host</th>
                <th class="py-1.5 px-2">Event</th>
                <th class="py-1.5 px-2">Usuario</th>
                <th class="py-1.5 px-2">Red</th>
                <th class="py-1.5 px-2">Descripción / Comando / URI</th>
                <th class="py-1.5 px-2">Severidad</th>
              </tr>
            </thead>
            <tbody>${evidenceRowsHtml}</tbody>
          </table>
        </div>
      </div>
    `;
    container.appendChild(card);
  });
}

/* =========================================================================
 * TAB 3: LOG EXPLORER & FILTERING
 * ========================================================================= */
function initLogExplorerHandlers() {
  ["logSearchInput", "logFilterMode", "logFilterIncident", "logFilterSeverity", "logFilterHost"].forEach(
    (id) => {
      const el = document.getElementById(id);
      el.addEventListener("input", () => {
        currentLogPage = 1;
        applyLogFilters();
      });
      el.addEventListener("change", () => {
        currentLogPage = 1;
        applyLogFilters();
      });
    }
  );

  document.getElementById("btnResetLogFilters").addEventListener("click", () => {
    document.getElementById("logSearchInput").value = "";
    document.getElementById("logFilterMode").value = "ALL";
    document.getElementById("logFilterIncident").value = "ALL";
    document.getElementById("logFilterSeverity").value = "ALL";
    document.getElementById("logFilterHost").value = "ALL";
    currentLogPage = 1;
    applyLogFilters();
  });

  document.getElementById("btnPrevPage").addEventListener("click", () => {
    if (currentLogPage > 1) {
      currentLogPage--;
      renderLogTablePage();
    }
  });

  document.getElementById("btnNextPage").addEventListener("click", () => {
    const maxPage = Math.max(1, Math.ceil(filteredLogs.length / LOGS_PER_PAGE));
    if (currentLogPage < maxPage) {
      currentLogPage++;
      renderLogTablePage();
    }
  });
}

function populateLogFilters(data) {
  const incSelect = document.getElementById("logFilterIncident");
  incSelect.innerHTML = `<option value="ALL">Todos los Incidentes</option>`;
  data.incidents.forEach((inc) => {
    const opt = document.createElement("option");
    opt.value = inc.incident_id;
    opt.textContent = `${inc.incident_id} — ${inc.title.slice(0, 48)}...`;
    incSelect.appendChild(opt);
  });

  const hostSelect = document.getElementById("logFilterHost");
  hostSelect.innerHTML = `<option value="ALL">Todos los Sistemas (Hostname)</option>`;
  const hosts = Array.from(new Set(data.logs.map((l) => l.hostname).filter(Boolean))).sort();
  hosts.forEach((h) => {
    const opt = document.createElement("option");
    opt.value = h;
    opt.textContent = h;
    hostSelect.appendChild(opt);
  });
}

function filterLogsByIncident(incidentId) {
  switchMainTab("tab-logs");
  document.getElementById("logFilterIncident").value = incidentId;
  document.getElementById("logFilterMode").value = "ALL";
  currentLogPage = 1;
  applyLogFilters();
}

function applyLogFilters() {
  if (!currentAnalysis) return;
  const q = document.getElementById("logSearchInput").value.trim().toLowerCase();
  const mode = document.getElementById("logFilterMode").value;
  const incId = document.getElementById("logFilterIncident").value;
  const sev = document.getElementById("logFilterSeverity").value;
  const host = document.getElementById("logFilterHost").value;

  filteredLogs = currentAnalysis.logs.filter((l) => {
    if (mode === "SUSPICIOUS" && !l.is_suspicious) return false;
    if (mode === "ELEVATED" && !l.elevated_from_informational) return false;
    if (incId !== "ALL" && l.correlated_incident_id !== incId) return false;
    if (sev !== "ALL" && l.severity !== sev) return false;
    if (host !== "ALL" && l.hostname !== host) return false;
    if (q) {
      const hay = `${l.log_id} ${l.timestamp} ${l.hostname} ${l.event_id} ${l.user} ${l.source_ip} ${l.destination} ${l.event_description} ${l.process_command_line} ${l.correlated_incident_id || ""}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  renderLogTablePage();
}

function renderLogTablePage() {
  const tbody = document.getElementById("logTableBody");
  tbody.innerHTML = "";

  const total = filteredLogs.length;
  const maxPage = Math.max(1, Math.ceil(total / LOGS_PER_PAGE));
  if (currentLogPage > maxPage) currentLogPage = maxPage;

  const startIdx = (currentLogPage - 1) * LOGS_PER_PAGE;
  const pageItems = filteredLogs.slice(startIdx, startIdx + LOGS_PER_PAGE);

  document.getElementById("logTableStatusText").textContent =
    `Mostrando ${total === 0 ? 0 : startIdx + 1}–${Math.min(startIdx + LOGS_PER_PAGE, total)} de ${total} registros filtrados`;
  document.getElementById("logPageIndicator").textContent = `Página ${currentLogPage} / ${maxPage}`;
  document.getElementById("btnPrevPage").disabled = currentLogPage <= 1;
  document.getElementById("btnNextPage").disabled = currentLogPage >= maxPage;

  pageItems.forEach((l) => {
    const tr = document.createElement("tr");
    if (l.elevated_from_informational) {
      tr.className = "log-row-elevated hover:bg-amber-950/40";
    } else if (l.is_suspicious) {
      tr.className = "log-row-suspicious hover:bg-rose-950/30";
    } else {
      tr.className = "hover:bg-slate-800/40";
    }

    tr.innerHTML = `
      <td class="py-2 px-2.5 font-bold ${l.is_suspicious ? "text-rose-300" : "text-slate-300"}">${escapeHtml(l.log_id)}</td>
      <td class="py-2 px-2.5 text-slate-400 whitespace-nowrap">${escapeHtml(l.timestamp)}</td>
      <td class="py-2 px-2.5 text-white font-semibold">${escapeHtml(l.hostname)}</td>
      <td class="py-2 px-2.5 text-sky-300">${escapeHtml(l.event_id)}</td>
      <td class="py-2 px-2.5 text-slate-200">${escapeHtml(l.user)}</td>
      <td class="py-2 px-2.5 text-slate-300 whitespace-nowrap">${escapeHtml(l.source_ip)} → ${escapeHtml(l.destination || "-")}</td>
      <td class="py-2 px-2.5 text-slate-200">
        <div>${escapeHtml(l.event_description)}</div>
        ${l.process_command_line ? `<div class="text-amber-300 break-all mt-0.5"><code>${escapeHtml(l.process_command_line)}</code></div>` : ""}
      </td>
      <td class="py-2 px-2.5 whitespace-nowrap">
        <span class="px-1.5 py-0.5 rounded text-[10px] ${getRawSeverityClass(l.severity)}">${escapeHtml(l.severity)}</span>
        ${l.elevated_from_informational ? `<span class="ml-1 px-1.5 py-0.5 rounded bg-amber-500/30 text-amber-200 text-[10px] font-bold">OCULTO</span>` : ""}
      </td>
      <td class="py-2 px-2.5">
        ${l.correlated_incident_id ? `<button onclick="jumpToIncident('${l.correlated_incident_id}')" class="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold hover:underline">${escapeHtml(l.correlated_incident_id)}</button>` : `<span class="text-slate-600">—</span>`}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

/* =========================================================================
 * TAB 4: DUAL SPANISH REPORTS PREVIEW & PDF EXPORT
 * ========================================================================= */
function initReportTabHandlers() {
  const btnExec = document.getElementById("btnViewExecReport");
  const btnTech = document.getElementById("btnViewTechReport");
  const viewExec = document.getElementById("previewExecutiveReport");
  const viewTech = document.getElementById("previewTechnicalReport");

  btnExec.addEventListener("click", () => {
    viewExec.classList.remove("hidden");
    viewTech.classList.add("hidden");
    btnExec.className = "px-3.5 py-1.5 rounded-md text-xs font-semibold bg-amber-600 text-white transition";
    btnTech.className = "px-3.5 py-1.5 rounded-md text-xs font-semibold text-slate-300 hover:text-white transition";
  });

  btnTech.addEventListener("click", () => {
    viewTech.classList.remove("hidden");
    viewExec.classList.add("hidden");
    btnTech.className = "px-3.5 py-1.5 rounded-md text-xs font-semibold bg-rose-600 text-white transition";
    btnExec.className = "px-3.5 py-1.5 rounded-md text-xs font-semibold text-slate-300 hover:text-white transition";
  });

  document.getElementById("btnDownloadExecPdfTop").addEventListener("click", () => downloadPdfReport("executive"));
  document.getElementById("btnDownloadTechPdfTop").addEventListener("click", () => downloadPdfReport("technical"));
  document.getElementById("btnDownloadExecPdfReportTab").addEventListener("click", () => downloadPdfReport("executive"));
  document.getElementById("btnDownloadTechPdfReportTab").addEventListener("click", () => downloadPdfReport("technical"));
}

async function downloadPdfReport(type) {
  if (!currentAnalysis) {
    showError("Primero debe subir y analizar un archivo Excel (.xlsx) antes de descargar el PDF.");
    return;
  }
  try {
    const url = type === "executive" ? "/api/reports/pdf/executive" : "/api/reports/pdf/technical";
    const filename =
      type === "executive"
        ? "Informe_Ejecutivo_SOC_L2_ES.pdf"
        : "Informe_Tecnico_SOC_L2_ES.pdf";

    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentAnalysis),
    });
    if (!resp.ok) {
      throw new Error(`No se pudo generar el PDF (${resp.status})`);
    }
    const blob = await resp.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
  } catch (err) {
    showError(err.message || "Error al descargar el informe PDF.");
  }
}

function renderExecutiveReportPreview(data) {
  const rep = data.executive_report;
  const container = document.getElementById("previewExecutiveReport");

  const incidentsHtml = rep.plain_language_incidents
    .map(
      (item) => `
      <div class="rounded-xl bg-slate-950/80 border border-slate-800 p-4 space-y-2">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <span class="font-bold text-white text-sm">[${escapeHtml(item.incident_id)}] ${escapeHtml(item.title)}</span>
          ${getRiskBadgeHtml(item.risk_level)}
        </div>
        <p class="text-xs text-slate-300"><strong>¿Qué sucedió?:</strong> ${escapeHtml(item.what_happened)}</p>
        <p class="text-xs text-amber-200/90"><strong>Impacto de Negocio:</strong> ${escapeHtml(item.business_risk)}</p>
        <p class="text-xs text-emerald-300"><strong>Decisión Inmediata:</strong> ${escapeHtml(item.recommended_decision)}</p>
      </div>`
    )
    .join("");

  container.innerHTML = `
    <div class="border-b border-slate-800 pb-4 flex flex-wrap items-center justify-between gap-4">
      <div>
        <span class="text-xs font-bold uppercase tracking-wider text-amber-400">${escapeHtml(rep.consultancy_location)}</span>
        <h3 class="text-xl sm:text-2xl font-bold text-white mt-1">${escapeHtml(rep.report_title)}</h3>
        <p class="text-xs sm:text-sm text-slate-400">${escapeHtml(rep.subtitle)}</p>
      </div>
      <div class="text-right">
        <div class="text-xs text-slate-400 mb-1">Riesgo Global</div>
        ${getRiskBadgeHtml(rep.global_risk_level)}
      </div>
    </div>

    <div class="rounded-xl bg-rose-950/30 border border-rose-500/40 p-4 text-sm font-semibold text-rose-200">
      ${escapeHtml(rep.incident_determination)}
    </div>

    <div class="space-y-2">
      <h4 class="text-sm font-bold uppercase tracking-wider text-sky-400">1. Resumen para la Alta Dirección (En Lenguaje Claro)</h4>
      <p class="text-sm text-slate-200 leading-relaxed whitespace-pre-line">${escapeHtml(rep.executive_overview)}</p>
    </div>

    <div class="space-y-2">
      <h4 class="text-sm font-bold uppercase tracking-wider text-sky-400">2. Impactos Clave en el Negocio</h4>
      <ul class="space-y-1.5 text-sm text-slate-300 list-disc list-inside">
        ${rep.key_business_impacts.map((b) => `<li>${escapeHtml(b)}</li>`).join("")}
      </ul>
    </div>

    <div class="space-y-3">
      <h4 class="text-sm font-bold uppercase tracking-wider text-sky-400">3. Incidentes Traducidos a Lenguaje Ejecutivo</h4>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">${incidentsHtml}</div>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
      <div class="rounded-xl bg-slate-950/70 border border-slate-800 p-4 space-y-2">
        <h4 class="text-sm font-bold uppercase tracking-wider text-amber-400">4. Decisiones Prioritarias Inmediatas</h4>
        <ul class="space-y-1.5 text-xs sm:text-sm text-slate-300 list-disc list-inside">
          ${rep.priority_decisions.map((d) => `<li>${escapeHtml(d)}</li>`).join("")}
        </ul>
      </div>
      <div class="rounded-xl bg-slate-950/70 border border-slate-800 p-4 space-y-2">
        <h4 class="text-sm font-bold uppercase tracking-wider text-emerald-400">5. Inversiones y Mejoras Estratégicas</h4>
        <ul class="space-y-1.5 text-xs sm:text-sm text-slate-300 list-disc list-inside">
          ${rep.investment_recommendations.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}
        </ul>
      </div>
    </div>
  `;
}

function renderTechnicalReportPreview(data) {
  const tech = data.technical_report;
  const container = document.getElementById("previewTechnicalReport");

  const findingsDetailHtml = data.incidents
    .map(
      (inc) => `
      <div class="rounded-xl bg-slate-950/90 border border-slate-800 p-5 space-y-3">
        <div class="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
          <h5 class="text-base font-bold text-white">[${escapeHtml(inc.incident_id)}] ${escapeHtml(inc.title)}</h5>
          ${getRiskBadgeHtml(inc.risk_level)}
        </div>
        <p class="text-xs text-amber-200"><strong>Criticidad y Justificación:</strong> ${escapeHtml(inc.justification)}</p>
        <p class="text-xs text-slate-300 whitespace-pre-line"><strong>Explicación Técnica:</strong>\n${escapeHtml(inc.technical_explanation)}</p>
        <p class="text-xs text-slate-300"><strong>Posible Impacto en la Organización:</strong> ${escapeHtml(inc.organizational_impact)}</p>
        <div class="text-xs font-mono text-sky-300 bg-slate-900 p-2.5 rounded border border-slate-800">
          <strong>Evidencias en los Logs (Log_IDs):</strong> ${escapeHtml(inc.evidence_log_ids.join(", "))}
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
          <div class="bg-slate-900 p-2.5 rounded border border-slate-800">
            <strong class="text-sky-400">Investigar:</strong>
            <ul class="list-disc list-inside text-slate-300 mt-1">${inc.action_plan.investigar.map((i) => `<li>${escapeHtml(i)}</li>`).join("")}</ul>
          </div>
          <div class="bg-slate-900 p-2.5 rounded border border-slate-800">
            <strong class="text-rose-400">Contener:</strong>
            <ul class="list-disc list-inside text-slate-300 mt-1">${inc.action_plan.contener.map((i) => `<li>${escapeHtml(i)}</li>`).join("")}</ul>
          </div>
          <div class="bg-slate-900 p-2.5 rounded border border-slate-800">
            <strong class="text-emerald-400">Remediar:</strong>
            <ul class="list-disc list-inside text-slate-300 mt-1">${inc.action_plan.remediar.map((i) => `<li>${escapeHtml(i)}</li>`).join("")}</ul>
          </div>
        </div>
      </div>`
    )
    .join("");

  container.innerHTML = `
    <div class="border-b border-slate-800 pb-4 flex flex-wrap items-center justify-between gap-4">
      <div>
        <span class="text-xs font-bold uppercase tracking-wider text-rose-400">${escapeHtml(tech.consultancy_location)}</span>
        <h3 class="text-xl sm:text-2xl font-bold text-white mt-1">${escapeHtml(tech.report_title)}</h3>
        <p class="text-xs sm:text-sm text-slate-400">${escapeHtml(tech.subtitle)}</p>
      </div>
      <div class="text-right">
        <div class="text-xs text-slate-400 mb-1">Criticidad Global</div>
        ${getRiskBadgeHtml(tech.global_risk_level)}
      </div>
    </div>

    <div class="space-y-2">
      <h4 class="text-sm font-bold uppercase tracking-wider text-sky-400">1. Resumen Ejecutivo</h4>
      <p class="text-sm text-slate-200 leading-relaxed">${escapeHtml(tech.resumen_ejecutivo)}</p>
      <p class="text-xs text-emerald-300 font-mono">${escapeHtml(tech.nota_rigor_analitico)}</p>
    </div>

    <div class="space-y-2">
      <h4 class="text-sm font-bold uppercase tracking-wider text-sky-400">2. Hallazgos Identificados</h4>
      <p class="text-sm text-slate-300 leading-relaxed">${escapeHtml(tech.hallazgos_resumen)}</p>
    </div>

    <div class="space-y-3">
      <h4 class="text-sm font-bold uppercase tracking-wider text-sky-400">
        3, 4, 5 y 7. Explicación Técnica, Evidencias en los Logs, Criticidad y Plan de Acción por Hallazgo
      </h4>
      <div class="space-y-4">${findingsDetailHtml}</div>
    </div>

    <div class="space-y-2">
      <h4 class="text-sm font-bold uppercase tracking-wider text-sky-400">6. Posible Impacto Global en la Organización</h4>
      <p class="text-sm text-slate-200 whitespace-pre-line leading-relaxed">${escapeHtml(tech.impacto_organizacion_global)}</p>
    </div>

    <div class="space-y-2">
      <h4 class="text-sm font-bold uppercase tracking-wider text-sky-400">8. Recomendaciones Generales de Seguridad</h4>
      <ul class="space-y-1.5 text-sm text-slate-300 list-disc list-inside">
        ${tech.recomendaciones_generales.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}
      </ul>
    </div>
  `;
}

/* =========================================================================
 * MICROSOFT FOUNDRY CONFIGURATION MODAL
 * ========================================================================= */
function initAiModalHandlers() {
  const modal = document.getElementById("aiConfigModal");
  const btnOpen = document.getElementById("btnOpenAiModal");
  const btnClose = document.getElementById("btnCloseAiModal");
  const btnTest = document.getElementById("btnTestAiConnection");
  const btnSave = document.getElementById("btnSaveAiConfig");

  document.getElementById("inputAiEndpoint").value = aiConfig.endpoint;
  document.getElementById("inputAiKey").value = aiConfig.api_key;
  document.getElementById("inputAiDeployment").value = aiConfig.deployment_name;
  document.getElementById("inputAiVersion").value = aiConfig.api_version;
  document.getElementById("inputUseAi").checked = aiConfig.use_ai;

  btnOpen.addEventListener("click", () => modal.classList.remove("hidden"));
  btnClose.addEventListener("click", () => modal.classList.add("hidden"));

  btnTest.addEventListener("click", async () => {
    readModalInputs();
    const box = document.getElementById("aiTestResultBox");
    box.classList.remove("hidden");
    box.className = "rounded-lg p-3 text-xs border bg-slate-950 border-slate-700 text-slate-300";
    box.textContent = "Probando conexión con Microsoft Foundry...";

    try {
      const resp = await fetch("/api/ai-config/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(aiConfig),
      });
      const res = await resp.json();
      if (res.ok) {
        box.className = "rounded-lg p-3 text-xs border bg-emerald-950/60 border-emerald-500/40 text-emerald-200";
      } else {
        box.className = "rounded-lg p-3 text-xs border bg-amber-950/60 border-amber-500/40 text-amber-200";
      }
      box.textContent = res.message;
    } catch (e) {
      box.className = "rounded-lg p-3 text-xs border bg-rose-950/60 border-rose-500/40 text-rose-200";
      box.textContent = `Error de red: ${e.message}`;
    }
  });

  btnSave.addEventListener("click", () => {
    readModalInputs();
    localStorage.setItem("foundry_endpoint", aiConfig.endpoint);
    localStorage.setItem("foundry_api_key", aiConfig.api_key);
    localStorage.setItem("foundry_deployment", aiConfig.deployment_name);
    localStorage.setItem("foundry_api_version", aiConfig.api_version);
    localStorage.setItem("foundry_use_ai", String(aiConfig.use_ai));
    modal.classList.add("hidden");
    checkBackendAiStatus();

    // Re-analyze if the user already uploaded a file
    const fileInput = document.getElementById("fileInput");
    if (fileInput.files && fileInput.files.length > 0) {
      uploadAndAnalyzeFile(fileInput.files[0]);
    }
  });
}

function readModalInputs() {
  aiConfig.endpoint = document.getElementById("inputAiEndpoint").value.trim();
  aiConfig.api_key = document.getElementById("inputAiKey").value.trim();
  aiConfig.deployment_name = document.getElementById("inputAiDeployment").value.trim() || "gpt-4o-mini";
  aiConfig.api_version = document.getElementById("inputAiVersion").value.trim() || "2024-10-21";
  aiConfig.use_ai = document.getElementById("inputUseAi").checked;
}

/* =========================================================================
 * UTILITIES
 * ========================================================================= */
function getRiskBadgeHtml(risk) {
  const map = {
    Crítico: "badge-critico",
    Alto: "badge-alto",
    Medio: "badge-medio",
    Bajo: "badge-bajo",
  };
  const cls = map[risk] || "badge-medio";
  return `<span class="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide ${cls}">${escapeHtml(risk)}</span>`;
}

function getRawSeverityClass(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "high") return "bg-rose-500/25 text-rose-300 border border-rose-500/40";
  if (s === "medium") return "bg-amber-500/25 text-amber-300 border border-amber-500/40";
  if (s === "warning") return "bg-yellow-500/20 text-yellow-300 border border-yellow-500/30";
  return "bg-slate-800 text-slate-400";
}

function setLoading(isLoading) {
  const el = document.getElementById("loadingBanner");
  if (isLoading) el.classList.remove("hidden");
  else el.classList.add("hidden");
}

function showError(msg) {
  const el = document.getElementById("errorBanner");
  document.getElementById("errorBannerText").textContent = msg;
  el.classList.remove("hidden");
}

function hideError() {
  document.getElementById("errorBanner").classList.add("hidden");
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
