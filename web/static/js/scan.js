/**
 * scan.js
 * Controla o formulário de varredura: dispara POST /scan, mostra a
 * animação de radar enquanto a requisição está em andamento (o scan
 * real demora alguns segundos, então a animação reflete um estado
 * real de espera, não é só decoração), e renderiza o resultado
 * agrupado por porta com severidade e MITRE.
 */

const SEVERITY_CLASS = {
  "Alto": "ng-badge-alto",
  "Médio": "ng-badge-medio",
  "Baixo": "ng-badge-baixo",
};

const form = document.getElementById("ng-scan-form");
const scanBtn = document.getElementById("ng-scan-btn");
const radarBox = document.getElementById("ng-radar-box");
const radarStatus = document.getElementById("ng-radar-status");
const emptyState = document.getElementById("ng-empty-state");
const errorBox = document.getElementById("ng-scan-error");
const resultsBox = document.getElementById("ng-results");

const statusMessages = [
  "enviando pacotes ARP...",
  "descobrindo dispositivos ativos...",
  "varrendo portas conhecidas...",
  "cruzando com MITRE ATT&CK...",
];
let statusInterval = null;

function startRadarStatusLoop() {
  let i = 0;
  radarStatus.textContent = statusMessages[0];
  statusInterval = setInterval(() => {
    i = (i + 1) % statusMessages.length;
    radarStatus.textContent = statusMessages[i];
  }, 1400);
}

function stopRadarStatusLoop() {
  clearInterval(statusInterval);
}

function renderResults(data) {
  document.getElementById("ng-metric-score").textContent = `${data.score_de_risco}/100`;
  document.getElementById("ng-metric-devices").textContent = data.dispositivos_encontrados;
  document.getElementById("ng-metric-ports").textContent = data.portas_agrupadas.length;

  const mitreByPort = {};
  (data.correlacao_mitre || []).forEach((m) => { mitreByPort[m.porta] = m; });

  const tbody = document.getElementById("ng-ports-tbody");
  tbody.innerHTML = "";

  data.portas_agrupadas.forEach((p) => {
    const mitre = mitreByPort[p.porta];
    const badgeClass = SEVERITY_CLASS[p.severidade] || "ng-badge-medio";

    const mitreHtml = mitre
      ? `<div class="ng-mitre-box">
           <b>${mitre.mitre_tactica}</b> · ${mitre.mitre_tecnica}<br>
           ${mitre.impacto_seguranca}
         </div>`
      : "";

    const row = document.createElement("tr");
    row.innerHTML = `
      <td class="mono">${p.porta}</td>
      <td>
        ${p.servico}
        ${mitreHtml}
      </td>
      <td><span class="ng-badge ${badgeClass}">${p.severidade}</span></td>
      <td class="mono">${p.dispositivos_afetados.join(", ")}</td>
    `;
    tbody.appendChild(row);
  });

  resultsBox.style.display = "block";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const targetRange = document.getElementById("target_range").value.trim();
  errorBox.style.display = "none";
  emptyState.style.display = "none";
  resultsBox.style.display = "none";
  radarBox.classList.add("active");
  scanBtn.disabled = true;
  startRadarStatusLoop();

  try {
    const response = await ngFetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_range: targetRange }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail ? JSON.stringify(err.detail) : "Falha ao executar a varredura.");
    }

    const data = await response.json();
    renderResults(data);
  } catch (err) {
    errorBox.textContent = err.message || "Erro ao executar a varredura.";
    errorBox.style.display = "block";
    emptyState.style.display = "block";
  } finally {
    stopRadarStatusLoop();
    radarBox.classList.remove("active");
    scanBtn.disabled = false;
  }
});
