/**
 * sniffer.js
 * Conecta ao WebSocket /ws/sniffer (autenticado via token na query
 * string, já que o WebSocket do navegador não envia headers), e
 * atualiza os contadores agregados + a lista de eventos ao vivo.
 */

let ws = null;
let counts = { total: 0, inseguro: 0, critico: 0, seguro: 0 };

const toggleBtn = document.getElementById("ng-sniffer-toggle");
const modeSelect = document.getElementById("ng-sniffer-mode");
const statusDot = document.getElementById("ng-status-dot");
const statusText = document.getElementById("ng-status-text");
const feedBody = document.getElementById("ng-sniffer-feed");
const emptyState = document.getElementById("ng-sniffer-empty");

const BADGE_BY_STATUS = {
  "CRÍTICO": "ng-badge-alto",
  "INSEGURO": "ng-badge-medio",
  "SEGURO": "ng-badge-baixo",
  "N/A": "ng-badge-medio",
};

function setLive(isLive) {
  statusDot.classList.toggle("live", isLive);
  statusText.textContent = isLive ? "monitorando..." : "parado";
  toggleBtn.textContent = isLive ? "Parar monitoramento" : "Iniciar monitoramento";
  modeSelect.disabled = isLive;
}

function formatTime(iso) {
  return new Date(iso).toLocaleTimeString("pt-BR");
}

function addAlertRow(event) {
  emptyState.style.display = "none";

  counts.total += 1;
  if (event.alert_type === "CRÍTICO") counts.critico += 1;
  else if (event.alert_type === "INSEGURO") counts.inseguro += 1;
  else if (event.alert_type === "SEGURO") counts.seguro += 1;

  document.getElementById("ng-count-total").textContent = counts.total;
  document.getElementById("ng-count-inseguro").textContent = counts.inseguro;
  document.getElementById("ng-count-critico").textContent = counts.critico;
  document.getElementById("ng-count-seguro").textContent = counts.seguro;

  const badgeClass = BADGE_BY_STATUS[event.alert_type] || "ng-badge-medio";
  const row = document.createElement("tr");
  row.className = "ng-live-row";
  row.innerHTML = `
    <td class="mono">${formatTime(event.timestamp)}</td>
    <td class="mono">${event.source_ip}</td>
    <td class="mono">${event.destination_ip}</td>
    <td>${event.protocol}</td>
    <td><span class="ng-badge ${badgeClass}">${event.alert_type}</span></td>
    <td>${event.vendor}</td>
  `;
  feedBody.prepend(row);

  // Mantém a lista com no máximo 100 linhas na tela, pra não pesar o navegador.
  while (feedBody.rows.length > 100) {
    feedBody.deleteRow(feedBody.rows.length - 1);
  }
}

function startSniffer() {
  const token = ngGetToken();
  const mode = modeSelect.value;
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${protocol}://${window.location.host}/ws/sniffer?token=${token}&mode=${mode}`);

  ws.onopen = () => setLive(true);
  ws.onclose = () => setLive(false);
  ws.onerror = () => setLive(false);
  ws.onmessage = (event) => addAlertRow(JSON.parse(event.data));
}

function stopSniffer() {
  if (ws) {
    ws.close();
    ws = null;
  }
  setLive(false);
}

toggleBtn.addEventListener("click", () => {
  if (ws) {
    stopSniffer();
  } else {
    startSniffer();
  }
});

window.addEventListener("beforeunload", () => {
  if (ws) ws.close();
});
