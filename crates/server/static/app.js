const TOKEN_KEY = "watchtower_token";
const KINDS = ["Reboot", "ServiceFailed", "ServiceCrashLoop", "DiskHigh", "InodeHigh",
               "CpuSpike", "MemHigh", "LoadHigh", "SwapHigh", "NetDevErrors", "HostUnreachable"];
let token = localStorage.getItem(TOKEN_KEY) || "";

function requireToken() {
  if (token) return true;
  token = prompt("Watchtower API token:", "") || "";
  if (token) localStorage.setItem(TOKEN_KEY, token);
  return !!token;
}

function fmt(ms) {
  return new Date(ms).toISOString().replace("T", " ").slice(0, 19);
}

async function loadEvents() {
  if (!requireToken()) return;
  const kind = document.getElementById("f-kind").value;
  const sev = document.getElementById("f-sev").value;
  const params = new URLSearchParams({ limit: "200" });
  if (kind) params.set("kind", kind);
  if (sev) params.set("severity", sev);
  const resp = await fetch("/v1/events?" + params, {
    headers: { authorization: "Bearer " + token },
  });
  if (resp.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    token = "";
    requireToken();
    return;
  }
  if (!resp.ok) throw new Error("HTTP " + resp.status);
  return (await resp.json()).events || [];
}

function render(events) {
  const box = document.getElementById("events");
  document.getElementById("empty").style.display = events.length ? "none" : "block";
  box.innerHTML = "";
  for (const ev of events) {
    const el = document.createElement("div");
    el.className = "ev " + (ev.severity || "info").toLowerCase();
    const evs = (ev.evidence || []).map(e =>
      `<div>${fmt(e.ts)} — [${escapeHtml(e.source)}] ${escapeHtml(e.detail)}</div>`).join("");
    el.innerHTML =
      `<div class="top">
         <span class="badge ${(ev.severity || "info").toLowerCase()}">${ev.severity || "?"}</span>
         <span class="time">${fmt(ev.ts)}</span>
         <span class="summary">${escapeHtml(ev.summary)}</span>
         <span class="host">${escapeHtml(ev.host_id)}</span>
       </div>
       <div class="evidence">${evs}</div>`;
    el.addEventListener("click", () => el.classList.toggle("open"));
    box.appendChild(el);
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function init() {
  const fKind = document.getElementById("f-kind");
  for (const k of KINDS) {
    const o = document.createElement("option");
    o.value = k; o.textContent = k;
    fKind.appendChild(o);
  }
  fKind.addEventListener("change", refresh);
  document.getElementById("f-sev").addEventListener("change", refresh);
  refresh();
  setInterval(refresh, 5000);
  const status = document.getElementById("status");
  status.textContent = "updating every 5s";
}

async function refresh() {
  const status = document.getElementById("status");
  try {
    const events = await loadEvents();
    render(events);
    status.textContent = "updated " + fmt(Date.now());
  } catch (e) {
    const err = document.getElementById("err");
    err.style.display = "block";
    err.textContent = "load failed: " + e.message;
  }
}

init();
