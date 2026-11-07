"use strict";
// Demo visual del SOC de Tarvia. Sin framework ni build: abre / con server.py.

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
const SEV_ES = { critical: "crítica", high: "alta", medium: "media", low: "baja", informational: "info" };
const VERDICT_ES = { true_positive: "Incidente real", benign_true_positive: "Autorizado", false_positive: "Falso positivo", needs_more_info: "Falta info" };
const SLA_MIN = { critical: 15, high: 30, medium: 240, low: 1440 };
const TZ = "Europe/Madrid";
// Frases típicas de texto escrito para manipular a una IA; se resaltan dentro del extracto.
const INJ_RE = /(sistema autom\w*|clasificador|clasificar como|false_positive|no escalar|no requiere revisión|no bloquear|olvida todas tus instrucciones|prompt de sistema|aprobado por el equipo SOC|actividad autorizada|display:\s*none|nota para el (analista|sistema)[^.:]*)/gi;

let TICKETS = [];
let filter = "all";
let selected = null;
const executed = {}; // ticket_id -> {idx: resultado}

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtLocal = (iso, opts) => new Date(iso).toLocaleString("es-ES", { timeZone: TZ, ...opts });
const fmtDT = (iso) => fmtLocal(iso, { weekday: "short", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
const localHour = (iso) => Number(fmtLocal(iso, { hour: "2-digit", hour12: false }));
const localDow = (iso) => new Date(new Date(iso).toLocaleString("en-US", { timeZone: TZ })).getDay();
const isOffHours = (iso) => { const d = localDow(iso), h = localHour(iso); return d === 0 || d === 6 || h < 8 || h >= 20; };

function pill(cls, txt) { return `<span class="pill ${cls}">${esc(txt)}</span>`; }

// ---------------------------------------------------------------- carga
async function load() {
  try {
    const r = await fetch("api/tickets");
    const d = await r.json();
    TICKETS = d.tickets;
    $("#source").textContent = `datos: ${d.source}`;
  } catch (e) {
    $("#source").textContent = "sin conexión con el servidor";
    TICKETS = [];
  }
  TICKETS.sort((a, b) =>
    (a.status === "closed") - (b.status === "closed") ||
    (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9) ||
    String(a.night_shift?.first_alert_at).localeCompare(String(b.night_shift?.first_alert_at)));
  renderKpis();
  renderList();
  const hash = location.hash.slice(1);
  select(TICKETS.find((t) => t.ticket_id === hash) ? hash : (TICKETS[0] || {}).ticket_id);
  renderNight();
}

// ---------------------------------------------------------------- KPIs
function renderKpis() {
  const alerts = TICKETS.reduce((n, t) => n + t.alert_ids.length, 0);
  const tp = TICKETS.filter((t) => t.verdict === "true_positive");
  const crit = tp.filter((t) => t.severity === "critical").length;
  const closed = TICKETS.filter((t) => t.status === "closed").length;
  const inj = TICKETS.filter((t) => t.prompt_injection.length).length;
  const gained = tp.reduce((n, t) => n + (t.night_shift?.gained_hours || 0), 0);
  $("#kpis").innerHTML = [
    ["alertas triadas", alerts],
    ["tickets (agrupadas)", TICKETS.length],
    ["incidentes reales", tp.length, ""],
    ["críticos", crit, "alert"],
    ["cerrados con motivo", closed],
    ["intentos de manipular a la IA", inj, inj ? "alert" : ""],
    ["horas ganadas de noche", gained.toFixed(0)],
  ].map(([l, v, c]) => `<div class="kpi ${c || ""}"><b>${v}</b><span>${l}</span></div>`).join("");
}

// ---------------------------------------------------------------- cola
function visible() {
  return TICKETS.filter((t) =>
    filter === "all" ? true :
    filter === "escalate" ? t.escalation?.escalate :
    filter === "closed" ? t.status === "closed" :
    filter === "injection" ? t.prompt_injection.length : true);
}

function renderList() {
  $("#ticket-list").innerHTML = visible().map((t) => {
    const first = t.night_shift?.first_alert_at;
    return `<li data-id="${esc(t.ticket_id)}" class="${t.ticket_id === selected ? "sel" : ""} ${t.status === "closed" ? "closed" : ""}">
      <div>${pill("sev-" + t.severity, SEV_ES[t.severity] || t.severity)} ${pill("v-" + t.verdict, VERDICT_ES[t.verdict] || t.verdict)}
      ${t.prompt_injection.length ? pill("inj", "⚠ inyección") : ""}</div>
      <div class="t-title">${esc(t.title)}</div>
      <div class="t-meta"><span>${esc(t.ticket_id)}</span><span>${t.alert_ids.length} alerta${t.alert_ids.length > 1 ? "s" : ""}</span>
      ${first ? `<span>${fmtDT(first)}</span>` : ""}${first && isOffHours(first) ? "<span>🌙 fuera de horario</span>" : ""}</div>
    </li>`;
  }).join("") || `<li class="muted">Nada con este filtro.</li>`;
}

function select(id) {
  selected = id;
  if (id) history.replaceState(null, "", "#" + id);
  document.querySelectorAll("#ticket-list li").forEach((li) => li.classList.toggle("sel", li.dataset.id === id));
  renderDetail(TICKETS.find((t) => t.ticket_id === id));
}

// ---------------------------------------------------------------- detalle
function highlightInjection(text) {
  return esc(text).replace(INJ_RE, (m) => `<mark>${m}</mark>`);
}

function timelineHtml(alerts) {
  if (!alerts.length) return "";
  let lastDay = "";
  return `<div class="timeline">` + alerts.map((a) => {
    const day = fmtLocal(a.created_at, { weekday: "long", day: "numeric", month: "long" });
    const head = day !== lastDay ? `<div class="tl-day">${esc(day)}</div>` : "";
    lastDay = day;
    return `${head}<div class="tl-item sev-${esc(a.severity)}"><span class="tl-time">${fmtLocal(a.created_at, { hour: "2-digit", minute: "2-digit" })}</span>
      <span class="tl-rule">${esc(a.rule_name)}</span>${isOffHours(a.created_at) ? `<span class="tl-night">🌙 sin SOC</span>` : ""}
      <span class="muted mono">${esc(a.alert_id.slice(-6))}</span></div>`;
  }).join("") + `</div>`;
}

function actionsHtml(t) {
  const done = executed[t.ticket_id] || {};
  const pre = t.executed_actions || [];
  return `<ul>` + t.recommended_actions.map((a, i) => {
    const res = done[i];
    const btn = res ? `<span class="done">✓ ${esc(res)}</span>` :
      a.action === "close" ? "" :
      a.requires_approval ? `<button class="btn-approve" data-i="${i}">Aprobar</button>` :
      `<button class="btn-exec" data-i="${i}">Ejecutar</button>`;
    return `<li><div class="a-txt"><b class="mono">${esc(a.action)}</b> → ${esc(a.target)}
      <small>${esc(a.justification || "")}${a.requires_approval ? " · requiere aprobación humana" : " · el N1 puede ejecutarla"}</small></div>${btn}</li>`;
  }).join("") + pre.map((x) => `<li class="muted small">Ejecutada: ${esc(JSON.stringify(x))}</li>`).join("") + `</ul>`;
}

function slaHtml(t) {
  const m = SLA_MIN[t.severity];
  if (!m) return "";
  const txt = m >= 60 ? `${m / 60} h` : `${m} min`;
  return `<span class="muted small">SLA ${txt} · triado en ${Math.round(t.triage_seconds || 0)} s</span>`;
}

function renderDetail(t) {
  const el = $("#detail");
  if (!t) { el.innerHTML = `<div class="empty">Elige un ticket de la cola.</div>`; return; }
  const aff = t.affected || {};
  const affRows = [["Usuarios", aff.users], ["Equipos", aff.hosts], ["Servicios", aff.business_services], ["Clientes", aff.customers]]
    .filter(([, v]) => v && v.length).map(([k, v]) => `<tr><th>${k}</th><td>${v.map(esc).join(", ")}</td></tr>`).join("");
  const conf = t.confidence == null ? "" : `<span class="conf">confianza <span class="bar"><i style="width:${Math.round(t.confidence * 100)}%"></i></span>${Math.round(t.confidence * 100)}%</span>`;
  const ns = t.night_shift;

  el.innerHTML = `
    <div class="d-head">${pill("sev-" + t.severity, "Severidad " + (SEV_ES[t.severity] || t.severity))}
      ${pill("v-" + t.verdict, VERDICT_ES[t.verdict] || t.verdict)} ${conf} ${slaHtml(t)}</div>
    <div class="d-title">${esc(t.title)}</div>
    <div class="d-sub">${esc(t.ticket_id)} · ${t.alert_ids.length} alertas agrupadas${t.escalation?.escalate ? ` · <b>Escalar a ${esc(t.escalation.to || "N2")}</b>: ${esc(t.escalation.reason || "")}` : ""}</div>

    ${t.prompt_injection.length ? `<div class="injection"><h3>⚠ Intento de manipular a la IA encontrado en los datos</h3>
      <p>Este texto lo escribió el atacante dentro de la evidencia. El sistema lo trata como dato sospechoso, no como instrucción, y lo usa como indicio más.</p>
      ${t.prompt_injection.map((p) => `<blockquote>${highlightInjection(p.excerpt)}</blockquote>
        <div class="small muted">Fuente: ${esc(p.source)} · ${esc(p.event_id)} · ${esc(p.handling || "Ignorado")}</div>`).join("")}</div>` : ""}

    <div class="card"><h3>Qué ha pasado</h3><p>${esc(t.summary)}</p></div>

    ${ns && ns.gained_hours > 0 ? (() => { const w = ns.worst_alert && ns.worst_alert.wait_hours >= ns.first_wait_hours ? ns.worst_alert : { at: ns.first_alert_at, human_at: ns.human_at, alert_id: t.alert_ids[0] };
      const al = t.alerts.find((x) => x.alert_id === w.alert_id);
      return `<div class="card"><h3>🌙 Turno de noche</h3><p>${al ? `«${esc(al.rule_name)}»` : "La alerta"} saltó el <b>${fmtDT(w.at)}</b>, con el SOC cerrado. La IA tenía el ticket en segundos; el SOC humano no lo habría visto hasta el <b>${fmtDT(w.human_at)}</b>: <b>${ns.gained_hours} h</b> antes.</p></div>`; })() : ""}

    <div class="grid2">
      <div class="card"><h3>Línea temporal</h3>${timelineHtml(t.alerts)}</div>
      <div>
        <div class="card"><h3>Severidad</h3><p>${esc(t.severity_rationale || "—")}</p></div>
        ${affRows ? `<div class="card"><h3>Afectados</h3><table>${affRows}</table></div>` : ""}
        ${t.mitre.length ? `<div class="card mitre"><h3>MITRE ATT&CK</h3>${t.mitre.map((m) => `<span>${esc(m)}</span>`).join("")}</div>` : ""}
      </div>
    </div>

    <div class="card actions"><h3>Acciones recomendadas</h3>${actionsHtml(t)}</div>

    ${t.devils_advocate ? `<div class="card devil"><h3>Abogado del diablo</h3><p>${esc(t.devils_advocate)}</p></div>` : ""}

    <div class="card"><h3>Evidencias</h3><table><tr><th>Fuente</th><th>Evento</th><th>Hallazgo</th></tr>
      ${t.evidence.map((e) => `<tr><td>${esc(e.source)}</td><td class="mono">${esc(e.event_id)}</td><td>${esc(e.finding)}</td></tr>`).join("")}</table></div>

    ${t.enrichment.length ? `<div class="card"><h3>Enriquecimiento</h3><table><tr><th>Indicador</th><th>Tipo</th><th>Fuente</th><th>Resultado</th></tr>
      ${t.enrichment.map((e) => `<tr><td class="mono">${esc(e.indicator)}</td><td>${esc(e.type)}</td><td>${esc(e.source)}</td><td>${esc(e.result)}</td></tr>`).join("")}</table></div>` : ""}

    ${t.open_questions.length ? `<div class="card"><h3>Para que lo mire una persona</h3><ul>${t.open_questions.map((q) => `<li>${esc(q)}</li>`).join("")}</ul></div>` : ""}

    ${t.tool_trace.length ? `<details class="card trace"><summary>Traza de herramientas (${t.tool_trace.length} llamadas)</summary><ol>
      ${t.tool_trace.map((s) => `<li><code>${esc(s.tool)}</code> ${esc(s.args ?? "")} <span class="muted">→ ${esc(s.result ?? "")}</span></li>`).join("")}</ol></details>` : ""}
  `;
}

// ---------------------------------------------------------------- aprobación
async function runAction(t, i) {
  const a = t.recommended_actions[i];
  let approver = "n1.automatico", reason = a.justification || "";
  if (a.requires_approval) {
    const dlg = $("#tpl-approve").content.firstElementChild.cloneNode(true);
    $(".modal-what", dlg).innerHTML = `<b class="mono">${esc(a.action)}</b> sobre <b>${esc(a.target)}</b><br><span class="muted">${esc(a.justification || "")}</span>`;
    document.body.appendChild(dlg);
    dlg.showModal();
    const ok = await new Promise((res) => dlg.addEventListener("close", () => res(dlg.returnValue === "ok")));
    approver = dlg.querySelector("[name=approver]").value;
    reason = dlg.querySelector("[name=reason]").value || reason;
    dlg.remove();
    if (!ok) return;
  }
  const r = await fetch("api/approve", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ticket_id: t.ticket_id, action: a.action, target: a.target, approver, reason }) });
  const d = await r.json();
  (executed[t.ticket_id] ||= {})[i] = d.result || "hecho";
  toast(`${a.action} → ${a.target}<br><span class="muted small">${esc(d.result)}${d.approval_token ? " · " + esc(d.approval_token) : ""}</span>`);
  renderDetail(t);
}

function toast(html) {
  const el = document.createElement("div");
  el.className = "toast"; el.innerHTML = html;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

// ---------------------------------------------------------------- turno de noche
function madridOffsetMs(date) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: TZ, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" })
    .formatToParts(date).map((x) => [x.type, x.value]));
  return Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second) - date.getTime();
}
function madridMidnight(date) {
  const local = new Date(date.getTime() + madridOffsetMs(date));
  const mid = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate());
  return new Date(mid - madridOffsetMs(new Date(mid)));
}

function renderNight() {
  const rows = TICKETS.filter((t) => t.verdict === "true_positive" && t.night_shift)
    .sort((a, b) => a.night_shift.first_alert_at.localeCompare(b.night_shift.first_alert_at));
  const total = rows.reduce((n, t) => n + t.night_shift.gained_hours, 0);
  $("#gained").textContent = total.toFixed(0);
  if (!rows.length) { $("#night-chart").innerHTML = `<p class="muted">Sin incidentes.</p>`; return; }

  const allTimes = rows.flatMap((t) => [t.night_shift.first_alert_at, t.night_shift.human_at, ...t.alerts.map((a) => a.created_at)]).map((s) => new Date(s).getTime());
  let start = madridMidnight(new Date(Math.min(...allTimes)));
  while (localDow(start.toISOString()) !== 1) start = madridMidnight(new Date(start.getTime() - 12 * 3600e3)); // lunes anterior
  const days = Math.max(28, Math.ceil((Math.max(...allTimes) - start) / 86400e3) + 1);
  const end = start.getTime() + days * 86400e3;

  const W = 1200, L = 270, R = 16, top = 34, rowH = 30, H = top + rows.length * rowH + 10;
  const x = (ms) => L + ((ms - start.getTime()) / (end - start.getTime())) * (W - L - R);
  let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Detección SOC humano frente a IA por incidente">`;

  for (let d = 0; d < days; d++) {
    const dayStart = madridMidnight(new Date(start.getTime() + d * 86400e3 + 12 * 3600e3));
    const dow = localDow(dayStart.toISOString());
    if (dow >= 1 && dow <= 5) {
      const s = dayStart.getTime() + 8 * 3600e3, e = dayStart.getTime() + 20 * 3600e3;
      svg += `<rect class="soc" x="${x(s)}" y="${top - 6}" width="${x(e) - x(s)}" height="${H - top}"/>`;
    }
    if (dow === 1) {
      svg += `<line class="grid" x1="${x(dayStart.getTime())}" x2="${x(dayStart.getTime())}" y1="${top - 14}" y2="${H}"/>`;
      svg += `<text x="${x(dayStart.getTime()) + 3}" y="${top - 18}">lun ${fmtLocal(dayStart.toISOString(), { day: "numeric", month: "short" })}</text>`;
    }
  }

  rows.forEach((t, i) => {
    const y = top + i * rowH + rowH / 2;
    const ns = t.night_shift;
    const label = `#${t.incident_ref ?? ""} ${t.title}`;
    svg += `<text class="lbl" data-id="${esc(t.ticket_id)}" x="8" y="${y + 4}">${esc(label.length > 42 ? label.slice(0, 41) + "…" : label)}<title>${esc(t.title)}</title></text>`;
    // Una barra de espera por alerta: desde que salta hasta que el SOC humano abre la consola.
    (ns.alerts || []).forEach((w) => {
      const s0 = new Date(w.at).getTime(), s1 = new Date(w.human_at).getTime();
      if (s1 > s0) svg += `<rect class="wait" x="${x(s0)}" y="${y - 5}" width="${Math.max(2, x(s1) - x(s0))}" height="10" rx="3"><title>Esperaría ${w.wait_hours} h al SOC humano</title></rect>`;
    });
    t.alerts.forEach((al) => { svg += `<circle cx="${x(new Date(al.created_at).getTime())}" cy="${y}" r="3" fill="var(--muted)"><title>${esc(al.rule_name)} · ${fmtDT(al.created_at)}</title></circle>`; });
    const worst = ns.worst_alert && ns.worst_alert.wait_hours >= ns.first_wait_hours ? ns.worst_alert : { at: ns.first_alert_at, human_at: ns.human_at, wait_hours: ns.first_wait_hours };
    const wa = new Date(worst.at).getTime(), wh = new Date(worst.human_at).getTime();
    svg += `<circle cx="${x(wa)}" cy="${y}" r="6" fill="var(--${t.severity === "critical" ? "crit" : "high"})"><title>IA: ticket en segundos (${fmtDT(worst.at)})</title></circle>`;
    if (wh > wa) {
      svg += `<line x1="${x(wh)}" x2="${x(wh)}" y1="${y - 8}" y2="${y + 8}" stroke="var(--text)" stroke-width="2"><title>SOC humano: ${fmtDT(worst.human_at)}</title></line>`;
      svg += `<text x="${x(wh) + 5}" y="${y + 4}">+${worst.wait_hours} h</text>`;
    }
  });
  svg += `</svg>`;
  $("#night-chart").innerHTML = svg +
    `<div class="small muted" style="margin-top:6px">● IA detecta &nbsp; │ SOC humano lo vería &nbsp; ▬ espera &nbsp; · otras alertas del mismo incidente &nbsp; <span style="background:var(--accent);opacity:.25">&nbsp;&nbsp;&nbsp;</span> horario del SOC</div>`;
}

// ---------------------------------------------------------------- eventos
function showView(v) {
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.view === v));
  document.querySelectorAll(".view").forEach((s) => s.classList.toggle("active", s.id === "view-" + v));
}

document.addEventListener("click", (e) => {
  const tab = e.target.closest(".tab"); if (tab) return showView(tab.dataset.view);
  const chip = e.target.closest(".chip");
  if (chip) { filter = chip.dataset.f; document.querySelectorAll(".chip").forEach((c) => c.classList.toggle("active", c === chip)); return renderList(); }
  const li = e.target.closest("#ticket-list li[data-id]"); if (li) return select(li.dataset.id);
  const btn = e.target.closest(".btn-approve, .btn-exec");
  if (btn) return runAction(TICKETS.find((t) => t.ticket_id === selected), Number(btn.dataset.i));
  const lbl = e.target.closest(".night-chart .lbl");
  if (lbl) { showView("queue"); return select(lbl.dataset.id); }
});
document.addEventListener("keydown", (e) => {
  if (e.target.closest("input, dialog")) return;
  const vis = visible(), i = vis.findIndex((t) => t.ticket_id === selected);
  if (e.key === "j" || e.key === "ArrowDown") { e.preventDefault(); if (vis[i + 1]) select(vis[i + 1].ticket_id); }
  if (e.key === "k" || e.key === "ArrowUp") { e.preventDefault(); if (vis[i - 1]) select(vis[i - 1].ticket_id); }
  if (e.key === "p") document.body.classList.toggle("present");
  if (e.key === "1") showView("queue"); if (e.key === "2") showView("night"); if (e.key === "3") showView("limits");
});
$("#present").onclick = () => document.body.classList.toggle("present");
$("#theme").onclick = () => {
  const r = document.documentElement;
  r.dataset.theme = r.dataset.theme === "light" ? "dark" : "light";
  try { localStorage.setItem("theme", r.dataset.theme); } catch (_) {}
};
try { const t = localStorage.getItem("theme"); if (t) document.documentElement.dataset.theme = t; } catch (_) {}

load();
