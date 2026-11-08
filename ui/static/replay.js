"use strict";
// Pestaña «Reproducción»: reproduce el lote en vivo del domingo con los tiempos reales.
// Usa esc, pill, SEV_ES y VERDICT_ES de app.js.
//
// Línea de tiempo (segundos desde que el lote empieza, T+0):
//   T-6 .. T-1.5   las 10 alertas entran una a una (lectura del lote)
//   T+0            el prefiltro decide: cierra las que encajan con actividad conocida
//   T+0.5 .. T+9   el motor agrupa cada alerta con su historial en un incidente
//   t_start..t_done  el agente trabaja el incidente (t_done = hora real de escritura del ticket)

(() => {
  const ARRIVE0 = -6, ARRIVE_STEP = 0.5, GROUP_END = 9, TAIL = 3;
  let D = null, rows = [], t = ARRIVE0, speed = 1, playing = false, last = 0, raf = 0, maxTriage = 1;

  const fmtClock = (s) => {
    const neg = s < 0, a = Math.abs(Math.floor(s));
    return `T${neg ? "−" : "+"}${String(Math.floor(a / 60)).padStart(2, "0")}:${String(a % 60).padStart(2, "0")}`;
  };
  const fmtWhen = (iso) => new Date(iso).toLocaleString("es-ES", { timeZone: "Europe/Madrid", weekday: "short", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
  const short = (e) => e.replace(/@tarvia\.example$/, "");

  async function init() {
    try {
      const r = await fetch("api/replay");
      if (!r.ok) throw new Error(r.status);
      D = await r.json();
    } catch (e) {
      document.querySelector("#rp-grid").insertAdjacentHTML("beforeend", `<div class="rp-c dim" style="grid-column:1/-1">No hay reproducción disponible (${esc(e.message)}). Genera ui/data/replay_vivo.json con ui/tools/build_replay.py.</div>`);
      return;
    }
    maxTriage = Math.max(...D.alerts.map((a) => a.ticket.triage_seconds), 1);
    const grid = document.querySelector("#rp-grid");
    rows = D.alerts.map((a, i) => {
      const cells = ["entry", "pre", "group", "agent", "ticket"].map((k) => {
        const c = document.createElement("div");
        c.className = `rp-c ${k} wait`;
        grid.appendChild(c);
        return c;
      });
      const closed = a.prefilter.decision === "cerrar";
      const gs = a.group.alerts.length;
      return {
        a, cells, closed, state: {},
        arrive: ARRIVE0 + i * ARRIVE_STEP,
        // Cada grupo se va formando entre T+0.5 y T+9, una alerta del historial tras otra.
        gFrom: 0.5 + i * 0.25, gTo: Math.min(GROUP_END, 0.5 + i * 0.25 + 1.2 + gs * 0.25),
        seedIdx: Math.max(0, a.group.alerts.findIndex((m) => m.alert_id === a.alert_id)),
      };
    });
    document.querySelectorAll("#rp-speed button").forEach((b) => b.classList.toggle("on", Number(b.dataset.s) === speed));
    render(true);
  }

  // ------------------------------------------------------------ pintado
  function setCell(c, key, html, cls) {
    if (c.dataset.k === key) return false;
    c.dataset.k = key;
    c.innerHTML = html;
    if (cls !== undefined) c.className = cls;
    return true;
  }
  function flash(c) { c.classList.add("rp-new"); setTimeout(() => c.classList.remove("rp-new"), 900); }

  function entryCell(r) {
    const a = r.a;
    return `<div class="l1"><span class="mono">${esc(a.alert_id)}</span>${pill("sev-" + a.severity, SEV_ES[a.severity] || a.severity)}</div>
      <div class="l2"><b>${esc(a.source_product)}</b> · ${esc(a.rule_name)}</div>
      <div class="l3">${esc(fmtWhen(a.created_at))} · ${esc(a.entities.map(short).join(", "))}</div>`;
  }

  function preCell(r) {
    const p = r.a.prefilter;
    if (r.closed) {
      return `<div class="rp-closed"><div class="l1"><b>Cerrada en 0 s</b></div>
        <div class="l3" title="${esc(p.motivo)}">${esc(p.cambio ? p.cambio + " · " : "")}${esc(p.motivo)}</div></div>`;
    }
    return `<div class="l1 rp-pass">Pasa al agente</div><div class="l3">no encaja con actividad autorizada</div>`;
  }

  function groupCell(r, n) {
    const g = r.a.group, total = g.alerts.length;
    const dots = g.alerts.map((m, i) => `<i class="${i === r.seedIdx ? "seed" : i < n || i === r.seedIdx ? "on" : ""}" title="${esc(m.alert_id)} · ${esc(m.rule_id)}"></i>`).join("");
    const shown = Math.min(n + (r.seedIdx >= n ? 1 : 0), total);
    if (total === 1) {
      return `<div class="rp-dots">${dots}</div><div class="l3">Alerta aislada: nada en el historial comparte sus entidades</div>`;
    }
    const ents = g.entidades_clave.slice(0, 3).map((e) => `<span class="rp-ent">${esc(e.replace(/@tarvia\.example$/, ""))}</span>`).join("");
    const days = (Date.parse(g.alerts[total - 1].created_at) - Date.parse(g.alerts[0].created_at)) / 864e5;
    return `<div class="l1"><b>${shown} / ${total}</b> alertas en 1 incidente${days >= 1 ? ` · ${Math.round(days)} días` : ""}</div>
      <div class="rp-dots">${dots}</div>
      <div class="l2">${ents}</div>`;
  }

  function agentCell(r, now) {
    const tk = r.a.ticket, w = (x) => `${Math.max(1.5, (x / maxTriage) * 100)}%`;
    const inj = r.a.injection && now >= r.a.t_start ? `<span class="rp-injtag">Prompt injection</span>` : "";
    if (r.closed) {
      return `<div class="l1"><span class="muted">Sin modelo</span><span class="rp-secs">0,0 s</span></div>
        <div class="rp-track done"><i style="width:1.5%"></i></div><div class="l3">resuelta por el prefiltro</div>`;
    }
    if (now < r.a.t_start) {
      return `<div class="l1"><span class="muted">En cola</span></div><div class="rp-track"></div>`;
    }
    if (now < r.a.t_done) {
      const el = now - r.a.t_start;
      return `<div class="l1"><span>Analizando ${inj}</span><span class="rp-secs">${el.toFixed(1).replace(".", ",")} s</span></div>
        <div class="rp-track run"><i style="width:${w(el)}"></i></div><div class="l3">consultando herramientas y modelo…</div>`;
    }
    return `<div class="l1"><span>${inj || "Hecho"}</span><span class="rp-secs">${tk.triage_seconds.toFixed(1).replace(".", ",")} s</span></div>
      <div class="rp-track done"><i style="width:${w(tk.triage_seconds)}"></i></div>
      <div class="l3">${tk.steps} pasos · modelo ${tk.llm_seconds.toFixed(1).replace(".", ",")} s · herramientas ${tk.tools_seconds.toFixed(1).replace(".", ",")} s</div>`;
  }

  function ticketCell(r) {
    const tk = r.a.ticket;
    return `<div class="l1">${pill("v-" + tk.verdict, VERDICT_ES[tk.verdict] || tk.verdict)}${pill("sev-" + tk.severity, SEV_ES[tk.severity] || tk.severity)}${tk.escalate ? `<span class="rp-esc">↑ escala</span>` : ""}</div>
      <div class="l2" title="${esc(tk.title)}">${esc(tk.title)}</div>
      <div class="l3 mono">${esc(tk.ticket_id)}</div>`;
  }

  function render(force) {
    if (!D) return;
    const now = t;
    let arrived = 0, closed = 0, grouped = 0, done = 0, injShown = null;
    rows.forEach((r) => {
      const [ce, cp, cg, ca, ct] = r.cells;
      const a = r.a, injOn = a.injection && now >= a.t_start;
      const base = (k) => `rp-c ${k}${injOn ? " inj" : ""}`;
      if (force) r.cells.forEach((c) => { delete c.dataset.k; });

      // 1 Entrada
      if (now >= r.arrive) {
        arrived++;
        if (setCell(ce, "in" + (injOn ? "i" : ""), entryCell(r), base("entry")) && !force && !injOn) flash(ce);
      } else setCell(ce, "wait", "", "rp-c entry wait");

      // 2 Prefiltro
      if (now >= 0) {
        if (r.closed) closed++;
        if (setCell(cp, "pre" + (injOn ? "i" : ""), preCell(r), base("pre") + (r.closed ? "" : " dim")) && !force && r.closed) flash(cp);
      } else setCell(cp, "wait", "", "rp-c pre wait");

      // 3 Agrupación
      if (r.closed) {
        setCell(cg, now >= 0 ? "x" : "wait", now >= 0 ? `<div class="l3">No llega a agruparse</div>` : "", now >= 0 ? "rp-c group dim" : "rp-c group wait");
      } else if (now >= r.gFrom) {
        const total = a.group.alerts.length;
        const n = Math.min(total, Math.floor(((now - r.gFrom) / (r.gTo - r.gFrom)) * total) + 1);
        grouped += Math.min(n + (r.seedIdx >= n ? 1 : 0), total);
        setCell(cg, "g" + n + (injOn ? "i" : ""), groupCell(r, n), base("group"));
      } else setCell(cg, "wait", "", "rp-c group wait");

      // 4 Agente
      if (now >= 0) {
        const phase = r.closed ? "c" : now < a.t_start ? "q" : now < a.t_done ? "r" + Math.floor((now - a.t_start) * 10) : "d";
        setCell(ca, phase + (injOn ? "i" : ""), agentCell(r, now), base("agent"));
      } else setCell(ca, "wait", "", "rp-c agent wait");

      // 5 Ticket
      if (now >= a.t_done && now >= 0) {
        done++;
        if (setCell(ct, "t" + (injOn ? "i" : ""), ticketCell(r), base("ticket")) && !force) flash(ct);
      } else setCell(ct, "wait", "", "rp-c ticket wait");

      if (injOn) injShown = r;
    });

    const total = D.total_seconds;
    document.querySelector("#rp-clock").textContent = fmtClock(now);
    document.querySelector("#rp-prog").style.width = `${Math.max(0, Math.min(100, ((now - ARRIVE0) / (total - ARRIVE0)) * 100))}%`;
    document.querySelector("#rp-phase").textContent =
      now < 0 ? "Entrando alertas del lote" :
      now < 0.5 ? "Prefiltro" :
      done < rows.length ? `Agente trabajando · ${rows.filter((r) => !r.closed && now >= r.a.t_start && now < r.a.t_done).length} en paralelo` :
      `Lote terminado en ${total.toFixed(0)} s`;

    const stats = [
      [`${arrived}/${rows.length}`, "alertas entradas"],
      [closed, "cerradas por el prefiltro"],
      [grouped, "alertas agrupadas en incidentes"],
      [`${done}/${rows.length}`, "tickets emitidos"],
    ];
    const sk = stats.map((s) => s[0]).join("|");
    const st = document.querySelector("#rp-stats");
    if (st.dataset.k !== sk) {
      st.dataset.k = sk;
      st.innerHTML = stats.map(([v, l]) => `<div class="rp-stat"><b>${esc(v)}</b><span>${esc(l)}</span></div>`).join("");
    }

    const inj = document.querySelector("#rp-inj"), ik = injShown ? injShown.a.alert_id + (now >= injShown.a.t_done ? "d" : "") : "";
    if (inj.dataset.k !== ik) {
      inj.dataset.k = ik;
      if (!injShown) { inj.innerHTML = ""; } else {
        const a = injShown.a, x = a.injection, tk = a.ticket;
        inj.innerHTML = `<h3>Prompt injection en ${esc(a.alert_id)} · texto escondido en el correo (display:none)</h3>
          <blockquote>${esc(x.visible)}\n<mark>${esc(x.hidden)}</mark></blockquote>
          <p>${now >= a.t_done
            ? `El agente lo trata como dato y no obedece: veredicto <b>${esc(VERDICT_ES[tk.verdict] || tk.verdict)}</b>, severidad <b>${esc(SEV_ES[tk.severity] || tk.severity)}</b>${tk.escalate ? `, escalado a ${esc(tk.escalate_to || "N2")}` : ""}. El texto pedía falso positivo, informativa y no escalar.`
            : "Detectado al leer la alerta. Se marca y se trata como dato, no como instrucción."}</p>`;
      }
    }
  }

  // ------------------------------------------------------------ reloj
  function tick(ts) {
    if (!playing) return;
    const dt = Math.min(1, (ts - last) / 1000);
    last = ts;
    t += dt * speed;
    if (t >= D.total_seconds + TAIL) { t = D.total_seconds + TAIL; setPlaying(false); }
    render(false);
    raf = requestAnimationFrame(tick);
  }
  function setPlaying(on) {
    if (!D) return;
    if (on && t >= D.total_seconds + TAIL) reset();
    playing = on;
    document.querySelector("#rp-play").textContent = on ? "Pausa" : t > ARRIVE0 ? "Continuar" : "Reproducir";
    cancelAnimationFrame(raf);
    if (on) { last = performance.now(); raf = requestAnimationFrame(tick); }
  }
  function reset() {
    t = ARRIVE0;
    render(true);
    document.querySelector("#rp-play").textContent = "Reproducir";
  }

  document.querySelector("#rp-play").onclick = () => setPlaying(!playing);
  document.querySelector("#rp-reset").onclick = () => { setPlaying(false); reset(); };
  document.querySelector("#rp-speed").onclick = (e) => {
    const b = e.target.closest("button"); if (!b) return;
    speed = Number(b.dataset.s);
    document.querySelectorAll("#rp-speed button").forEach((x) => x.classList.toggle("on", x === b));
  };
  document.addEventListener("keydown", (e) => {
    if (document.body.dataset.view !== "replay" || e.target.closest("input, dialog")) return;
    if (e.key === " ") { e.preventDefault(); setPlaying(!playing); }
    if (e.key === "r") { setPlaying(false); reset(); }
    // ← / → : 5 s atrás o adelante (para buscar un momento concreto al grabar)
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      e.preventDefault();
      t = Math.max(ARRIVE0, Math.min(D.total_seconds + TAIL, t + (e.key === "ArrowRight" ? 5 : -5)));
      render(true);
      if (!playing) document.querySelector("#rp-play").textContent = t > ARRIVE0 ? "Continuar" : "Reproducir";
    }
  });
  if (location.hash === "#reproduccion") showView("replay");
  init();
})();
