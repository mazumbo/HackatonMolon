"""Servidor de la demo visual (rol C).

Sirve la interfaz estática de ui/static y una API pequeña para ella:

    GET  /api/tickets            lista de tickets (con el cálculo del turno de noche)
    GET  /api/tickets/{id}       un ticket
    GET  /api/nightshift         resumen "SOC humano vs IA" por incidente
    POST /api/approve            aprobación humana -> /approvals + /containment de la API mock

De dónde salen los tickets (variable UI_TICKETS):
    - un fichero .json con una lista de tickets, o .jsonl con un ticket por línea
    - una carpeta con un .json por ticket (lo que vaya escribiendo el agente)
    - si no se indica nada: ui/data/tickets_mock.json

Arranque:
    pip install fastapi uvicorn httpx
    uvicorn server:app --app-dir ui --port 8080 --reload
"""
from __future__ import annotations

import datetime as dt
import json
import os
import uuid
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

HERE = Path(__file__).resolve().parent
TICKETS_SRC = Path(os.environ.get("UI_TICKETS", HERE / "data" / "tickets_mock.json"))
SOC_API = os.environ.get("SOC_API_URL", "http://localhost:8000").rstrip("/")
MADRID = ZoneInfo("Europe/Madrid")

# Horario del SOC de Tarvia (empresa_tarvia.md): 8:00-20:00 de lunes a viernes.
SOC_START, SOC_END = 8, 20

# Acciones que la API mock sabe ejecutar. El resto solo queda aprobado.
CONTAINMENT = {"isolate_host", "disable_user", "revoke_sessions", "reset_password",
               "block_ioc", "purge_email", "disable_access_key"}

app = FastAPI(title="Tarvia SOC · demo visual", docs_url=None, redoc_url=None)


@app.middleware("http")
async def security_headers(request, call_next):
    # Solo recursos propios: sin scripts externos ni incrustación en otras páginas.
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp
APPROVALS_LOCAL: list[dict] = []


# ---------------------------------------------------------------------------
# Carga de tickets
# ---------------------------------------------------------------------------
def _read_tickets() -> list[dict]:
    src = TICKETS_SRC
    if not src.exists():
        return []
    if src.is_dir():
        out = []
        for p in sorted(src.glob("*.json")):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
                out.extend(d if isinstance(d, list) else [d])
            except json.JSONDecodeError:
                continue  # un ticket a medio escribir no debe romper la demo
        return out
    text = src.read_text(encoding="utf-8")
    if src.suffix == ".jsonl":
        return [json.loads(l) for l in text.splitlines() if l.strip()]
    d = json.loads(text)
    return d if isinstance(d, list) else [d]


def _parse(ts: str | None) -> dt.datetime | None:
    if not ts:
        return None
    try:
        return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def human_soc_sees(ts: dt.datetime) -> dt.datetime:
    """Primer momento en que alguien del SOC humano mira la consola (suposición optimista:
    la alerta se trata en cuanto se abre el turno)."""
    local = ts.astimezone(MADRID)
    day = local
    for _ in range(8):
        start = day.replace(hour=SOC_START, minute=0, second=0, microsecond=0)
        end = day.replace(hour=SOC_END, minute=0, second=0, microsecond=0)
        if day.weekday() < 5:
            if local < start:
                return start.astimezone(dt.timezone.utc)
            if start <= local < end:
                return local.astimezone(dt.timezone.utc)
        day = (day + dt.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return local.astimezone(dt.timezone.utc)


def _first_alert(t: dict) -> dt.datetime | None:
    first = _parse(t.get("first_alert_at"))
    if first is None and t.get("alerts"):
        first = min(filter(None, (_parse(a.get("created_at")) for a in t["alerts"])), default=None)
    return first


def _z(d: dt.datetime) -> str:
    return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def enrich(t: dict) -> dict:
    """Rellena con valores por defecto lo que la UI necesita, para que un ticket
    incompleto del agente nunca rompa la pantalla."""
    t = dict(t)
    t.setdefault("alert_ids", [])
    t.setdefault("title", "(sin título)")
    t.setdefault("verdict", "needs_more_info")
    t.setdefault("severity", "medium")
    t.setdefault("confidence", None)
    t.setdefault("summary", "")
    for k in ("evidence", "enrichment", "mitre", "recommended_actions", "executed_actions",
              "open_questions", "alerts", "prompt_injection", "tool_trace"):
        t[k] = t.get(k) or []
    t["affected"] = t.get("affected") or {}
    t["escalation"] = t.get("escalation") or {"escalate": False}
    t.setdefault("status", "open")
    first = _first_alert(t)
    if first:
        triage = dt.timedelta(seconds=float(t.get("triage_seconds") or 60))
        # Espera de cada alerta hasta que el SOC humano abre la consola.
        waits = []
        for a in t["alerts"]:
            ts = _parse(a.get("created_at"))
            if ts:
                h = human_soc_sees(ts)
                waits.append({"alert_id": a.get("alert_id"), "at": _z(ts), "human_at": _z(h),
                              "wait_hours": round(max(0.0, (h - ts - triage).total_seconds()) / 3600, 1)})
        human = human_soc_sees(first)
        first_wait = round(max(0.0, (human - first - triage).total_seconds()) / 3600, 1)
        worst = max(waits, key=lambda w: w["wait_hours"], default=None)
        t["night_shift"] = {
            "first_alert_at": _z(first),
            "ai_at": _z(first + triage),
            "human_at": _z(human),
            "first_wait_hours": first_wait,
            # Lo que se enseña: la peor espera del incidente (p. ej. el LSASS del sábado a las 2:00).
            "gained_hours": max(first_wait, worst["wait_hours"] if worst else 0.0),
            "worst_alert": worst,
            "out_of_hours": any(w["wait_hours"] > 0 for w in waits) or human > first,
            "alerts": waits,
        }
    return t


def all_tickets() -> list[dict]:
    return [enrich(t) for t in _read_tickets()]


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@app.get("/api/tickets")
def list_tickets():
    return {"source": str(TICKETS_SRC.name), "tickets": all_tickets()}


@app.get("/api/tickets/{ticket_id}")
def get_ticket(ticket_id: str):
    for t in all_tickets():
        if t.get("ticket_id") == ticket_id:
            return t
    raise HTTPException(404, "ticket no encontrado")


@app.get("/api/nightshift")
def nightshift():
    rows = [t for t in all_tickets() if t["verdict"] == "true_positive" and t.get("night_shift")]
    rows.sort(key=lambda t: t["night_shift"]["first_alert_at"])
    out = [{"ticket_id": t["ticket_id"], "incident_ref": t.get("incident_ref"), "title": t["title"],
            "severity": t["severity"], **t["night_shift"]} for t in rows]
    return {
        "soc_hours": f"L-V {SOC_START}:00-{SOC_END}:00 (Europe/Madrid)",
        "incidents": out,
        "total_gained_hours": round(sum(r["gained_hours"] for r in out), 1),
        "out_of_hours": sum(1 for r in out if r["out_of_hours"]),
    }


class ApproveIn(BaseModel):
    ticket_id: str
    action: str
    target: str
    approver: str = "analista.demo"
    reason: str = ""


@app.post("/api/approve")
def approve(a: ApproveIn):
    rec = {"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(), **a.model_dump()}
    try:
        with httpx.Client(timeout=4) as c:
            ap = c.post(f"{SOC_API}/approvals", json={"action": a.action, "target": a.target,
                                                       "approver": a.approver, "reason": a.reason})
            ap.raise_for_status()
            rec["approval_token"] = ap.json()["approval_token"]
            if a.action in CONTAINMENT:
                r = c.post(f"{SOC_API}/containment/{a.action}", json={
                    "target": a.target, "justification": a.reason or "Aprobado en la demo",
                    "approval_token": rec["approval_token"], "ticket_id": a.ticket_id})
                if r.status_code >= 400:
                    rec["result"] = f"rechazado por la API: {r.json().get('detail', r.text)}"
                else:
                    rec["result"] = r.json().get("result", "ok")
            else:
                rec["result"] = "aprobado (acción manual, la API no la ejecuta)"
            rec["mode"] = "api"
    except (httpx.HTTPError, KeyError):
        rec["approval_token"] = "LOCAL-" + uuid.uuid4().hex[:8]
        rec["result"] = "ok (simulado en la UI: API mock no disponible)"
        rec["mode"] = "local"
    APPROVALS_LOCAL.append(rec)
    return rec


@app.get("/api/approvals")
def approvals():
    return APPROVALS_LOCAL


@app.get("/")
def index():
    return FileResponse(HERE / "static" / "index.html")


app.mount("/", StaticFiles(directory=HERE / "static"), name="static")
