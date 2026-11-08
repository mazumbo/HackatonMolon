"""Prepara la reproducción del lote en vivo para la pestaña «Reproducción» de la UI.

Lee la carpeta del lote (por defecto demo/vivo):
    vivas.jsonl      las alertas en el orden en que entraron
    tickets/*.json   los tickets que escribió el sistema

y deja en ui/data/replay_vivo.json una línea de tiempo con los tiempos reales:
    t_done  = momento en que se escribió el ticket (mtime), relativo al primero
    t_start = t_done - triage_seconds

Se guarda en un .json aparte porque la hora de los ficheros se pierde al pasar por git.

    python ui/tools/build_replay.py [carpeta_del_lote] [salida.json]
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "demo" / "vivo"
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "ui" / "data" / "replay_vivo.json"

HIDDEN_RE = re.compile(r"<div[^>]*display\s*:\s*none[^>]*>(.*?)</div>", re.I | re.S)


def entities(a: dict) -> list[str]:
    e = a.get("entities") or {}
    out = [u.get("upn", "") for u in e.get("users") or []]
    out += [h.get("hostname", "") for h in e.get("hosts") or []]
    out += list(e.get("domains") or [])
    return [x for x in out if x][:3]


def injection_text(alert: dict) -> dict | None:
    """Busca en la alerta original el texto escondido dirigido a la IA."""
    for k, v in (alert.get("evidence") or {}).items():
        if isinstance(v, str):
            m = HIDDEN_RE.search(v)
            if m:
                return {"field": f"evidence.{k}", "visible": HIDDEN_RE.sub("", v).strip(),
                        "hidden": m.group(1).strip()}
    return None


def main() -> None:
    alerts = [json.loads(l) for l in (SRC / "vivas.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    files = sorted((SRC / "tickets").glob("*.json"))
    t0 = min(p.stat().st_mtime for p in files)
    tickets = []
    for p in files:
        t = json.loads(p.read_text(encoding="utf-8"))
        t["_t_done"] = round(p.stat().st_mtime - t0, 1)
        tickets.append(t)

    rows = []
    for a in alerts:
        aid = a["alert_id"]
        t = next((x for x in tickets if aid in (x.get("alert_ids") or [])), None)
        if t is None:
            continue
        pre = t.get("prefilter") or {}
        pre = pre if "decision" in pre else pre.get(aid, {})
        g = t.get("group") or {}
        members = sorted(t.get("alerts") or [], key=lambda x: x.get("created_at", ""))
        usage = t.get("usage") or {}
        trig = float(t.get("triage_seconds") or 0)
        inj = injection_text(a) if t.get("prompt_injection") else None
        rows.append({
            "alert_id": aid, "created_at": a.get("created_at"), "source_product": a.get("source_product"),
            "rule_id": a.get("rule_id"), "rule_name": a.get("rule_name"), "severity": a.get("severity"),
            "entities": entities(a),
            "prefilter": {"decision": pre.get("decision", "pasar"), "motivo": pre.get("motivo", ""),
                          "cambio": pre.get("cambio")},
            "group": {
                "id": g.get("grupo_id"),
                "alerts": [{"alert_id": m.get("alert_id"), "created_at": m.get("created_at"),
                            "rule_id": m.get("rule_id"), "source_product": m.get("source_product"),
                            "severity": m.get("severity")} for m in members],
                "entidades_clave": (g.get("entidades_clave") or [])[:4],
                "uniones": [u.get("motivo", "") for u in (g.get("uniones") or [])[:3]],
                "reglas": g.get("reglas") or {},
            },
            "ticket": {
                "ticket_id": t.get("ticket_id"), "title": t.get("title"), "verdict": t.get("verdict"),
                "severity": t.get("severity"), "confidence": t.get("confidence"), "status": t.get("status"),
                "model": t.get("model"), "escalate": bool((t.get("escalation") or {}).get("escalate")),
                "escalate_to": (t.get("escalation") or {}).get("to"),
                "triage_seconds": trig, "steps": usage.get("steps", 0),
                "llm_seconds": usage.get("llm_seconds_total", 0), "tools_seconds": usage.get("tools_seconds", 0),
                "prefetch_seconds": usage.get("prefetch_seconds", 0),
                "tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
                "injection_handling": (t.get("prompt_injection") or [{}])[0].get("handling"),
            },
            "t_done": t["_t_done"],
            "t_start": round(max(0.0, t["_t_done"] - trig), 1),
            "injection": inj,
        })
    out = {"source": SRC.name, "total_seconds": max(r["t_done"] for r in rows), "alerts": rows}
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{OUT}: {len(rows)} alertas, {out['total_seconds']} s")


if __name__ == "__main__":
    main()
