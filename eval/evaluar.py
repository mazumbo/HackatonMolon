"""Evaluación del sistema contra los 12 incidentes conocidos (rol D).

Uso:
  # 0) Solo el motor, sin LLM ni API (segundos)
  python -m eval.evaluar --motor --salida eval/RESULTADOS_MOTOR.md
  # 1) Preparar la lista de alertas de los 12 incidentes + benignos de control (sin LLM, sin API)
  python -m eval.evaluar --preparar eval/casos.jsonl
  # 2) Triarlas con el pipeline completo (en el PC con la clave y la API mock en el 8000)
  python -m agent.run_batch --ids-file eval/casos.jsonl --out out/eval --limit 40
  # 3) Puntuar los tickets y escribir el informe
  python -m eval.evaluar --tickets out/eval --salida eval/RESULTADOS.md

Qué mide, por incidente: veredicto (debe ser true_positive), severidad (la de la política, ver ESPERADA),
escalado, segundos de triaje, tokens y cobertura (cuántas alertas del incidente acaban en un ticket de ataque).
Marca como FALLO GRAVE cualquier alerta de un incidente cerrada como no-ataque (falso negativo).
En los benignos de control comprueba que NO se escalen como ataque.
"""
import argparse
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MD = ROOT / "docs" / "incidentes_localizados.md"

# Severidad esperada según politica_soc.md §2 (revisada el 07/11 con engine/severidad.py): 9 critical, 3 high.
ESPERADA = {1: "critical", 2: "critical", 3: "critical", 4: "critical", 5: "high", 6: "critical",
            7: "critical", 8: "critical", 9: "critical", 10: "high", 11: "high", 12: "critical"}
NOMBRE = {1: "BEC + AiTM (Laura Ferrer)", 2: "Ransomware en preparación (WS-BCN-1770)",
          3: "Cadena de suministro → AWS → CRM", 4: "Skimming TPV tienda 07", 5: "Logisoft + túnel DNS WMS01",
          6: "Fuga de datos empleada saliente", 7: "Password spraying Tor → svc_backup",
          8: "Fatiga MFA (Sergio Navarro)", 9: "Credential stuffing + toma de cuentas",
          10: "Phishing Packaging Iberia + prompt injection", 11: "Abuso del asistente Vela",
          12: "Criptominería JENKINS-DEV01"}
# Benignos de control: actividad autorizada que no debe acabar escalada como ataque.
BENIGNOS = {"Nóminas a la gestoría (FLUJO-0007)": ["011874", "011875"]}
ATAQUE = {"true_positive"}
NO_ATAQUE = {"false_positive", "benign_true_positive"}
LIMITE_S = 60


def _alertas():
    from engine import datos
    return datos.cargar_alertas()


def incidentes(alertas=None):
    from engine.agrupacion import incidentes_de_referencia
    return incidentes_de_referencia(MD, alertas if alertas is not None else _alertas())


def benignos(alertas=None):
    suf = {a["alert_id"][-6:]: a["alert_id"] for a in (alertas if alertas is not None else _alertas())}
    return {k: [suf[s] for s in v if s in suf] for k, v in BENIGNOS.items()}


def preparar(ruta):
    al = _alertas()
    inc, ben = incidentes(al), benignos(al)
    ids = sorted({i for s in inc.values() for i in s} | {i for v in ben.values() for i in v})
    Path(ruta).parent.mkdir(parents=True, exist_ok=True)
    with open(ruta, "w", encoding="utf-8") as f:
        for i in ids:
            f.write(json.dumps({"alert_id": i}) + "\n")
    print(f"{len(ids)} alertas ({len(inc)} incidentes + benignos de control) en {ruta}")


def cargar_tickets(carpeta):
    p = Path(carpeta)
    if p.is_file():  # p. ej. ui/data/tickets_mock.json
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, list) else [d]
    out = []
    for f in sorted(p.glob("*.json")):
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"aviso: {f.name} no es JSON válido ({e})", file=sys.stderr)
    return out


def puntuar(tickets, inc, ben):
    por_alerta = {}
    for t in tickets:
        for a in t.get("alert_ids") or []:
            por_alerta.setdefault(a, []).append(t)
    filas = []
    for n, ids in sorted(inc.items()):
        ts = {id(t): t for a in ids for t in por_alerta.get(a, [])}.values()
        ts = sorted(ts, key=lambda t: -len(set(t.get("alert_ids") or []) & ids))
        principal = ts[0] if ts else None
        cubiertas = {a for a in ids for t in por_alerta.get(a, []) if t.get("verdict") in ATAQUE}
        cerradas = sorted({a for a in ids for t in por_alerta.get(a, []) if t.get("verdict") in NO_ATAQUE}
                          - cubiertas)
        segs = [float(t.get("triage_seconds") or 0) for t in ts if t.get("model") != "prefiltro"]
        tok = sum((t.get("usage") or {}).get("input_tokens", 0) + (t.get("usage") or {}).get("output_tokens", 0)
                  for t in ts)
        filas.append({
            "n": n, "nombre": NOMBRE.get(n, ""), "tickets": len(ts),
            "ticket": principal.get("ticket_id") if principal else None,
            "veredicto": principal.get("verdict") if principal else None,
            "veredicto_ok": bool(principal) and principal.get("verdict") in ATAQUE,
            "severidad": principal.get("severity") if principal else None, "esperada": ESPERADA.get(n),
            "severidad_ok": bool(principal) and principal.get("severity") == ESPERADA.get(n),
            "escala": bool(principal) and bool((principal.get("escalation") or {}).get("escalate")),
            "cobertura": f"{len(cubiertas)}/{len(ids)}", "cerradas_como_no_ataque": cerradas,
            "segundos": max(segs) if segs else None, "tokens": tok,
            "inyeccion": bool(principal) and bool(principal.get("prompt_injection")),
        })
    filas_b = []
    for nombre, ids in ben.items():
        ts = {id(t): t for a in ids for t in por_alerta.get(a, [])}.values()
        malos = [t.get("ticket_id") for t in ts if t.get("verdict") in ATAQUE
                 and (t.get("escalation") or {}).get("escalate")]
        filas_b.append({"nombre": nombre, "tickets": len(ts), "veredictos": sorted({t.get("verdict") for t in ts}),
                        "ok": bool(ts) and not malos, "escalados_por_error": malos})
    return filas, filas_b


def resumen(filas, filas_b, tickets):
    con = [f for f in filas if f["tickets"]]
    segs = [f["segundos"] for f in filas if f["segundos"] is not None]
    llm = [t for t in tickets if t.get("model") != "prefiltro"]
    return {
        "incidentes_con_ticket": len(con), "total": len(filas),
        "veredicto_ok": sum(f["veredicto_ok"] for f in filas),
        "severidad_ok": sum(f["severidad_ok"] for f in filas),
        "escalados": sum(f["escala"] for f in filas),
        "falsos_negativos": sum(bool(f["cerradas_como_no_ataque"]) for f in filas),
        "benignos_ok": sum(f["ok"] for f in filas_b), "benignos": len(filas_b),
        "seg_media": round(statistics.mean(segs), 1) if segs else None,
        "seg_max": round(max(segs), 1) if segs else None,
        "bajo_60s": sum(s < LIMITE_S for s in segs), "con_tiempo": len(segs),
        "tickets": len(tickets), "tickets_llm": len(llm),
        "tokens_llm": sum((t.get("usage") or {}).get("input_tokens", 0) + (t.get("usage") or {}).get("output_tokens", 0)
                          for t in llm),
    }


def informe(filas, filas_b, r, origen):
    s = lambda v: "—" if v is None else v  # noqa: E731
    ok = lambda b: "✅" if b else "❌"  # noqa: E731
    L = ["# Resultados de la evaluación", "",
         f"Tickets evaluados: `{origen}` ({r['tickets']} tickets, {r['tickets_llm']} con LLM). "
         f"Generado con `python -m eval.evaluar`.", "",
         "## Resumen", "",
         "| Métrica | Valor |", "| --- | --- |",
         f"| Incidentes con ticket | {r['incidentes_con_ticket']}/{r['total']} |",
         f"| Veredicto correcto (ataque) | {r['veredicto_ok']}/{r['total']} |",
         f"| Severidad igual a la política | {r['severidad_ok']}/{r['total']} |",
         f"| Escalados a N2 | {r['escalados']}/{r['total']} |",
         f"| Incidentes con alguna alerta cerrada como no-ataque | {r['falsos_negativos']} |",
         f"| Benignos de control sin escalar | {r['benignos_ok']}/{r['benignos']} |",
         f"| Segundos por ticket (media / máx.) | {s(r['seg_media'])} / {s(r['seg_max'])} |",
         f"| Tickets por debajo de {LIMITE_S} s | {r['bajo_60s']}/{r['con_tiempo']} |",
         f"| Tokens LLM (entrada + salida) | {r['tokens_llm']} |", "",
         "## Por incidente", "",
         "| # | Incidente | Ticket | Veredicto | Severidad (esperada) | Escala | Cobertura | s | Inyección |",
         "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for f in filas:
        L.append(f"| {f['n']} | {f['nombre']} | {s(f['ticket'])} | {ok(f['veredicto_ok'])} {s(f['veredicto'])} | "
                 f"{ok(f['severidad_ok'])} {s(f['severidad'])} ({f['esperada']}) | {'sí' if f['escala'] else 'no'} | "
                 f"{f['cobertura']} | {s(f['segundos'])} | {'⚠️' if f['inyeccion'] else ''} |")
    fn = [f for f in filas if f["cerradas_como_no_ataque"]]
    if fn:
        L += ["", "## ⚠️ Alertas de incidentes cerradas como no-ataque", ""]
        L += [f"- Incidente {f['n']}: {', '.join(f['cerradas_como_no_ataque'])}" for f in fn]
    L += ["", "## Benignos de control", ""]
    L += [f"- {ok(b['ok'])} {b['nombre']}: {b['tickets']} tickets, veredictos {b['veredictos']}"
          + (f", escalados por error: {b['escalados_por_error']}" if b["escalados_por_error"] else "")
          for b in filas_b]
    L += ["", "## Qué no resolvemos (honestidad)", "",
          "- La verdad de referencia es nuestro análisis manual (`docs/incidentes_localizados.md`), no la de la organización.",
          "- Cobertura < 100 % significa que alguna alerta del incidente no se unió al ticket principal: el analista la ve aparte.",
          "- Los tiempos dependen de la pasarela UAB (`ornith`): con carga, pueden subir.", ""]
    return "\n".join(L)


def evaluar_motor():
    """Nivel motor (sin LLM ni API): prefiltro, agrupación y severidad de engine/ sobre los 12 incidentes."""
    from agent.pipeline import Motor
    from engine.severidad import calcular_severidad
    m = Motor()
    inc, ben = incidentes(m.alertas), benignos(m.alertas)
    L = ["# Evaluación del motor (sin LLM)", "",
         f"Motor construido en {m.build_seconds} s: {len(m.alertas)} alertas, "
         f"{sum(map(m.cerrada, m.por_id))} cerradas por el prefiltro, {len(m.grupos)} grupos.", "",
         "| # | Incidente | Cerradas por prefiltro | Grupos | Alertas en el grupo principal | Severidad motor (esperada) |",
         "| --- | --- | --- | --- | --- | --- |"]
    ok_sev = cerradas_tot = 0
    for n, ids in sorted(inc.items()):
        cerr = [i for i in ids if m.cerrada(i)]
        cerradas_tot += bool(cerr)
        gs = [m.grupo_de[i] for i in ids if i in m.grupo_de]
        g = max(gs, key=lambda g: len(set(g["alert_ids"]) & ids)) if gs else None
        sev = calcular_severidad([m.por_id[i] for i in g["alert_ids"]], contexto=m.ctx)["severidad"] if g else None
        ok_sev += sev == ESPERADA[n]
        L.append(f"| {n} | {NOMBRE[n]} | {len(cerr)} | {len({x['grupo_id'] for x in gs})} | "
                 f"{len(set(g['alert_ids']) & ids) if g else 0}/{len(ids)} | "
                 f"{'✅' if sev == ESPERADA[n] else '❌'} {sev} ({ESPERADA[n]}) |")
    L += ["", f"**Severidad del motor igual a la política: {ok_sev}/12. "
              f"Incidentes con alguna alerta cerrada por el prefiltro: {cerradas_tot}.**", ""]
    for k, v in ben.items():
        L.append(f"- Benigno de control {k}: " + ", ".join(
            f"{i} → {m.pref[i]['decision']} ({m.pref[i].get('veredicto') or '-'})" for i in v))
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--preparar", metavar="JSONL", help="escribe los alert_id a triar y sale")
    ap.add_argument("--tickets", default="out/eval", help="carpeta de tickets (o un .json con una lista)")
    ap.add_argument("--salida", help="escribe el informe Markdown aquí")
    ap.add_argument("--json", help="escribe también las filas en JSON")
    ap.add_argument("--motor", action="store_true", help="evalúa solo el motor (sin LLM ni API) y sale")
    a = ap.parse_args(argv)
    if a.motor:
        md = evaluar_motor()
        print(md)
        if a.salida:
            Path(a.salida).write_text(md, encoding="utf-8")
        return 0
    if a.preparar:
        preparar(a.preparar)
        return 0
    tickets = cargar_tickets(a.tickets)
    if not tickets:
        sys.exit(f"No hay tickets en {a.tickets}")
    al = _alertas()
    filas, filas_b = puntuar(tickets, incidentes(al), benignos(al))
    r = resumen(filas, filas_b, tickets)
    md = informe(filas, filas_b, r, a.tickets)
    print(md)
    if a.salida:
        Path(a.salida).write_text(md, encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps({"resumen": r, "incidentes": filas, "benignos": filas_b},
                                           ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
