"""Ensayo general del domingo: 10 alertas "nuevas" que la API mock NO conoce (como las de las 9:00).

Copia 10 alertas reales del dataset con un alert_id nuevo (ALR-20261108-9100NN), de modo que get_alert da 404
y el pipeline tiene que usar la alerta que le llega en el fichero, igual que el domingo.

  python -m eval.ensayo --preparar eval/ensayo_vivas.jsonl
  python -m agent.run_batch --ids-file eval/ensayo_vivas.jsonl --out out/ensayo
  python -m eval.ensayo --puntuar out/ensayo --salida eval/RESULTADOS_ENSAYO.md

El domingo, el mismo comando run_batch con el fichero que publique la organización (si trae alertas enteras,
una por línea, el motor no necesita la API para conocerlas).
"""
import argparse
import json
import sys
from pathlib import Path

from .evaluar import ATAQUE, ESPERADA, LIMITE_S, cargar_tickets

# sufijo original -> (qué es, veredicto esperado, severidad esperada o None si no la fijamos)
CASOS = [
    ("011785", "Inc. 1 · phishing de firma (BEC)", "true_positive", ESPERADA[1]),
    ("011826", "Inc. 12 · criptominería JENKINS", "true_positive", ESPERADA[12]),
    ("011914", "Inc. 10 · sesión reutilizada tras phishing con inyección", "true_positive", ESPERADA[10]),
    ("011898", "Inc. 4 · SMB del portátil a los TPV", "true_positive", ESPERADA[4]),
    ("011815", "Inc. 7 · password spraying por Tor", "true_positive", ESPERADA[7]),
    ("011877", "Inc. 5 · VPN de Logisoft (entra como low)", "true_positive", ESPERADA[5]),
    ("011874", "Benigno · nóminas a la gestoría (FLUJO-0007)", "benign_true_positive", None),
    ("000301", "Ruido · PowerShell codificado (desarrollo)", None, None),
    ("000440", "Ruido · firma WAF (desarrollo)", None, None),
    ("000099", "Ruido · correo (desarrollo)", None, None),
]


def preparar(ruta):
    from engine import datos
    suf = {a["alert_id"][-6:]: a for a in datos.cargar_alertas()}
    meta = []
    with open(ruta, "w", encoding="utf-8") as f:
        for k, (s, que, ver, sev) in enumerate(CASOS, 1):
            a = dict(suf[s])
            nuevo = f"ALR-20261108-9100{k:02d}"
            meta.append({"alert_id": nuevo, "origen": a["alert_id"], "que": que, "veredicto": ver, "severidad": sev})
            a["alert_id"] = nuevo
            f.write(json.dumps(a, ensure_ascii=False) + "\n")
    Path(ruta).with_suffix(".meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"10 alertas nuevas en {ruta} (y la clave de respuestas en {Path(ruta).with_suffix('.meta.json')})")


def puntuar(carpeta, meta_path):
    meta = json.loads(Path(meta_path).read_text(encoding="utf-8"))
    tickets = cargar_tickets(carpeta)
    por_alerta = {}
    for t in tickets:
        for a in t.get("alert_ids") or []:
            por_alerta.setdefault(a, []).append(t)
        por_alerta.setdefault((t.get("ticket_id") or "")[4:], []).append(t)
    L = ["# Ensayo general: 10 alertas nuevas", "",
         "| # | Alerta | Qué es | Veredicto (esperado) | Severidad (esperada) | Escala | s |",
         "| --- | --- | --- | --- | --- | --- | --- |"]
    ok_v = n_v = ok_s = n_s = rapidas = con_t = 0
    for k, m in enumerate(meta, 1):
        ts = por_alerta.get(m["alert_id"], [])
        t = ts[0] if ts else {}
        v, s = t.get("verdict"), t.get("severity")
        seg = t.get("triage_seconds")
        if m["veredicto"]:
            n_v += 1
            ok_v += v == m["veredicto"] or (m["veredicto"] in ATAQUE and v in ATAQUE)
        if m["severidad"]:
            n_s += 1
            ok_s += s == m["severidad"]
        if seg is not None:
            con_t += 1
            rapidas += float(seg) < LIMITE_S
        marca = lambda ok, esp: "" if not esp else ("✅ " if ok else "❌ ")  # noqa: E731
        L.append(f"| {k} | {m['alert_id']} | {m['que']} | {marca(v == m['veredicto'], m['veredicto'])}{v or 'SIN TICKET'}"
                 f" ({m['veredicto'] or '—'}) | {marca(s == m['severidad'], m['severidad'])}{s or '—'} ({m['severidad'] or '—'})"
                 f" | {'sí' if (t.get('escalation') or {}).get('escalate') else 'no'} | {seg if seg is not None else '—'} |")
    L += ["", f"**Veredicto: {ok_v}/{n_v} · Severidad: {ok_s}/{n_s} · Por debajo de {LIMITE_S} s: {rapidas}/{con_t} · "
              f"Tickets con ticket: {sum(bool(por_alerta.get(m['alert_id'])) for m in meta)}/10**", ""]
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--preparar", metavar="JSONL")
    ap.add_argument("--puntuar", metavar="CARPETA")
    ap.add_argument("--meta", default="eval/ensayo_vivas.meta.json")
    ap.add_argument("--salida")
    a = ap.parse_args(argv)
    if a.preparar:
        preparar(a.preparar)
    elif a.puntuar:
        md = puntuar(a.puntuar, a.meta)
        print(md)
        if a.salida:
            Path(a.salida).write_text(md, encoding="utf-8")
    else:
        ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
