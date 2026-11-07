"""Tria en lot amb el motor del rol A (prefiltre + agrupacio) i l'agent LLM.

  python -m agent.run_batch                       # grups de >=2 alertes (incidents), un ticket per grup
  python -m agent.run_batch --ids-file vivas.jsonl  # els grups que contenen aquestes alertes; les tancades pel
                                                  # prefiltre surten sense LLM
  --cerradas   escriu tambe els tickets del prefiltre de TOTES les alertes tancades (sense LLM)
Escriu out/tickets/<ticket_id>.json (la UI el llegeix amb UI_TICKETS=out/tickets/)."""
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .pipeline import Motor


def _write(out, t):
    tmp = out / f"{t['ticket_id']}.json.tmp"
    tmp.write_text(json.dumps(t, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(out / f"{t['ticket_id']}.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids-file", help="JSONL amb un camp alert_id per linia")
    ap.add_argument("--limit", type=int, default=50, help="maxim de grups que passen pel LLM")
    ap.add_argument("--min-group", type=int, default=2, help="sense --ids-file: mida minima del grup")
    ap.add_argument("--cerradas", action="store_true", help="escriu tambe els tickets del prefiltre")
    ap.add_argument("--out", default="out/tickets")
    ap.add_argument("--workers", type=int, default=3, help="grups en paral·lel (compte amb el limit de la passarela)")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    extra = []
    if a.ids_file:
        with open(a.ids_file, encoding="utf-8") as f:
            extra = [json.loads(l) for l in f if l.strip()]
    motor = Motor(extra_alerts=[x for x in extra if x.get("rule_id")])  # si el fitxer porta alertes senceres
    if a.ids_file:
        ids = motor.asegurar([x["alert_id"] for x in extra])
    print(f"motor: {len(motor.alertas)} alertas, {sum(map(motor.cerrada, motor.por_id))} cerradas por el prefiltro, "
          f"{len(motor.grupos)} grupos ({motor.build_seconds} s)")

    cerradas = [i for i in motor.por_id if motor.cerrada(i)] if a.cerradas else []
    if a.ids_file:
        cerradas += [i for i in ids if motor.cerrada(i) and i not in cerradas]
        heads, seen = [], set()
        for i in ids:
            g = motor.grupo_de.get(i)
            key = g["grupo_id"] if g else i
            if not motor.cerrada(i) and key not in seen:
                seen.add(key)
                heads.append(i)
    else:
        heads = [g["alert_ids"][0] for g in motor.grupos if len(g["alert_ids"]) >= a.min_group]
    for i in cerradas:
        _write(out, motor.ticket_prefiltro(i))
    if cerradas:
        print(f"{len(cerradas)} tickets del prefiltro (0 s, sin LLM)")

    heads = heads[: a.limit]
    print(f"{len(heads)} grupos al agente")
    tot_in = tot_out = 0
    with ThreadPoolExecutor(max_workers=max(1, a.workers)) as ex:
        futs = {ex.submit(motor.triar_grupo_de, h): h for h in heads}
        for fut in as_completed(futs):
            t = fut.result()
            if a.ids_file:  # en viu el ticket porta el nom de l'alerta nova, encara que el grup tingui historic
                t["ticket_id"] = "TKT-" + futs[fut]
            _write(out, t)
            u = t.get("usage", {})
            tot_in, tot_out = tot_in + u.get("input_tokens", 0), tot_out + u.get("output_tokens", 0)
            print(f"{t['ticket_id']} ({len(t['alert_ids'])} alertas): {t['verdict']} / {t['severity']} / "
                  f"{t['triage_seconds']}s")
    print(f"tokens totals: in={tot_in} out={tot_out}")


if __name__ == "__main__":
    main()
