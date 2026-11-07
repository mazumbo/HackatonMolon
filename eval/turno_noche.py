"""Diferenciador "turno de noche": cuánto habría tardado el SOC humano en ver cada incidente.

  python -m eval.turno_noche --salida eval/TURNO_NOCHE.md [--tickets out/eval]

El SOC de Tarvia trabaja de lunes a viernes de 8:00 a 20:00 (hora de Madrid) y nadie mira la consola por la noche
ni en fin de semana (01_contexto/empresa_tarvia.md). Suposición optimista para el humano: trata la alerta en cuanto
abre el turno. Misma regla que la vista Turno de noche de la UI (ui/server.py, human_soc_sees).
Con --tickets usa los segundos reales de triaje del agente; si no, solo cuenta la espera del humano.
"""
import argparse
import datetime as dt
import sys
from pathlib import Path
from zoneinfo import ZoneInfo

from .evaluar import NOMBRE, cargar_tickets, incidentes

MADRID = ZoneInfo("Europe/Madrid")
SOC_START, SOC_END = 8, 20
DIAS = ["lun", "mar", "mié", "jue", "vie", "sáb", "dom"]


def humano_ve(ts):
    local = ts.astimezone(MADRID)
    day = local
    for _ in range(8):
        start = day.replace(hour=SOC_START, minute=0, second=0, microsecond=0)
        end = day.replace(hour=SOC_END, minute=0, second=0, microsecond=0)
        if day.weekday() < 5:
            if local < start:
                return start
            if start <= local < end:
                return local
        day = (day + dt.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return local


def _ts(v):
    return dt.datetime.fromisoformat(v.replace("Z", "+00:00"))


def _fmt(d):
    d = d.astimezone(MADRID)
    return f"{DIAS[d.weekday()]} {d:%d/%m %H:%M}"


def calcular(alertas, inc, segundos=None):
    por_id = {a["alert_id"]: a for a in alertas}
    filas = []
    for n, ids in sorted(inc.items()):
        als = sorted((por_id[i] for i in ids if i in por_id), key=lambda a: a["created_at"])
        esperas = []
        for a in als:
            t = _ts(a["created_at"])
            esperas.append(((humano_ve(t) - t).total_seconds() / 3600, a, t))
        peor = max(esperas, key=lambda e: e[0])
        fuera = sum(e[0] > 0 for e in esperas)
        filas.append({"n": n, "nombre": NOMBRE[n], "alertas": len(als), "fuera_horario": fuera,
                      "peor_h": round(peor[0], 1), "peor_alerta": peor[1]["alert_id"],
                      "peor_regla": peor[1].get("rule_name") or peor[1].get("rule_id"),
                      "peor_cuando": _fmt(peor[2]), "humano": _fmt(humano_ve(peor[2])),
                      "ia_s": (segundos or {}).get(n)})
    return filas


def informe(filas, total_alertas, total_fuera):
    con = [f for f in filas if f["peor_h"] > 0]
    L = ["# Turno de noche: lo que el SOC humano no ve", "",
         "SOC de Tarvia: lunes a viernes de 8:00 a 20:00 (Madrid). Por la noche y en fin de semana nadie mira la consola.",
         "Suposición **optimista** para el humano: atiende la alerta en cuanto abre el turno (sin cola).", "",
         f"- **{total_fuera:,} de {total_alertas:,} alertas** ({total_fuera / total_alertas:.0%}) del dataset llegan fuera de horario.".replace(",", "."),
         f"- **{len(con)} de {len(filas)} incidentes** tienen alguna alerta clave fuera de horario.",
         f"- Suma de horas de ventaja del sistema (peor alerta de cada incidente): **{sum(f['peor_h'] for f in filas):.0f} h**.",
         *([f"- El caso fuerte es el ransomware (#2): el reconocimiento y el volcado de credenciales empiezan el "
            f"{r['peor_cuando']} y el humano no lo ve hasta el {r['humano']}: **{r['peor_h']} h** de ventaja para el atacante. "
            f"Si llega a cifrar y tirar la web en campaña, cada una de esas horas vale unos 120.000 € de venta "
            f"(≈ {r['peor_h'] * 0.12:.1f} M€ si la web estuviera caída todo ese tiempo, cota máxima)."
            for r in filas if r["n"] == 2 and r["peor_h"] > 0]), "",
         "| # | Incidente | Alertas fuera de horario | Alerta que más espera | Llega | El humano la ve | Espera | Sistema |",
         "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for f in sorted(filas, key=lambda f: -f["peor_h"]):
        ia = f"{f['ia_s']:.0f} s" if f["ia_s"] is not None else "< 60 s"
        L.append(f"| {f['n']} | {f['nombre']} | {f['fuera_horario']}/{f['alertas']} | {f['peor_regla']} | "
                 f"{f['peor_cuando']} | {f['humano']} | **{f['peor_h']} h** | {ia} |")
    L += ["", "## Cómo contarlo con honestidad", "",
          "- Las horas son de espera hasta que alguien **abre** la alerta; un SOC con 4.000 alertas al día tardaría más.",
          "- Hay una guardia N2 localizable por teléfono, pero solo si alguien la llama: sin sistema, nadie la llama.",
          "- Los 120.000 €/hora son el coste de caída de la venta online en campaña (empresa_tarvia.md): aplica a los "
          "incidentes que la paran (ransomware, skimming, robo del CRM), no a todos.", ""]
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tickets", help="carpeta de tickets del agente para poner sus segundos reales")
    ap.add_argument("--salida")
    a = ap.parse_args(argv)
    from engine import datos
    al = datos.cargar_alertas()
    inc = incidentes(al)
    segundos = None
    if a.tickets:
        ts = cargar_tickets(a.tickets)
        segundos = {}
        for n, ids in inc.items():
            s = [float(t.get("triage_seconds") or 0) for t in ts if set(t.get("alert_ids") or []) & ids
                 and t.get("model") != "prefiltro"]
            if s:
                segundos[n] = max(s)
    fuera = sum(humano_ve(_ts(x["created_at"])) > _ts(x["created_at"]) for x in al)
    md = informe(calcular(al, inc, segundos), len(al), fuera)
    print(md)
    if a.salida:
        Path(a.salida).write_text(md, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
