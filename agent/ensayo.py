"""Ensayo general de la demo: 10 alertas del dataset con ids nuevos, como si llegaran el domingo.

    python -m agent.ensayo                 # escribe demo/ensayo/vivas.jsonl
    python -m agent.run_batch --ids-file demo/ensayo/vivas.jsonl --workers 3 --out demo/ensayo/tickets

Los ids nuevos no estan en la API mock, asi que tambien prueba el camino de las alertas que la API no conoce.
"""
import json
from pathlib import Path

# 8 incidentes reales de docs/incidentes_localizados.md + 2 casos que debe cerrar el prefiltro (SCCM y WAF)
ORIGEN = ["011785", "011790", "011819", "011829", "011817", "011815", "011825", "011902", "000301", "000172"]


def main():
    from engine import datos
    por_sufijo = {a["alert_id"][-6:]: a for a in datos.cargar_alertas()}
    out = Path("demo/ensayo")
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "vivas.jsonl", "w", encoding="utf-8") as f:
        for n, suf in enumerate(ORIGEN, 1):
            a = dict(por_sufijo[suf])
            a["alert_id"] = f"ALR-20261108-9{n:05d}"
            a["ensayo_origen"] = por_sufijo[suf]["alert_id"]
            f.write(json.dumps(a, ensure_ascii=False) + "\n")
    print(f"{len(ORIGEN)} alertas en {out / 'vivas.jsonl'}")


if __name__ == "__main__":
    main()
