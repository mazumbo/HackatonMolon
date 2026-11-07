"""Plan B de la demo (rol A): que la demo funcione aunque fallen la red o el LLM.

Tres niveles, de mejor a peor:
  1. En directo: API mock + LLM de la pasarela UAB -> el agente tría las alertas al momento.
  2. Tickets guardados: los tickets REALES que el agente generó antes, guardados en demo/plan_b/<nombre>/.
  3. Tickets de ejemplo: ui/data/tickets_mock.json (escritos a mano, siempre están).

Comandos (desde la carpeta HackatonMolon):
  python demo/plan_b.py comprobar                     # semáforo: ¿qué funciona ahora mismo?
  python demo/plan_b.py guardar out/tickets vivas     # copia los tickets del agente a demo/plan_b/vivas/
  python demo/plan_b.py lista                         # qué tickets guardados hay
  python demo/plan_b.py demo vivas                    # abre la UI con los tickets guardados (sin LLM)
  python demo/plan_b.py demo                          # sin nombre: los guardados más recientes, o los de ejemplo

Solo usa la librería estándar de Python, para que funcione aunque falle todo lo demás.
"""
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
GUARDADOS = RAIZ / "demo" / "plan_b"
MOCK = RAIZ / "ui" / "data" / "tickets_mock.json"
OBLIGATORIOS = ["ticket_id", "alert_ids", "title", "verdict", "confidence", "severity",
                "summary", "evidence", "recommended_actions", "escalation"]
ORDEN_SEV = ["critical", "high", "medium", "low", "informational"]


def _env_agente():
    """Lee agent/.env sin depender de python-dotenv."""
    vals = {}
    p = RAIZ / "agent" / ".env"
    if p.exists():
        for linea in p.read_text(encoding="utf-8").splitlines():
            if "=" in linea and not linea.strip().startswith("#"):
                k, v = linea.split("=", 1)
                vals[k.strip()] = v.strip().strip('"').strip("'")
    vals.update({k: v for k, v in os.environ.items() if k in ("LLM_BASE_URL", "LLM_API_KEY", "SOC_API_URL")})
    return vals


def _get(url, cabeceras=None, timeout=5):
    req = urllib.request.Request(url, headers=cabeceras or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def _leer_tickets(carpeta):
    buenos, malos = [], []
    for p in sorted(Path(carpeta).glob("*.json")):
        try:
            t = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            malos.append((p.name, "no es JSON válido (¿a medio escribir?)"))
            continue
        for x in (t if isinstance(t, list) else [t]):
            falta = [c for c in OBLIGATORIOS if c not in x] if isinstance(x, dict) else ["todo"]
            (malos.append((p.name, "faltan " + ", ".join(falta))) if falta else buenos.append(x))
    return buenos, malos


def _guardados():
    if not GUARDADOS.is_dir():
        return []
    dirs = [d for d in GUARDADOS.iterdir() if d.is_dir() and any(d.glob("*.json"))]
    return sorted(dirs, key=lambda d: d.stat().st_mtime, reverse=True)


# ---------------------------------------------------------------------------
def comprobar():
    env = _env_agente()
    soc = env.get("SOC_API_URL", "http://localhost:8000").rstrip("/")
    llm = env.get("LLM_BASE_URL", "https://dcc-llm-gw.uab.cat/uabthehack/v1").rstrip("/")
    clave = env.get("LLM_API_KEY", "")

    print("\n=== Plan B: estado ahora mismo ===\n")
    try:
        _get(soc + "/alerts?limit=1")
        api = True
        print(f"[OK]    API mock responde en {soc}")
    except (urllib.error.URLError, OSError) as e:
        api = False
        print(f"[FALLA] API mock no responde en {soc} ({e.__class__.__name__}). Arráncala en otra terminal.")

    if not clave:
        llm_ok = False
        print("[FALLA] No hay LLM_API_KEY en agent/.env: el agente no puede llamar al modelo.")
    else:
        try:
            _get(llm + "/models", {"Authorization": f"Bearer {clave}"}, timeout=8)
            llm_ok = True
            print(f"[OK]    La pasarela del LLM responde ({llm})")
        except urllib.error.HTTPError as e:
            llm_ok = e.code < 500 and e.code not in (401, 403)
            print(f"[{'OK' if llm_ok else 'FALLA'}]{' ' * (4 if llm_ok else 1)}La pasarela del LLM contesta con HTTP {e.code}")
        except (urllib.error.URLError, OSError) as e:
            llm_ok = False
            print(f"[FALLA] La pasarela del LLM no responde ({e.__class__.__name__}): ¿sin red o fuera de la UAB?")

    gs = _guardados()
    if gs:
        for d in gs:
            buenos, malos = _leer_tickets(d)
            print(f"[OK]    Tickets guardados '{d.name}': {len(buenos)} válidos" + (f", {len(malos)} con problemas" if malos else ""))
    else:
        print("[AVISO] Aún no hay tickets guardados en demo/plan_b/. Guárdalos en cuanto el agente los genere.")
    print(f"[{'OK' if MOCK.exists() else 'FALLA'}]{' ' * (4 if MOCK.exists() else 1)}Tickets de ejemplo (último recurso): {MOCK.relative_to(RAIZ)}")

    print("\n=== Qué hacer ===")
    if api and llm_ok:
        print("Nivel 1, EN DIRECTO: todo funciona. Usa el agente normalmente.")
    elif gs:
        print(f"Nivel 2, TICKETS GUARDADOS: python demo/plan_b.py demo {gs[0].name}")
    else:
        print("Nivel 3, TICKETS DE EJEMPLO: python demo/plan_b.py demo")
    print()


def guardar(origen, nombre):
    origen = Path(origen)
    if not origen.is_dir():
        sys.exit(f"No existe la carpeta {origen}. ¿Has ejecutado antes el agente (python -m agent.run_batch ...)?")
    buenos, malos = _leer_tickets(origen)
    if not buenos:
        sys.exit(f"En {origen} no hay ningún ticket válido. No guardo nada.")
    destino = GUARDADOS / nombre
    if destino.exists():
        viejo = destino.with_name(f"{nombre}_anterior_{datetime.now():%H%M%S}")
        destino.rename(viejo)
        print(f"Ya existía '{nombre}': lo he movido a '{viejo.name}' para no perderlo.")
    destino.mkdir(parents=True)
    for t in buenos:
        nombre_fichero = "".join(c if c.isalnum() or c in "-_." else "_" for c in str(t["ticket_id"])) + ".json"
        (destino / nombre_fichero).write_text(json.dumps(t, ensure_ascii=False, indent=2), encoding="utf-8")

    buenos.sort(key=lambda t: ORDEN_SEV.index(t["severity"]) if t["severity"] in ORDEN_SEV else 9)
    filas = [f"| {t['ticket_id']} | {len(t['alert_ids'])} | {t['verdict']} | {t['severity']} | "
             f"{t.get('triage_seconds', '')} | {str(t['title']).replace('|', '/')[:80]} |" for t in buenos]
    (destino / "RESUMEN.md").write_text(
        f"# Tickets guardados: {nombre}\n\nGuardados el {datetime.now():%d/%m/%Y a las %H:%M} desde `{origen}`.\n"
        f"Para enseñarlos sin red ni LLM: `python demo/plan_b.py demo {nombre}`\n\n"
        "| Ticket | Alertas | Veredicto | Severidad | Segundos | Título |\n|---|---|---|---|---|---|\n"
        + "\n".join(filas) + "\n", encoding="utf-8")
    print(f"Guardados {len(buenos)} tickets en {destino.relative_to(RAIZ)} (resumen en RESUMEN.md).")
    for f, motivo in malos:
        print(f"  No guardado {f}: {motivo}")
    print("Súbelos a GitHub para que el equipo los tenga:\n"
          f"  git add demo/plan_b/{nombre}\n  git commit -m \"plan B: tickets {nombre}\"\n  git push")


def lista():
    gs = _guardados()
    if not gs:
        print("No hay tickets guardados todavía.")
    for d in gs:
        buenos, _ = _leer_tickets(d)
        sev = {s: sum(t["severity"] == s for t in buenos) for s in ORDEN_SEV}
        print(f"{d.name}: {len(buenos)} tickets · " + ", ".join(f"{n} {s}" for s, n in sev.items() if n))


def demo(nombre=None, puerto="8080"):
    if nombre:
        fuente = GUARDADOS / nombre
        if not fuente.is_dir():
            sys.exit(f"No existe demo/plan_b/{nombre}. Mira cuáles hay con: python demo/plan_b.py lista")
    else:
        gs = _guardados()
        fuente = gs[0] if gs else MOCK
    print(f"Abriendo la demo con: {fuente.relative_to(RAIZ)}")
    print(f"Abre el navegador en http://localhost:{puerto}   (Ctrl+C para parar)")
    entorno = dict(os.environ, UI_TICKETS=str(fuente))
    try:
        subprocess.run([sys.executable, "-m", "uvicorn", "server:app", "--app-dir", str(RAIZ / "ui"),
                        "--host", "127.0.0.1", "--port", puerto], env=entorno, check=False)
    except KeyboardInterrupt:
        pass


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "ayuda"):
        print(__doc__)
    elif argv[0] == "comprobar":
        comprobar()
    elif argv[0] == "guardar" and len(argv) == 3:
        guardar(argv[1], argv[2])
    elif argv[0] == "lista":
        lista()
    elif argv[0] == "demo":
        demo(*argv[1:3])
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
