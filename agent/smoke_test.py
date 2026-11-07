"""Test de fum del pipeline en viu: python -m agent.smoke_test ALR-XXXXXXXX-XXXXXX
Prefiltre del motor -> ticket sense LLM, o el grup sencer de l'alerta al LLM."""
import time
import json
import sys

import requests

from . import config
from .pipeline import Motor


def main():
    try:
        requests.get(config.SOC_API_URL + "/alerts", params={"limit": 1}, timeout=5).raise_for_status()
    except requests.RequestException as e:
        sys.exit(f"API mock no disponible a {config.SOC_API_URL}: {e}")
    if len(sys.argv) > 1:
        aid = sys.argv[1]
    else:
        aid = requests.get(config.SOC_API_URL + "/alerts", params={"limit": 1}, timeout=5).json()["items"][0]["alert_id"]
    t0 = time.time()
    motor = Motor()
    print(f"motor: {motor.build_seconds} s")
    g = motor.grupo_de.get(aid)
    print("prefiltro:", motor.pref.get(aid, {}).get("decision"), "| grupo:", g["grupo_id"] if g else None,
          f"({len(g['alert_ids'])} alertas)" if g else "")
    t = motor.ticket_de(aid)
    print(f"temps total amb motor: {round(time.time() - t0, 1)} s")
    print(json.dumps({k: t.get(k) for k in ("ticket_id", "alert_ids", "verdict", "severity", "severity_rationale", "confidence",
                                         "escalation", "triage_seconds", "usage")}, indent=2, ensure_ascii=False))
    u = t.get("usage", {})
    print(f"temps: total {t.get('triage_seconds')} s | precarrega {u.get('prefetch_seconds')} s | "
          f"LLM per pas {u.get('llm_seconds')} | eines {u.get('tools_seconds')} s")
    print("eines usades:", [x["tool"] for x in t.get("tool_trace", [])])
    print("resum:", t.get("summary"))


if __name__ == "__main__":
    main()
