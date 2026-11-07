"""Test de fum del hito H1: python -m agent.smoke_test ALR-XXXXXXXX-XXXXXX"""
import json
import sys

import requests

from . import config
from .triar import triar


def main():
    try:
        requests.get(config.SOC_API_URL + "/alerts", params={"limit": 1}, timeout=5).raise_for_status()
    except requests.RequestException as e:
        sys.exit(f"API mock no disponible a {config.SOC_API_URL}: {e}")
    if len(sys.argv) > 1:
        aid = sys.argv[1]
    else:
        aid = requests.get(config.SOC_API_URL + "/alerts", params={"limit": 1}, timeout=5).json()["items"][0]["alert_id"]
    t = triar(aid)
    print(json.dumps({k: t.get(k) for k in ("ticket_id", "verdict", "severity", "severity_rationale", "confidence",
                                         "escalation", "triage_seconds", "usage")}, indent=2, ensure_ascii=False))
    u = t.get("usage", {})
    print(f"temps: total {t.get('triage_seconds')} s | precarrega {u.get('prefetch_seconds')} s | "
          f"LLM per pas {u.get('llm_seconds')} | eines {u.get('tools_seconds')} s")
    print("eines usades:", [x["tool"] for x in t.get("tool_trace", [])])
    print("resum:", t.get("summary"))


if __name__ == "__main__":
    main()
