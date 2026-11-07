"""Comprova la clau de Quiver i que el model sap cridar eines, sense tocar la API mock.
python -m agent.probar_quiver"""
import json
import sys

import requests

from . import config


def main():
    if not config.QUIVER_API_KEY:
        sys.exit("falta QUIVER_API_KEY a agent/.env")
    h = {"Authorization": f"Bearer {config.QUIVER_API_KEY}", "Content-Type": "application/json"}
    r = requests.get(config.QUIVER_BASE_URL + "/models", headers=h, timeout=30)
    print("GET /models ->", r.status_code)
    if r.ok:
        for m in r.json().get("data", []):
            print("  ", m.get("id"), m.get("supported_operations", ""))
    tool = {"type": "function", "name": "get_alert", "description": "Detall d'una alerta pel seu alert_id.",
            "parameters": {"type": "object", "properties": {"alert_id": {"type": "string"}}, "required": ["alert_id"]},
            "strict": False}
    body = {"model": config.MODEL, "store": False, "tool_choice": "required", "tools": [tool],
            "input": [{"type": "message", "role": "user", "content": "Tria l'alerta ALR-TEST. Comenca amb get_alert."}]}
    r = requests.post(config.QUIVER_BASE_URL + "/responses", json=body, headers=h, timeout=120)
    print(f"POST /responses ({config.MODEL}) ->", r.status_code)
    if not r.ok:
        sys.exit(r.text[:800])
    out = r.json().get("output") or []
    print(json.dumps(out, ensure_ascii=False, indent=2)[:1500])
    ok = any(o.get("type") == "function_call" and o.get("name") == "get_alert" for o in out)
    print("\nOK: el model crida eines" if ok else "\nATENCIO: el model no ha cridat l'eina")


if __name__ == "__main__":
    main()
