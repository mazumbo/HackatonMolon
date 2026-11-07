"""Bucle d'agent sobre Quiver AI (https://docs.quiver.ai), API estil OpenAI Responses.

POST {QUIVER_BASE_URL}/responses, Authorization: Bearer <QUIVER_API_KEY>.
- Sense estat: store=false i previous_response_id=null, aixi que reenviem tot l'historial a `input`.
- Les eines de funcio tornen com a items `function_call`; les executem nosaltres i les retornem
  com a `function_call_output` amb el mateix call_id.
- arrow-2 / arrow-2-telos rebutgen temperature/top_p/presence_penalty no per defecte: no els enviem.
- tool_choice="required": el model sempre ha de cridar una eina (acaba amb submit_ticket),
  aixi no depenem que torni text lliure (els models Arrow estan pensats per a SVG).
"""
import json
import time

import requests

from . import config


def to_responses_tools(anthropic_tools):
    """Converteix el format d'eines d'Anthropic (input_schema) al de Responses (parameters)."""
    return [{"type": "function", "name": t["name"], "description": t.get("description", ""),
             "parameters": t["input_schema"], "strict": False} for t in anthropic_tools]


def _post(body):
    url = config.QUIVER_BASE_URL + "/responses"
    headers = {"Authorization": f"Bearer {config.QUIVER_API_KEY}", "Content-Type": "application/json"}
    for intent in range(4):
        r = requests.post(url, json=body, headers=headers, timeout=180)
        if r.status_code in (429, 500, 502, 503, 504) and intent < 3:
            espera = r.headers.get("Retry-After")
            time.sleep(float(espera) if espera and espera.replace(".", "", 1).isdigit() else 2 ** (intent + 1))
            continue
        if r.status_code >= 400:
            raise RuntimeError(f"Quiver HTTP {r.status_code}: {r.text[:500]}")
        return r.json()
    raise RuntimeError("Quiver: massa reintents")


def run_loop(system_prompt, user_msg, tools, run_tool, usage):
    """Executa el bucle fins que el model crida submit_ticket.

    tools: llista d'eines en format Anthropic (inclou submit_ticket).
    run_tool(name, args) -> text per al model.
    Retorna el dict d'arguments de submit_ticket.
    """
    if not config.QUIVER_API_KEY:
        raise RuntimeError("falta QUIVER_API_KEY")
    rtools = to_responses_tools(tools)
    history = [{"type": "message", "role": "user", "content": user_msg}]
    for _ in range(config.MAX_STEPS):
        body = {"model": config.MODEL, "instructions": system_prompt, "input": history, "tools": rtools,
                "tool_choice": "required", "parallel_tool_calls": True, "max_output_tokens": 4096, "store": False}
        resp = _post(body)
        u = resp.get("usage") or {}
        usage["input_tokens"] += u.get("input_tokens", 0) or 0
        usage["output_tokens"] += u.get("output_tokens", 0) or 0
        usage["steps"] += 1
        output = resp.get("output") or []
        calls = [o for o in output if o.get("type") == "function_call"]
        # Reenviem els items del model (sense el text de raonament privat, nomes la referencia).
        for o in output:
            if o.get("type") == "function_call":
                history.append({"type": "function_call", "call_id": o["call_id"], "name": o["name"],
                                "arguments": o.get("arguments") or "{}"})
            elif o.get("type") == "reasoning" and o.get("id"):
                history.append({"type": "reasoning", "id": o["id"]})
            elif o.get("type") == "message":
                text = "".join(c.get("text", "") for c in o.get("content") or [] if c.get("type") == "output_text")
                if text:
                    history.append({"type": "message", "role": "assistant", "content": text})
        for c in calls:
            if c["name"] == "submit_ticket":
                return _parse_args(c.get("arguments"))
        if not calls:
            history.append({"type": "message", "role": "user",
                            "content": "Acaba cridant submit_ticket amb la teva conclusio."})
            continue
        for c in calls:
            args = _parse_args(c.get("arguments"))
            history.append({"type": "function_call_output", "call_id": c["call_id"],
                            "output": run_tool(c["name"], args)})
    raise RuntimeError(f"maxim de {config.MAX_STEPS} passos sense conclusio")


def _parse_args(raw):
    if isinstance(raw, dict):
        return raw
    try:
        v = json.loads(raw or "{}")
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}
