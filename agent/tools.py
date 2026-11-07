"""Eines de NOMES LECTURA sobre la API mock. No hi ha cap POST (ni contencio ni aprovacions)."""
import json
import re
from urllib.parse import quote

import requests

from .config import MAX_TOOL_CHARS, SOC_API_URL


def _tool(name, desc, props, required):
    return {"name": name, "description": desc,
            "input_schema": {"type": "object", "properties": props, "required": required}}


_S = {"type": "string"}
TOOLS = [
    _tool("get_alert", "Detalle de una alerta por su alert_id.", {"alert_id": _S}, ["alert_id"]),
    _tool("get_asset", "CMDB: criticidad, servicio, propietario, vulnerabilidades. Busca por hostname o IP. "
          "status 404 = no está en la CMDB (desconocido, NO significa benigno).", {"key": _S}, ["key"]),
    _tool("get_user", "Directorio: rol, privilegios, VIP, manager, eventos de RRHH. UPN o username.",
          {"key": _S}, ["key"]),
    _tool("search_logs", "Búsqueda de texto libre en una fuente de logs (proxy, dns, edr_events, idp_signins, waf, email, "
          "ecom_auth, firewall, email_clicks, vpn, ai_gateway, ecom_account, cloudtrail, sql_audit, dlp, idp_audit, "
          "cicd_builds, ad_events). q: un término, varios separados por espacio (AND) o \"a OR b\". desde/hasta en ISO 8601 UTC. "
          "Si truncated=true, afina la consulta.",
          {"source": _S, "q": _S, "desde": _S, "hasta": _S, "limit": {"type": "integer"}}, ["source"]),
    _tool("get_intel", "TIP interno + GeoIP/ASN para una IP, dominio o hash. tip=null NO significa limpio.",
          {"indicator": _S}, ["indicator"]),
    _tool("get_sandbox", "Informe de sandbox por sha256. 404 = no se ha enviado, no significa limpio.",
          {"sha256": _S}, ["sha256"]),
    _tool("search_changes", "Calendario de cambios y flujos aprobados (búsqueda por texto: host, usuario, ticket...; q vacío = todos).",
          {"q": _S}, []),
]

PATHS = {
    "get_alert": ("/alerts/{alert_id}", ()),
    "get_asset": ("/assets/{key}", ()),
    "get_user": ("/users/{key}", ()),
    "search_logs": ("/logs/{source}", ("q", "desde", "hasta", "limit")),
    "get_intel": ("/intel/{indicator}", ()),
    "get_sandbox": ("/sandbox/{sha256}", ()),
    "search_changes": ("/changes", ("q",)),
}

INJECTION_PATTERNS = [
    r"ignor(a|e|ar)\b.{0,40}(instruc|prompt|reglas)", r"ignore\b.{0,40}(instruction|previous|prompt|rules)",
    r"system prompt", r"prompt del sistema", r"you are now", r"ahora eres", r"act(ua|ing) as",
    r"(cierra|close|marca|mark)\b.{0,30}(alerta|alert|ticket).{0,30}(falso|false|benign|benig)",
    r"no (escales|escalar|alert)", r"do not (escalate|alert|flag)",
]
_INJ = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE | re.DOTALL)


def scan_injection(text):
    return [text[max(0, m.start() - 40): m.end() + 40] for m in _INJ.finditer(text)][:5]


def _search_logs_multi(args):
    """La API busca q com a subcadena literal. Aqui: "a OR b" uneix resultats; "a b" (espais) = AND:
    es demana el terme mes llarg i es filtren els events que contenen tots els altres."""
    q = str(args.get("q") or "").strip()
    if " OR " in q:
        parts = [p.strip() for p in q.split(" OR ") if p.strip()]
        items, seen, trunc, status = [], set(), False, 200
        for p in parts[:6]:
            r = _search_logs_multi({**args, "q": p})
            b = r.get("body") if isinstance(r.get("body"), dict) else {}
            status = r.get("status", status)
            trunc = trunc or bool(b.get("truncated"))
            for it in b.get("items") or []:
                k = json.dumps(it, sort_keys=True) if not isinstance(it, dict) else str(it.get("event_id") or it.get("id") or json.dumps(it, sort_keys=True))
                if k not in seen:
                    seen.add(k)
                    items.append(it)
        return {"status": 200 if items else status, "body": {"count": len(items), "truncated": trunc, "items": items}}
    terms = q.split()
    if len(terms) <= 1:
        return _call(*PATHS["search_logs"], args)
    # es demana cada terme i es filtra a partir del mes selectiu (menys resultats, preferint no truncat)
    best = None
    for t in terms[:4]:
        r = _call(*PATHS["search_logs"], {**args, "q": t})
        b = r.get("body")
        if not isinstance(b, dict) or not isinstance(b.get("items"), list):
            continue
        key = (bool(b.get("truncated")), len(b["items"]))
        if best is None or key < best[0]:
            best = (key, t, r)
    if best is None:
        return _call(*PATHS["search_logs"], args)
    _, main, r = best
    b = r["body"]
    rest = [t.lower() for t in terms if t != main]
    items = [it for it in b["items"] if all(t in json.dumps(it, ensure_ascii=False).lower() for t in rest)]
    return {"status": r.get("status"), "body": {**b, "count": len(items), "items": items,
                                                "query_note": f"AND de {terms}: se buscó '{main}' y se filtró por el resto"}}


def call_tool(name, args):
    if name == "search_logs":
        return _search_logs_multi(args)
    if name not in PATHS:
        return {"status": 0, "error": f"eina desconeguda: {name}"}
    return _call(*PATHS[name], args, name=name)


def _call(path, qkeys, args, name="search_logs"):
    try:
        url = SOC_API_URL + path.format(**{k: quote(str(v), safe="") for k, v in args.items()})
    except KeyError as e:
        return {"status": 0, "error": f"falta l'argument {e}"}
    params = {k: args[k] for k in qkeys if args.get(k) not in (None, "")}
    if "limit" in params:
        params["limit"] = max(1, min(int(params["limit"]), 200))
    elif name == "search_logs":
        params["limit"] = 200  # el model en rep un resum (context.summarize_logs), no els 200 en brut
    try:
        r = requests.get(url, params=params, timeout=20)
    except requests.RequestException as e:
        return {"status": 0, "error": str(e)}
    try:
        body = r.json()
    except ValueError:
        body = r.text
    return {"status": r.status_code, "body": body}


def format_for_model(name, result):
    """Resultat en un bloc delimitat: son DADES, mai instruccions."""
    text = json.dumps(result, ensure_ascii=False)
    if len(text) > MAX_TOOL_CHARS:
        text = text[:MAX_TOOL_CHARS] + f" ...[CORTADO a {MAX_TOOL_CHARS} caracteres; afina la consulta]"
    text = text.replace("</untrusted_data>", "<\\/untrusted_data>")
    return f'<untrusted_data tool="{name}">\n{text}\n</untrusted_data>'
