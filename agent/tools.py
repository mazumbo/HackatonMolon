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
    _tool("get_alert", "Detall d'una alerta pel seu alert_id.", {"alert_id": _S}, ["alert_id"]),
    _tool("get_asset", "CMDB: criticitat, servei, propietari, vulnerabilitats. Cerca per hostname o IP. "
          "status 404 = no es a la CMDB (desconegut, NO vol dir benigne).", {"key": _S}, ["key"]),
    _tool("get_user", "Directori: rol, privilegis, VIP, manager, esdeveniments de RRHH. UPN o username.",
          {"key": _S}, ["key"]),
    _tool("search_logs", "Cerca de text lliure en una font de logs (proxy, dns, edr_events, idp_signins, waf, email, "
          "ecom_auth, firewall, email_clicks, vpn, ai_gateway, ecom_account, cloudtrail, sql_audit, dlp, idp_audit, "
          "cicd_builds, ad_events). desde/hasta en ISO 8601 UTC. Si truncated=true, afina la consulta.",
          {"source": _S, "q": _S, "desde": _S, "hasta": _S, "limit": {"type": "integer"}}, ["source"]),
    _tool("get_intel", "TIP intern + GeoIP/ASN per a una IP, domini o hash. tip=null NO vol dir net.",
          {"indicator": _S}, ["indicator"]),
    _tool("get_sandbox", "Informe de sandbox per sha256. 404 = no s'ha enviat, no vol dir net.",
          {"sha256": _S}, ["sha256"]),
    _tool("search_changes", "Calendari de canvis i fluxos aprovats (cerca per text: host, usuari, ticket...).",
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


def call_tool(name, args):
    if name not in PATHS:
        return {"status": 0, "error": f"eina desconeguda: {name}"}
    path, qkeys = PATHS[name]
    try:
        url = SOC_API_URL + path.format(**{k: quote(str(v), safe="") for k, v in args.items()})
    except KeyError as e:
        return {"status": 0, "error": f"falta l'argument {e}"}
    params = {k: args[k] for k in qkeys if args.get(k) not in (None, "")}
    if "limit" in params:
        params["limit"] = max(1, min(int(params["limit"]), 200))
    elif name == "search_logs":
        params["limit"] = 50
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
        text = text[:MAX_TOOL_CHARS] + f" ...[TALLAT a {MAX_TOOL_CHARS} caracters; afina la consulta]"
    text = text.replace("</untrusted_data>", "<\\/untrusted_data>")
    return f'<untrusted_data tool="{name}">\n{text}\n</untrusted_data>'
