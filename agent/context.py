"""Acceleradors del triatge: precarrega de context per codi i resum de logs.

- prefetch(alert): demana EN PARAL·LEL l'actiu, l'usuari, la intel i els canvis de les entitats de l'alerta,
  aixi el model no gasta passos (cada pas ~20 s) nomes per demanar dades que sempre calen.
- summarize_logs(body): en lloc de passar 50 esdeveniments en brut, passa recomptes + uns quants exemples.
"""
import ipaddress
import json
from urllib.parse import urlparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from .tools import call_tool

MAX_PREFETCH = 10
# Dominis publics de Tarvia -> actiu de la CMDB que els serveix (la CMDB indexa per hostname/IP, no per domini).
SERVICE_HOSTS = {"www.tarvia.example": "WEB-ECOM01", "tarvia.example": "WEB-ECOM01"}


_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _internal(ip):
    """Xarxa interna de Tarvia (RFC 1918). 198.18.x i similars son externes al dataset."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _RFC1918)


def _plan(alert):
    """Llista de (eina, args) a demanar segons les entitats de l'alerta, sense duplicats."""
    e = alert.get("entities") or {}
    plan = []
    for h in e.get("hosts") or []:
        if isinstance(h, dict) and h.get("hostname"):
            plan.append(("get_asset", {"key": h["hostname"]}))
    for u in e.get("users") or []:
        upn = u.get("upn") if isinstance(u, dict) else u
        if upn:
            plan.append(("get_user", {"key": upn}))
    for url in e.get("urls") or []:  # el servei atacat (p. ex. la botiga online) dona la criticitat de l'actiu
        host = urlparse(url if "://" in url else "http://" + url).hostname
        if host:
            host = SERVICE_HOSTS.get(host.lower(), host)
            plan.append(("get_asset", {"key": host}) if not host.endswith(".example") else ("get_intel", {"indicator": host}))
    for ip in e.get("ips") or []:
        plan.append(("get_asset", {"key": ip}) if _internal(ip) else ("get_intel", {"indicator": ip}))
    for d in e.get("domains") or []:
        plan.append(("get_intel", {"indicator": d}))
    for f in e.get("files") or []:
        if isinstance(f, dict) and f.get("sha256"):
            plan.append(("get_intel", {"indicator": f["sha256"]}))
            plan.append(("get_sandbox", {"sha256": f["sha256"]}))
    # El calendari es petit (~13 canvis) i molts tenen abast generic ("Todos los puestos") que no conte el hostname:
    # el passem sencer perque el model pugui comprovar finestra, origen i abast.
    plan.insert(0, ("search_changes", {"q": ""}))
    seen, out = set(), []
    for name, args in plan:
        k = (name, json.dumps(args, sort_keys=True))
        if k not in seen:
            seen.add(k)
            out.append((name, args))
    return out[:MAX_PREFETCH]


def prefetch(alert_id, run_tool):
    """Retorna (alert_dict, [(eina, args, text_per_al_model)]). run_tool(name, args) -> text."""
    first = call_tool("get_alert", {"alert_id": alert_id})
    alert = first.get("body") if first.get("status") == 200 and isinstance(first.get("body"), dict) else {}
    calls = [("get_alert", {"alert_id": alert_id})] + _plan(alert)
    with ThreadPoolExecutor(max_workers=8) as ex:
        texts = list(ex.map(lambda c: run_tool(c[0], c[1]), calls))
    return alert, [(n, a, t) for (n, a), t in zip(calls, texts)]


_SKIP = {"timestamp", "eventTime", "event_id", "id", "_id", "message", "raw", "body", "prompt", "response", "subject"}


def summarize_logs(body, samples=5, top=5):
    """Resum compacte d'un resultat de /logs/{source}."""
    if not isinstance(body, dict) or not isinstance(body.get("items"), list):
        return body
    items = body["items"]
    times = [str(i.get("timestamp") or i.get("eventTime") or "") for i in items if isinstance(i, dict)]
    times = [t for t in times if t]
    ids = [str(i.get("event_id") or i.get("id") or "") for i in items if isinstance(i, dict)]
    counts = {}
    for k in {k for i in items if isinstance(i, dict) for k in i}:
        if k in _SKIP:
            continue
        vals = [i.get(k) for i in items if isinstance(i, dict) and isinstance(i.get(k), (str, int, float, bool))]
        if not vals:
            continue
        c = Counter(str(v)[:80] for v in vals)
        if len(c) == len(vals) and len(vals) > top:  # tot diferent: no aporta com a recompte
            counts[k] = {"distinct": len(c)}
        else:
            counts[k] = dict(c.most_common(top)) | ({"_distinct": len(c)} if len(c) > top else {})

    def short(i):
        s = json.dumps(i, ensure_ascii=False)
        return s if len(s) <= 500 else s[:500] + "...]"
    ex = items[:samples - 2] + items[-2:] if len(items) > samples else items
    return {"count": body.get("count", len(items)), "truncated": body.get("truncated", False),
            "first": min(times) if times else None, "last": max(times) if times else None,
            "event_ids": [i for i in ids if i][:25], "field_counts": counts,
            "examples": [short(i) for i in ex],
            "note": "Resumen hecho por código. Para ver un evento concreto, búscalo por su event_id con q."}
