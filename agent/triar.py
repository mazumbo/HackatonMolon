"""triar(alert_id) -> ticket (formato ticket_salida.schema.json + extras de ui/CONTRATO_TICKET.md).
El LLM investiga i argumenta; el CODI calcula severitat, escalat obligatori i aprovacions."""
import json
import re
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

from openai import BadRequestError, OpenAI

from . import config
from .prompts import SYSTEM_PROMPT
from .severity import LEVELS, compute_severity
from .context import SERVICE_HOSTS, prefetch, prefetch_group, summarize_logs
from .tools import TOOLS, call_tool, format_for_model, scan_injection

B, S = {"type": "boolean"}, {"type": "string"}
SUBMIT = {
    "name": "submit_ticket",
    "description": "Entrega la conclusión final del triaje. Llámala una sola vez, al final.",
    "input_schema": {"type": "object", "required": ["alert_ids", "title", "verdict", "confidence", "summary",
                                                   "severity_factors", "evidence", "recommended_actions"],
        "properties": {
            "alert_ids": {"type": "array", "items": S},
            "title": S,
            "verdict": {"enum": ["true_positive", "benign_true_positive", "false_positive", "needs_more_info"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "summary": S,
            "severity_factors": {"type": "object", "properties": {
                "rule_severity": {"enum": LEVELS},
                "asset_criticality": {"enum": ["low", "medium", "high", "critical", "unknown"]},
                "confirmed_execution_or_access": B, "privileged_or_vip": B, "personal_or_payment_data": B,
                "blocked_before_effect": B, "authorized_flow": B,
                "factor_evidence": {"type": "object", "description": "Por cada factor que marques (y por la criticidad), "
                    "una frase breve con el hecho concreto y su event_id. Se cita en severity_rationale.",
                    "properties": {k: S for k in ("asset_criticality", "confirmed_execution_or_access", "privileged_or_vip",
                                                  "personal_or_payment_data", "blocked_before_effect")}}}},
            "escalation_flags": {"type": "object", "properties": {
                "malicious_execution_credential_theft_or_persistence": B, "customer_or_employee_data_exfil": B,
                "financial_fraud": B, "attack_chain": B, "ot_involved": B}},
            "affected": {"type": "object"},
            "evidence": {"type": "array", "items": {"type": "object", "properties": {"source": S, "event_id": S, "finding": S}}},
            "enrichment": {"type": "array", "items": {"type": "object", "properties": {"indicator": S, "type": S, "source": S, "result": S}}},
            "mitre": {"type": "array", "items": S},
            "recommended_actions": {"type": "array", "items": {"type": "object", "required": ["action", "target"],
                "properties": {"action": S, "target": S, "justification": S}}},
            "open_questions": {"type": "array", "items": S},
            "prompt_injection": {"type": "array", "items": {"type": "object", "properties": {"source": S, "event_id": S, "excerpt": S, "handling": S}}},
            "devils_advocate": S,
        }},
}
CONTAINMENT = {"isolate_host", "disable_user", "revoke_sessions", "reset_password", "block_ioc", "purge_email", "disable_access_key"}


def _alerts_meta(alert_ids):
    out = []
    for aid in alert_ids:
        r = call_tool("get_alert", {"alert_id": aid})
        a = r.get("body") if r.get("status") == 200 and isinstance(r.get("body"), dict) else {}
        out.append({"alert_id": aid, "created_at": a.get("created_at"), "rule_id": a.get("rule_id"),
                    "rule_name": a.get("rule_name") or a.get("name"),
                    "severity": a.get("severity") or a.get("rule_severity"),
                    "source_product": a.get("source_product") or a.get("product")})
    return out


_engine = {}
_FACTOR_TXT = {"asset_criticality": "criticidad", "confirmed_execution_or_access": "acceso/ejecución",
               "privileged_or_vip": "VIP/privilegios", "personal_or_payment_data": "datos personales/pagos",
               "blocked_before_effect": "bloqueo"}


def _with_service_hosts(a):
    """Copia de l'alerta amb l'actiu que serveix les URL atacades (www.tarvia.example -> WEB-ECOM01), perque el motor
    trobi la criticitat real a l'inventari en lloc d'assumir 'alta' per desconegut."""
    hosts = []
    for url in (a.get("entities") or {}).get("urls") or []:
        h = (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
        if h in SERVICE_HOSTS:
            hosts.append({"hostname": SERVICE_HOSTS[h]})
    if not hosts:
        return a
    e = dict(a.get("entities") or {})
    known = {(x.get("hostname") if isinstance(x, dict) else x) for x in e.get("hosts") or []}
    e["hosts"] = list(e.get("hosts") or []) + [x for x in hosts if x["hostname"] not in known]
    return {**a, "entities": e}


def _rationale(why, alerts, f):
    """Justificacio del motor (regla x criticitat = base, +-1, final) amb les regles concretes i els fets del LLM."""
    rules = sorted({a.get("rule_id") for a in alerts if a.get("rule_id")})
    if rules and why.startswith("Regla "):
        lvl, rest = why[len("Regla "):].split(" ", 1)
        why = f"Regla {lvl} ({', '.join(rules[:4])}{'...' if len(rules) > 4 else ''}) {rest}"
    ev = f.get("factor_evidence") if isinstance(f.get("factor_evidence"), dict) else {}
    det = [f"{_FACTOR_TXT[k]}: {str(v).strip().rstrip('.')[:160]}" for k, v in ev.items()
           if k in _FACTOR_TXT and isinstance(v, str) and v.strip() and (k == "asset_criticality" or f.get(k))]
    return why + (" Hechos: " + "; ".join(det) + "." if det else "")


def _severity(f, alert_ids, alerts_by_id=None, contexto=None):
    """Severitat amb el motor definitiu del rol A (engine/severidad.py): la regla i la criticitat surten de les DADES,
    el LLM nomes pot pujar. Si el motor o el dataset no hi son, es fa servir la matriu provisional d'agent/severity.py."""
    try:
        if "mod" not in _engine:
            from engine import severidad as mod
            _engine["mod"] = mod
            _engine["ctx"] = contexto
        if _engine.get("ctx") is None and contexto is None and not _engine.get("ctx_tried"):
            _engine["ctx_tried"] = True
            try:
                from engine.prefiltro import Contexto
                _engine["ctx"] = Contexto.desde_dataset()
            except Exception:  # sense calendari/WAF: el motor funciona igual, sense verificar autoritzacions
                _engine["ctx"] = None
        alerts = []
        for aid in alert_ids:
            if alerts_by_id and aid in alerts_by_id:
                alerts.append(alerts_by_id[aid])
                continue
            r = call_tool("get_alert", {"alert_id": aid})
            if r.get("status") == 200 and isinstance(r.get("body"), dict):
                alerts.append(r["body"])
        note = ""
        if alerts and all(str(a.get("rule_id", "")).startswith("UC-AI-") for a in alerts):
            # Asistent d'IA: el que filtra son dades del seu propi context (prompt, codis de descompte). El LLM tendeix a
            # comptar-ho com a acces confirmat o dades personals; aqui els +1 nomes poden sortir de les dades.
            ups = [k for k in ("confirmed_execution_or_access", "privileged_or_vip", "personal_or_payment_data") if f.get(k)]
            if ups:
                f = {**f, **{k: False for k in ups}}
                note = (" En alertas del asistente de IA no se aplican los +1 que propone el LLM sin datos que lo confirmen "
                        "(" + ", ".join(ups) + ").")
        r = _engine["mod"].calcular_severidad([_with_service_hosts(a) for a in alerts], f,
                                               contexto=contexto or _engine["ctx"])
        return r["severidad"], _rationale(r["justificacion"], alerts, f) + note, r.get("autorizado_verificado", False)
    except Exception as e:
        sev, why = compute_severity(f)
        return sev, why + f" (matriz provisional: motor del rol A no disponible: {type(e).__name__})", False


_LIST_OF_DICT = {"evidence": "finding", "enrichment": "result", "recommended_actions": "action", "prompt_injection": "excerpt"}


def _as_json(v):
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def _normalize(sub):
    """Els models oberts a vegades envien objectes o llistes com a text JSON, o elements de llista com a text.
    Es deixa tot amb la forma de l'esquema perque build_ticket no peti."""
    sub = dict(sub) if isinstance(sub, dict) else {}
    for k in ("severity_factors", "escalation_flags", "affected"):
        v = _as_json(sub.get(k))
        sub[k] = v if isinstance(v, dict) else {}
    for k, main in _LIST_OF_DICT.items():
        v = _as_json(sub.get(k))
        v = v if isinstance(v, list) else ([v] if v else [])
        sub[k] = [x if isinstance(x, dict) else {main: str(x)} for x in v]
        if k == "recommended_actions":
            for x in sub[k]:
                x.setdefault("action", "")
                x.setdefault("target", "")
    for k in ("open_questions", "mitre", "alert_ids"):
        v = _as_json(sub.get(k))
        sub[k] = [str(x) for x in v] if isinstance(v, list) else ([str(v)] if v else [])
    for k in ("title", "summary", "devils_advocate"):
        if not isinstance(sub.get(k, ""), str):
            sub[k] = json.dumps(sub[k], ensure_ascii=False)
    try:
        sub["confidence"] = float(sub.get("confidence", 0.0))
    except (TypeError, ValueError):
        sub["confidence"] = 0.0
    return sub


def build_ticket(sub, trace, seconds, usage, inj_hits, group_ids=None, grupo=None, alerts_by_id=None, contexto=None,
                 prefilter=None):
    sub = _normalize(sub)
    f = sub.get("severity_factors") or {}
    # Els alert_ids del ticket son els del GRUP (motor del rol A); el que proposi el model de mes, a part.
    llm_ids = [i for i in (sub.get("alert_ids") or []) if isinstance(i, str)]
    ids = list(group_ids) if group_ids else llm_ids
    extra_ids = [i for i in llm_ids if i not in ids]
    sev, why, authorized = _severity(f, ids, alerts_by_id, contexto)
    verdict = sub.get("verdict", "needs_more_info")
    open_q = list(sub.get("open_questions") or [])
    if authorized and verdict in ("true_positive", "false_positive"):
        # politica_soc.md: alerta explicada per un canvi aprovat (verificat pel codi) -> benign_true_positive
        verdict = "benign_true_positive"
    elif verdict == "benign_true_positive" and not authorized:
        # "Autoritzat" nomes si el codi ho verifica al calendari (autorizado_verificado); si nomes ho diu el LLM, no.
        # No es pot tancar com a autoritzat, pero tampoc afirmar un atac que el model no veu: decideix una persona.
        verdict = "needs_more_info"
        if sev in ("high", "critical"):  # el model no hi veu atac: revisio humana, pero sense ocupar la cua urgent
            why += f" El modelo no ve ataque y falta verificarlo: severidad medium en lugar de {sev}."
            sev = "medium"
        open_q.append("El modelo ve actividad legítima, pero el calendario de cambios no la verifica: "
                      "confirmar con el responsable antes de cerrar.")
    if verdict == "false_positive" and sev not in ("informational", "low"):
        # La regla s'equivoca i no hi ha atac: no pot passar per davant d'alertes reals a la cua.
        why += f" Falso positivo (sin ataque): severidad informational en lugar de {sev}."
        sev = "informational"
    fl = dict(sub.get("escalation_flags") or {})
    rules = [str((alerts_by_id or {}).get(i, {}).get("rule_id", "")) for i in ids]
    if rules and all(r.startswith("UC-AI-") for r in rules) and fl.get("customer_or_employee_data_exfil"):
        # mateix criteri que a _severity: el que filtra l'assistent (prompt, codis interns) no implica DPO sense dades
        fl["customer_or_employee_data_exfil"] = False
        open_q.append("El modelo marcaba posible salida de datos personales (DPO) desde el asistente de IA: "
                      "confirmar si se expusieron datos reales de clientes antes de avisar al DPO.")
    reasons = []
    if verdict == "true_positive" and sev in ("high", "critical"):
        reasons.append(f"true_positive de severidad {sev}")
    for k, txt in (("malicious_execution_credential_theft_or_persistence", "ejecucion/robo de credenciales/persistencia"),
                   ("customer_or_employee_data_exfil", "posible salida de datos personales (implica DPO)"),
                   ("financial_fraud", "fraude economico"), ("attack_chain", "cadena de ataque")):
        if fl.get(k):
            reasons.append(txt)
    if verdict == "needs_more_info":
        reasons.append("evidencia insuficiente: revision humana")
    to = "N2 de guardia (telefono)" if sev == "critical" else "N2"
    if fl.get("ot_involved"):
        to, reasons = "Responsable de Operaciones (OT: solo escalar)", reasons + ["OT implicada"]
    actions = []
    for a in sub.get("recommended_actions") or []:
        a = dict(a)
        a["requires_approval"] = True if a.get("action") in CONTAINMENT else bool(a.get("requires_approval", False))
        if fl.get("ot_involved") and a.get("action") in CONTAINMENT:
            continue
        actions.append(a)
    escalate = bool(reasons)
    status = "pending_approval" if any(a["requires_approval"] for a in actions) else ("open" if escalate or verdict == "true_positive" else "closed")
    inj = list(sub.get("prompt_injection") or [])
    known = {i.get("excerpt") for i in inj}
    inj += [{"source": s, "event_id": "", "excerpt": e, "handling": "detectado por heuristica de codigo; tratado como dato"}
            for s, e in inj_hits if e not in known]
    alerts = _alerts_meta(ids)
    return {
        "ticket_id": "TKT-" + (ids[0] if ids else "SIN-ALERTA"), "alert_ids": ids,
        "title": sub.get("title", ""), "verdict": verdict, "confidence": sub.get("confidence", 0.0),
        "severity": sev, "severity_rationale": why, "severity_factors": f, "affected": sub.get("affected") or {},
        "summary": sub.get("summary", ""), "evidence": sub.get("evidence") or [], "enrichment": sub.get("enrichment") or [],
        "mitre": sub.get("mitre") or [], "recommended_actions": actions, "executed_actions": [],
        "escalation": {"escalate": escalate, "to": to if escalate else "", "reason": "; ".join(reasons)},
        "open_questions": open_q, "triage_seconds": round(seconds, 1),
        "alerts": alerts, "first_alert_at": min((a["created_at"] for a in alerts if a["created_at"]), default=None),
        "prompt_injection": inj, "devils_advocate": sub.get("devils_advocate", ""), "tool_trace": trace,
        "status": status, "usage": usage, "model": config.MODEL,
        **({"group": {"grupo_id": grupo.get("grupo_id"), "uniones": grupo.get("uniones", []),
                      "entidades_clave": grupo.get("entidades_clave", []), "reglas": grupo.get("reglas", {})}}
           if grupo else {}),
        **({"prefilter": prefilter} if prefilter else {}),
        **({"related_alert_ids_suggested": extra_ids} if extra_ids else {}),
    }


def fallback_ticket(alert_id, error, trace, seconds, usage):
    return {"ticket_id": "TKT-" + alert_id, "alert_ids": [alert_id], "title": "Triaje automatico fallido: requiere revision humana",
            "verdict": "needs_more_info", "confidence": 0.0, "severity": "medium",
            "severity_rationale": "No calculada: fallo del agente. Severidad provisional.",
            "summary": f"El agente no pudo completar el triaje ({error}).", "evidence": [], "recommended_actions": [],
            "executed_actions": [], "escalation": {"escalate": True, "to": "N2", "reason": "fallo del agente"},
            "open_questions": [error], "triage_seconds": round(seconds, 1), "tool_trace": trace, "status": "open", "usage": usage}


def _as_openai_tool(t):
    return {"type": "function", "function": {"name": t["name"], "description": t.get("description", ""),
                                             "parameters": t["input_schema"]}}


def _args(raw):
    try:
        v = json.loads(raw or "{}")
        return v if isinstance(v, dict) else None
    except (TypeError, ValueError):
        return None


def _submit_from_text(text):
    """Si el model respon amb el ticket en JSON dins del text (sense tool call), el recuperem."""
    if not text or "{" not in text:
        return None
    try:
        v = json.loads(text[text.index("{"):text.rindex("}") + 1])
    except ValueError:
        return None
    v = v.get("arguments", v) if isinstance(v, dict) else None
    return v if isinstance(v, dict) and "verdict" in v and "alert_ids" in v else None


_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_no_think = {"on": config.LLM_NO_THINK}


def _strip_think(text):
    """El raonament intern no es reenvia: nomes engreixa l'historial i alenteix cada pas."""
    return _THINK.sub("", text or "").strip()


FORCE_SUBMIT = {"type": "function", "function": {"name": "submit_ticket"}}


def _complete(client, msgs, tools, usage, tool_choice="auto"):
    kw = dict(model=config.MODEL, max_tokens=config.MAX_OUTPUT_TOKENS, temperature=0,
              tools=tools, tool_choice=tool_choice, messages=msgs)
    if _no_think["on"]:
        kw["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}
    t = time.time()
    try:
        resp = client.chat.completions.create(**kw)
    except BadRequestError:
        if kw["tool_choice"] != "auto":  # passarela sense tool_choice amb nom: ho demanem en text
            kw["tool_choice"] = "auto"
        elif _no_think["on"]:
            _no_think["on"] = False  # la passarela no accepta el parametre: seguim sense
            kw.pop("extra_body", None)
        else:
            raise
        resp = client.chat.completions.create(**kw)
    usage["llm_seconds"].append(round(time.time() - t, 1))
    if resp.usage:
        usage["input_tokens"] += resp.usage.prompt_tokens or 0
        usage["output_tokens"] += resp.usage.completion_tokens or 0
    usage["steps"] += 1
    return resp.choices[0].message


def _make_runner(trace, inj_hits):
    seen = {}

    def run(name, args):
        key = name + json.dumps(args, sort_keys=True, ensure_ascii=False)
        if key in seen:  # el model repeteix una consulta: no la tornem a fer ni a enviar sencera
            return (f'<untrusted_data tool="{name}">{{"repetida": true, "nota": "Ya tienes este resultado más arriba; '
                    f'no lo vuelvas a pedir."}}</untrusted_data>')
        seen[key] = True
        r = call_tool(name, args)
        txt = json.dumps(r, ensure_ascii=False)
        inj_hits.extend((name, e) for e in scan_injection(txt))  # sobre les dades en brut, abans de resumir
        if name == "search_logs" and r.get("status") == 200:
            r = {**r, "body": summarize_logs(r.get("body"))}
        trace.append({"tool": name, "args": args, "result": txt[:600]})
        return format_for_model(name, r)
    return run


def triar(alert_id):
    """Una sola alerta, sense motor (compatibilitat). Per a la cadena completa: agent.pipeline.triar_alerta()."""
    return triar_grupo([alert_id])


def _calendar_check(alert_ids, alerts_by_id, contexto):
    """Quines alertes del grup cobreix un canvi aprovat, verificat pel codi (finestra, origen i abast)."""
    if contexto is None:
        return None
    si, no = {}, []
    for aid in alert_ids:
        a = alerts_by_id.get(aid)
        if not a:
            continue
        try:
            e = contexto._cambio_que_explica(a)
        except Exception:
            e = None
        if e:
            si[aid] = getattr(e[0], "id", str(e[0]))
        else:
            no.append(aid)
    return si, no


def _first_message(alert_ids, compact, ctx, grupo, prefilter, calendar=None):
    head = (f"Tría el incidente formado por {len(alert_ids)} alertas ({', '.join(alert_ids[:6])}"
            f"{'...' if len(alert_ids) > 6 else ''}). Es UN solo ticket con TODOS esos alert_ids. "
            if len(alert_ids) > 1 else f"Tría la alerta {alert_ids[0]}. ")
    parts = [head + "El código ya ha pedido las alertas y el contexto de sus entidades (activos, usuarios, intel, "
             "calendario de cambios completo); NO lo vuelvas a pedir. Correlaciona con search_logs solo si hace falta "
             "(varias búsquedas a la vez) y acaba con submit_ticket. Si ves relación con alertas o logs que NO están en el grupo "
             "(p. ej. una build de CI y el uso posterior de su clave cloud), dilo en evidence y pon esos alert_ids en alert_ids."]
    if grupo and len(alert_ids) > 1:
        parts.append("POR QUÉ SE HAN AGRUPADO (motor determinista):\n" + json.dumps(
            {"uniones": grupo.get("uniones", [])[:15], "entidades_clave": grupo.get("entidades_clave", []),
             "reglas": grupo.get("reglas", {})}, ensure_ascii=False))
    if len(compact) > 1:
        parts.append("TODAS LAS ALERTAS DEL INCIDENTE (orden temporal):\n<untrusted_data tool=\"grupo\">\n"
                     + "\n".join(json.dumps(c, ensure_ascii=False) for c in compact) + "\n</untrusted_data>")
    if calendar is not None:
        si, no = calendar
        parts.append("VERIFICACIÓN DEL CALENDARIO POR CÓDIGO (ventana, origen y alcance): "
                     + (f"cubiertas por un cambio aprobado: {json.dumps(si)}. " if si else "ninguna alerta está cubierta por un cambio aprobado. ")
                     + (f"NO cubiertas ({len(no)}): {', '.join(no[:12])}{'...' if len(no) > 12 else ''}. Un cambio con un título "
                        "parecido NO autoriza estas alertas: si ocurren fuera de la ventana o desde otro origen, trátalas como "
                        "posible ataque (true_positive), no como actividad autorizada." if no else ""))
    pistas = [p for r in (prefilter or {}).values() for p in (r.get("pistas") or [])]
    if pistas:
        parts.append("PISTAS DEL PREFILTRO (código): " + " | ".join(dict.fromkeys(pistas))[:1500])
    parts.append("\n".join(f"[{n} {json.dumps(a, ensure_ascii=False)}]\n{t}" for n, a, t in ctx))
    return "\n\n".join(parts)


def triar_grupo(alert_ids, grupo=None, alerts=None, contexto=None, prefilter=None):
    """Tria un grup d'alertes (un incident) i torna UN ticket amb tots els alert_ids.
    grupo: dict de engine.agrupacion (uniones, entidades_clave...). alerts: {alert_id: dict} si ja es tenen.
    contexto: engine.prefiltro.Contexto per a la severitat. prefilter: {alert_id: resultat de prefiltrar()}."""
    alert_ids = list(alert_ids)
    t0, trace, inj_hits = time.time(), [], []
    usage = {"input_tokens": 0, "output_tokens": 0, "steps": 0, "llm_seconds": [], "tools_seconds": 0.0}
    alerts_by_id = dict(alerts or {})
    try:
        if not config.MODEL:
            raise RuntimeError("falta TRIAGE_MODEL (id del modelo)")
        if not config.LLM_API_KEY:
            raise RuntimeError("falta LLM_API_KEY (clave del LLM del equipo)")
        client = OpenAI(base_url=config.LLM_BASE_URL, api_key=config.LLM_API_KEY, timeout=config.LLM_TIMEOUT)
        tools = [_as_openai_tool(t) for t in TOOLS + [SUBMIT]]
        run = _make_runner(trace, inj_hits)
        if config.PREFETCH:
            tp = time.time()
            compact, ctx, alerts_by_id = prefetch_group(alert_ids, run, alerts_by_id)
            usage["prefetch_seconds"] = round(time.time() - tp, 1)
            first = _first_message(alert_ids, compact, ctx, grupo, prefilter,
                                   _calendar_check(alert_ids, alerts_by_id, contexto))
        else:
            first = f"Tría la alerta {alert_ids[0]}. Empieza con get_alert."
        msgs = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": first}]
        force_next = False
        with ThreadPoolExecutor(max_workers=8) as pool:
            for step in range(1, config.MAX_STEPS + 1):
                # si el proper pas (estimat com l'ultim que s'ha fet) acabaria passat el pressupost, s'obliga a entregar ja
                next_step = max(usage["llm_seconds"][-1:] or [8.0]) + usage["tools_seconds"] / max(1, step - 1)
                last = (step >= min(config.FORCE_SUBMIT_AT, config.MAX_STEPS)
                        or (step > 1 and time.time() - t0 + next_step > config.TIME_BUDGET))
                if step == config.NUDGE_AFTER + 1 or last:
                    msgs.append({"role": "user", "content": (
                        "ÚLTIMO PASO: llama YA a submit_ticket con lo que tengas; pon lo que falte en open_questions."
                        if last else "Ya tienes contexto suficiente: si no te falta nada esencial, llama a submit_ticket ahora.")})
                m = _complete(client, msgs, tools, usage, FORCE_SUBMIT if last or force_next else "auto")
                calls = list(m.tool_calls or [])
                content = _strip_think(m.content)
                msgs.append({"role": "assistant", "content": content,
                             **({"tool_calls": [{"id": c.id, "type": "function",
                                                 "function": {"name": c.function.name, "arguments": c.function.arguments or "{}"}}
                                                for c in calls]} if calls else {})})
                parsed = [(c, _args(c.function.arguments)) for c in calls]
                sub = next((a for c, a in parsed if c.function.name == "submit_ticket" and a is not None), None)
                if sub is None and not calls:
                    sub = _submit_from_text(content)  # alguns models oberts escriuen el JSON en text
                if sub is not None:
                    usage["llm_seconds_total"] = round(sum(usage["llm_seconds"]), 1)
                    return build_ticket(sub, trace, time.time() - t0, usage, inj_hits, alert_ids, grupo, alerts_by_id,
                                        contexto, prefilter)
                if not calls:
                    if force_next:
                        raise RuntimeError("el modelo no ha llamado a submit_ticket ni forzándolo")
                    force_next = True  # el proper pas obliga submit_ticket (tool_choice), com l'ultim pas
                    msgs.append({"role": "user", "content": "Acaba llamando a submit_ticket con tu conclusión."})
                    continue

                def one(item):
                    c, args = item
                    if args is None:
                        content = json.dumps({"error": "los argumentos no son JSON válido; vuelve a intentarlo"})
                        trace.append({"tool": c.function.name, "args": c.function.arguments, "result": content})
                        return content
                    return run(c.function.name, args)
                tt = time.time()
                outs = list(pool.map(one, parsed))  # eines en paral·lel, resultats en ordre
                usage["tools_seconds"] = round(usage["tools_seconds"] + time.time() - tt, 1)
                for (c, _), content in zip(parsed, outs):
                    msgs.append({"role": "tool", "tool_call_id": c.id, "content": content})
        raise RuntimeError(f"máximo de {config.MAX_STEPS} pasos sin conclusión")
    except Exception as e:  # triar no ha de llancar mai
        t = fallback_ticket(alert_ids[0] if alert_ids else "SIN-ALERTA", f"{type(e).__name__}: {e}", trace,
                            time.time() - t0, usage)
        t["alert_ids"] = alert_ids
        return t
