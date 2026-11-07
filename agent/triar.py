"""triar(alert_id) -> ticket (formato ticket_salida.schema.json + extras de ui/CONTRATO_TICKET.md).
El LLM investiga i argumenta; el CODI calcula severitat, escalat obligatori i aprovacions."""
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor

from openai import BadRequestError, OpenAI

from . import config
from .prompts import SYSTEM_PROMPT
from .severity import LEVELS, compute_severity
from .context import prefetch, summarize_logs
from .tools import TOOLS, call_tool, format_for_model, scan_injection

B, S = {"type": "boolean"}, {"type": "string"}
SUBMIT = {
    "name": "submit_ticket",
    "description": "Lliura la conclusio final del triatge. Crida-la una sola vegada, al final.",
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
                "blocked_before_effect": B, "authorized_flow": B}},
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


def build_ticket(sub, trace, seconds, usage, inj_hits):
    f = sub.get("severity_factors") or {}
    sev, why = compute_severity(f)
    verdict = sub.get("verdict", "needs_more_info")
    if f.get("authorized_flow") and verdict == "true_positive":
        verdict = "benign_true_positive"
    fl = sub.get("escalation_flags") or {}
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
    ids = sub.get("alert_ids") or []
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
        "severity": sev, "severity_rationale": why, "affected": sub.get("affected") or {},
        "summary": sub.get("summary", ""), "evidence": sub.get("evidence") or [], "enrichment": sub.get("enrichment") or [],
        "mitre": sub.get("mitre") or [], "recommended_actions": actions, "executed_actions": [],
        "escalation": {"escalate": escalate, "to": to if escalate else "", "reason": "; ".join(reasons)},
        "open_questions": sub.get("open_questions") or [], "triage_seconds": round(seconds, 1),
        "alerts": alerts, "first_alert_at": min((a["created_at"] for a in alerts if a["created_at"]), default=None),
        "prompt_injection": inj, "devils_advocate": sub.get("devils_advocate", ""), "tool_trace": trace,
        "status": status, "usage": usage, "model": config.MODEL,
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
            return (f'<untrusted_data tool="{name}">{{"repetida": true, "nota": "Ja tens aquest resultat mes amunt; '
                    f'no el tornis a demanar."}}</untrusted_data>')
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
    t0, trace, inj_hits = time.time(), [], []
    usage = {"input_tokens": 0, "output_tokens": 0, "steps": 0, "llm_seconds": [], "tools_seconds": 0.0}
    try:
        if not config.MODEL:
            raise RuntimeError("falta TRIAGE_MODEL (id del model)")
        if not config.LLM_API_KEY:
            raise RuntimeError("falta LLM_API_KEY (clau del LLM de l'equip)")
        client = OpenAI(base_url=config.LLM_BASE_URL, api_key=config.LLM_API_KEY, timeout=config.LLM_TIMEOUT)
        tools = [_as_openai_tool(t) for t in TOOLS + [SUBMIT]]
        run = _make_runner(trace, inj_hits)
        if config.PREFETCH:
            tp = time.time()
            _, ctx = prefetch(alert_id, run)
            usage["prefetch_seconds"] = round(time.time() - tp, 1)
            first = (f"Tria l'alerta {alert_id}. El codi ja ha demanat l'alerta i el context de les seves entitats "
                     "(actius, usuaris, intel, canvis); NO ho tornis a demanar. Correlaciona amb search_logs "
                     "(diverses cerques a la vegada si cal) i acaba amb submit_ticket.\n\n"
                     + "\n".join(f"[{n} {json.dumps(a, ensure_ascii=False)}]\n{t}" for n, a, t in ctx))
        else:
            first = f"Tria l'alerta {alert_id}. Comenca amb get_alert."
        msgs = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": first}]
        nudged = False
        with ThreadPoolExecutor(max_workers=8) as pool:
            for step in range(1, config.MAX_STEPS + 1):
                last = step == config.MAX_STEPS
                if step == config.NUDGE_AFTER + 1 or last:
                    msgs.append({"role": "user", "content": (
                        "ULTIM PAS: crida ARA submit_ticket amb el que tinguis; posa el que falti a open_questions."
                        if last else "Ja tens prou context: si no et falta res essencial, crida submit_ticket ara.")})
                m = _complete(client, msgs, tools, usage, FORCE_SUBMIT if last else "auto")
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
                    return build_ticket(sub, trace, time.time() - t0, usage, inj_hits)
                if not calls:
                    if nudged:
                        raise RuntimeError("el model no ha cridat submit_ticket")
                    nudged = True
                    msgs.append({"role": "user", "content": "Acaba cridant submit_ticket amb la teva conclusio."})
                    continue

                def one(item):
                    c, args = item
                    if args is None:
                        content = json.dumps({"error": "arguments no son JSON valid; torna-ho a provar"})
                        trace.append({"tool": c.function.name, "args": c.function.arguments, "result": content})
                        return content
                    return run(c.function.name, args)
                tt = time.time()
                outs = list(pool.map(one, parsed))  # eines en paral·lel, resultats en ordre
                usage["tools_seconds"] = round(usage["tools_seconds"] + time.time() - tt, 1)
                for (c, _), content in zip(parsed, outs):
                    msgs.append({"role": "tool", "tool_call_id": c.id, "content": content})
        raise RuntimeError(f"maxim de {config.MAX_STEPS} passos sense conclusio")
    except Exception as e:  # triar no ha de llancar mai
        return fallback_ticket(alert_id, f"{type(e).__name__}: {e}", trace, time.time() - t0, usage)
