"""triar(alert_id) -> ticket (formato ticket_salida.schema.json + extras de ui/CONTRATO_TICKET.md).
El LLM investiga i argumenta; el CODI calcula severitat, escalat obligatori i aprovacions."""
import json
import time

import anthropic

from . import config
from .prompts import SYSTEM_PROMPT
from .severity import LEVELS, compute_severity
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


def triar(alert_id):
    t0, trace, inj_hits = time.time(), [], []
    usage = {"input_tokens": 0, "output_tokens": 0, "steps": 0}
    try:
        if not config.MODEL:
            raise RuntimeError("falta TRIAGE_MODEL (id del model)")
        client = anthropic.Anthropic()
        msgs = [{"role": "user", "content": f"Tria l'alerta {alert_id}. Comenca amb get_alert."}]
        nudged = False
        for _ in range(config.MAX_STEPS):
            resp = client.messages.create(model=config.MODEL, max_tokens=4096, system=SYSTEM_PROMPT,
                                          tools=TOOLS + [SUBMIT], messages=msgs)
            usage["input_tokens"] += resp.usage.input_tokens
            usage["output_tokens"] += resp.usage.output_tokens
            usage["steps"] += 1
            msgs.append({"role": "assistant", "content": resp.content})
            calls = [b for b in resp.content if b.type == "tool_use"]
            sub = next((c.input for c in calls if c.name == "submit_ticket"), None)
            if sub is not None:
                return build_ticket(sub, trace, time.time() - t0, usage, inj_hits)
            if not calls:
                if nudged:
                    raise RuntimeError("el model no ha cridat submit_ticket")
                nudged = True
                msgs.append({"role": "user", "content": "Acaba cridant submit_ticket amb la teva conclusio."})
                continue
            results = []
            for c in calls:
                r = call_tool(c.name, c.input)
                txt = json.dumps(r, ensure_ascii=False)
                inj_hits += [(c.name, e) for e in scan_injection(txt)]
                trace.append({"tool": c.name, "args": c.input, "result": txt[:600]})
                results.append({"type": "tool_result", "tool_use_id": c.id, "content": format_for_model(c.name, r)})
            msgs.append({"role": "user", "content": results})
        raise RuntimeError(f"maxim de {config.MAX_STEPS} passos sense conclusio")
    except Exception as e:  # triar no ha de llancar mai
        return fallback_ticket(alert_id, f"{type(e).__name__}: {e}", trace, time.time() - t0, usage)
