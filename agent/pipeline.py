"""Pipeline complet: motor del rol A (prefiltre + agrupacio) + agent LLM (rol B).

1. prefiltrar() a cada alerta: si decideix "cerrar", el ticket surt sense LLM (0 s) amb el veredicte i el motiu del motor.
2. La resta s'agrupen en incidents (engine.agrupacion) i el LLM tria cada GRUP i escriu UN ticket amb tots els alert_ids.

Motor().ticket_de(alert_id) es el cami en viu: si l'alerta no es al dataset (p. ex. les 10 de diumenge) es demana a l'API,
s'afegeix i es reconstrueix el motor (~3 s).
"""
import threading
import time
from collections import Counter

from .tools import call_tool
from .triar import triar_grupo

CERRAR = "cerrar"


class Motor:
    def __init__(self, extra_alerts=()):
        from engine import datos
        self._datos = datos
        self._base = datos.cargar_alertas()
        self._extra = {a["alert_id"]: a for a in extra_alerts if a.get("alert_id")}
        self._lock = threading.Lock()
        self._build()

    def _build(self):
        from engine.agrupacion import Pivotes, agrupar
        from engine.prefiltro import Contexto, prefiltrar
        t0 = time.time()
        base_ids = {a["alert_id"] for a in self._base}
        self.alertas = self._base + [a for i, a in self._extra.items() if i not in base_ids]
        self.por_id = {a["alert_id"]: a for a in self.alertas}
        self.ctx = Contexto.desde_dataset(alertas=self.alertas)
        self.pref = {a["alert_id"]: prefiltrar(a, self.ctx) for a in self.alertas}
        abiertas = [a for a in self.alertas if self.pref[a["alert_id"]]["decision"] != CERRAR]
        piv = Pivotes.desde_dataset(alertas=abiertas)
        self.grupos = agrupar(abiertas, piv, Counter(a.get("rule_id") for a in self.alertas))
        self.grupo_de = {i: g for g in self.grupos for i in g["alert_ids"]}
        self.build_seconds = round(time.time() - t0, 1)

    def asegurar(self, alert_ids):
        """Afegeix al motor les alertes que no coneix (demanades a l'API) i el reconstrueix una sola vegada."""
        nous = []
        for aid in alert_ids:
            if aid in self.por_id:
                continue
            r = call_tool("get_alert", {"alert_id": aid})
            if r.get("status") == 200 and isinstance(r.get("body"), dict):
                nous.append(r["body"])
        if nous:
            with self._lock:
                self._extra.update({a["alert_id"]: a for a in nous})
                self._build()
        return [a for a in alert_ids if a in self.por_id]

    def cerrada(self, aid):
        return self.pref.get(aid, {}).get("decision") == CERRAR

    def ticket_prefiltro(self, aid):
        return ticket_prefiltro(self.por_id[aid], self.pref[aid])

    def triar_grupo_de(self, aid):
        g = self.grupo_de.get(aid)
        ids = g["alert_ids"] if g else [aid]
        return triar_grupo(ids, grupo=g, alerts={i: self.por_id[i] for i in ids if i in self.por_id},
                           contexto=self.ctx, prefilter={i: self.pref[i] for i in ids if i in self.pref})

    def ticket_de(self, aid):
        """Cami en viu d'una alerta: prefiltre -> ticket sense LLM, o el grup sencer al LLM."""
        if not self.asegurar([aid]):
            return triar_grupo([aid])  # l'API no la coneix: que l'agent ho intenti i ho expliqui
        if self.cerrada(aid):
            return self.ticket_prefiltro(aid)
        t = self.triar_grupo_de(aid)
        t["ticket_id"] = "TKT-" + aid
        return t


def ticket_prefiltro(alert, r):
    """Ticket tancat pel motor, sense LLM. Mateix format que els de l'agent."""
    aid = alert["alert_id"]
    cambio = r.get("cambio")
    veredicto = r.get("veredicto") or "benign_true_positive"
    sev = r.get("severidad") or "informational"
    meta = [{"alert_id": aid, "created_at": alert.get("created_at"), "rule_id": alert.get("rule_id"),
             "rule_name": alert.get("rule_name") or alert.get("name"), "severity": alert.get("severity"),
             "source_product": alert.get("source_product") or alert.get("product")}]
    motivo = r.get("motivo") or "cerrada por el prefiltro"
    return {
        "ticket_id": "TKT-" + aid, "alert_ids": [aid],
        "title": ("Actividad autorizada: " if veredicto == "benign_true_positive" else "Ataque bloqueado sin efecto: ")
                 + (alert.get("rule_name") or alert.get("rule_id") or "alerta"),
        "verdict": veredicto, "confidence": 0.9, "severity": sev,
        "severity_rationale": f"Prefiltro del motor: {motivo}",
        "affected": {}, "summary": f"Cerrada por código sin LLM. {motivo}",
        "evidence": [{"source": "changes" if cambio else "prefiltro", "event_id": str(cambio or ""), "finding": motivo}],
        "enrichment": [], "mitre": [], "recommended_actions": [], "executed_actions": [],
        "escalation": {"escalate": False, "to": "", "reason": ""},
        "open_questions": [], "triage_seconds": 0.0, "alerts": meta, "first_alert_at": meta[0]["created_at"],
        "prompt_injection": [], "devils_advocate": "", "tool_trace": [], "status": "closed",
        "usage": {"input_tokens": 0, "output_tokens": 0, "steps": 0}, "model": "prefiltro",
        "prefilter": r,
    }
