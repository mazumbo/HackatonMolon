"""Tests de la matriz de severidad: sobre todo, que el LLM pueda subir pero nunca bajar."""
from engine.prefiltro import Contexto
from engine.severidad import Inventario, calcular_severidad, compute_severity

INV = Inventario(
    activos={"WS-1": {"criticality": "Media"}, "SQL-CRM01": {"criticality": "Crítica"}, "TPV-1": {"criticality": "Baja"}},
    usuarios={"ana@tarvia.example": {"account_type": "user", "vip": "False", "privileged": "False"},
              "ceo@tarvia.example": {"account_type": "user", "vip": "True", "privileged": "False"}},
)


def alerta(sev="medium", hosts=(), users=(), ev=None, rule="UC-X", aid="A1"):
    return {"alert_id": aid, "created_at": "2026-10-10T10:00:00.000Z", "rule_id": rule, "severity": sev,
            "entities": {"hosts": [{"hostname": h} for h in hosts], "users": [{"upn": u} for u in users]},
            "evidence": ev or {}}


def sev(alertas, f=None, ctx=None):
    return calcular_severidad(alertas, f, inventario=INV, contexto=ctx)


def test_matriz_basica():
    assert sev([alerta("medium", hosts=["WS-1"])])["severidad"] == "medium"
    assert sev([alerta("high", hosts=["SQL-CRM01"])])["severidad"] == "critical"
    assert sev([alerta("low", hosts=["TPV-1"])])["severidad"] == "informational"


def test_manda_el_afectado_mas_critico():
    r = sev([alerta("medium", hosts=["WS-1", "SQL-CRM01"])])
    assert r["criticidad"] == "critical" and r["severidad"] == "high"


def test_desconocido_cuenta_como_alta():
    r = sev([alerta("medium", hosts=["NO-EXISTE"])])
    assert r["criticidad"] == "high" and "no está en el inventario" in r["justificacion"]


def test_vip_sube_un_nivel():
    assert sev([alerta("medium", users=["ceo@tarvia.example"])])["severidad"] == "high"


def test_bloqueado_baja_un_nivel_sin_actividad_posterior():
    r = sev([alerta("medium", hosts=["WS-1"], ev={"action": "blocked"})])
    assert r["severidad"] == "low" and r["ajuste"] == -1


def test_llm_no_puede_bajar_nada():
    base = alerta("high", hosts=["SQL-CRM01"])
    trampa = {"rule_severity": "informational", "asset_criticality": "low",
              "blocked_before_effect": True, "authorized_flow": True}
    r = sev([base], trampa)
    assert r["severidad"] == "critical"
    assert any("no se baja" in a for a in r["avisos"]) and any("se ignora" in a for a in r["avisos"])


def test_llm_si_puede_subir():
    r = sev([alerta("medium", hosts=["WS-1"])], {"asset_criticality": "critical", "confirmed_execution_or_access": True})
    assert r["severidad"] == "critical"


def test_maximo_un_nivel_y_se_compensan():
    a = alerta("medium", hosts=["WS-1"], users=["ceo@tarvia.example"], ev={"action": "blocked"})
    r = sev([a], {"confirmed_execution_or_access": True, "personal_or_payment_data": True})
    assert r["severidad"] == "high"  # +1 como mucho, y no se baja porque hay motivos para subir


def test_bloqueado_con_actividad_posterior_no_baja():
    a = alerta("medium", hosts=["WS-1"], ev={"action": "blocked"}, aid="A1")
    otra = alerta("high", hosts=["WS-1"], rule="UC-EDR-004", aid="B1")
    ctx = Contexto([a, otra], [])
    r = sev([a], ctx=ctx)
    assert r["severidad"] == "medium" and any("actividad posterior" in x for x in r["avisos"])


def test_autorizado_solo_si_lo_verifica_el_calendario():
    cambio = [{"id": "CHG-2026-1042", "titulo": "Pentest externo de la tienda online",
               "inicio": "2026-10-08 08:00", "fin": "2026-10-10 18:00", "alcance": ""}]
    a = {"alert_id": "A1", "created_at": "2026-10-09T10:00:00.000Z", "rule_id": "UC-WEB-001", "severity": "high",
         "entities": {"ips": ["192.0.2.10"]}, "evidence": {}}
    r = sev([a], ctx=Contexto([a], cambio))
    assert r["autorizado_verificado"] and r["severidad"] in ("informational", "low")


def test_compatible_con_el_agente_de_b():
    s, why = compute_severity({"rule_severity": "high", "asset_criticality": "critical"})
    assert s == "critical" and isinstance(why, str)


def test_sin_datos_no_rompe():
    assert sev([])["severidad"] in ("medium", "high")
    assert sev([{"alert_id": "X", "entities": None, "evidence": "texto"}])["severidad"]


def test_ataque_web_bloqueado_oportunista_es_informational_aunque_el_activo_sea_critico():
    """01_contexto/ticket_ejemplo.json: regla low x activo crítico = medium, -1 por bloqueo -> informational."""
    a = {"alert_id": "W1", "created_at": "2026-10-06T10:00:00.000Z", "rule_id": "UC-WEB-001", "severity": "low",
         "entities": {"ips": ["198.18.5.5"]}, "evidence": {"action": "blocked"}}
    ctx = Contexto([a], [], waf=[])
    assert sev([a], {"asset_criticality": "critical"}, ctx)["severidad"] == "informational"
    # si esa IP tuvo alguna petición permitida, ya no es oportunista: aplica la matriz (medium - 1 = low)
    ctx2 = Contexto([a], [], waf=[{"src_ip": "198.18.5.5", "action": "allowed"}])
    assert sev([a], {"asset_criticality": "critical"}, ctx2)["severidad"] == "low"


def test_vpn_con_mfa_aprobado_cuenta_como_acceso_confirmado():
    a = {"alert_id": "V1", "created_at": "2026-10-11T01:40:00.000Z", "rule_id": "UC-VPN-001", "severity": "medium",
         "entities": {"hosts": [{"hostname": "WS-1"}]}, "evidence": {"mfa": "TOTP aprobado"}}
    assert sev([a])["severidad"] == "high"
