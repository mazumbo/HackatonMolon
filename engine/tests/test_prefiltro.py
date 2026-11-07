"""Tests del prefiltro. Los sintéticos no necesitan el dataset; los de dataset usan DATASET_DIR."""
import os
import re
from pathlib import Path

import pytest

from engine import datos
from engine.prefiltro import CERRAR, PASAR, Contexto, prefiltrar

CAMBIOS = [
    {"id": "CHG-2026-1042", "titulo": "Pentest externo de la tienda online", "inicio": "2026-10-08 08:00",
     "fin": "2026-10-10 18:00", "alcance": "WEB-ECOM01..04"},
    {"id": "CHG-2026-1031", "titulo": "Script de inventario de software vía SCCM (PowerShell codificado)",
     "inicio": "2026-09-28 00:00", "fin": "2026-12-31 23:59", "alcance": "Todos los puestos"},
    {"id": "CHG-2026-1057", "titulo": "Despliegue agente de monitorización 3.4 en servidores",
     "inicio": "2026-10-13 10:00", "fin": "2026-10-13 13:00", "alcance": "ERP-APP01, HR-APP01, PRINT01, CRM-APP01"},
]


def waf(aid, ip, t="2026-10-08T10:00:00.000Z", action="blocked"):
    return {"alert_id": aid, "created_at": t, "rule_id": "UC-WEB-001", "severity": "low",
            "entities": {"ips": [ip]}, "evidence": {"action": action}}


def sccm(aid, host="WS-BCN-1993", t="2026-10-06T06:30:00.000Z", parent="CcmExec.exe"):
    return {"alert_id": aid, "created_at": t, "rule_id": "UC-EDR-002", "severity": "medium",
            "entities": {"hosts": [{"hostname": host, "ip": "10.10.3.210"}],
                         "processes": [{"name": "powershell.exe", "parent": parent}]},
            "evidence": {"user": "SYSTEM"}}


def psexec(aid, src="JUMP01", dst="PRINT01", t="2026-10-13T09:00:00.000Z"):
    return {"alert_id": aid, "created_at": t, "rule_id": "UC-NET-004", "severity": "high",
            "entities": {"hosts": [{"hostname": src}, {"hostname": dst}]},
            "evidence": {"src": src, "dst": dst, "account": "adm.dnavarro", "change_ticket": "CHG-2026-1057"}}


def ctx(alertas, waf_logs=None):
    return Contexto(alertas, CAMBIOS, waf_logs or [])


def test_pentest_dentro_de_ventana_se_cierra():
    a = waf("A1", "192.0.2.11")
    r = prefiltrar(a, ctx([a], [{"src_ip": "192.0.2.11", "action": "allowed"}]))
    assert r["decision"] == CERRAR and r["cambio"] == "CHG-2026-1042"
    assert r["veredicto"] == "benign_true_positive"


def test_pentest_fuera_de_ventana_no_es_pentest():
    a = waf("A1", "192.0.2.11", t="2026-10-12T10:00:00.000Z")
    r = prefiltrar(a, ctx([a], [{"src_ip": "192.0.2.11", "action": "allowed"}]))
    assert r["decision"] == PASAR


def test_waf_bloqueado_sin_trafico_permitido_se_cierra():
    a = waf("A1", "198.18.11.49")
    r = prefiltrar(a, ctx([a]))
    assert r["decision"] == CERRAR
    assert r["veredicto"] == "true_positive" and r["severidad"] == "informational"


def test_waf_con_trafico_permitido_pasa():
    a = waf("A1", "198.18.11.49")
    assert prefiltrar(a, ctx([a], [{"src_ip": "198.18.11.49", "action": "allowed"}]))["decision"] == PASAR


def test_sccm_en_franja_se_cierra_y_fuera_pasa():
    dentro = sccm("A1")                                   # 08:30 hora de Madrid
    fuera = sccm("A2", t="2026-10-06T20:00:00.000Z")     # 22:00 hora de Madrid
    c = ctx([dentro, fuera])
    assert prefiltrar(dentro, c)["decision"] == CERRAR
    assert prefiltrar(fuera, c)["decision"] == PASAR


def test_sccm_con_otro_padre_pasa():
    a = sccm("A1", parent="winword.exe")
    assert prefiltrar(a, ctx([a]))["decision"] == PASAR


def test_psexec_solo_desde_jump01_y_a_destinos_del_cambio():
    ok = psexec("A1")
    otro_origen = psexec("A2", src="WS-BCN-1770")          # como el atacante del incidente 2
    otro_destino = psexec("A3", dst="FS01")
    assert prefiltrar(ok, ctx([ok]))["decision"] == CERRAR
    c = ctx([ok, otro_origen, otro_destino])
    assert prefiltrar(otro_origen, c)["decision"] == PASAR
    assert prefiltrar(otro_destino, c)["decision"] == PASAR


def test_el_texto_de_la_alerta_no_basta():
    """'change_ticket' lo puede escribir cualquiera: sin origen correcto no se cierra."""
    a = psexec("A1", src="PRINT01", dst="ERP-APP01")
    assert prefiltrar(a, ctx([a]))["decision"] == PASAR


def test_entidad_caliente_impide_cerrar():
    limpia = sccm("A1")
    sospechosa = {"alert_id": "B1", "created_at": "2026-10-07T01:00:00.000Z", "rule_id": "UC-EDR-004",
                  "severity": "critical", "entities": {"hosts": [{"hostname": "WS-BCN-1993"}]}, "evidence": {}}
    r = prefiltrar(limpia, ctx([limpia, sospechosa]))
    assert r["decision"] == PASAR
    assert any("B1" in p for p in r["pistas"])


def test_entidad_caliente_lejos_en_el_tiempo_no_cuenta():
    limpia = sccm("A1")
    vieja = {"alert_id": "B1", "created_at": "2026-10-20T01:00:00.000Z", "rule_id": "UC-EDR-004",
             "severity": "critical", "entities": {"hosts": [{"hostname": "WS-BCN-1993"}]}, "evidence": {}}
    assert prefiltrar(limpia, ctx([limpia, vieja]))["decision"] == CERRAR


def test_pico_de_volumen_suspende_el_cierre():
    normales = [waf(f"N{h}", f"198.18.0.{h}", t=f"2026-10-0{1 + h // 24}T{h % 24:02d}:10:00.000Z") for h in range(48)]
    pico = [waf(f"P{i}", f"198.18.1.{i}", t="2026-10-05T03:20:00.000Z") for i in range(30)]
    c = ctx(normales + pico)
    assert prefiltrar(normales[0], c)["decision"] == CERRAR
    r = prefiltrar(pico[0], c)
    assert r["decision"] == PASAR and any("volumen" in p for p in r["pistas"])


def test_alerta_rota_no_lanza():
    r = prefiltrar({"alert_id": "X", "entities": None, "evidence": "texto"}, ctx([]))
    assert r["decision"] == PASAR


# ---------------------------------------------------------------- contra el dataset real

DATASET = os.environ.get("DATASET_DIR")
con_dataset = pytest.mark.skipif(not DATASET or not Path(DATASET, "03_alertas").is_dir(),
                                 reason="define DATASET_DIR con la ruta del repo del reto")


def _ids_incidentes():
    md = (Path(__file__).resolve().parents[2] / "docs" / "incidentes_localizados.md").read_text(encoding="utf-8")
    md = md.split("## Actividad autorizada")[0]
    ids = set(re.findall(r"\b(0\d{5})\b", md))
    for a, b in re.findall(r"(0\d{5})[–-](0\d{5})", md):
        ids |= {f"{n:06d}" for n in range(int(a), int(b) + 1)}
    return ids


@con_dataset
def test_ningun_incidente_real_se_cierra():
    alertas = datos.cargar_alertas(DATASET)
    c = Contexto.desde_dataset(DATASET, alertas)
    ids = _ids_incidentes()
    assert len(ids) > 50
    cerradas = [a["alert_id"] for a in alertas if a["alert_id"][-6:] in ids and prefiltrar(a, c)["decision"] == CERRAR]
    assert cerradas == []


@con_dataset
def test_autorizados_conocidos_se_cierran():
    alertas = datos.cargar_alertas(DATASET)
    c = Contexto.desde_dataset(DATASET, alertas)
    r = {a["alert_id"][-6:]: prefiltrar(a, c) for a in alertas}
    for sufijo in ("011874", "011875", "011869", "011870", "011871", "011872", "011915", "011922"):
        assert r[sufijo]["decision"] == CERRAR, (sufijo, r[sufijo]["pistas"])
    assert r["011896"]["decision"] == PASAR  # parada del EDR en PRINT01 del 18/10: sin cambio
