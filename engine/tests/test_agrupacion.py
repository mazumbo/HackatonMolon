"""Tests de la agrupación. Los sintéticos no necesitan el dataset; el de dataset usa DATASET_DIR."""
import os
from collections import Counter
from pathlib import Path

import pytest

from engine import datos
from engine.agrupacion import Pivotes, agrupar, evaluar, familia_dominio, incidentes_de_referencia


def al(aid, t, rule="UC-RARA", **entities):
    return {"alert_id": aid, "created_at": t, "rule_id": rule, "severity": "high", "entities": entities, "evidence": {}}


def grupo_de(grupos, aid):
    return next(g for g in grupos if aid in g["alert_ids"])


def test_hash_une_aunque_pasen_dias():
    a = al("A", "2026-10-09T10:00:00Z", files=[{"sha256": "70aa"}], hosts=[{"hostname": "FS01"}])
    b = al("B", "2026-10-18T01:00:00Z", files=[{"sha256": "70aa"}], hosts=[{"hostname": "PRINT01"}])
    g = grupo_de(agrupar([a, b]), "A")
    assert g["alert_ids"] == ["A", "B"] and "hash" in g["uniones"][0]["motivo"]


def test_equipo_solo_une_dentro_de_72_h():
    a = al("A", "2026-10-01T10:00:00Z", hosts=[{"hostname": "WS-1"}])
    b = al("B", "2026-10-02T10:00:00Z", hosts=[{"hostname": "WS-1"}])
    c = al("C", "2026-10-20T10:00:00Z", hosts=[{"hostname": "WS-1"}])
    gs = agrupar([a, b, c])
    assert grupo_de(gs, "A")["alert_ids"] == ["A", "B"]
    assert grupo_de(gs, "C")["alert_ids"] == ["C"]


def test_el_ruido_no_hace_de_pegamento():
    """Dos incidentes distintos del mismo usuario no se unen a través de un reporte de phishing."""
    inc1 = al("I1", "2026-10-01T10:00:00Z", users=[{"upn": "ana@tarvia.example"}], files=[{"sha256": "x1"}])
    ruido = al("R", "2026-10-03T12:00:00Z", rule="UC-RUIDO", users=[{"upn": "ana@tarvia.example"}])
    inc2 = al("I2", "2026-10-05T14:00:00Z", users=[{"upn": "ana@tarvia.example"}], files=[{"sha256": "x2"}])
    volumen = Counter({"UC-RARA": 2, "UC-RUIDO": 5000})
    gs = agrupar([inc1, ruido, inc2], volumen_reglas=volumen)
    assert grupo_de(gs, "I1")["alert_ids"] == ["I1"]
    assert grupo_de(gs, "I2")["alert_ids"] == ["I2"]


def test_el_ruido_cercano_se_cuelga_del_incidente():
    inc = al("I", "2026-10-01T10:00:00Z", users=[{"upn": "ana@tarvia.example"}])
    ruido = al("R", "2026-10-01T12:00:00Z", rule="UC-RUIDO", users=[{"upn": "ana@tarvia.example"}])
    gs = agrupar([inc, ruido], volumen_reglas=Counter({"UC-RARA": 1, "UC-RUIDO": 5000}))
    assert grupo_de(gs, "I")["alert_ids"] == ["I", "R"]


def test_familia_de_dominios():
    assert familia_dominio("packaging-iberia-pagos.example") == familia_dominio("packaging-iberia-portal.example")
    assert familia_dominio("microsoft.com") is None
    a = al("A", "2026-10-20T06:00:00Z", domains=["packaging-iberia-pagos.example"])
    b = al("B", "2026-10-20T07:00:00Z", domains=["packaging-iberia-portal.example"])
    assert grupo_de(agrupar([a, b]), "A")["alert_ids"] == ["A", "B"]


def test_pista_desde_los_logs():
    """La VPN no menciona WMS01, pero su evento de firewall hace RDP a la IP de WMS01."""
    vpn = al("V", "2026-10-11T01:40:00Z", users=[{"upn": "ext.logisoft@tarvia.example"}])
    vpn["related_events"] = ["FW-1"]
    dns = al("D", "2026-10-11T02:28:00Z", hosts=[{"hostname": "WMS01", "ip": "10.40.2.10"}])
    sin_logs = agrupar([vpn, dns])
    assert grupo_de(sin_logs, "V")["alert_ids"] == ["V"]
    piv = Pivotes(eventos={"FW-1": {"src_ip": "10.99.60.10", "dst_ip": "10.40.2.10"}},
                  ip_a_equipo={"10.40.2.10": "WMS01"})
    assert grupo_de(agrupar([vpn, dns], piv), "V")["alert_ids"] == ["V", "D"]


def test_entidad_omnipresente_no_une():
    alertas = [al(f"A{i}", f"2026-10-01T{i % 24:02d}:00:00Z", hosts=[{"hostname": "JUMP01"}]) for i in range(60)]
    assert all(len(g["alert_ids"]) == 1 for g in agrupar(alertas))


def test_alerta_rota_no_rompe():
    gs = agrupar([{"alert_id": "X", "entities": None}, {"alert_id": "Y", "created_at": "basura"}])
    assert len(gs) == 2


DATASET = os.environ.get("DATASET_DIR")


@pytest.mark.skipif(not DATASET or not Path(DATASET, "03_alertas").is_dir(), reason="define DATASET_DIR")
def test_contra_los_12_incidentes():
    from engine.prefiltro import CERRAR, Contexto, prefiltrar
    todas = datos.cargar_alertas(DATASET)
    ctx = Contexto.desde_dataset(DATASET, todas)
    abiertas = [a for a in todas if prefiltrar(a, ctx)["decision"] != CERRAR]
    grupos = agrupar(abiertas, Pivotes.desde_dataset(DATASET, abiertas), Counter(a["rule_id"] for a in todas))
    md = Path(__file__).resolve().parents[2] / "docs" / "incidentes_localizados.md"
    filas, media = evaluar(grupos, incidentes_de_referencia(md, todas))
    assert media["completitud"] >= 0.90 and media["pureza"] >= 0.95, (media, filas)
    assert filas[2]["completitud"] == 1.0  # el ransomware de 9 días, entero, gracias al hash repetido
