"""Matriz de severidad de politica_soc.md, apartado 2 (rol A).

Severidad final = severidad de la regla x criticidad del activo o identidad MÁS crítica afectada,
con un ajuste total de un nivel como mucho (+1 / -1).

Reglas de seguridad acordadas (protección frente a prompt injection):
  - El código calcula todo lo que puede sacar de datos estructurados: la severidad de la regla,
    la criticidad (activos.csv / usuarios.csv), VIP/privilegiado, bloqueos, datos personales...
  - El LLM puede proponer SUBIR (más criticidad, ejecución confirmada, datos personales...),
    pero NUNCA BAJAR. Un -1 solo se aplica si el código ve el bloqueo en los datos y no hay
    actividad posterior en las entidades afectadas.
  - "Flujo autorizado" (benign_true_positive, informational/low) solo vale si el código lo verifica
    contra calendario_cambios.csv. Si solo lo dice el LLM, se ignora y se avisa.
  - Lo que no está en el inventario cuenta como criticidad ALTA, y se dice en la justificación.
"""
import csv
import os

from . import datos

LEVELS = ["informational", "low", "medium", "high", "critical"]
CRITICIDADES = ["low", "medium", "high", "critical"]
_CRIT_ES = {"baja": "low", "media": "medium", "alta": "high", "crítica": "critical", "critica": "critical",
            "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
_CRIT_TXT = {"low": "baja", "medium": "media", "high": "alta", "critical": "crítica"}
MATRIZ = {  # regla -> [baja, media, alta, crítica]
    "informational": ["informational", "informational", "low", "low"],
    "low": ["informational", "low", "low", "medium"],
    "medium": ["low", "medium", "medium", "high"],
    "high": ["medium", "high", "high", "critical"],
    "critical": ["high", "critical", "critical", "critical"],
}
DESCONOCIDO = "high"  # criticidad que se asume si algo no está en el inventario
_BLOQUEADO = {"blocked", "quarantined", "denied"}
_REGLAS_FRAUDE = {"UC-EML-004", "UC-WEB-003"}


# --------------------------------------------------------------------------- inventario

class Inventario:
    def __init__(self, activos=None, usuarios=None):
        self.activos = {k.upper(): v for k, v in (activos or {}).items()}
        self.usuarios = {k.lower(): v for k, v in (usuarios or {}).items()}

    @classmethod
    def desde_dataset(cls, ruta=None):
        base = datos.dataset_dir(ruta) / "02_inventario"
        with open(base / "activos.csv", encoding="utf-8") as f:
            activos = {r["hostname"]: r for r in csv.DictReader(f)}
        with open(base / "usuarios.csv", encoding="utf-8") as f:
            usuarios = {r["upn"]: r for r in csv.DictReader(f)}
        return cls(activos, usuarios)

    def criticidad_host(self, host):
        a = self.activos.get(str(host).upper())
        return _CRIT_ES.get(str(a.get("criticality", "")).lower()) if a else None

    def usuario(self, upn):
        return self.usuarios.get(str(upn).lower())


_INVENTARIO = None


def inventario_por_defecto():
    """Inventario del dataset (DATASET_DIR). Si no hay dataset, uno vacío: todo cuenta como desconocido."""
    global _INVENTARIO
    if _INVENTARIO is None:
        try:
            _INVENTARIO = Inventario.desde_dataset(os.environ.get("DATASET_DIR"))
        except (FileNotFoundError, OSError):
            _INVENTARIO = Inventario()
    return _INVENTARIO


def _si(v):
    return str(v).strip().lower() in ("true", "1", "sí", "si", "yes")


# --------------------------------------------------------------------------- hechos sacados de los datos

def _afectados(alertas, inv):
    """Lista de (descripción, criticidad, conocido) de equipos e identidades de las alertas."""
    out, vip_priv = [], []
    for a in alertas:
        e = a.get("entities") or {}
        for h in e.get("hosts") or []:
            nombre = h.get("hostname") if isinstance(h, dict) else h
            if not nombre:
                continue
            c = inv.criticidad_host(nombre)
            out.append((f"equipo {nombre}", c or DESCONOCIDO, c is not None))
        for u in e.get("users") or []:
            upn = (u.get("upn") if isinstance(u, dict) else u) or ""
            if "@" not in upn:
                continue
            r = inv.usuario(upn)
            if r is None:
                out.append((f"usuario {upn}", DESCONOCIDO, False))
                continue
            # una persona normal cuenta como media; las cuentas de servicio pueden parar un proceso de negocio
            c = "high" if r.get("account_type") == "service" else "medium"
            out.append((f"usuario {upn}", c, True))
            if _si(r.get("vip")) or _si(r.get("privileged")) or r.get("account_type") == "admin":
                vip_priv.append(upn)
        nube = e.get("cloud") or {}
        for k in ("identity", "new_user", "bucket", "account"):
            if nube.get(k):
                out.append((f"cloud {k} {nube[k]}", DESCONOCIDO, False))
    return out, vip_priv


def _datos_personales_o_pagos(a):
    ev = a.get("evidence") if isinstance(a.get("evidence"), dict) else {}
    if a.get("rule_id") in _REGLAS_FRAUDE or ev.get("pci_scope") is True:
        return True
    m = ev.get("matches")
    if isinstance(m, dict) and any(isinstance(v, (int, float)) and v > 0 for v in m.values()):
        return True
    n = ev.get("personal_data_matches")
    return isinstance(n, (int, float)) and n > 0


def _acceso_confirmado(a):
    ev = a.get("evidence") if isinstance(a.get("evidence"), dict) else {}
    if str(ev.get("final_result", "")).lower() == "approved" or str(ev.get("mfa_result", "")).lower() == "approved":
        return True
    for k in ("successes", "success_count"):
        if isinstance(ev.get(k), (int, float)) and ev[k] > 0:
            return True
    return str(ev.get("action", "")).lower() == "allow" or ev.get("executed") is True


def _bloqueado(a):
    """True solo si un campo estructurado dice que el control lo paró."""
    ev = a.get("evidence") if isinstance(a.get("evidence"), dict) else {}
    if any(str(ev.get(k, "")).lower() in _BLOQUEADO for k in ("action", "edr_action", "tool_result")):
        return True
    if ev.get("executed") is False:
        return True
    return any(isinstance(ev.get(k), (int, float)) and ev[k] == 0 for k in ("successes", "success_count"))


# --------------------------------------------------------------------------- cálculo

def calcular_severidad(alertas, factores=None, inventario=None, contexto=None):
    """Severidad final de un grupo de alertas (un ticket).

    alertas:   lista de alertas (dicts del dataset/API). Puede ir vacía: entonces se usan los factores.
    factores:  severity_factors que propone el LLM (opcionales). Solo pueden subir.
    contexto:  engine.prefiltro.Contexto (opcional), para comprobar actividad posterior y cambios aprobados.
    Devuelve {"severidad", "justificacion", "regla", "criticidad", "ajuste", "autorizado_verificado", "avisos"}.
    """
    f = factores or {}
    inv = inventario or inventario_por_defecto()
    alertas = [a for a in (alertas or []) if isinstance(a, dict)]
    avisos, motivos_sube, motivos_baja = [], [], []

    # 1. severidad de la regla: la del dato manda; el LLM solo puede subirla
    del_dato = [a.get("severity") for a in alertas if a.get("severity") in LEVELS]
    regla = max(del_dato, key=LEVELS.index) if del_dato else None
    llm_regla = f.get("rule_severity") if f.get("rule_severity") in LEVELS else None
    if regla is None:
        regla = llm_regla or "medium"
        if not llm_regla:
            avisos.append("sin severidad de regla: se asume medium")
    elif llm_regla and LEVELS.index(llm_regla) > LEVELS.index(regla):
        avisos.append(f"el LLM sube la severidad de la regla de {regla} a {llm_regla}")
        regla = llm_regla

    # 2. criticidad: la más alta de lo afectado; desconocido = alta; el LLM solo puede subirla
    afectados, vip_priv = _afectados(alertas, inv)
    if afectados:
        desc, crit, conocido = max(afectados, key=lambda x: CRITICIDADES.index(x[1]))
        crit_txt = f"{_CRIT_TXT[crit]} ({desc}{'' if conocido else ', no está en el inventario: se asume alta'})"
    else:
        crit, crit_txt = DESCONOCIDO, "alta (no hay equipos ni identidades afectados en el inventario: se asume alta)"
    llm_crit = _CRIT_ES.get(str(f.get("asset_criticality", "")).lower())
    if llm_crit and CRITICIDADES.index(llm_crit) > CRITICIDADES.index(crit):
        crit, crit_txt = llm_crit, f"{_CRIT_TXT[llm_crit]} (propuesta del LLM, por encima del inventario)"

    base = MATRIZ[regla][CRITICIDADES.index(crit)]

    # 3. ajustes (+1 lo puede pedir el código o el LLM; -1 solo el código)
    if vip_priv:
        motivos_sube.append(f"identidad VIP o privilegiada ({', '.join(sorted(set(vip_priv))[:3])})")
    if any(_acceso_confirmado(a) for a in alertas):
        motivos_sube.append("acceso o ejecución confirmados en los datos")
    if any(_datos_personales_o_pagos(a) for a in alertas):
        motivos_sube.append("datos personales o pagos implicados")
    for k, txt in (("confirmed_execution_or_access", "el LLM confirma ejecución o acceso"),
                   ("privileged_or_vip", "el LLM indica identidad VIP o privilegiada"),
                   ("personal_or_payment_data", "el LLM indica datos personales o pagos")):
        if f.get(k):
            motivos_sube.append(txt)

    if alertas and all(_bloqueado(a) for a in alertas) and not motivos_sube:
        posterior = []
        if contexto is not None:
            for a in alertas:
                posterior += list(contexto.entidades_calientes(a))
        if posterior:
            avisos.append("bloqueado, pero hay actividad posterior en " + ", ".join(sorted(set(posterior))[:3]) + ": no se baja")
        else:
            motivos_baja.append("el control lo bloqueó antes de producir efecto")
    elif f.get("blocked_before_effect"):
        avisos.append("el LLM dice que se bloqueó, pero los datos no lo confirman: no se baja")

    ajuste = (1 if motivos_sube else 0) - (1 if motivos_baja else 0)
    final = LEVELS[max(0, min(len(LEVELS) - 1, LEVELS.index(base) + ajuste))]

    # 4. flujo autorizado: solo si el código lo verifica contra el calendario
    autorizado = False
    if contexto is not None and alertas:
        explicaciones = [contexto._cambio_que_explica(a) for a in alertas]
        if all(explicaciones):
            autorizado = True
            final = "informational" if base == "informational" else "low"
            avisos.append("actividad autorizada por " + ", ".join(sorted({c.id for c, _ in explicaciones})))
    if f.get("authorized_flow") and not autorizado:
        avisos.append("el LLM dice que es un flujo autorizado, pero no se ha podido verificar en el calendario: se ignora")

    partes = [f"Regla {regla} x criticidad {crit_txt} = {base}"]
    if motivos_sube:
        partes.append("+1: " + "; ".join(motivos_sube))
    if motivos_baja:
        partes.append("-1: " + "; ".join(motivos_baja))
    if ajuste == 0 and motivos_sube and motivos_baja:
        partes.append("los ajustes se compensan")
    partes.append(f"final {final}")
    return {"severidad": final, "justificacion": ". ".join(partes) + "." + (" " + " ".join(a.capitalize() + "." for a in avisos) if avisos else ""),
            "regla": regla, "criticidad": crit, "ajuste": ajuste, "autorizado_verificado": autorizado, "avisos": avisos}


def compute_severity(f, alertas=None, contexto=None):
    """Compatible con agent/severity.py: devuelve (severidad, justificación).
    Para que funcione la protección completa, pasar también las alertas del ticket."""
    r = calcular_severidad(alertas or [], f, contexto=contexto)
    return r["severidad"], r["justificacion"]
