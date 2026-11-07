"""Prefiltro determinista del N1 (rol A).

prefiltrar(alerta, contexto) decide, sin LLM, si una alerta se CIERRA (actividad autorizada ->
benign_true_positive; ataque web bloqueado sin efecto -> true_positive informational) o PASA al agente. Criterio acordado: cerrar solo lo seguro y ser precavidos.

Una alerta solo se cierra si se cumplen las tres cosas:
  1. Encaja con un cambio aprobado de calendario_cambios.csv (origen, ventana horaria y alcance),
     o es un ataque web bloqueado sin ninguna petición permitida de esa IP.
  2. Ninguna de sus entidades (IP, equipo, usuario, hash, identidad cloud) aparece en otra alerta
     sin explicar en las 72 h de alrededor ("entidad caliente").
  3. El volumen de su regla en esa hora no se dispara frente a lo normal ("baremo dinámico"):
     si entra mucho más de lo habitual, se suspende el cierre automático y todo pasa al agente.

Si falla cualquiera, la alerta pasa al agente con pistas que explican por qué.
Solo se usan campos estructurados. Nunca se usan textos libres de la alerta (descripciones,
"change_ticket", "maintenance_window"...) como prueba: los puede escribir el atacante.
Tampoco se usa la numeración de los alert_id.
"""
import ipaddress
import json
import statistics
import sys
from collections import Counter, defaultdict
from datetime import timedelta

from . import datos

VENTANA_CALIENTE = timedelta(hours=72)
TOLERANCIA_VENTANA = timedelta(minutes=30)  # margen en los bordes de una ventana de cambio
PICO_FACTOR, PICO_MINIMO = 3.0, 5           # pico si la hora supera max(3 x lo normal, normal + 5)

CERRAR, PASAR = "cerrar", "pasar"


# --------------------------------------------------------------------------- entidades

def _host(h):
    return (h.get("hostname") or "").upper() if isinstance(h, dict) else str(h).upper()


def _upn(u):
    v = u.get("upn") if isinstance(u, dict) else u
    return (v or "").lower()


def entidades(alerta):
    """Conjunto de claves 'tipo:valor' de la alerta, para cruzarla con otras."""
    e = alerta.get("entities") or {}
    out = set()
    for ip in e.get("ips") or []:
        out.add(f"ip:{ip}")
    for h in e.get("hosts") or []:
        if _host(h):
            out.add(f"host:{_host(h)}")
        if isinstance(h, dict) and h.get("ip"):
            out.add(f"ip:{h['ip']}")
    for u in e.get("users") or []:
        if _upn(u) and "@" in _upn(u):
            out.add(f"user:{_upn(u)}")
    for f in e.get("files") or []:
        if isinstance(f, dict) and f.get("sha256"):
            out.add(f"hash:{f['sha256'].lower()}")
    nube = e.get("cloud") or {}
    for k in ("identity", "new_user", "access_key"):
        if nube.get(k):
            out.add(f"cloud:{nube[k]}")
    for c in e.get("customers") or []:
        if isinstance(c, dict) and c.get("customer_id"):
            out.add(f"cliente:{c['customer_id']}")
    return out


def _ip_en_rango(ip, desde, hasta):
    try:
        return ipaddress.ip_address(desde) <= ipaddress.ip_address(ip) <= ipaddress.ip_address(hasta)
    except ValueError:
        return False


def _hosts(alerta):
    return [_host(h) for h in (alerta.get("entities") or {}).get("hosts") or []]


def _ips(alerta):
    return list((alerta.get("entities") or {}).get("ips") or [])


def _ev(alerta):
    ev = alerta.get("evidence")
    return ev if isinstance(ev, dict) else {}


# --------------------------------------------------------------------------- cambios aprobados

class Cambio:
    def __init__(self, fila):
        self.id = fila["id"]
        self.titulo = fila["titulo"]
        self.inicio = datos.hora_local_cambio(fila["inicio"])
        self.fin = datos.hora_local_cambio(fila["fin"])
        self.alcance = fila.get("alcance", "")

    def en_ventana(self, t):
        return t is not None and self.inicio - TOLERANCIA_VENTANA <= t <= self.fin + TOLERANCIA_VENTANA


def _hora_local(t):
    return t.astimezone(datos.MADRID)


def _es_servidor_windows(host, activos):
    a = activos.get(host)
    return bool(a) and "windows server" in a.get("os", "").lower()


# Cada comprobador recibe (alerta, cambio, t, contexto) y devuelve un motivo (str) si encaja.
# Están escritos a mano para cada tipo de cambio, pero las fechas salen siempre del calendario.

def _pentest(a, c, t, ctx):
    if not a.get("rule_id", "").startswith("UC-WEB-") or not c.en_ventana(t):
        return None
    ips = _ips(a)
    if ips and all(_ip_en_rango(ip, "192.0.2.10", "192.0.2.12") for ip in ips):
        return f"IP {', '.join(ips)} del pentest autorizado, dentro de su ventana"
    return None


def _nessus(a, c, t, ctx):
    if a.get("rule_id") != "UC-NET-003" or not c.en_ventana(t):
        return None
    if _hosts(a) == ["NESSUS01"]:
        return "escaneo desde NESSUS01 dentro de la ventana del escaneo semanal"
    return None


def _sccm(a, c, t, ctx):
    if a.get("rule_id") != "UC-EDR-002" or not c.en_ventana(t):
        return None
    ev = _ev(a)
    procs = (a.get("entities") or {}).get("processes") or []
    padres = {str(p.get("parent", "")).lower() for p in procs if isinstance(p, dict)}
    hl = _hora_local(t)
    en_franja = (8 * 60 - 30) <= hl.hour * 60 + hl.minute <= (10 * 60 + 30)  # 08:00-10:00 con margen
    if padres == {"ccmexec.exe"} and str(ev.get("user", "")).upper() == "SYSTEM" and en_franja:
        return f"PowerShell lanzado por el agente SCCM como SYSTEM a las {hl:%H:%M}, franja del inventario diario"
    return None


def _psexec_despliegue(a, c, t, ctx):
    if a.get("rule_id") != "UC-NET-004" or not c.en_ventana(t):
        return None
    ev = _ev(a)
    destinos = {h.strip().upper() for h in c.alcance.split(",")}
    if (str(ev.get("src", "")).upper() == "JUMP01" and str(ev.get("dst", "")).upper() in destinos
            and str(ev.get("account", "")).lower().startswith("adm.")):
        return f"PsExec desde JUMP01 con cuenta adm a {ev.get('dst')}, dentro del despliegue"
    return None


def _logisoft(a, c, t, ctx):
    if a.get("rule_id") != "UC-VPN-001" or not c.en_ventana(t):
        return None
    ev = _ev(a)
    users = {_upn(u) for u in (a.get("entities") or {}).get("users") or []}
    if users == {"ext.logisoft@tarvia.example"} and ev.get("src_asn") == "Logisoft Solutions S.L.":
        return "VPN de Logisoft desde su red corporativa, dentro de la ventana de actualización del WMS"
    return None


def _backup_operators(a, c, t, ctx):
    if a.get("rule_id") != "UC-IDP-008" or not c.en_ventana(t):
        return None
    ev = _ev(a)
    if (ev.get("group") == "Backup Operators" and str(ev.get("from_host", "")).upper() == "JUMP01"
            and str(ev.get("by", "")).lower().startswith("adm.")):
        return "alta en Backup Operators hecha desde JUMP01 por una cuenta adm, dentro del cambio"
    return None


def _parada_edr(a, c, t, ctx):
    if a.get("rule_id") != "UC-EDR-011" or not c.en_ventana(t):
        return None
    hosts = _hosts(a)
    procs = (a.get("entities") or {}).get("processes") or []
    files = (a.get("entities") or {}).get("files") or []
    if len(hosts) == 1 and _es_servidor_windows(hosts[0], ctx.activos) and not procs and not files:
        return f"parada del EDR en el servidor Windows {hosts[0]} durante la actualización del agente"
    return None


def _nominas(a, c, t, ctx):
    if a.get("rule_id") != "UC-DLP-002" or not c.en_ventana(t):
        return None
    if _ev(a).get("recipient") == "asesoria@gestoria-pons.example":
        return "envío de nóminas a la gestoría con contrato de encargado de tratamiento vigente"
    return None


COMPROBADORES = [  # (prefijo del id del cambio o palabra del título, comprobador)
    ("Pentest", _pentest),
    ("Escaneo semanal", _nessus),
    ("SCCM", _sccm),
    ("Despliegue agente", _psexec_despliegue),
    ("Actualización del WMS", _logisoft),
    ("Backup Operators", _backup_operators),
    ("agente EDR", _parada_edr),
    ("nómina", _nominas),
]
# A propósito NO se cierran: el mantenimiento OT (la política dice "solo escalar") y la rotación de
# certificados de la VPN (no tiene un origen concreto que comprobar). Pasan al agente con pista.


# --------------------------------------------------------------------------- contexto

class Contexto:
    """Lo que el prefiltro sabe del resto de alertas: entidades, volumen por hora y logs del WAF."""

    def __init__(self, alertas, cambios, waf=None, activos=None):
        self.alertas = {a["alert_id"]: a for a in alertas if a.get("alert_id")}
        self.cambios = [Cambio(f) for f in cambios]
        self.activos = activos or {}
        self._t = {i: datos.instante(a.get("created_at")) for i, a in self.alertas.items()}
        self._por_entidad = defaultdict(list)
        for i, a in self.alertas.items():
            for e in entidades(a):
                self._por_entidad[e].append(i)
        # volumen por regla y hora, y lo "normal" de cada regla (mediana de horas con actividad)
        self._por_hora = Counter()
        for i, a in self.alertas.items():
            if self._t[i]:
                self._por_hora[(a.get("rule_id"), self._t[i].replace(minute=0, second=0, microsecond=0))] += 1
        horas = defaultdict(list)
        for (regla, _), n in self._por_hora.items():
            horas[regla].append(n)
        self._normal = {r: statistics.median(v) for r, v in horas.items()}
        # IPs con alguna petición permitida en el WAF
        self._waf_permitidas = {w.get("src_ip") for w in (waf or []) if w.get("action") != "blocked"}
        self._explicadas = {i for i, a in self.alertas.items() if self._cambio_que_explica(a)}

    @classmethod
    def desde_dataset(cls, ruta=None, alertas=None):
        import csv
        alertas = alertas if alertas is not None else datos.cargar_alertas(ruta)
        with open(datos.dataset_dir(ruta) / "02_inventario" / "activos.csv", encoding="utf-8") as f:
            activos = {r["hostname"].upper(): r for r in csv.DictReader(f)}
        return cls(alertas, datos.cargar_cambios(ruta), datos.cargar_waf(ruta), activos)

    def añadir(self, alerta):
        """Para el modo en directo: incorpora una alerta nueva al contexto."""
        i = alerta["alert_id"]
        self.alertas[i] = alerta
        self._t[i] = t = datos.instante(alerta.get("created_at"))
        for e in entidades(alerta):
            self._por_entidad[e].append(i)
        if t:
            self._por_hora[(alerta.get("rule_id"), t.replace(minute=0, second=0, microsecond=0))] += 1
        if self._cambio_que_explica(alerta):
            self._explicadas.add(i)

    def _cambio_que_explica(self, a):
        t = datos.instante(a.get("created_at"))
        for c in self.cambios:
            for clave, comprobar in COMPROBADORES:
                if clave.lower() in c.titulo.lower():
                    motivo = comprobar(a, c, t, self)
                    if motivo:
                        return c, motivo
        return None

    def entidades_calientes(self, a):
        """Entidades de la alerta que salen en otras alertas sin explicar en +-72 h."""
        t = datos.instante(a.get("created_at"))
        calientes = {}
        for e in entidades(a):
            for otra in self._por_entidad.get(e, []):
                if otra == a.get("alert_id") or otra in self._explicadas:
                    continue
                o = self.alertas[otra]
                if o.get("rule_id") == a.get("rule_id"):
                    continue  # la misma regla repetida no es "otra" señal
                to = self._t.get(otra)
                if t and to and abs(to - t) <= VENTANA_CALIENTE:
                    calientes.setdefault(e, []).append(otra)
        return calientes

    def pico(self, a):
        """(n en esa hora, normal) si el volumen de su regla se dispara en esa hora; si no, None."""
        t = datos.instante(a.get("created_at"))
        if not t:
            return None
        n = self._por_hora.get((a.get("rule_id"), t.replace(minute=0, second=0, microsecond=0)), 0)
        normal = self._normal.get(a.get("rule_id"), 0)
        umbral = max(PICO_FACTOR * normal, normal + PICO_MINIMO)
        return (n, normal) if n > umbral else None


# --------------------------------------------------------------------------- prefiltro

def _waf_bloqueado(a, ctx):
    if a.get("rule_id") != "UC-WEB-001" or _ev(a).get("action") != "blocked":
        return None
    ips = _ips(a)
    if not ips:
        return None
    if any(ip in ctx._waf_permitidas for ip in ips):
        return None
    return f"ataque web bloqueado por el WAF; la IP {', '.join(ips)} no tiene ninguna petición permitida"


def prefiltrar(alerta, contexto):
    """Devuelve un dict con la decisión. Nunca lanza excepciones: ante la duda, pasa al agente.

    {"alert_id", "decision": "cerrar"|"pasar", "veredicto", "severidad", "motivo", "cambio", "pistas": [...]}
    """
    aid = alerta.get("alert_id", "")
    salida = {"alert_id": aid, "decision": PASAR, "veredicto": None, "severidad": None,
              "motivo": "", "cambio": None, "pistas": []}
    try:
        explica = contexto._cambio_que_explica(alerta)
        ruido = None if explica else _waf_bloqueado(alerta, contexto)
        if not explica and not ruido:
            _pistas_sin_cierre(alerta, contexto, salida)
            return salida

        motivo = explica[1] if explica else ruido
        bloqueos = []
        calientes = contexto.entidades_calientes(alerta)
        if calientes:
            for e, ids in list(calientes.items())[:3]:
                bloqueos.append(f"{e} aparece en otras alertas sin explicar: {', '.join(sorted(ids)[:4])}")
        p = contexto.pico(alerta)
        if p:
            bloqueos.append(f"volumen anómalo de {alerta.get('rule_id')}: {p[0]} alertas en esa hora (lo normal es {p[1]:g})")

        if bloqueos:
            salida["pistas"] = [f"Parecería cerrable ({motivo}), pero no se cierra:"] + bloqueos
            return salida

        salida.update(decision=CERRAR, motivo=motivo)
        if explica:
            salida.update(veredicto="benign_true_positive", severidad="informational", cambio=explica[0].id)
        else:
            # Ataque real pero sin efecto: true_positive informational, como en 01_contexto/ticket_ejemplo.json.
            # benign_true_positive es solo para actividad autorizada (politica_soc.md, apartado 1).
            salida.update(veredicto="true_positive", severidad="informational")
        return salida
    except Exception as e:  # el prefiltro nunca debe tumbar la cadena
        salida["pistas"] = [f"prefiltro con error ({type(e).__name__}); revisar con el agente"]
        return salida


def _pistas_sin_cierre(a, ctx, salida):
    """Pistas útiles para el agente cuando la alerta se parece a un cambio pero no encaja del todo."""
    t = datos.instante(a.get("created_at"))
    for c in ctx.cambios:
        if t and c.inicio - timedelta(hours=6) <= t <= c.fin + timedelta(hours=6):
            salida["pistas"].append(f"cerca de {c.id} ({c.titulo}), pero no encaja en origen, hora o alcance")
    if "OT" in str(_ev(a).get("dst_zone", "")).upper():
        salida["pistas"].append("toca la red OT: la política solo permite escalar al Responsable de Operaciones")


# --------------------------------------------------------------------------- uso por línea de comandos

def main(argv=None):
    """python -m engine.prefiltro [--dataset RUTA] [--muestra]  -> resumen de lo que se cerraría."""
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset")
    ap.add_argument("--muestra", action="store_true", help="usar alertas_muestra_desarrollo.jsonl")
    ap.add_argument("--salida", help="escribe las decisiones en un .jsonl")
    args = ap.parse_args(argv)
    todas = datos.cargar_alertas(args.dataset)
    ctx = Contexto.desde_dataset(args.dataset, todas)
    objetivo = datos.cargar_alertas(args.dataset, "alertas_muestra_desarrollo.jsonl") if args.muestra else todas
    res = [prefiltrar(a, ctx) for a in objetivo]
    cerradas = [r for r in res if r["decision"] == CERRAR]
    print(f"{len(objetivo)} alertas: {len(cerradas)} cerradas por el prefiltro, {len(res) - len(cerradas)} pasan al agente")
    for motivo, n in Counter((r["cambio"] or "WAF bloqueado") for r in cerradas).most_common():
        print(f"  {n:5d}  {motivo}")
    retenidas = [r for r in res if r["pistas"] and r["pistas"][0].startswith("Parecería")]
    print(f"{len(retenidas)} parecían cerrables pero se retienen por entidad caliente o volumen anómalo")
    if args.salida:
        with open(args.salida, "w", encoding="utf-8") as f:
            for r in res:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
