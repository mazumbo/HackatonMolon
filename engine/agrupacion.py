"""Agrupación de alertas en incidentes (rol A). Política, apartado 6: varias alertas de la misma
intrusión van en un único ticket.

agrupar(alertas, contexto, pivotes) -> lista de grupos, cada uno con sus alert_ids, su línea temporal
y el MOTIVO de cada unión ("comparten el hash 70aa..."), para que el agente, la UI y la defensa lo expliquen.

Tres ideas, ajustadas midiendo contra los 12 incidentes de docs/incidentes_localizados.md:

1. Pistas de los logs, no solo de la alerta. Cada alerta trae sus related_events; de esos eventos
   salen más entidades (la IP interna que da la VPN y adónde hace RDP, el runner de una build...).
   Además se aprende de los logs normales quién usa qué: la identidad cloud que se usa siempre
   desde una IP interna (cloudtrail) y el equipo de cada IP (activos.csv).
2. El ruido no hace de pegamento. Las reglas que saltan muchísimo (reportes de phishing, antivirus,
   viaje imposible...) no pueden unir grupos por un usuario o un equipo. Solo se cuelgan del grupo
   más cercano si están a menos de 6 h, o se unen por una pista fuerte.
3. Campañas de dominios parecidos: packaging-iberia-pagos y packaging-iberia-portal son la misma.

Pistas fuertes (unen sin límite de tiempo): hash, identidad o clave cloud, IP externa, dominio,
huella de navegador headless y familia de dominios (esta, solo en 72 h).
Pistas débiles (usuario, equipo, IP interna, cliente): unen si están a menos de 72 h.
Una entidad que sale en más de 50 alertas abiertas no une nada (JUMP01, dominios de Microsoft...).
"""
import csv
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import timedelta

from . import datos
from .prefiltro import entidades as entidades_alerta

VENTANA_DEBIL = timedelta(hours=72)
VENTANA_FAMILIA = timedelta(hours=72)
VENTANA_RUIDO = timedelta(hours=6)
MAX_ALERTAS_POR_ENTIDAD = 50
# Un dominio/IP externa que se repite en muchas alertas es tráfico recurrente (DNSBL, antivirus, etc.):
# solo une alertas cercanas, para no encadenar semanas de ruido en un único grupo.
UMBRAL_RECURRENTE = 8
VENTANA_RECURRENTE = timedelta(hours=24)
VOLUMEN_RUIDO = 200  # una regla con al menos tantas alertas se trata como ruido de fondo

_FUERTES = {"hash", "cloud", "dom", "fp"}
_PALABRAS_COMUNES = {"example", "www", "mail", "login", "secure", "portal", "pagos", "cdn", "service",
                     "update", "online", "app", "api", "tarvia", "com", "net", "org"}
_TIPO_TXT = {"hash": "el hash", "cloud": "la identidad cloud", "dom": "el dominio", "fp": "la huella de navegador",
             "ip": "la IP", "host": "el equipo", "user": "el usuario", "cliente": "el cliente",
             "fam": "la campaña de dominios"}


def _privada(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # rangos como "10.40.16.21-26": se tratan como internos


def _sin_significado(ip):
    """Loopback, enlace local, reservada, sin especificar o multicast (p. ej. 127.0.0.2 de las respuestas DNSBL):
    no identifica a ningún equipo y nunca debe unir alertas."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_loopback or a.is_link_local or a.is_reserved or a.is_unspecified or a.is_multicast


def es_fuerte(entidad):
    tipo, _, valor = entidad.partition(":")
    return tipo in _FUERTES or tipo == "fam" or (tipo == "ip" and not _privada(valor))


def familia_dominio(dominio):
    """'packaging-iberia-pagos.example' -> 'packaging-iberia' (None si no hay dos palabras significativas)."""
    base = dominio.rsplit(".", 1)[0]
    palabras = [p for p in re.split(r"[-.]", base) if len(p) > 3 and p not in _PALABRAS_COMUNES]
    return "-".join(palabras[:2]) if len(palabras) >= 2 else None


# --------------------------------------------------------------------------- pivotes desde los logs

class Pivotes:
    """Lo que se sabe de los logs: eventos relacionados, equipo de cada IP e identidad cloud habitual por IP."""

    def __init__(self, eventos=None, ip_a_equipo=None, identidades_por_ip=None):
        self.eventos = eventos or {}
        self.ip_a_equipo = ip_a_equipo or {}
        self.identidades_por_ip = identidades_por_ip or {}

    @classmethod
    def desde_dataset(cls, ruta=None, alertas=()):
        base = datos.dataset_dir(ruta)
        necesarios = {e for a in alertas for e in a.get("related_events") or []}
        eventos = {}
        logs = base / "04_logs"
        for f in sorted(os.listdir(logs)):
            p = logs / f
            if f.endswith(".jsonl"):
                with open(p, encoding="utf-8") as fh:
                    for linea in fh:
                        i = linea.find('"event_id": "')
                        if i < 0:
                            continue
                        eid = linea[i + 13:linea.find('"', i + 13)]
                        if eid in necesarios:
                            eventos[eid] = json.loads(linea)
            elif f.endswith(".csv"):
                with open(p, encoding="utf-8") as fh:
                    for fila in csv.DictReader(fh):
                        if fila.get("event_id") in necesarios:
                            eventos[fila["event_id"]] = fila
        with open(base / "02_inventario" / "activos.csv", encoding="utf-8") as fh:
            ip_a_equipo = {r["ip"]: r["hostname"].upper() for r in csv.DictReader(fh) if r.get("ip")}
        identidades = defaultdict(set)
        ct = logs / "cloudtrail.jsonl"
        if ct.exists():
            with open(ct, encoding="utf-8") as fh:
                for linea in fh:
                    c = json.loads(linea)
                    ip = c.get("sourceIPAddress", "")
                    quien = (c.get("userIdentity") or {}).get("userName")
                    if quien and _privada(ip) and ip:  # solo uso habitual desde dentro
                        identidades[ip].add(quien)
        return cls(eventos, ip_a_equipo, dict(identidades))

    def _de_ip(self, ip):
        if _sin_significado(ip):
            return set()
        out = {f"ip:{ip}"}
        if ip in self.ip_a_equipo:
            out.add(f"host:{self.ip_a_equipo[ip]}")
        for quien in self.identidades_por_ip.get(ip, ()):
            out.add(f"cloud:{quien}")
        return out

    def de_evento(self, evento):
        out = set()

        def recorrer(v, clave=""):
            if isinstance(v, dict):
                for k, x in v.items():
                    recorrer(x, k)
            elif isinstance(v, list):
                for x in v:
                    recorrer(x, clave)
            elif isinstance(v, str) and v:
                k = clave.lower()
                try:
                    ipaddress.ip_address(v)
                    out.update(self._de_ip(v))
                    return
                except ValueError:
                    pass
                if k in ("user", "username", "account") and v[0].isalpha():
                    v = v.split("\\")[-1]  # "TARVIA\\marta.puig" -> "marta.puig"
                    out.add("user:" + (v if "@" in v else v + "@tarvia.example").lower())
                elif k in ("runner", "host", "hostname", "src_host", "dst_host"):
                    out.add("host:" + v.upper())
                elif k == "device_fp" and "headless" in v:
                    out.add("fp:" + v)
                elif k == "accesskeyid":
                    out.add("cloud:" + v)

        recorrer(evento)
        return out

    def entidades(self, alerta):
        """Entidades de la alerta + las de sus eventos de log + pivotes por IP + familia de dominios."""
        e = {x for x in entidades_alerta(alerta) if not (x.startswith("ip:") and _sin_significado(x[3:]))}
        for d in (alerta.get("entities") or {}).get("domains") or []:
            e.add("dom:" + str(d).lower())
        for x in [x for x in e if x.startswith("ip:")]:
            e.update(self._de_ip(x[3:]))
        for ref in alerta.get("related_events") or []:
            if ref in self.eventos:
                e.update(self.de_evento(self.eventos[ref]))
        for x in [x for x in e if x.startswith("dom:")]:
            fam = familia_dominio(x[4:])
            if fam:
                e.add("fam:" + fam)
        return e


# --------------------------------------------------------------------------- agrupación

class _Uniones:
    def __init__(self, ids):
        self.padre = {i: i for i in ids}
        self.motivos = []

    def raiz(self, x):
        while self.padre[x] != x:
            self.padre[x] = self.padre[self.padre[x]]
            x = self.padre[x]
        return x

    def unir(self, a, b, motivo):
        ra, rb = self.raiz(a), self.raiz(b)
        if ra != rb:
            self.padre[ra] = rb
            self.motivos.append((a, b, motivo))


def _motivo(entidad, a, b, horas):
    tipo, _, valor = entidad.partition(":")
    corto = valor[:12] + "…" if tipo == "hash" else valor
    return {"de": a, "a": b, "entidad": entidad,
            "motivo": f"comparten {_TIPO_TXT.get(tipo, tipo)} {corto} ({horas:.0f} h entre una y otra)"}


def agrupar(alertas, pivotes=None, volumen_reglas=None):
    """Agrupa alertas abiertas (las que el prefiltro no ha cerrado).

    volumen_reglas: Counter rule_id -> nº de alertas totales (para saber qué es ruido de fondo).
                    Si no se da, se calcula con las alertas recibidas.
    Devuelve una lista de grupos ordenada por la primera alerta:
      {"grupo_id", "alert_ids", "first_alert_at", "last_alert_at", "reglas", "entidades_clave", "uniones"}
    """
    piv = pivotes or Pivotes()
    alertas = [a for a in alertas if a.get("alert_id")]
    por_id = {a["alert_id"]: a for a in alertas}
    t = {i: datos.instante(a.get("created_at")) for i, a in por_id.items()}
    volumen = volumen_reglas or Counter(a.get("rule_id") for a in alertas)
    ent = {i: piv.entidades(a) for i, a in por_id.items()}
    indice = defaultdict(list)
    for i, es in ent.items():
        for x in es:
            indice[x].append(i)
    ancla = {i for i, a in por_id.items() if volumen.get(a.get("rule_id"), 0) < VOLUMEN_RUIDO}
    u = _Uniones(por_id)

    def horas(a, b):
        return abs((t[b] - t[a]).total_seconds()) / 3600 if t[a] and t[b] else 0.0

    # fase 1: anclas por cualquier pista; el ruido solo por pistas fuertes
    for x, ids in indice.items():
        if len(ids) > MAX_ALERTAS_POR_ENTIDAD:
            continue
        fuerte = es_fuerte(x)
        ids = sorted((i for i in ids if fuerte or i in ancla), key=lambda i: (t[i] is None, t[i] or 0))
        for a, b in zip(ids, ids[1:]):
            if not (t[a] and t[b]):
                continue
            dt = t[b] - t[a]
            limite = VENTANA_FAMILIA if x.startswith("fam:") else (None if fuerte else VENTANA_DEBIL)
            if fuerte and x.split(":", 1)[0] in ("dom", "fam", "ip") and len(indice[x]) > UMBRAL_RECURRENTE:
                limite = VENTANA_RECURRENTE
            if limite is None or dt <= limite:
                u.unir(a, b, _motivo(x, a, b, horas(a, b)))

    # fase 2: el ruido que sigue suelto se cuelga del ancla más cercana (nunca une dos grupos)
    tamano = Counter(u.raiz(i) for i in por_id)
    for i in por_id:
        if i in ancla or tamano[u.raiz(i)] > 1:
            continue
        mejor = None
        for x in ent[i]:
            if es_fuerte(x) or len(indice[x]) > MAX_ALERTAS_POR_ENTIDAD:
                continue
            for j in indice[x]:
                if j in ancla and t[i] and t[j] and abs(t[j] - t[i]) <= VENTANA_RUIDO:
                    if mejor is None or abs(t[j] - t[i]) < mejor[0]:
                        mejor = (abs(t[j] - t[i]), j, x)
        if mejor:
            u.padre[i] = u.raiz(mejor[1])
            u.motivos.append((i, mejor[1], _motivo(mejor[2], i, mejor[1], horas(i, mejor[1]))))

    miembros = defaultdict(list)
    for i in por_id:
        miembros[u.raiz(i)].append(i)
    motivos_por_raiz = defaultdict(list)
    for a, _, m in u.motivos:
        motivos_por_raiz[u.raiz(a)].append(m)

    grupos = []
    for raiz, ids in miembros.items():
        ids.sort(key=lambda i: (t[i] is None, t[i] or 0, i))
        comunes = Counter(x for i in ids for x in ent[i])
        clave = [x for x, n in comunes.most_common() if n > 1 and len(indice[x]) <= MAX_ALERTAS_POR_ENTIDAD][:8]
        grupos.append({
            "grupo_id": "GRP-" + ids[0],
            "alert_ids": ids,
            "first_alert_at": por_id[ids[0]].get("created_at"),
            "last_alert_at": por_id[ids[-1]].get("created_at"),
            "reglas": dict(Counter(por_id[i].get("rule_id") for i in ids)),
            "entidades_clave": clave,
            "uniones": motivos_por_raiz.get(raiz, []),
        })
    grupos.sort(key=lambda g: (g["first_alert_at"] or "", g["grupo_id"]))
    return grupos


# --------------------------------------------------------------------------- evaluación contra nuestra verdad

def incidentes_de_referencia(ruta_md, alertas):
    """{nº incidente: set(alert_id)} a partir de docs/incidentes_localizados.md."""
    texto = open(ruta_md, encoding="utf-8").read().split("## Actividad autorizada")[0]
    sufijo = {a["alert_id"][-6:]: a["alert_id"] for a in alertas}
    out = {}
    for linea in texto.splitlines():
        m = re.match(r"\| (\d+) \|", linea)
        if not m:
            continue
        celda = linea.split("|")[4]
        ids = set(re.findall(r"\b(0\d{5})\b", celda))
        for x, y in re.findall(r"(0\d{5})[–-](0\d{5})", celda):
            ids |= {f"{n:06d}" for n in range(int(x), int(y) + 1)}
        out[int(m.group(1))] = {sufijo[s] for s in ids if s in sufijo}
    return out


def evaluar(grupos, incidentes):
    """Para cada incidente: qué parte acaba en su grupo principal (completitud) y qué parte del grupo es suya (pureza)."""
    grupo_de = {i: k for k, g in enumerate(grupos) for i in g["alert_ids"]}
    filas = {}
    for n, ids in sorted(incidentes.items()):
        presentes = [grupo_de[i] for i in ids if i in grupo_de]
        if not presentes:
            filas[n] = {"completitud": 0.0, "pureza": 0.0, "en_grupo": 0, "total": len(ids)}
            continue
        k, dentro = Counter(presentes).most_common(1)[0]
        filas[n] = {"completitud": dentro / len(ids), "pureza": dentro / len(grupos[k]["alert_ids"]),
                    "en_grupo": dentro, "total": len(ids)}
    media = {m: sum(f[m] for f in filas.values()) / max(1, len(filas)) for m in ("completitud", "pureza")}
    return filas, media


def main(argv=None):
    """python -m engine.agrupacion [--dataset RUTA] [--salida grupos.json]"""
    import argparse
    from pathlib import Path

    from .prefiltro import CERRAR, Contexto, prefiltrar
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset")
    ap.add_argument("--salida")
    args = ap.parse_args(argv)
    todas = datos.cargar_alertas(args.dataset)
    ctx = Contexto.desde_dataset(args.dataset, todas)
    abiertas = [a for a in todas if prefiltrar(a, ctx)["decision"] != CERRAR]
    piv = Pivotes.desde_dataset(args.dataset, abiertas)
    grupos = agrupar(abiertas, piv, Counter(a.get("rule_id") for a in todas))
    varias = [g for g in grupos if len(g["alert_ids"]) > 1]
    print(f"{len(abiertas)} alertas abiertas -> {len(grupos)} grupos ({len(varias)} con más de una alerta)")
    md = Path(__file__).resolve().parents[1] / "docs" / "incidentes_localizados.md"
    if md.exists():
        filas, media = evaluar(grupos, incidentes_de_referencia(md, todas))
        for n, f in filas.items():
            print(f"  incidente {n:2d}: {f['en_grupo']}/{f['total']} en su grupo, pureza {f['pureza']:.0%}")
        print(f"  media: completitud {media['completitud']:.0%}, pureza {media['pureza']:.0%}")
    if args.salida:
        with open(args.salida, "w", encoding="utf-8") as fh:
            json.dump(grupos, fh, ensure_ascii=False, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
