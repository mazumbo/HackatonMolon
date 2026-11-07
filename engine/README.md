# Motor determinista (rol A)

Código sin LLM que va delante y detrás del agente: el **prefiltro de ruido** (`prefiltro.py`) la **matriz de severidad** (`severidad.py`) y la **agrupación en incidentes** (`agrupacion.py`).

```bash
pip install pytest                              # solo para los tests
export DATASET_DIR=/ruta/a/DTT-UAB-The-Hack     # repo del reto
python -m engine.prefiltro                      # resumen sobre las 11.061 alertas
python -m engine.prefiltro --muestra            # sobre las 150 de desarrollo
python -m engine.prefiltro --salida out/prefiltro.jsonl
python -m pytest -q engine/tests
```

## Cómo usarlo desde el agente

```python
from engine.prefiltro import Contexto, prefiltrar
ctx = Contexto.desde_dataset()          # una vez al arrancar
r = prefiltrar(alerta, ctx)
if r["decision"] == "cerrar":
    ...   # r["veredicto"]: benign_true_positive si es un cambio aprobado (r["cambio"]),
          # true_positive informational si es un ataque web bloqueado sin efecto; r["motivo"] explica por qué
else:
    ...   # pasa al agente; r["pistas"] le cuenta lo que el prefiltro ha visto
```

En modo en directo, `ctx.añadir(alerta)` incorpora cada alerta nueva antes de prefiltrarla.

## Criterio: cerrar solo lo seguro

Una alerta solo se cierra si se cumplen las tres condiciones:

1. **Encaja con un cambio aprobado** de `calendario_cambios.csv` en origen, ventana horaria (±30 min) y alcance, o es un **ataque web bloqueado** de una IP que no tiene ninguna petición permitida en el WAF.
2. **Ninguna entidad caliente.** Ninguna de sus IP, equipos, usuarios, hashes o identidades cloud sale en otra alerta sin explicar en las 72 h de alrededor.
3. **Ningún pico de volumen.** Si su regla recibe en esa hora más de max(3 × lo normal, lo normal + 5) alertas, se suspende el cierre automático de esa hora. Es el "baremo que se desplaza con lo que entra".

No se usan textos libres de la alerta como prueba (`change_ticket`, `maintenance_window`, descripciones), porque los puede escribir el atacante. Tampoco se usa la numeración de los `alert_id`. A propósito no se cierran el mantenimiento OT ni la rotación de certificados de la VPN.

## Resultado sobre el dataset completo (07/11/2026)

- Se cierran 4.271 de las 11.061 alertas: 3.386 ataques web bloqueados, 833 de SCCM, las 20 del pentest, las 19 de Nessus y unas pocas de otros cambios.
- Otras 516 parecían cerrables, pero se retienen por entidad caliente. Son casi todas de SCCM en equipos que tienen alguna otra alerta.
- No se cierra **ninguna** de las alertas de los 12 incidentes de `docs/incidentes_localizados.md`, y hay un test que lo comprueba.

# Matriz de severidad (`severidad.py`)

```python
from engine.severidad import calcular_severidad, compute_severity
r = calcular_severidad(alertas_del_ticket, factores_del_llm, contexto=ctx)
r["severidad"], r["justificacion"], r["autorizado_verificado"], r["avisos"]

# Para el agente de B basta con cambiar el import y pasar las alertas:
sev, why = compute_severity(f, alertas=alertas_del_ticket, contexto=ctx)
```

Sigue el apartado 2 de `politica_soc.md` con estas reglas de seguridad:

- **El LLM puede subir, nunca bajar.** La severidad de la regla y la criticidad salen de los datos (`activos.csv` y `usuarios.csv`). El LLM solo puede proponer valores más altos. El -1 por "bloqueado" solo se aplica si un campo estructurado lo dice (`action`, `edr_action`, `executed`...) y no hay actividad posterior en las entidades.
- **"Flujo autorizado" solo si lo verifica el calendario.** Si solo lo dice el LLM, se ignora y queda un aviso. El agente debería usar `autorizado_verificado` para decidir si el veredicto es `benign_true_positive`.
- **Lo que no está en el inventario cuenta como criticidad alta**, y la justificación lo dice.
- El MFA aprobado en una VPN o un inicio de sesión (`mfa`, `mfa_result`, `final_result`) cuenta como acceso confirmado.
- Las personas cuentan como criticidad media y las cuentas de servicio como alta. VIP, administradores y privilegiados suben un nivel.
- Como mucho, un nivel arriba o abajo en total.

Resultado sobre los 12 incidentes de `docs/incidentes_localizados.md`: 9 salen critical y 3 high (los #5, #10 y #11). La matriz sigue `politica_soc.md` al pie de la letra; el documento se corrigió donde estaba desfasado (#8, #9 y #12 son critical por el +1 de acceso o ejecución confirmados).

Solo hay una excepción al "un nivel como mucho", y solo se aplica si el código la verifica: un **ataque web bloqueado por el WAF sin ninguna petición permitida de esa IP** es `informational` aunque el activo sea crítico. Es lo que hace el `01_contexto/ticket_ejemplo.json` oficial (regla low x activo crítico = medium, -1 por el bloqueo, y "ruta inexistente": informational). Para que se aplique hay que pasar `contexto=` a `calcular_severidad`.

# Agrupación en incidentes (`agrupacion.py`)

```bash
python -m engine.agrupacion                       # agrupa las alertas abiertas y se mide contra los 12 incidentes
python -m engine.agrupacion --salida out/grupos.json
```

```python
from collections import Counter
from engine.agrupacion import Pivotes, agrupar
abiertas = [a for a in todas if prefiltrar(a, ctx)["decision"] != "cerrar"]
grupos = agrupar(abiertas, Pivotes.desde_dataset(alertas=abiertas), Counter(a["rule_id"] for a in todas))
# cada grupo: grupo_id, alert_ids (en orden temporal), first_alert_at, last_alert_at, reglas,
#             entidades_clave y uniones (por qué se ha unido cada alerta: "comparten el hash 70aa…")
```

Un grupo equivale a un ticket: el agente lo recibe entero y escribe un solo ticket con todos los `alert_ids`.

Cómo agrupa (ajustado midiendo contra `docs/incidentes_localizados.md`):

1. **Pistas de los logs.** Además de las entidades de la alerta, usa las de sus `related_events` (la IP interna que asigna la VPN y adónde hace RDP, el runner de una build…). También aprende de los logs normales el equipo de cada IP y la identidad cloud que se usa siempre desde cada IP interna.
2. **El ruido no hace de pegamento.** Las reglas con 200 alertas o más (reportes de phishing, antivirus, viaje imposible…) no unen grupos por usuario o equipo. Solo se cuelgan del grupo más cercano si están a menos de 6 h, o se unen por una pista fuerte.
3. **Campañas de dominios parecidos** (`packaging-iberia-pagos` y `packaging-iberia-portal`), si están a menos de 72 h.

Las pistas fuertes (hash, identidad o clave cloud, IP externa, dominio y huella headless) unen sin límite de tiempo. Las débiles (usuario, equipo, IP interna) solo unen si están a menos de 72 h. Lo que sale en más de 50 alertas abiertas no une nada.

Resultado (07/11/2026): 6.790 alertas abiertas se quedan en 6.605 grupos. Contra los 12 incidentes, la **completitud media es del 92 %** y la **pureza del 96 %**. Diez incidentes salen enteros, entre ellos el ransomware de 9 días, que se une por el hash repetido entre FS01 y PRINT01. Límite conocido: en el incidente 3 la build de CI no se une con el uso posterior de la clave cloud, porque esa identidad sale en demasiadas alertas legítimas. Eso lo tiene que conectar el agente.

Como comparación, agrupar sin más todo lo que comparte algo en 72 h da una completitud del 84 % y una pureza del 87 %.
