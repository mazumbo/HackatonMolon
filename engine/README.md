# Motor determinista (rol A)

Código sin LLM que va delante y detrás del agente: el **prefiltro de ruido** (`prefiltro.py`) y la **matriz de severidad** (`severidad.py`). La agrupación vendrá después.

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
    ...   # benign_true_positive, severidad informational; r["motivo"] y r["cambio"] explican por qué
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
- Las personas cuentan como criticidad media y las cuentas de servicio como alta. VIP, administradores y privilegiados suben un nivel.
- Como mucho, un nivel arriba o abajo en total.

Resultado sobre los 12 incidentes de `docs/incidentes_localizados.md`: 9 salen critical, 2 high y 1 medium (el #5, Logisoft, porque su regla es medium; el agente puede subirlo).
