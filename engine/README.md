# Motor determinista (rol A)

Código sin LLM que va delante del agente. Por ahora tiene el **prefiltro de ruido**. La matriz de severidad y la agrupación vendrán después.

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
