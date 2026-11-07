# Progreso del proyecto

Estado vivo del equipo. **Actualizadlo en el mismo PR que cierra cada tarea**: mover la línea de "Por hacer" a "Hecho", con el PR o commit al lado.
Leyenda: ✅ hecho · 🔄 en curso · ⏳ por hacer · ⛔ bloqueado. Plan completo en [`HOJA_DE_RUTA.md`](HOJA_DE_RUTA.md).

_Última actualización: 07/11/2026 16:00_

## Resumen

| Hito | Estado | Qué falta |
| --- | --- | --- |
| H1 · Arranque | 🔄 | Clave del LLM (Quiver) sin entregar por la organización |
| H6 · N1 de punta a punta | ⏳ | Probar `triar()` con la clave real y pintar sus tickets en la UI |
| H12 · N1 fiable + N2 | ⏳ | Pre-filtro, agrupación, evaluación contra los 12 incidentes |
| H18 · Congelación | ⏳ | |
| H22 · Ensayo general | ⏳ | |

## Bloqueos

- ⛔ **Clave de Quiver AI**: la organización aún no la ha dado. Cuando llegue: `agent/.env` → `QUIVER_API_KEY=...` y `python -m agent.probar_quiver`.
- ⚠️ Los modelos Arrow de Quiver están pensados para SVG. Hay que confirmar con la clave que razonan bien sobre alertas; si no, preguntar a los mentores por otro modelo (el agente ya admite `LLM_PROVIDER=anthropic`).

## Por rol

### A · Datos y motor determinista

- ✅ API mock del reto levantada en local (puerto 8000); `LEVANTAR_API.py` comprueba que responde (pide 5 alertas).
- ⏳ Matriz de severidad definitiva (ahora hay una provisional en `agent/severity.py`).
- ⏳ `prefiltrar(alerta)`: pentest, Nessus, SCCM y flujos aprobados, con motivo de cierre.
- ⏳ `agrupar(alertas)`: correlación por usuario, host, IP y hash.
- ⏳ Métricas del turno de noche con datos reales del agente.
- ⏳ Pre-calcular resultados por si falla la red en la demo.

### B · Agente IA

- ✅ Esqueleto del agente (`agent/`): herramientas de solo lectura sobre la API mock, prompt, `triar()`, `run_batch`, `smoke_test`.
- ✅ Defensas: datos dentro de `<untrusted_data>`, heurística de prompt injection, contención solo propuesta y siempre con aprobación.
- 🔄 Soporte para Quiver AI además de Anthropic ([PR #2](https://github.com/mazumbo/HackatonMolon/pull/2)), sin probar contra la API real.
- ⏳ Primera alerta triada de punta a punta con la clave real.
- ⏳ Playbooks por regla a partir de los runbooks.
- ⏳ Validar la salida contra `ticket_salida.schema.json`.
- ⏳ Detectar OT a partir de la zona de la CMDB.
- ⏳ Estable en las 150 alertas de desarrollo, sin errores.
- ⏳ Robustez con alertas raras o campos vacíos.

### C · Interfaz y demo

- ✅ Demo visual en `ui/` ([PR #1](https://github.com/mazumbo/HackatonMolon/pull/1)): cola, detalle del ticket con traza, línea temporal, aviso de prompt injection, botón de aprobación, vista Turno de noche.
- ✅ Datos de prueba: `ui/data/tickets_mock.json` (12 incidentes + 6 autorizados).
- ✅ Contrato de ticket con el agente: [`ui/CONTRATO_TICKET.md`](../ui/CONTRATO_TICKET.md).
- ⏳ Conectar a tickets reales del agente (`UI_TICKETS=out/tickets/`).
- ⏳ Vista de incidente agrupado (depende de `agrupar()` de A).
- ⏳ Modo presentación y pulido final.

### D · Analista, evaluación y pitch

- ✅ 12 incidentes y benignos localizados: [`incidentes_localizados.md`](incidentes_localizados.md).
- ✅ Hoja de ruta: [`HOJA_DE_RUTA.md`](HOJA_DE_RUTA.md).
- ⏳ `eval/`: verdad esperada + script que mida aciertos del agente (veredicto y severidad).
- ⏳ Etiquetar a mano ~40 alertas de desarrollo.
- ⏳ Medir tokens y segundos por alerta (coste).
- ⏳ Página para el comité de dirección.
- ⏳ Guion de 5 minutos, ensayos y vídeo de respaldo.

## Registro

- **07/11 ~13:00** · Repo creado. Hoja de ruta e incidentes subidos.
- **07/11 ~13:30** · UI de la demo mergeada (PR #1).
- **07/11 ~14:00** · Esqueleto del agente (rol B) y script de prueba de la API mock.
- **07/11 ~15:00** · La organización da Quiver AI como LLM; PR #2 para soportarlo. Clave pendiente.
