# Contrato del ticket entre el agente (B) y la interfaz (C)

La interfaz lee **exactamente** el formato oficial del reto, `01_contexto/ticket_salida.schema.json`
del repo `dttdfr/DTT-UAB-The-Hack`. Un ticket que cumpla el esquema ya se pinta.

Además acepta estos campos **opcionales** (el esquema permite campos extra). Si faltan, la pantalla
no se rompe: simplemente no enseña ese bloque.

| Campo | Tipo | Para qué lo usa la UI |
|---|---|---|
| `first_alert_at` | ISO 8601 UTC | Hora de la primera alerta del ticket (si no está, se calcula de `alerts`) |
| `alerts` | `[{alert_id, created_at, rule_id, rule_name, severity, source_product}]` | Línea temporal del incidente y cálculo del turno de noche |
| `prompt_injection` | `[{source, event_id, excerpt, handling}]` | Recuadro rojo con el texto del atacante y las frases resaltadas |
| `devils_advocate` | string | Bloque "Abogado del diablo" |
| `tool_trace` | `[{tool, args, result}]` | Traza de herramientas plegable |
| `incident_ref` | int \| null | Número del incidente en `docs/incidentes_localizados.md` (solo para la evaluación) |
| `status` | `open` \| `pending_approval` \| `closed` | Orden de la cola y filtro "Cerrados" |
| `group` | `{grupo_id, uniones, entidades_clave, reglas}` | Bloque "Por qué estas alertas van juntas": entidades en común, reglas con su recuento y las primeras 8 uniones (`uniones` es una lista de textos; `reglas` un dict `rule_id -> nº`) |
| `prefilter` | dict | Resultado de `prefiltrar()` (`decision`, `veredicto`, `severidad`, `motivo`, `cambio`, `pistas`). En un ticket cerrado por el pre-filtro es **un solo** dict (con `decision`); en un ticket de grupo es un dict `alert_id -> resultado` y la UI enseña, plegadas, solo las alertas con motivo o pistas |
| `model` | string | Si vale `"prefiltro"`, el ticket se marca con la etiqueta "pre-filtro" en la cola (lo cerró el motor sin pasar por el modelo; suele venir con `triage_seconds = 0`) |
| `related_alert_ids_suggested` | `[alert_id]` | Bloque "Alertas que podrían estar relacionadas": sugerencias del agente que no están en `alert_ids`, para que las mire una persona |

Un ticket puede llevar varios `alert_ids` (un incidente agrupado); la línea temporal y el turno de noche usan todas.

Nota para B: `alerts` sale casi gratis (son campos de cada alerta de `GET /alerts/{id}`) y es lo que
más luce en la demo, porque alimenta la línea temporal y el turno de noche. Si solo podéis añadir un
extra, que sea ese.

## Cómo enchufar la salida real del agente

```bash
UI_TICKETS=out/tickets/            uvicorn server:app --app-dir ui --port 8080   # carpeta con un .json por ticket
UI_TICKETS=out/tickets.jsonl       uvicorn server:app --app-dir ui --port 8080   # o un .jsonl
```

La UI relee la fuente en cada petición: si el agente escribe tickets nuevos, basta con recargar la página.
Un `.json` a medio escribir se ignora en vez de romper la pantalla.

## Botón de aprobación

`POST /api/approve` llama a la API mock del reto (`SOC_API_URL`, por defecto `http://localhost:8000`):
primero `POST /approvals` y, si la acción es una de las que la API ejecuta (`isolate_host`, `disable_user`,
`revoke_sessions`, `reset_password`, `block_ioc`, `purge_email`, `disable_access_key`), `POST /containment/{accion}`
con el `approval_token`. Si la API no está levantada, la aprobación se simula en la UI y se dice en pantalla.
