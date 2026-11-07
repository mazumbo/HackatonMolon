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
