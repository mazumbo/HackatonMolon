# HackatonMolon · Triaje N1 para el SOC de Tarvia

Proyecto para el reto de la hackathon DTT-UAB (Deloitte · UAB): triaje de nivel 1 de las alertas del SOC
de Tarvia Group. Para cada alerta el sistema decide el veredicto (ataque real, actividad autorizada o falso
positivo), calcula la severidad según la política del SOC y deja un ticket con evidencias y acciones
propuestas. La contención nunca se ejecuta sola: siempre la aprueba una persona.

Trabaja sobre el dataset del reto ([DTT-UAB-The-Hack](https://github.com/dttdfr/DTT-UAB-The-Hack)):
11.061 alertas, logs, CMDB y una API mock en el puerto 8000.

## Cómo funciona

1. **Prefiltro** (`engine/prefiltro.py`). Cierra con motivo el ruido conocido (pentest y escaneos
   autorizados, flujos aprobados, DNS de productos de seguridad) sin llamar al LLM. Una alerta solo cuenta
   como autorizada si el calendario de cambios lo confirma.
2. **Agrupación** (`engine/agrupacion.py`). Junta las alertas de un mismo incidente por usuario, host, IP
   y hash, para escribir un ticket por incidente y no uno por alerta.
3. **Agente** (`agent/`). Investiga cada grupo con herramientas de solo lectura sobre la API mock y propone
   veredicto, evidencias y acciones. Lo que viene de los datos (correos, prompts, logs) se trata como dato,
   nunca como instrucción, y se marca si intenta manipular al modelo.
4. **Severidad y ticket** (`engine/severidad.py`). El código aplica la matriz de la política (regla ×
   criticidad del activo). El LLM puede subir la severidad pero no bajarla. El ticket sale con
   `requires_approval` en toda acción de contención.

## Resultados

Medidos con el modelo `ornith` de la pasarela UAB.

| Prueba | Resultado | Fuente |
| --- | --- | --- |
| 12 incidentes del dataset | Veredicto 12/12 y severidad 12/12. Media de 41 s por incidente, máximo 54 s | [`docs/PROGRESO.md`](docs/PROGRESO.md) |
| Motor sin LLM | El prefiltro cierra 4.339 de 11.061 alertas y ninguna de los 12 incidentes | [`eval/RESULTADOS_MOTOR.md`](eval/RESULTADOS_MOTOR.md) |
| 10 alertas oficiales del domingo | 57 alertas en 10 tickets en 142,8 s (unos 2 min 23 s, 3 en paralelo). Unos 33 s por ticket investigado (máximo 45 s). 4 cerradas con motivo, 2 de ellas en 0 s. La inyección de prompt se detecta y no se obedece | [`demo/vivo/tickets/`](demo/vivo/tickets/), [`ui/data/replay_vivo.json`](ui/data/replay_vivo.json) |
| Turno de noche | El SOC humano trabaja de lunes a viernes de 8:00 a 20:00. En el lote del domingo, los ataques reales habrían esperado 85,4 h hasta que alguien los viera: 53,7 h el ransomware (de sábado 02:16 a lunes 08:00) y 31,7 h el acceso de Logisoft. El sistema los tría en menos de un minuto | [`eval/TURNO_NOCHE.md`](eval/TURNO_NOCHE.md) |

Las horas del turno de noche suponen un humano optimista que atiende la alerta en cuanto abre el turno.

## Qué lo diferencia

- **Turno de noche.** El SOC de Tarvia solo mira la consola de lunes a viernes de 8:00 a 20:00. El 32 % de
  las alertas (3.503 de 11.061) llega fuera de ese horario, y 8 de los 12 incidentes tienen alguna alerta
  clave fuera de horario. Medimos cuántas horas esperaría cada una hasta que la viera una persona, frente a
  menos de un minuto del sistema. Si un ataque tira la venta online en campaña, cada hora cuesta unos
  120.000 €. Detalle en [`eval/TURNO_NOCHE.md`](eval/TURNO_NOCHE.md).
- **No cierra ante la duda.** El prefiltro solo cierra lo que puede justificar, y lo "autorizado" solo
  cuenta si el calendario de cambios lo confirma. Ninguna alerta de los 12 incidentes se cierra por error.
- **La severidad la decide el código.** Se aplica la matriz de la política. El LLM puede subirla, pero
  nunca bajarla.
- **Defensa contra la inyección de prompt.** Los datos del atacante van marcados como datos no fiables,
  el código detecta los intentos de manipulación y la UI los marca en rojo con el texto escondido.
- **Una persona aprueba siempre la contención.** El agente solo tiene herramientas de lectura. Bloquear
  un indicador o purgar un correo también pide aprobación, aunque la política interna no lo exija.
- **Incidentes, no alertas.** Las alertas relacionadas se agrupan en un solo ticket: las 10 alertas del
  domingo arrastran 57 alertas del historial y salen en 10 tickets.
- **Se puede ver el lote entero.** La pestaña Reproducción de la UI repite las 10 alertas oficiales con
  sus tiempos reales: entrada, prefiltro, agrupación, agente y ticket.

## Estructura

| Carpeta | Qué hay |
| --- | --- |
| `engine/` | Motor determinista: prefiltro, severidad y agrupación, con tests |
| `agent/` | Agente de triaje: herramientas, prompt, `run_batch` y guía del día de la demo ([`DEMO.md`](agent/DEMO.md)) |
| `ui/` | Pantalla de la demo (FastAPI + HTML/JS sin build): cola, detalle del ticket, turno de noche y reproducción del lote |
| `eval/` | Evaluación contra los 12 incidentes, ensayo con alertas nuevas y cálculo del turno de noche |
| `demo/` | Tickets reales de las 10 alertas en vivo, plan B offline y el vídeo |
| `docs/` | Hoja de ruta, progreso del equipo e incidentes localizados |

## Arrancar

Hace falta Python 3 y el repo del reto clonado al lado (`DATASET_DIR` apunta a él).

**Solo la UI con los tickets ya generados** (no necesita LLM ni API mock):

```bash
pip install -r ui/requirements.txt
UI_TICKETS=demo/vivo/tickets uvicorn server:app --app-dir ui --host 127.0.0.1 --port 8080
# http://localhost:8080
```

Sin `UI_TICKETS` carga los tickets de ejemplo de `ui/data/tickets_mock.json`.

**Triar alertas en vivo:**

```bash
pip install -r agent/requirements.txt
cp agent/.env.example agent/.env          # rellenar LLM_API_KEY
# API mock del reto en otra terminal, desde 06_herramientas/: uvicorn mock_soc_api:app --port 8000
python -m agent.run_batch --ids-file vivas.jsonl --workers 3 --out out/vivas
UI_TICKETS=out/vivas uvicorn server:app --app-dir ui --host 127.0.0.1 --port 8080
```

Paso a paso del día de la demo en [`agent/DEMO.md`](agent/DEMO.md). Plan B sin red en
[`demo/plan_b/LEEME.md`](demo/plan_b/LEEME.md).

## Vídeo

La demo grabada con las 10 alertas oficiales está en
[`demo/video/Video_Demo_Hack.mp4`](demo/video/Video_Demo_Hack.mp4).
