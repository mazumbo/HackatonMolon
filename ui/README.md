# Demo visual (rol C)

Pantalla para la defensa: cola de tickets, detalle con evidencias y traza, línea temporal del incidente,
aviso en rojo cuando los datos traen texto escrito para manipular a la IA, botón de aprobación humana
y la vista **Turno de noche** (cuándo lo habría visto el SOC humano frente a la IA).

**Stack:** Python + FastAPI (mismo lenguaje que la API mock del reto) y una página HTML/JS sin framework
ni build. Nada que compilar el día de la demo. Seguridad: sin dependencias de frontend ni CDN, todo el texto de los tickets se escapa antes de pintarse (el dataset trae texto del atacante), cabeceras CSP estrictas y la API escucha en local si se arranca con `--host 127.0.0.1`.

## Arrancar

```bash
pip install -r ui/requirements.txt
uvicorn server:app --app-dir ui --host 127.0.0.1 --port 8080
# http://localhost:8080
```

Para que el botón de aprobación ejecute contra la API simulada, levantadla en el puerto 8000
(`06_herramientas/LEEME_herramientas.md` del repo del reto).

## Datos

Por defecto carga `ui/data/tickets_mock.json`: los 12 incidentes de `docs/incidentes_localizados.md`
y 6 tickets de actividad autorizada, con alertas y horas reales del dataset y texto escrito a mano.
Se regenera con:

```bash
python ui/tools/build_mock.py /ruta/a/DTT-UAB-The-Hack
```

Cuando el agente produzca tickets, apuntad `UI_TICKETS` a su salida. El formato está en
[`CONTRATO_TICKET.md`](CONTRATO_TICKET.md).

## Turno de noche

Horario del SOC de Tarvia: lunes a viernes de 8:00 a 20:00 (hora de Madrid). Para cada alerta del
incidente se calcula cuánto esperaría hasta que alguien abra la consola; la cifra del incidente es la
peor espera. Suposición optimista para el humano: trata la alerta en cuanto empieza el turno.

## Reproducción del lote en vivo

Pestaña **Reproducción** (tecla `4`): reproduce en una pantalla el lote de las 10 alertas oficiales del domingo,
con los tiempos reales. Cada fila es una alerta: entra, pasa por el prefiltro (que cierra el pentest autorizado y
el falso túnel DNS de McAfee), se agrupa con su historial en un incidente, el agente la trabaja (la barra es el
tiempo real de esa alerta, misma escala para todas) y sale el ticket con veredicto y severidad. La alerta con
prompt injection se marca en rojo y abajo aparece el texto escondido del correo.

Los datos salen de `ui/data/replay_vivo.json`, generado a partir de `demo/vivo` (orden de `vivas.jsonl`,
hora de escritura de cada ticket y su `triage_seconds`):

```bash
python ui/tools/build_replay.py            # o: python ui/tools/build_replay.py <carpeta_lote> <salida.json>
```

Controles: `espacio` reproducir/pausa · `r` reiniciar · `←` `→` 5 s atrás/adelante · 1x/2x/4x. El lote real dura unos 143 s.

## Atajos para presentar

`j`/`k` o flechas: ticket siguiente/anterior · `1` `2` `3` `4`: pestañas · `p`: modo presentación (letra grande).
Se puede enlazar un ticket directo: `http://localhost:8080/#TKT-INC-10`.
