# Demo visual (rol C)

Pantalla para la defensa: cola de tickets, detalle con evidencias y traza, línea temporal del incidente,
aviso en rojo cuando los datos traen texto escrito para manipular a la IA, botón de aprobación humana
y la vista **Turno de noche** (cuándo lo habría visto el SOC humano frente a la IA).

**Stack:** Python + FastAPI (mismo lenguaje que la API mock del reto) y una página HTML/JS sin framework
ni build. Nada que compilar el día de la demo.

## Arrancar

```bash
pip install -r ui/requirements.txt
uvicorn server:app --app-dir ui --port 8080
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

## Atajos para presentar

`j`/`k` o flechas: ticket siguiente/anterior · `1` `2` `3`: pestañas · `p`: modo presentación (letra grande).
Se puede enlazar un ticket directo: `http://localhost:8080/#TKT-INC-10`.
