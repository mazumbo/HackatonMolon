# Día de la demo (domingo 08/11, 9:00)

La organización publica 10 alertas nuevas en el repo del reto, con el mismo formato que `03_alertas/alertas.jsonl`.

## 1. Preparar (5 min)
```powershell
cd DTT-UAB-The-Hack; git pull                       # trae las alertas nuevas (y logs, si los hay)
cd ..\HackatonMolon; git pull origin main
$env:DATASET_DIR = "C:\...\DTT-UAB-The-Hack"
# si han cambiado los logs: reiniciar la API mock (uvicorn mock_soc_api:app --port 8000 en 06_herramientas)
```
Copia el fichero de las alertas nuevas a `demo\vivo\vivas.jsonl`. Si solo trae ids, también vale: `run_batch` acepta una línea `{"alert_id": ...}`.

## 2. Triar las 10 en vivo (~1-2 min)
```powershell
python -m agent.run_batch --ids-file demo\vivo\vivas.jsonl --workers 3 --out demo\vivo\tickets
```
- Las que cierra el prefiltro salen en 0 s sin LLM.
- El resto se agrupa con su incidente (si ya tiene historia en el dataset) y el LLM escribe un ticket por grupo, en 30-45 s cada uno.
- Las alertas nuevas no están en la API mock: el agente usa la copia que ya tiene el motor (`get_alert` no falla).

## 3. Enseñarlo en la UI
```powershell
$env:UI_TICKETS = "demo\vivo\tickets"
uvicorn server:app --app-dir ui --port 8080
```

## Plan B (sin red o con la pasarela del LLM caída)
- **Graba con lo ya calculado.** En cuanto termine el paso 2, haz commit de `demo\vivo\tickets\`. La UI solo lee esos ficheros, no llama al LLM: si después falla la red o la pasarela, la demo sigue igual con `UI_TICKETS=demo\vivo\tickets`.
- **Si la pasarela falla en el paso 2**, el prefiltro sigue cerrando sus alertas sin LLM, y las demás salen como "Triaje automático fallido" con escalado a N2 (no se pierde ninguna). Vuelve a lanzar el paso 2 cuando la pasarela responda; solo hay que repetir las que fallaron.
- **Ensayo de reserva:** `demo\ensayo\tickets\` tiene los tickets de 10 alertas del dataset con ids nuevos (8 incidentes reales + SCCM + WAF), generados con `python -m agent.ensayo`. Sirven para grabar el vídeo si el domingo no hay forma de triar las nuevas.
