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

## Plan B
Lo prepara otro miembro del equipo; aquí solo el camino normal.
