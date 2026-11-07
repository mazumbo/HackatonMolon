# Evaluación, ensayo y plan B (rol D)

Todo se ejecuta desde la raíz del repo con `DATASET_DIR` apuntando al repo del reto
(en el PC de mazumbo: `..\DTT-UAB-The-Hack`, que es el valor por defecto).

## 1. Evaluación contra los 12 incidentes

```bash
# Nivel motor, sin LLM ni API (3 s): prefiltro, agrupación y severidad
python -m eval.evaluar --motor --salida eval/RESULTADOS_MOTOR.md

# Sistema completo (API mock en el 8000 y LLM_API_KEY en agent/.env)
python -m eval.evaluar --preparar eval/casos.jsonl          # 85 alertas: 12 incidentes + benignos
python -m agent.run_batch --ids-file eval/casos.jsonl --out out/eval --limit 40
python -m eval.evaluar --tickets out/eval --salida eval/RESULTADOS.md
```

Mide por incidente: veredicto (`true_positive`), severidad contra la política (9 critical y 3 high),
escalado, cobertura de alertas, segundos y tokens. Marca aparte cualquier alerta de un incidente cerrada
como no-ataque, que es el fallo grave, y comprueba que los benignos de control no se escalan.

## 2. Ensayo general con 10 alertas nuevas

Simula las 10 alertas del domingo: copias de alertas reales con un `alert_id` que la API mock no conoce
(6 de incidentes, 1 benigna, 3 de ruido).

```bash
python -m eval.ensayo --preparar eval/ensayo_vivas.jsonl
python -m agent.run_batch --ids-file eval/ensayo_vivas.jsonl --out out/ensayo
python -m eval.ensayo --puntuar out/ensayo --salida eval/RESULTADOS_ENSAYO.md
UI_TICKETS=out/ensayo uvicorn server:app --app-dir ui --host 127.0.0.1 --port 8080
```

## 3. Domingo 08/11 a las 9:00

1. Bajar el fichero de las 10 alertas del GitHub del reto y guardarlo como `vivas.jsonl` (una alerta por línea).
2. `python -m agent.run_batch --ids-file vivas.jsonl --out out/vivas`
3. **Copia de seguridad inmediata** (plan B): `cp -r out/vivas ui/data/tickets_vivas` y subirla al repo.
4. `UI_TICKETS=out/vivas uvicorn server:app --app-dir ui --host 127.0.0.1 --port 8080` y grabar.

## 4. Plan B offline

La UI no necesita red ni LLM: solo lee tickets de una carpeta. Si algo falla al grabar:

| Falla | Qué hacemos |
| --- | --- |
| La pasarela UAB (`ornith`) cae o va lenta | Grabamos con los tickets ya generados (`ui/data/tickets_vivas`). Si no llegó a generar ninguno, el motor sigue cerrando el ruido sin LLM y lo contamos con honestidad. |
| La API mock no arranca | El pipeline lee las alertas del fichero; el botón de aprobar no ejecuta, se dice en el vídeo. |
| Sin red en la presentación | El vídeo ya está grabado; la UI con `ui/data/tickets_vivas` funciona en local. |
| Sin tickets reales | `ui/data/tickets_mock.json` (12 incidentes escritos a mano), avisando de que es un ejemplo. |
