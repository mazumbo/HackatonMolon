# Evaluación y ensayo (rol D)

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

Mide por incidente: veredicto (`true_positive`), severidad contra la política (10 critical y 2 high),
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

## 3. Turno de noche (diferenciador)

```bash
python -m eval.turno_noche --salida eval/TURNO_NOCHE.md            # horas que espera el SOC humano
python -m eval.turno_noche --tickets out/eval --salida eval/TURNO_NOCHE.md  # con los segundos reales del agente
```

## 4. Domingo 08/11 a las 9:00

1. Bajar el fichero de las 10 alertas del GitHub del reto y guardarlo como `vivas.jsonl` (una alerta por línea).
2. `python -m agent.run_batch --ids-file vivas.jsonl --out out/vivas`
3. `UI_TICKETS=out/vivas uvicorn server:app --app-dir ui --host 127.0.0.1 --port 8080` y grabar.

El plan B offline lo lleva otro compañero; esta carpeta no lo cubre.
