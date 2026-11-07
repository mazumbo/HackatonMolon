# Progreso del proyecto

Estado vivo del equipo. **Actualizadlo en el mismo PR que cierra cada tarea**: mover la línea de "Por hacer" a "Hecho", con el PR o commit al lado.
Leyenda: ✅ hecho · 🔄 en curso · ⏳ por hacer · ⛔ bloqueado. Plan completo en [`HOJA_DE_RUTA.md`](HOJA_DE_RUTA.md).

_Última actualización: 07/11/2026 18:00_

## Resumen

| Hito | Estado | Qué falta |
| --- | --- | --- |
| H1 · Arranque | ✅ | LLM de la pasarela UAB (`ornith`) funcionando |
| H6 · N1 de punta a punta | 🔄 | Funciona, pero tarda 114 s por alerta: hay que bajar de 60 s. Pintar sus tickets en la UI |
| H12 · N1 fiable + N2 | 🔄 | Prefiltro hecho; falta severidad a main, agrupación, enchufar ambos en `agent/` y evaluar contra los 12 incidentes |
| H18 · Congelación | ⏳ | |
| H22 · Ensayo general | ⏳ | |

## Entrega (domingo 08/11, 9:00)

- La organización publica **10 alertas en vivo** en el GitHub del reto, con el mismo formato que las del repo. Podemos consumirlas como queramos.
- Con ellas hay que **grabar un vídeo de la demo**, que se mostrará en la presentación (página 09).
- Para que la demo en vivo sea viable, el agente tiene que triar las 10 en pocos minutos: objetivo **menos de 60 s por alerta**.

## Bloqueos y riesgos

- ⚠️ **Velocidad del agente**: 114 s por alerta con `ornith`. Propuesta (pendiente de visto bueno): precargar el contexto, resumir los logs antes de pasarlos al LLM, limitar el número de pasos y procesar alertas en paralelo.
- ⚠️ **Rol D sin responsable activo**: evaluación y guion del vídeo sin empezar.
- ℹ️ La pasarela UAB solo ofrece el modelo `ornith` (`nemotron` no existe). Quiver AI queda descartado ([PR #2](https://github.com/mazumbo/HackatonMolon/pull/2) cerrado).

## Por rol

### A · Datos y motor determinista

- ✅ API mock del reto levantada en local (puerto 8000); `LEVANTAR_API.py` comprueba que responde (pide 5 alertas).
- ✅ `prefiltrar(alerta)` en `engine/prefiltro.py` ([PR #5](https://github.com/mazumbo/HackatonMolon/pull/5)): pentest, Nessus, SCCM y flujos aprobados, con motivo de cierre. Cierra 4.271 de 11.061 alertas y ninguno de los 12 incidentes.
- 🔄 Matriz de severidad ([PR #8](https://github.com/mazumbo/HackatonMolon/pull/8), pendiente de merge): regla × criticidad del afectado; lo desconocido cuenta como alta; el LLM puede subir pero nunca bajar. Resultado en los 12 incidentes: 9 critical, 2 high, 1 medium.
- ⏳ `agrupar(alertas)`: correlación por usuario, host, IP y hash (espera visto bueno).
- ⏳ Métricas del turno de noche con datos reales del agente.
- ⏳ Pre-calcular resultados por si falla la red en la demo.

### B · Agente IA

- ✅ Esqueleto del agente (`agent/`): herramientas de solo lectura sobre la API mock, prompt, `triar()`, `run_batch`, `smoke_test`.
- ✅ Defensas: datos dentro de `<untrusted_data>`, heurística de prompt injection, contención solo propuesta y siempre con aprobación.
- ✅ Agente con el LLM de la hackathon, API compatible con OpenAI ([PR #4](https://github.com/mazumbo/HackatonMolon/pull/4)).
- 🔄 `ornith` como modelo por defecto ([PR #7](https://github.com/mazumbo/HackatonMolon/pull/7), pendiente de merge).
- ✅ Primera alerta triada de punta a punta en local, contra la API mock.
- 🔄 Bajar de 114 s a menos de 60 s por alerta (ver Bloqueos).
- ⏳ Enchufar `prefiltrar()` y la matriz de severidad de A dentro de `agent/`.
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
- ⏳ Guion de 5 minutos y ensayos.
- ⏳ Guion y grabación del vídeo de la demo con las 10 alertas en vivo (domingo 08/11).

## Registro

- **07/11 ~13:00** · Repo creado. Hoja de ruta e incidentes subidos.
- **07/11 ~13:30** · UI de la demo mergeada (PR #1).
- **07/11 ~14:00** · Esqueleto del agente (rol B) y script de prueba de la API mock.
- **07/11 ~15:00** · La organización da Quiver AI como LLM; PR #2 para soportarlo. Clave pendiente.
- **07/11 ~16:00** · La pasarela UAB usa el modelo `ornith`. Agente con el LLM de la hackathon mergeado (PR #4); funciona de punta a punta, a 114 s por alerta. PR #2 (Quiver) cerrado.
- **07/11 ~16:30** · Prefiltro de A mergeado (PR #5). Matriz de severidad en PR #8 y `ornith` por defecto en PR #7, ambos pendientes de merge.
- **07/11 ~18:00** · Aviso de la organización: el domingo 08/11 a las 9:00 llegan 10 alertas en vivo y hay que grabar el vídeo de la demo. Prioridad: bajar el tiempo por alerta de 114 s a menos de 60 s.
