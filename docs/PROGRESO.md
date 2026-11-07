# Progreso del proyecto

Estado vivo del equipo. **Actualizadlo en el mismo PR que cierra cada tarea**: mover la línea de "Por hacer" a "Hecho", con el PR o commit al lado.
Leyenda: ✅ hecho · 🔄 en curso · ⏳ por hacer · ⛔ bloqueado. Plan completo en [`HOJA_DE_RUTA.md`](HOJA_DE_RUTA.md).

_Última actualización: 07/11/2026 20:40_

## Resumen

| Hito | Estado | Qué falta |
| --- | --- | --- |
| H1 · Arranque | ✅ | |
| H6 · N1 de punta a punta | ✅ | Agente a 42–56 s por alerta ([PR #9](https://github.com/mazumbo/HackatonMolon/pull/9)); la UI pinta los campos nuevos ([PR #14](https://github.com/mazumbo/HackatonMolon/pull/14)) |
| H12 · N1 fiable + N2 | 🔄 | Motor integrado en el agente. Falta: fix de loopback ([PR #16](https://github.com/mazumbo/HackatonMolon/pull/16)), acelerar grupos de ruido y evaluar contra los 12 incidentes (rol D) |
| H18 · Congelación | ⏳ | Antes de las 9:00 del domingo |
| H22 · Ensayo general | ⏳ | Vídeo de la demo con las 10 alertas en vivo |

## Entrega (domingo 08/11, 9:00)

- La organización publica **10 alertas en vivo** en el GitHub del reto, con el mismo formato que las del repo. Podemos consumirlas como queramos.
- Con ellas hay que **grabar un vídeo de la demo**, que se mostrará en la presentación (página 09).
- Objetivo: **menos de 60 s por alerta**. Las alertas sueltas ya cumplen (42–56 s); los grupos de ruido todavía no (63–79 s).

## Bloqueos y riesgos

- ⚠️ **Agrupación por IP de loopback**: `127.0.0.2` y otras IPs reservadas unían alertas sin relación. A lo corrige en [PR #16](https://github.com/mazumbo/HackatonMolon/pull/16) (abierto).
- ⚠️ **Velocidad en grupos de ruido**: 63–79 s por grupo, por encima del objetivo de 60 s.
- ⚠️ **Rol D sin hilo**: evaluación y guion del vídeo sin empezar. Es lo más urgente para el domingo.
- ⚠️ **Sin plan B offline**: si falla la red o la pasarela durante la demo no hay resultados precalculados.
- ℹ️ **Diferenciador creativo sin elegir**: falta decidir qué nos distingue en el pitch.
- ℹ️ La pasarela UAB solo ofrece el modelo `ornith` (`nemotron` no existe).

## Por rol

### A · Datos y motor determinista

- ✅ API mock del reto levantada en local (puerto 8000); `LEVANTAR_API.py` comprueba que responde.
- ✅ `prefiltrar(alerta)` en `engine/prefiltro.py` ([PR #5](https://github.com/mazumbo/HackatonMolon/pull/5)): pentest, Nessus, SCCM y flujos aprobados, con motivo de cierre.
- ✅ Ataque web bloqueado = `true_positive` informational ([PR #10](https://github.com/mazumbo/HackatonMolon/pull/10)).
- ✅ Matriz de severidad ([PR #6](https://github.com/mazumbo/HackatonMolon/pull/6), [PR #8](https://github.com/mazumbo/HackatonMolon/pull/8)): regla × criticidad del afectado; lo desconocido cuenta como alta; el LLM puede subir pero nunca bajar.
- ✅ `agrupar(alertas)`: correlación por usuario, host, IP y hash ([PR #11](https://github.com/mazumbo/HackatonMolon/pull/11)).
- ✅ Ajustes de la matriz ([PR #15](https://github.com/mazumbo/HackatonMolon/pull/15)): WAF bloqueado informational, MFA aprobado = acceso confirmado, grupos que no se encadenan, y el prefiltro cierra el DNS de productos de seguridad. **Prefiltro: cierra 4.339 de 11.061 alertas y ninguno de los 12 incidentes. Severidad en los 12 incidentes: 9 critical y 3 high.**
- 🔄 IPs de loopback y reservadas no unen alertas ([PR #16](https://github.com/mazumbo/HackatonMolon/pull/16), abierto).
- ⏳ Métricas del turno de noche con datos reales del agente.
- ⏳ Plan B offline: precalcular resultados por si falla la red en la demo.

### B · Agente IA

- ✅ Esqueleto del agente (`agent/`): herramientas de solo lectura sobre la API mock, prompt, `triar()`, `run_batch`, `smoke_test`.
- ✅ Defensas: datos dentro de `<untrusted_data>`, heurística de prompt injection, contención solo propuesta y siempre con aprobación.
- ✅ LLM de la hackathon, API compatible con OpenAI ([PR #4](https://github.com/mazumbo/HackatonMolon/pull/4)); `ornith` por defecto ([PR #7](https://github.com/mazumbo/HackatonMolon/pull/7)).
- ✅ Triaje más rápido: de 114 s a 42–56 s por alerta ([PR #9](https://github.com/mazumbo/HackatonMolon/pull/9)).
- ✅ Motor de A integrado ([PR #13](https://github.com/mazumbo/HackatonMolon/pull/13)): prefiltro antes del LLM, un ticket por grupo, campos `group`, `prefilter` y `related_alert_ids_suggested`, y justificación de severidad mejorada.
- ❌ [PR #12](https://github.com/mazumbo/HackatonMolon/pull/12) (`severity_rationale`) cerrado sin fusionar: lo cubre el #13.
- 🔄 Bajar los grupos de ruido de 63–79 s a menos de 60 s.
- ⏳ Validar la salida contra `ticket_salida.schema.json`.
- ⏳ Estable en las 150 alertas de desarrollo, sin errores.
- ⏳ Robustez con alertas raras o campos vacíos.

### C · Interfaz y demo

- ✅ Demo visual en `ui/` ([PR #1](https://github.com/mazumbo/HackatonMolon/pull/1)): cola, detalle del ticket con traza, línea temporal, aviso de prompt injection, botón de aprobación, vista Turno de noche.
- ✅ Contrato de ticket con el agente: [`ui/CONTRATO_TICKET.md`](../ui/CONTRATO_TICKET.md).
- ✅ Campos del motor en la UI: `group`, `prefilter`, `related_alert_ids_suggested` ([PR #14](https://github.com/mazumbo/HackatonMolon/pull/14)).
- ⏳ Conectar a los tickets reales del agente con las 10 alertas en vivo (`UI_TICKETS=out/tickets/`).
- ⏳ Modo presentación y pulido final.

### D · Analista, evaluación y pitch (sin hilo)

- ✅ 12 incidentes y benignos localizados: [`incidentes_localizados.md`](incidentes_localizados.md).
- ✅ Hoja de ruta: [`HOJA_DE_RUTA.md`](HOJA_DE_RUTA.md).
- ⏳ `eval/`: verdad esperada + script que mida aciertos del agente (veredicto y severidad).
- ⏳ Medir tokens y segundos por alerta (coste).
- ⏳ Elegir el diferenciador creativo del pitch.
- ⏳ Página para el comité de dirección y guion de 5 minutos.
- ⏳ Guion y grabación del vídeo de la demo con las 10 alertas en vivo (domingo 08/11).

## Registro

- **07/11 ~13:00** · Repo creado. Hoja de ruta e incidentes subidos.
- **07/11 ~13:30** · UI de la demo mergeada (PR #1).
- **07/11 ~14:00** · Esqueleto del agente (rol B) y script de prueba de la API mock.
- **07/11 ~16:00** · La pasarela UAB usa el modelo `ornith`. Agente con el LLM de la hackathon mergeado (PR #4), a 114 s por alerta. PR #2 (Quiver) cerrado.
- **07/11 ~16:30** · Prefiltro de A mergeado (PR #5).
- **07/11 ~18:00** · Aviso de la organización: el domingo 08/11 a las 9:00 llegan 10 alertas en vivo y hay que grabar el vídeo de la demo.
- **07/11 tarde** · Mergeados `ornith` por defecto (#7), matriz de severidad (#6, #8), agente más rápido (#9), prefiltro de WAF (#10) y agrupación (#11).
- **07/11 noche** · Motor integrado en el agente (#13), UI con los campos nuevos (#14) y ajustes de la matriz (#15). PR #12 cerrado sin fusionar. Abierto el fix de loopback (#16).
