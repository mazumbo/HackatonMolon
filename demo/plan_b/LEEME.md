# Plan B de la demo

Aquí se guardan los tickets **reales** que ha generado el agente, para poder enseñarlos aunque fallen la red o el LLM.
Cada subcarpeta es un lote (por ejemplo `vivas` para las 10 alertas del domingo) con un `RESUMEN.md`.

| Situación en la demo | Qué hacer |
|---|---|
| Todo funciona | Demo en directo, normal |
| Falla la red o el LLM | `python demo/plan_b.py demo vivas` (tickets guardados) |
| No hay nada guardado | `python demo/plan_b.py demo` (tickets de ejemplo de `ui/data`) |

Antes de presentar: `python demo/plan_b.py comprobar` dice en qué situación estamos.

## Domingo, en cuanto el agente trie las 10 alertas

```
python demo/plan_b.py guardar out/tickets vivas
git add demo/plan_b/vivas
git commit -m "plan B: tickets de las 10 alertas en vivo"
git push
```

El botón de aprobación ya funciona sin la API: si no responde, la aprobación se simula en la UI y se dice en pantalla.
