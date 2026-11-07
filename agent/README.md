# Agent de triatge N1 (rol B)

```bash
pip install -r agent/requirements.txt
cp agent/.env.example agent/.env   # omple LLM_API_KEY (clau de l'equip); TRIAGE_MODEL=nemotron o ornith
# API mock del reto (altre terminal): uvicorn mock_soc_api:app --port 8000   (a 06_herramientas/)
python -m agent.smoke_test                       # una alerta de punta a punta
python -m agent.run_batch --limit 10             # escriu out/tickets/*.json
UI_TICKETS=out/tickets/ uvicorn server:app --app-dir ui --port 8080
```

## Disseny
- Eines de nomes lectura (`tools.py`). La contencio no es accessible des del bucle: nomes es proposa a `recommended_actions`.
- El LLM aporta veredicte, evidencies i FACTORS; el codi calcula severitat (`severity.py`, provisional fins que A lliuri la seva), escalat obligatori i `requires_approval`.
- Les accions de contencio sempre porten `requires_approval=true`, tambe `block_ioc` i `purge_email` (criteri mes estricte que la politica interna).
- Resultats d'eines i camps d'alerta van dins de `<untrusted_data>`; una heuristica de codi marca possibles prompt injections.
- `triar()` no llanca excepcions: retorna un ticket `needs_more_info` escalat a N2.

## Pendent / limits coneguts
- Els noms dels camps de l'alerta (`created_at`, `rule_id`, `rule_name`, `severity`, `source_product`) es llegeixen amb alternatives; verificar-los contra `alertas.jsonl`.
- Falta: pre-filtre i agrupacio (rol A), playbooks per regla, deteccio d'OT a partir de la zona de la CMDB, validacio completa contra el JSON Schema.
- El valor de criticitat de la CMDB s'ha de confirmar (`activos.csv`); un valor desconegut es tracta com a `medium`.
