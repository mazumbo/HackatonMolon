# Agent de triatge N1 (rol B)

```bash
pip install -r agent/requirements.txt
cp agent/.env.example agent/.env   # omple QUIVER_API_KEY (o LLM_PROVIDER=anthropic + ANTHROPIC_API_KEY)
# API mock del reto (altre terminal): uvicorn mock_soc_api:app --port 8000   (a 06_herramientas/)
python -m agent.probar_quiver                     # comprova clau + crida d'eines (sense API mock)
python -m agent.smoke_test                       # una alerta de punta a punta
python -m agent.run_batch --limit 10             # escriu out/tickets/*.json
UI_TICKETS=out/tickets/ uvicorn server:app --app-dir ui --port 8080
```

## Proveidor del LLM
- `LLM_PROVIDER=quiver` (per defecte): Quiver AI, el que dona la hackathon. API estil OpenAI Responses
  (`POST https://api.quiver.ai/v1/responses`, `Authorization: Bearer`). Codi a `llm_quiver.py`.
  Models: `arrow-2` (rapid, per defecte) o `arrow-2-telos` (mes capac). Cal una clau de projecte.
  S'envia `tool_choice=required` perque el model sempre cridi eines i acabi amb `submit_ticket`.
  Ull: els models Arrow estan pensats per generar SVG; proveu-lo amb alguns dels 12 incidents abans de confiar-hi.
- `LLM_PROVIDER=anthropic`: Claude amb el SDK `anthropic` (`TRIAGE_MODEL=claude-sonnet-5-5`).
- Les eines, el prompt i la severitat son els mateixos per als dos; nomes canvia el bucle.

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
