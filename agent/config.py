import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

SOC_API_URL = os.environ.get("SOC_API_URL", "http://localhost:8000").rstrip("/")
# LLM de la hackathon (GPU del DCC, API compatible amb OpenAI). Model disponible: ornith (nemotron torna 404 "Model desconegut" a 07/11).
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "https://dcc-llm-gw.uab.cat/uabthehack/v1").rstrip("/")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "120"))
MODEL = os.environ.get("TRIAGE_MODEL", "ornith")
MAX_TOOL_CHARS = int(os.environ.get("MAX_TOOL_CHARS", "8000"))
MAX_STEPS = int(os.environ.get("MAX_STEPS", "12"))
MAX_OUTPUT_TOKENS = int(os.environ.get("MAX_OUTPUT_TOKENS", "1500"))
# Demana al model que no "pensi en veu alta" (chat_template_kwargs.enable_thinking=false). Si la passarela ho rebutja, es desactiva sol.
LLM_NO_THINK = os.environ.get("LLM_NO_THINK", "1") not in ("0", "false", "no")
PREFETCH = os.environ.get("PREFETCH", "1") not in ("0", "false", "no")
# A partir d'aquest pas es recorda al model que ha d'entregar; a l'ultim pas se l'obliga a cridar submit_ticket.
NUDGE_AFTER = int(os.environ.get("NUDGE_AFTER", "6"))
# Des d'aquest pas s'obliga a cridar submit_ticket (decidit 07/11: pas 8, < 1 min per alerta).
FORCE_SUBMIT_AT = int(os.environ.get("FORCE_SUBMIT_AT", "8"))
# Pressupost de temps per ticket: passat aquest temps (precarrega inclosa), el seguent pas obliga submit_ticket.
# L'ultim pas (escriure el ticket) tarda ~20 s, aixi que 35 s deixa el total per sota de ~60 s.
TIME_BUDGET = float(os.environ.get("TIME_BUDGET", "35"))
