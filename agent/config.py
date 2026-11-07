import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

SOC_API_URL = os.environ.get("SOC_API_URL", "http://localhost:8000").rstrip("/")
# LLM de la hackathon (GPU del DCC, API compatible amb OpenAI). Models: ornith, nemotron.
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "https://dcc-llm-gw.uab.cat/uabthehack/v1").rstrip("/")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "120"))
MODEL = os.environ.get("TRIAGE_MODEL", "nemotron")
MAX_TOOL_CHARS = int(os.environ.get("MAX_TOOL_CHARS", "8000"))
MAX_STEPS = int(os.environ.get("MAX_STEPS", "12"))
