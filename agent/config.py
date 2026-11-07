import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

SOC_API_URL = os.environ.get("SOC_API_URL", "http://localhost:8000").rstrip("/")
# Proveidor del LLM: "quiver" (el que dona la hackathon) o "anthropic".
PROVIDER = os.environ.get("LLM_PROVIDER", "quiver").strip().lower()
MODEL = os.environ.get("TRIAGE_MODEL", "") or ("arrow-2" if PROVIDER == "quiver" else "")
QUIVER_API_KEY = os.environ.get("QUIVER_API_KEY", "")
QUIVER_BASE_URL = os.environ.get("QUIVER_BASE_URL", "https://api.quiver.ai/v1").rstrip("/")
MAX_TOOL_CHARS = int(os.environ.get("MAX_TOOL_CHARS", "8000"))
MAX_STEPS = int(os.environ.get("MAX_STEPS", "12"))
