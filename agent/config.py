import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

SOC_API_URL = os.environ.get("SOC_API_URL", "http://localhost:8000").rstrip("/")
MODEL = os.environ.get("TRIAGE_MODEL", "")
MAX_TOOL_CHARS = int(os.environ.get("MAX_TOOL_CHARS", "8000"))
MAX_STEPS = int(os.environ.get("MAX_STEPS", "12"))
