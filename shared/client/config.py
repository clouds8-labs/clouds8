"""
Clouds8 shared client - config

Single place both the Dash UI and the future CLI load .env from and read
service URLs - consolidates what used to be a single load_dotenv() call
living only in ui/app.py (so anything importing shared.client outside the
Dash process, e.g. a script or the CLI, still gets .env loaded).
"""
import os
from pathlib import Path

from dotenv import load_dotenv

_ENV_PATH = Path(__file__).parent.parent.parent / ".env"
load_dotenv(_ENV_PATH)

DB_SERVICE_URL = os.getenv("DB_SERVICE_URL", "http://localhost:8001")
BACKEND_API_URL = os.getenv("BACKEND_API_URL", "http://localhost:8002")
