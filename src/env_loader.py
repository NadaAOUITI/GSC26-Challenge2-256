from pathlib import Path

from dotenv import load_dotenv

from src.paths import ROOT

_loaded = False


def load_project_env() -> None:
    """Load `.env` from project root (gitignored). Idempotent."""
    global _loaded
    if _loaded:
        return
    load_dotenv(ROOT / ".env")
    _loaded = True
