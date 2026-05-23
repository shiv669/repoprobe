"""
configuration management for repoprobe.

loads settings from environment variables and .env files.
each config value has a sensible default so the system
degrades gracefully if something is missing.
"""

import os
from pathlib import Path
from dotenv import load_dotenv


# load .env from project root (walks up from this file)
_project_root = Path(__file__).resolve().parent.parent.parent
_env_path = _project_root / ".env"
load_dotenv(dotenv_path=_env_path)


class Config:
    """central configuration object — all settings live here."""

    # google genai
    google_api_key: str = os.getenv("GOOGLE_API_KEY", "")
    agent_model: str = "antigravity-preview-05-2026"
    gemini_model: str = "gemini-3.5-flash"

    # sandbox
    sandbox_environment: str = "remote"

    # timeouts (seconds)
    sandbox_boot_timeout: int = 120
    phase_timeout: int = 300
    stream_reconnect_attempts: int = 3

    # ui
    app_name: str = "repoprobe"
    app_version: str = "0.1.0"

    @classmethod
    def validate(cls) -> list[str]:
        """
        check that all required config is present.
        returns a list of error messages (empty = all good).
        """
        errors: list[str] = []
        if not cls.google_api_key:
            errors.append(
                "GOOGLE_API_KEY is not set. "
                "create a .env file or export it in your shell."
            )
        return errors

    @classmethod
    def is_ready(cls) -> bool:
        """true when all required config is present."""
        return len(cls.validate()) == 0
