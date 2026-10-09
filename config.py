import os
from pathlib import Path
from dotenv import load_dotenv

# Tải cấu hình từ .env nếu tồn tại
load_dotenv()

class Config:
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini").lower()
    LLM_MODEL = os.getenv("LLM_MODEL", "gemini-2.5-flash")
    
    # API Keys
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
    DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
    
    # Security & Behavior
    REQUIRE_APPROVAL = os.getenv("REQUIRE_APPROVAL", "true").lower() in ("true", "1", "yes")
    COMMAND_TIMEOUT = int(os.getenv("COMMAND_TIMEOUT_SECONDS", "60"))
    
    # Workspace
    WORKSPACE_DIR = Path(os.getenv("WORKSPACE_DIR", "./workspace")).resolve()
    
    @classmethod
    def ensure_workspace(cls):
        cls.WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
