import json
from typing import List, Dict, Any, Optional
from config import Config

# Định nghĩa các tool specs theo chuẩn OpenAI function calling
TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "run_terminal_command",
            "description": "Thực thi một câu lệnh hệ thống / terminal (như ping, curl, nmap, nikto, whois, trích xuất thông tin, chạy script exploit).",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Câu lệnh shell cần thực thi."
                    }
                },
                "required": ["command"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Đọc nội dung một tệp tin (log, script, output scan) từ workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Đường dẫn hoặc tên tệp tin cần đọc."
                    }
                },
                "required": ["filepath"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Ghi dữ liệu hoặc tạo mới một tệp tin báo cáo / log / payload trong workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Tên hoặc đường dẫn tệp tin cần ghi."
                    },
                    "content": {
                        "type": "string",
                        "description": "Nội dung cần ghi vào tệp tin."
                    }
                },
                "required": ["filepath", "content"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "Liệt kê danh sách tất cả các tệp tin hiện có trong thư mục workspace.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    }
]

class LLMClient:
    def __init__(self):
        self.provider = Config.LLM_PROVIDER
        self.model = Config.LLM_MODEL
        self._init_client()

    def _init_client(self):
        if self.provider == "gemini":
            # Sử dụng Gemini qua OpenAI-compatible endpoint của Google hoặc Google GenAI
            import openai
            api_key = Config.GEMINI_API_KEY
            if not api_key:
                raise ValueError("Thiếu GEMINI_API_KEY trong file .env")
            self.client = openai.OpenAI(
                api_key=api_key,
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
            )
        elif self.provider == "openai":
            import openai
            api_key = Config.OPENAI_API_KEY
            if not api_key:
                raise ValueError("Thiếu OPENAI_API_KEY trong file .env")
            self.client = openai.OpenAI(api_key=api_key)
        elif self.provider == "openrouter":
            import openai
            api_key = Config.OPENROUTER_API_KEY
            if not api_key:
                raise ValueError("Thiếu OPENROUTER_API_KEY trong file .env")
            self.client = openai.OpenAI(
                api_key=api_key,
                base_url="https://openrouter.ai/api/v1"
            )
        elif self.provider == "deepseek":
            import openai
            api_key = Config.DEEPSEEK_API_KEY
            if not api_key:
                raise ValueError("Thiếu DEEPSEEK_API_KEY trong file .env")
            self.client = openai.OpenAI(
                api_key=api_key,
                base_url="https://api.deepseek.com"
            )
        else:
            raise ValueError(f"Nhà cung cấp LLM không được hỗ trợ: {self.provider}")

    def chat_completion(self, messages: List[Dict[str, Any]]) -> Any:
        """Gửi danh sách tin nhắn tới LLM kèm theo định nghĩa tools."""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=TOOLS_SCHEMA,
            tool_choice="auto"
        )
        return response.choices[0].message
