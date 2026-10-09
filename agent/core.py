import json
from typing import List, Dict, Any, Callable
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax

from config import Config
from llm.client import LLMClient
from agent.prompts import SYSTEM_PROMPT
from tools.terminal import execute_command
from tools.file_ops import read_file, write_file, append_file, list_workspace_files

console = Console()

class BetHackerAgent:
    def __init__(self, approval_callback: Callable[[str], bool] = None):
        self.client = LLMClient()
        self.approval_callback = approval_callback or self._default_approval
        self.history: List[Dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT}
        ]

    def _default_approval(self, command: str) -> bool:
        """Hộp thoại phê duyệt mặc định trên Terminal cho người dùng."""
        console.print(Panel(
            Syntax(command, "bash", theme="monokai", line_numbers=False),
            title="[bold yellow]⚠️ YÊU CẦU PHÊ DUYỆT LỆNH SHELL[/bold yellow]",
            subtitle="[dim]BetHacker muốn thực thi lệnh trên máy host[/dim]",
            border_style="yellow"
        ))
        return Confirm.ask("[bold cyan]👉 Bạn có cho phép thực thi lệnh này không?[/bold cyan]", default=True)

    def dispatch_tool(self, name: str, args: Dict[str, Any]) -> str:
        """Điều phối và thực thi công cụ được LLM yêu cầu."""
        if name == "run_terminal_command":
            cmd = args.get("command", "").strip()
            if not cmd:
                return "Lỗi: Không có lệnh nào được chỉ định."

            if Config.REQUIRE_APPROVAL:
                approved = self.approval_callback(cmd)
                if not approved:
                    return f"Người dùng đã TỪ CHỐI thực thi lệnh: '{cmd}'. Hãy đề xuất cách tiếp cận khác."

            console.print(f"[bold green]⚡ Đang thực thi:[/bold green] [dim]{cmd}[/dim]")
            returncode, stdout, stderr = execute_command(cmd)
            
            result = f"Mã thoát (Exit Code): {returncode}\n"
            if stdout:
                result += f"--- STDOUT ---\n{stdout}\n"
            if stderr:
                result += f"--- STDERR ---\n{stderr}\n"
            return result

        elif name == "read_file":
            filepath = args.get("filepath", "")
            return read_file(filepath)

        elif name == "write_file":
            filepath = args.get("filepath", "")
            content = args.get("content", "")
            return write_file(filepath, content)

        elif name == "list_files":
            files = list_workspace_files()
            if not files:
                return "Thư mục workspace hiện đang trống."
            return json.dumps(files, indent=2, ensure_ascii=False)

        else:
            return f"Lỗi: Không tìm thấy công cụ '{name}'."

    def step(self, user_input: str) -> str:
        """Thực hiện một chu kỳ đối thoại ReAct cho đến khi ra kết quả cuối cùng."""
        self.history.append({"role": "user", "content": user_input})
        max_turns = 10  # Tránh vòng lặp vô tận

        for _ in range(max_turns):
            response_msg = self.client.chat_completion(self.history)
            
            # Ghi nhận phản hồi của trợ lý vào lịch sử
            assistant_dict: Dict[str, Any] = {
                "role": "assistant",
                "content": response_msg.content or ""
            }
            if response_msg.tool_calls:
                assistant_dict["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": tc.type,
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments
                        }
                    }
                    for tc in response_msg.tool_calls
                ]
            self.history.append(assistant_dict)

            # Nếu không có tool calls, hoàn thành vòng lặp
            if not response_msg.tool_calls:
                return response_msg.content or ""

            # Xử lý từng tool call
            for tool_call in response_msg.tool_calls:
                func_name = tool_call.function.name
                try:
                    args = json.loads(tool_call.function.arguments)
                except Exception as e:
                    args = {}

                console.print(f"[bold magenta]🔧 Gọi công cụ:[/bold magenta] [cyan]{func_name}[/cyan]")
                output = self.dispatch_tool(func_name, args)

                # Thêm phản hồi của tool vào lịch sử để LLM tiếp tục suy luận
                self.history.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": output
                })

        return "Đã đạt giới hạn số lượt suy luận (Turn limit). Vui lòng gửi yêu cầu tiếp theo."
