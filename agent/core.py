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
        """Interactive terminal prompt requesting user approval before command execution."""
        console.print(Panel(
            Syntax(command, "bash", theme="monokai", line_numbers=False),
            title="[bold yellow]⚠️ SHELL COMMAND APPROVAL REQUIRED[/bold yellow]",
            subtitle="[dim]BetAker requests permission to execute a host command[/dim]",
            border_style="yellow"
        ))
        return Confirm.ask("[bold cyan]👉 Do you approve executing this command?[/bold cyan]", default=True)

    def dispatch_tool(self, name: str, args: Dict[str, Any]) -> str:
        """Dispatch and execute tool requested by the LLM."""
        if name == "run_terminal_command":
            cmd = args.get("command", "").strip()
            if not cmd:
                return "Error: No command specified."

            if Config.REQUIRE_APPROVAL:
                approved = self.approval_callback(cmd)
                if not approved:
                    return f"User REJECTED (TỪ CHỐI) execution of command: '{cmd}'. Please suggest an alternative approach."

            console.print(f"[bold green]⚡ Executing:[/bold green] [dim]{cmd}[/dim]")
            returncode, stdout, stderr = execute_command(cmd)
            
            result = f"Exit Code: {returncode}\n"
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
                return "Workspace directory is currently empty / Thư mục workspace hiện đang trống."
            return json.dumps(files, indent=2, ensure_ascii=False)

        else:
            return f"Error: Tool '{name}' not found / Lỗi: Không tìm thấy công cụ '{name}'."

    def step(self, user_input: str) -> str:
        """Execute a ReAct agentic reasoning loop until completion."""
        self.history.append({"role": "user", "content": user_input})
        max_turns = 10  # Turn limit to avoid infinite cycles

        for _ in range(max_turns):
            response_msg = self.client.chat_completion(self.history)
            
            # Record assistant response in conversation history
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

            # If no tool calls, completion is reached
            if not response_msg.tool_calls:
                return response_msg.content or ""

            # Execute tool calls
            for tool_call in response_msg.tool_calls:
                func_name = tool_call.function.name
                try:
                    args = json.loads(tool_call.function.arguments)
                except Exception:
                    args = {}

                console.print(f"[bold magenta]🔧 Calling Tool:[/bold magenta] [cyan]{func_name}[/cyan]")
                output = self.dispatch_tool(func_name, args)

                # Feed tool observation back into context
                self.history.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": output
                })

        return "Turn limit reached. / Đã đạt giới hạn số lượt suy luận (Turn limit). Please submit your next request."
