import sys
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.prompt import Prompt

from config import Config
from agent.core import BetHackerAgent

console = Console()

BANNER = """[bold red]
██████╗ ███████╗████████╗██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ 
██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██████╔╝█████╗     ██║   ███████║███████║██║     █████╔╝ █████╗  ██████╔╝
██╔══██╗██╔══╝     ██║   ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
██████╔╝███████╗   ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
[/bold red]
[bold cyan]  🛡️ AI-Powered Penetration Testing & Offensive Security Assistant 🛡️[/bold cyan]
"""

def print_help():
    help_text = """
[bold yellow]CÁC LỆNH ĐIỀU KHIỂN HỆ THỐNG:[/bold yellow]
 • [bold cyan]/help[/bold cyan]   : Hiển thị bảng trợ giúp này.
 • [bold cyan]/files[/bold cyan]  : Liệt kê danh sách các tệp tin trong thư mục workspace.
 • [bold cyan]/clear[/bold cyan]  : Xóa lịch sử hội thoại hiện tại.
 • [bold cyan]/exit[/bold cyan]   : Thoát chương trình.
"""
    console.print(Panel(help_text, title="Trợ giúp", border_style="blue"))

def main():
    Config.ensure_workspace()
    console.print(BANNER)
    
    info_panel = f"""[bold]Provider:[/bold] [green]{Config.LLM_PROVIDER}[/green] | [bold]Model:[/bold] [yellow]{Config.LLM_MODEL}[/yellow]
[bold]Approval Gate:[/bold] [cyan]{'BẬT (Human-in-the-loop)' if Config.REQUIRE_APPROVAL else 'TẮT (Auto)'}[/cyan]
[bold]Workspace:[/bold] [dim]{Config.WORKSPACE_DIR}[/dim]"""
    console.print(Panel(info_panel, title="Cấu hình hệ thống", border_style="cyan"))
    console.print("[dim]Gõ yêu cầu của bạn (hoặc /help để xem hướng dẫn, /exit để thoát).[/dim]\n")

    try:
        agent = BetHackerAgent()
    except Exception as e:
        console.print(f"[bold red]❌ Lỗi khởi tạo LLM Client:[/bold red] {e}")
        console.print("[yellow]💡 Hãy kiểm tra lại file .env đã điền đúng API Key và Provider chưa.[/yellow]")
        sys.exit(1)

    while True:
        try:
            user_input = Prompt.ask("\n[bold red]BetHacker[/bold red] [bold white]❯[/bold white]").strip()
            if not user_input:
                continue

            if user_input.lower() in ("/exit", "exit", "quit", ":q"):
                console.print("[bold yellow]Tạm biệt! Chúc bạn săn bug thành công! 🛡️[/bold yellow]")
                break
            elif user_input.lower() == "/help":
                print_help()
                continue
            elif user_input.lower() == "/clear":
                agent.history = [{"role": "system", "content": agent.history[0]["content"]}]
                console.print("[green]Đã làm mới phiên hội thoại![/green]")
                continue
            elif user_input.lower() == "/files":
                from tools.file_ops import list_workspace_files
                files = list_workspace_files()
                if not files:
                    console.print("[yellow]Thư mục workspace đang trống.[/yellow]")
                else:
                    for f in files:
                        console.print(f" • [cyan]{f['name']}[/cyan] ({f['size_bytes']} bytes)")
                continue

            with console.status("[bold green]Agent đang suy luận và phân tích...[/bold green]"):
                response = agent.step(user_input)

            console.print("\n[bold cyan]─── Kết quả phân tích ───[/bold cyan]")
            console.print(Markdown(response))

        except KeyboardInterrupt:
            console.print("\n[yellow]Đã ngắt thao tác bởi người dùng (Ctrl+C).[/yellow]")
        except Exception as e:
            console.print(f"[bold red]❌ Gặp lỗi:[/bold red] {str(e)}")

if __name__ == "__main__":
    main()
