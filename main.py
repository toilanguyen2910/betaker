import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.prompt import Prompt
from rich.table import Table

from config import Config
from agent.core import BetHackerAgent as BetAkerAgent
from tools.scanner import scan_directory, scan_dependencies
from tools.patcher import rollback_backup

console = Console()

BANNER = """[bold cyan]
██████╗ ███████╗████████╗ █████╗ ██╗  ██╗███████╗██████╗ 
██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝██╔══██╗
██████╔╝█████╗     ██║   ███████║█████╔╝ █████╗  ██████╔╝
██╔══██╗██╔══╝     ██║   ██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗
██████╔╝███████╗   ██║   ██║  ██║██║  ██╗███████╗██║  ██║
╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
[/bold cyan]
[bold green]  🛡️ BetAker — AI-Powered Security Code Auditor & Offensive Security Patching CLI Tool 🛡️[/bold green]
"""

def print_help():
    help_text = """
[bold yellow]CÁC LỆNH ĐIỀU KHIỂN HỆ THỐNG:[/bold yellow]
 • [bold cyan]/audit <thư_mục_hoặc_file>[/bold cyan] : Quét kiểm toán an ninh tĩnh (SAST) tìm lỗ hổng OWASP Top 10.
 • [bold cyan]/deps[/bold cyan]                         : Quét các file phụ thuộc (requirements.txt / package.json) tìm CVE.
 • [bold cyan]/rollback <đường_dẫn_file>[/bold cyan]    : Khôi phục lại file gốc từ bản sao lưu dự phòng .bak.
 • [bold cyan]/files[/bold cyan]                        : Liệt kê danh sách các tệp tin trong thư mục workspace.
 • [bold cyan]/clear[/bold cyan]                        : Làm mới lịch sử hội thoại hiện tại.
 • [bold cyan]/help[/bold cyan]                         : Hiển thị bảng trợ giúp này.
 • [bold cyan]/exit[/bold cyan]                         : Thoát chương trình.
"""
    console.print(Panel(help_text, title="Trợ giúp", border_style="blue"))

def handle_audit(target_path: str):
    p = Path(target_path).resolve()
    if not p.exists():
        console.print(f"[bold red]❌ Đường dẫn không tồn tại:[/bold red] {target_path}")
        return

    console.print(f"[bold green]🔍 Đang quét kiểm toán an ninh trên:[/bold green] [dim]{p}[/dim]")
    findings = scan_directory(str(p))

    if not findings:
        console.print("[bold green]✅ Không phát hiện lỗ hổng bảo mật nào theo tiêu chuẩn OWASP Top 10![/bold green]")
        return

    table = Table(title=f"Phát hiện {len(findings)} rủi ro bảo mật", border_style="yellow")
    table.add_column("Mức độ", style="bold")
    table.add_column("Lỗ hổng", style="cyan")
    table.add_column("Vị trí", style="magenta")
    table.add_column("Mô tả", style="white")

    for f in findings:
        sev = f.get("severity", "MEDIUM")
        color = "red" if sev in ("CRITICAL", "HIGH") else "yellow"
        table.add_row(
            f"[{color}]{sev}[/{color}]",
            f.get("title", "Unknown"),
            f"{Path(f.get('file', '')).name}:{f.get('line', '?')}",
            f.get("description", "")[:80] + "..."
        )

    console.print(table)
    console.print("\n[dim]Gợi ý: Bạn có thể nhập câu hỏi để nhờ BetAker phân tích nguyên nhân và sinh bản vá tự động![/dim]")

def handle_deps():
    console.print("[bold green]📦 Đang quét kiểm tra các file phụ thuộc trong thư mục hiện tại...[/bold green]")
    req_file = Path("requirements.txt")
    findings = []
    if req_file.exists():
        findings.extend(scan_dependencies(req_file))

    if not findings:
        console.print("[bold green]✅ Tất cả thư viện phụ thuộc đều an toàn hoặc chưa phát hiện CVE đã biết![/bold green]")
    else:
        for f in findings:
            console.print(f"[bold red]⚠️ {f['package']} ({f['current_version']}):[/bold red] {f['description']}")

def handle_rollback(filepath: str):
    success, msg = rollback_backup(Path(filepath))
    if success:
        console.print(f"[bold green]✅ {msg}[/bold green]")
    else:
        console.print(f"[bold red]❌ {msg}[/bold red]")

def main():
    Config.ensure_workspace()
    console.print(BANNER)
    
    info_panel = f"""[bold]Dự án:[/bold] [bold cyan]BetAker[/bold cyan] | [bold]Tác giả:[/bold] [bold magenta]@toilanguyen2910[/bold magenta]
[bold]Provider:[/bold] [green]{Config.LLM_PROVIDER}[/green] | [bold]Model:[/bold] [yellow]{Config.LLM_MODEL}[/yellow]
[bold]Approval Gate:[/bold] [cyan]{'BẬT (Human-in-the-loop)' if Config.REQUIRE_APPROVAL else 'TẮT (Auto)'}[/cyan]
[bold]Workspace:[/bold] [dim]{Config.WORKSPACE_DIR}[/dim]"""
    console.print(Panel(info_panel, title="Cấu hình hệ thống", border_style="cyan"))
    console.print("[dim]Gõ lệnh như /audit . để kiểm toán, hoặc gõ câu hỏi để trò chuyện với AI (gõ /help để xem hướng dẫn).[/dim]\n")

    try:
        agent = BetAkerAgent()
    except Exception as e:
        console.print(f"[bold red]❌ Lỗi khởi tạo LLM Client:[/bold red] {e}")
        console.print("[yellow]💡 Hãy kiểm tra lại file .env đã điền đúng API Key và Provider chưa.[/yellow]")
        sys.exit(1)

    while True:
        try:
            user_input = Prompt.ask("\n[bold cyan]BetAker[/bold cyan] [bold white]❯[/bold white]").strip()
            if not user_input:
                continue

            if user_input.lower() in ("/exit", "exit", "quit", ":q"):
                console.print("[bold yellow]Tạm biệt! Chúc bạn bảo mật mã nguồn an toàn! 🛡️[/bold yellow]")
                break
            elif user_input.lower() == "/help":
                print_help()
                continue
            elif user_input.lower().startswith("/audit"):
                parts = user_input.split(maxsplit=1)
                target = parts[1] if len(parts) > 1 else "."
                handle_audit(target)
                continue
            elif user_input.lower() == "/deps":
                handle_deps()
                continue
            elif user_input.lower().startswith("/rollback"):
                parts = user_input.split(maxsplit=1)
                if len(parts) < 2:
                    console.print("[yellow]Vui lòng chỉ định đường dẫn file cần rollback: /rollback <filepath>[/yellow]")
                else:
                    handle_rollback(parts[1])
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

            with console.status("[bold green]BetAker đang phân tích và suy luận...[/bold green]"):
                response = agent.step(user_input)

            console.print("\n[bold cyan]─── Phân tích & Đề xuất của BetAker ───[/bold cyan]")
            console.print(Markdown(response))

        except KeyboardInterrupt:
            console.print("\n[yellow]Đã ngắt thao tác bởi người dùng (Ctrl+C).[/yellow]")
        except Exception as e:
            console.print(f"[bold red]❌ Gặp lỗi:[/bold red] {str(e)}")

if __name__ == "__main__":
    main()
