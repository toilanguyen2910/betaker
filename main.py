import sys
from pathlib import Path
from datetime import datetime
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
[bold yellow]SYSTEM CONTROL COMMANDS:[/bold yellow]
 • [bold cyan]/audit <file_or_dir>[/bold cyan]   : Run static code security audit (SAST) for OWASP Top 10 vulnerabilities.
 • [bold cyan]/deps[/bold cyan]                   : Scan dependency manifests (requirements.txt / package.json) for CVEs.
 • [bold cyan]/rollback <filepath>[/bold cyan]   : Restore original file from its backup (.bak).
 • [bold cyan]/report[/bold cyan]                 : Generate a comprehensive Markdown audit report in the workspace.
 • [bold cyan]/files[/bold cyan]                  : List all files currently in the workspace sandbox directory.
 • [bold cyan]/clear[/bold cyan]                  : Reset conversation history.
 • [bold cyan]/help[/bold cyan]                   : Display this help message.
 • [bold cyan]/exit[/bold cyan]                   : Exit BetAker.
"""
    console.print(Panel(help_text, title="Help & Commands", border_style="blue"))

def handle_audit(target_path: str):
    p = Path(target_path).resolve()
    if not p.exists():
        console.print(f"[bold red]❌ Target path does not exist:[/bold red] {target_path}")
        return

    console.print(f"[bold green]🔍 Running security audit on:[/bold green] [dim]{p}[/dim]")
    findings = scan_directory(str(p))

    if not findings:
        console.print("[bold green]✅ No security vulnerabilities detected according to OWASP Top 10 standards![/bold green]")
        return

    table = Table(title=f"Detected {len(findings)} Security Findings", border_style="yellow")
    table.add_column("Severity", style="bold")
    table.add_column("Vulnerability", style="cyan")
    table.add_column("Location", style="magenta")
    table.add_column("Description", style="white")

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
    console.print("\n[dim]Tip: You can ask BetAker to perform root-cause analysis or generate automated secure patches![/dim]")

def handle_deps():
    console.print("[bold green]📦 Scanning dependency manifests in current directory...[/bold green]")
    findings = []
    for manifest_name in ("requirements.txt", "package.json"):
        manifest_path = Path(manifest_name)
        if manifest_path.exists():
            findings.extend(scan_dependencies(manifest_path))

    if not findings:
        console.print("[bold green]✅ All scanned dependencies are secure with no known CVE advisories detected![/bold green]")
    else:
        for f in findings:
            pkg = f.get('package', 'unknown')
            ver = f.get('current_version', 'unknown')
            desc = f.get('description', '')
            console.print(f"[bold red]⚠️ {pkg} ({ver}):[/bold red] {desc}")

def handle_rollback(filepath: str):
    success, msg = rollback_backup(Path(filepath))
    if success:
        console.print(f"[bold green]✅ {msg}[/bold green]")
    else:
        console.print(f"[bold red]❌ {msg}[/bold red]")

def handle_report():
    report_file = Config.WORKSPACE_DIR / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    findings = scan_directory(".")
    dep_findings = []
    for manifest_name in ("requirements.txt", "package.json"):
        manifest_path = Path(manifest_name)
        if manifest_path.exists():
            dep_findings.extend(scan_dependencies(manifest_path))

    lines = [
        "# 🛡️ BetAker Security Audit Report",
        f"\n**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Workspace:** `{Config.WORKSPACE_DIR}`",
        f"**Author / Credit:** `jack.vhknguyen@gmail.com` (@toilanguyen2910)",
        "\n---",
        f"\n## Summary",
        f"- **Static Code Findings (SAST):** {len(findings)}",
        f"- **Vulnerable Dependencies (SCA):** {len(dep_findings)}",
        "\n---",
        "\n## Static Code Analysis Findings",
    ]

    if not findings:
        lines.append("\n*No code vulnerabilities detected.*")
    else:
        for i, f in enumerate(findings, 1):
            lines.append(f"\n### {i}. [{f.get('severity', 'MEDIUM')}] {f.get('title', 'Finding')}")
            lines.append(f"- **File:** `{f.get('file', '')}:{f.get('line', '?')}`")
            lines.append(f"- **Category:** {f.get('category', 'OWASP Top 10')}")
            lines.append(f"- **Description:** {f.get('description', '')}")
            if f.get('snippet'):
                lines.append(f"```\n{f.get('snippet')}\n```")

    lines.append("\n---")
    lines.append("\n## Dependency Audit Findings (SCA)")
    if not dep_findings:
        lines.append("\n*No vulnerable dependencies detected.*")
    else:
        for i, df in enumerate(dep_findings, 1):
            lines.append(f"\n### {i}. [{df.get('severity', 'MEDIUM')}] {df.get('package', '')} ({df.get('current_version', '')})")
            lines.append(f"- **CVE:** `{df.get('cve', 'N/A')}`")
            lines.append(f"- **Advisory:** {df.get('description', '')}")
            if df.get('fixed_version'):
                lines.append(f"- **Recommended Fixed Version:** `{df.get('fixed_version')}`")

    report_content = "\n".join(lines)
    report_file.write_text(report_content, encoding="utf-8")
    console.print(f"[bold green]✅ Security audit report generated successfully:[/bold green] [cyan]{report_file}[/cyan]")

def main():
    Config.ensure_workspace()
    console.print(BANNER)
    
    info_panel = f"""[bold]Project:[/bold] [bold cyan]BetAker[/bold cyan] | [bold]Author:[/bold] [bold magenta]jack.vhknguyen@gmail.com (@toilanguyen2910)[/bold magenta]
[bold]Provider:[/bold] [green]{Config.LLM_PROVIDER}[/green] | [bold]Model:[/bold] [yellow]{Config.LLM_MODEL}[/yellow]
[bold]Approval Gate:[/bold] [cyan]{'ENABLED (Human-in-the-loop)' if Config.REQUIRE_APPROVAL else 'DISABLED (Auto)'}[/cyan]
[bold]Workspace:[/bold] [dim]{Config.WORKSPACE_DIR}[/dim]"""
    console.print(Panel(info_panel, title="System Configuration", border_style="cyan"))
    console.print("[dim]Type commands like '/audit .' to scan code, or ask questions to interact with AI (type '/help' for options).[/dim]\n")

    try:
        agent = BetAkerAgent()
    except Exception as e:
        console.print(f"[bold red]❌ LLM Client Initialization Error:[/bold red] {e}")
        console.print("[yellow]💡 Please check your .env configuration and verify your API Key and Provider.[/yellow]")
        sys.exit(1)

    while True:
        try:
            user_input = Prompt.ask("\n[bold cyan]BetAker[/bold cyan] [bold white]❯[/bold white]").strip()
            if not user_input:
                continue

            if user_input.lower() in ("/exit", "exit", "quit", ":q"):
                console.print("[bold yellow]Goodbye! Happy and secure coding! 🛡️[/bold yellow]")
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
                    console.print("[yellow]Please specify a target file path: /rollback <filepath>[/yellow]")
                else:
                    handle_rollback(parts[1])
                continue
            elif user_input.lower() == "/report":
                handle_report()
                continue
            elif user_input.lower() == "/clear":
                agent.history = [{"role": "system", "content": agent.history[0]["content"]}]
                console.print("[green]Conversation session reset successfully![/green]")
                continue
            elif user_input.lower() == "/files":
                from tools.file_ops import list_workspace_files
                files = list_workspace_files()
                if not files:
                    console.print("[yellow]Workspace directory is currently empty.[/yellow]")
                else:
                    for f in files:
                        console.print(f" • [cyan]{f['name']}[/cyan] ({f['size_bytes']} bytes)")
                continue

            with console.status("[bold green]BetAker is analyzing and reasoning...[/bold green]"):
                response = agent.step(user_input)

            console.print("\n[bold cyan]─── BetAker Analysis & Recommendations ───[/bold cyan]")
            console.print(Markdown(response))

        except KeyboardInterrupt:
            console.print("\n[yellow]Operation interrupted by user (Ctrl+C).[/yellow]")
        except Exception as e:
            console.print(f"[bold red]❌ Error encountered:[/bold red] {str(e)}")

if __name__ == "__main__":
    main()
