"""Zuultimate CLI -- Typer entry point."""

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(name="zuul", help="Zuultimate CLI")
console = Console()


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address"),
    port: int = typer.Option(8000, help="Port"),
    reload: bool = typer.Option(False, help="Auto-reload"),
):
    """Start the Zuultimate API server."""
    import uvicorn
    uvicorn.run("zuultimate.app:create_app", factory=True, host=host, port=port, reload=reload)


@app.command()
def scan(text: str = typer.Argument(..., help="Text to scan for injection")):
    """Scan text for prompt injection threats."""
    from zuultimate.ai_security.injection_detector import InjectionDetector
    detector = InjectionDetector()
    result = detector.scan(text)

    if result.is_threat:
        console.print(f"[bold red]THREAT DETECTED[/] (score: {result.threat_score})")
        table = Table(title="Detections")
        table.add_column("Pattern")
        table.add_column("Category")
        table.add_column("Severity")
        table.add_column("Match")
        for d in result.detections:
            color = {"critical": "red", "high": "yellow", "medium": "cyan"}.get(d.severity.value, "white")
            table.add_row(d.pattern_name, d.category.value, f"[{color}]{d.severity.value}[/]", d.matched_text[:60])
        console.print(table)
    else:
        console.print(f"[green]No threats detected[/] (score: {result.threat_score})")


@app.command()
def redteam(passphrase: str = typer.Option(..., prompt=True, hide_input=True)):
    """Run the red team attack suite."""
    import asyncio
    from zuultimate.ai_security.red_team import RedTeamTool
    from zuultimate.ai_security.injection_detector import InjectionDetector

    async def run():
        tool = RedTeamTool(InjectionDetector())
        tool.set_passphrase(passphrase)
        result = await tool.execute(passphrase)

        console.print(f"\n[bold]Red Team Results[/]")
        console.print(f"  Total attacks: {result.total_attacks}")
        console.print(f"  Detected: [green]{result.detected}[/]")
        console.print(f"  Bypassed: [red]{result.bypassed}[/]")
        console.print(f"  Detection rate: [bold]{result.detection_rate:.1%}[/]")

        if result.bypassed_payloads:
            console.print(f"\n[yellow]Bypassed payloads:[/]")
            for name in result.bypassed_payloads:
                console.print(f"  - {name}")

    asyncio.run(run())


@app.command()
def health():
    """Check server health."""
    import httpx
    try:
        r = httpx.get("http://localhost:8000/health", timeout=5)
        console.print(r.json())
    except Exception as e:
        console.print(f"[red]Server unreachable:[/] {e}")


if __name__ == "__main__":
    app()
