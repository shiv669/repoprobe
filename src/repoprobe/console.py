"""
shared rich console instance for repoprobe.

every module imports `console` from here so we get
consistent formatting and a single output stream.
"""

from rich.console import Console
from rich.theme import Theme

# custom theme — keeps colors consistent across the app
repoprobe_theme = Theme(
    {
        "info": "cyan",
        "success": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
        "phase": "bold magenta",
        "probe": "bold blue",
        "verdict.pass": "green",
        "verdict.fail": "red",
        "verdict.warn": "yellow",
        "muted": "dim white",
        "header": "bold white on #1a1a2e",
    }
)

console = Console(theme=repoprobe_theme)


def banner() -> None:
    """print the repoprobe startup banner."""
    console.print()
    console.print(
        "[header]  ╭──────────────────────────────────────╮  [/header]"
    )
    console.print(
        "[header]  │         r e p o p r o b e            │  [/header]"
    )
    console.print(
        "[header]  │   managed execution assurance  v0.1  │  [/header]"
    )
    console.print(
        "[header]  ╰──────────────────────────────────────╯  [/header]"
    )
    console.print()


def phase_header(phase_number: int, title: str) -> None:
    """print a phase header divider."""
    console.print()
    console.rule(f"[phase]phase {phase_number} — {title}[/phase]")
    console.print()


def success(msg: str) -> None:
    """print a success message."""
    console.print(f"  [success]✓[/success] {msg}")


def failure(msg: str) -> None:
    """print a failure message."""
    console.print(f"  [error]✗[/error] {msg}")


def warning(msg: str) -> None:
    """print a warning message."""
    console.print(f"  [warning]⚠[/warning] {msg}")


def info(msg: str) -> None:
    """print an info message."""
    console.print(f"  [info]●[/info] {msg}")


def muted(msg: str) -> None:
    """print a dim/muted message."""
    console.print(f"  [muted]{msg}[/muted]")


def event(tag: str, msg: str) -> None:
    """print a live event stream message with colored tag."""
    tag_styles = {
        "probe": "probe",
        "runtime": "warning",
        "analysis": "phase",
        "verify": "success",
        "agent": "info",
        "risk": "error",
    }
    style = tag_styles.get(tag, "muted")
    console.print(f"    [{style}][{tag}][/{style}] {msg}")

