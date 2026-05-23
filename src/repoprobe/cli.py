"""
repoprobe cli — the main entry point.

built with typer. each command is independent;
a failure in one does not affect others.
"""

import sys
from pathlib import Path

import typer

from repoprobe import __version__
from repoprobe.config import Config
from repoprobe import console as out

# ---------------------------------------------------------------------------
# typer app
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="repoprobe",
    help="managed execution assurance for ai-generated software.",
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=True,
)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


@app.command()
def run(
    repo: str = typer.Argument(
        ...,
        help="path to the target repository to verify.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="show detailed agent reasoning and shell output.",
    ),
) -> None:
    """
    execute a full verification run against a target repository.

    repoprobe will boot the application inside an isolated sandbox,
    discover its runtime surfaces, probe behavior, and produce
    a verification report with a readme trust score.
    """
    out.banner()

    # validate repo path
    repo_path = Path(repo).resolve()
    if not repo_path.exists():
        out.failure(f"repository path does not exist: {repo_path}")
        raise typer.Exit(code=1)

    if not repo_path.is_dir():
        out.failure(f"path is not a directory: {repo_path}")
        raise typer.Exit(code=1)

    out.info(f"target repository: {repo_path}")

    # validate config
    config_errors = Config.validate()
    if config_errors:
        for err in config_errors:
            out.failure(err)
        raise typer.Exit(code=1)

    out.success("configuration validated")

    # placeholder for the orchestration pipeline
    # (we'll wire this up in the next step)
    out.info("verification pipeline will be connected here")
    out.muted("setup complete — ready for phase integration")


@app.command()
def check() -> None:
    """
    verify that all required dependencies and config are in place.

    run this before your first `repoprobe run` to make sure
    everything is set up correctly.
    """
    out.banner()
    out.info("running pre-flight checks...\n")

    all_good = True

    # 1. python version
    v = sys.version_info
    if v.major >= 3 and v.minor >= 12:
        out.success(f"python {v.major}.{v.minor}.{v.micro}")
    else:
        out.failure(f"python {v.major}.{v.minor}.{v.micro} — need 3.12+")
        all_good = False

    # 2. google api key
    if Config.google_api_key:
        masked = Config.google_api_key[:4] + "..." + Config.google_api_key[-4:]
        out.success(f"GOOGLE_API_KEY is set ({masked})")
    else:
        out.failure("GOOGLE_API_KEY is not set")
        all_good = False

    # 3. genai sdk import
    try:
        from google import genai  # noqa: F401
        out.success("google-genai sdk is importable")
    except ImportError:
        out.failure("google-genai sdk not found — pip install google-genai")
        all_good = False

    # 4. typer
    try:
        import typer as _t  # noqa: F401
        out.success("typer is importable")
    except ImportError:
        out.failure("typer not found — pip install 'typer[all]'")
        all_good = False

    # 5. textual
    try:
        import textual as _tx  # noqa: F401
        out.success("textual is importable")
    except ImportError:
        out.failure("textual not found — pip install textual")
        all_good = False

    # 6. rich
    try:
        import rich as _r  # noqa: F401
        out.success("rich is importable")
    except ImportError:
        out.failure("rich not found — pip install rich")
        all_good = False

    # 7. genai client connectivity
    if Config.google_api_key:
        try:
            client = genai.Client(api_key=Config.google_api_key)
            # quick model list to verify connectivity
            models = client.models.list()
            out.success("genai client connected successfully")
        except Exception as e:
            out.warning(f"genai client connection test failed: {e}")
            all_good = False

    out.console.print()
    if all_good:
        out.success("all checks passed — repoprobe is ready")
    else:
        out.failure("some checks failed — fix the issues above")


@app.command()
def version() -> None:
    """print the current repoprobe version."""
    out.console.print(f"repoprobe v{__version__}")


# ---------------------------------------------------------------------------
# entry point (for `python -m repoprobe`)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
