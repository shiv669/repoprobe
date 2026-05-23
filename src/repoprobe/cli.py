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


# typer app


app = typer.Typer(
    name="repoprobe",
    help="managed execution assurance for ai-generated software.",
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=True,
)



# commands



@app.command(context_settings={"allow_extra_args": True, "allow_interspersed_args": False})
def run(
    ctx: typer.Context,
    repo: list[str] = typer.Argument(
        ...,
        help="path to the target repository to verify.",
    ),
    timeout: int = typer.Option(
        30,
        "--timeout",
        "-t",
        help="boot detection timeout in seconds.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="show detailed install output.",
    ),
) -> None:
    """
    execute a full verification run against a target repository.

    fingerprints the repo, synthesizes an execution plan,
    installs dependencies, boots the application, and detects
    successful startup.
    """
    out.banner()

    full_path = " ".join(repo + ctx.args)
    repo_path = Path(full_path).resolve()
    if not repo_path.exists():
        out.failure(f"path does not exist: {repo_path}")
        raise typer.Exit(code=1)

    if not repo_path.is_dir():
        out.failure(f"path is not a directory: {repo_path}")
        raise typer.Exit(code=1)

    out.info(f"target: {repo_path}")

    # phase 1: fingerprint
    from repoprobe.fingerprint import Fingerprinter
    from repoprobe.planner import RuntimePlanner, render_plan
    from repoprobe.runner import ExecutionRunner, RuntimeStatus
    from repoprobe.probe import RuntimeProbe, render_probe_result

    out.phase_header(1, "fingerprint")
    fingerprinter = Fingerprinter(repo_path)
    fp = fingerprinter.run()

    # phase 2: plan
    out.phase_header(2, "execution plan")
    planner = RuntimePlanner(fp, repo_path)
    execution_plan = planner.synthesize()
    render_plan(execution_plan)

    if execution_plan.start_command == "unknown":
        out.failure("cannot execute — no start command determined")
        raise typer.Exit(code=1)

    # phase 3: execute (keep app alive for probing)
    out.phase_header(3, "runtime execution")
    runner = ExecutionRunner(
        plan=execution_plan,
        repo_root=repo_path,
        boot_timeout=timeout,
        keep_alive=True,
    )
    result = runner.execute()

    # phase 4: probe (only if booted)
    probe_result = None
    if result.status == RuntimeStatus.BOOTED:
        out.phase_header(4, "surface discovery")
        try:
            prober = RuntimeProbe(execution_plan)
            probe_result = prober.probe()
            render_probe_result(probe_result)
        except Exception as e:
            out.warning(f"surface probing failed: {e}")
        finally:
            runner.shutdown()
    else:
        runner.shutdown()

    # final summary
    out.console.print()
    out.console.rule("[phase]result[/phase]")
    out.console.print()

    if result.status == RuntimeStatus.BOOTED:
        out.success(f"status: {result.status.value}")
        if probe_result:
            out.success(
                f"surfaces: {probe_result.reachable_count} reachable "
                f"/ {probe_result.total_probed} probed"
            )
    elif result.status in (RuntimeStatus.CRASHED, RuntimeStatus.BOOT_FAILED, RuntimeStatus.INSTALL_FAILED):
        out.failure(f"status: {result.status.value}")
        if result.error:
            out.muted(f"  {result.error}")
    else:
        out.warning(f"status: {result.status.value}")
        if result.error:
            out.muted(f"  {result.error}")

    out.console.print()



@app.command(context_settings={"allow_extra_args": True, "allow_interspersed_args": False})
def inspect(
    ctx: typer.Context,
    repo: list[str] = typer.Argument(
        ...,
        help="path to the target repository to inspect.",
    ),
) -> None:
    """
    traverse a repository and produce a runtime fingerprint.

    scans the codebase to detect repo type, package manager,
    entry point, environment files, route surfaces, and
    external service dependencies. does not execute anything —
    this is a read-only static traversal.
    """
    out.banner()

    full_path = " ".join(repo + ctx.args)
    repo_path = Path(full_path).resolve()
    if not repo_path.exists():
        out.failure(f"path does not exist: {repo_path}")
        raise typer.Exit(code=1)

    if not repo_path.is_dir():
        out.failure(f"path is not a directory: {repo_path}")
        raise typer.Exit(code=1)

    from repoprobe.fingerprint import Fingerprinter, render_fingerprint

    fingerprinter = Fingerprinter(repo_path)
    fp = fingerprinter.run()
    render_fingerprint(fp)


@app.command(context_settings={"allow_extra_args": True, "allow_interspersed_args": False})
def plan(
    ctx: typer.Context,
    repo: list[str] = typer.Argument(
        ...,
        help="path to the target repository to plan execution for.",
    ),
) -> None:
    """
    synthesize an execution plan from a repository fingerprint.

    runs the fingerprinter, then converts the result into
    an actionable runtime plan — install command, start command,
    expected port, required services, and a confidence score.
    """
    out.banner()

    full_path = " ".join(repo + ctx.args)
    repo_path = Path(full_path).resolve()
    if not repo_path.exists():
        out.failure(f"path does not exist: {repo_path}")
        raise typer.Exit(code=1)

    if not repo_path.is_dir():
        out.failure(f"path is not a directory: {repo_path}")
        raise typer.Exit(code=1)

    from repoprobe.fingerprint import Fingerprinter
    from repoprobe.planner import RuntimePlanner, render_plan

    fingerprinter = Fingerprinter(repo_path)
    fp = fingerprinter.run()

    out.console.print()
    out.info("synthesizing execution plan...")

    planner = RuntimePlanner(fp, repo_path)
    execution_plan = planner.synthesize()
    render_plan(execution_plan)


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


# entry point (for `python -m repoprobe`)

if __name__ == "__main__":
    app()
