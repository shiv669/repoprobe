"""
execution runner for repoprobe.

takes an ExecutionPlan and actually runs it:
  1. run install command
  2. spawn persistent start command
  3. stream stdout/stderr live
  4. detect successful boot (port open, keyword match, http probe)
  5. clean up subprocess on exit/timeout/failure

completely independent from gemini, textual, agents.
pure runtime layer: plan -> execute -> stream -> detect boot.
no retries. one clean deterministic pass.
"""

import asyncio
import re
import socket
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from repoprobe.planner import ExecutionPlan
from repoprobe import console as out


# boot detection keywords — case insensitive search
_BOOT_KEYWORDS = [
    "listening on",
    "listening at",
    "server running",
    "server started",
    "server is running",
    "started server",
    "ready on",
    "ready in",
    "ready at",
    "running on",
    "running at",
    "started on",
    "started at",
    "accepting connections",
    "development server",
    "compiled successfully",
    "compiled client",
    "webpack compiled",
    "localhost:",
    "0.0.0.0:",
    "127.0.0.1:",
]

# regex to extract port numbers from stdout lines like:
# "localhost:5173", "0.0.0.0:8000", "port 3000", ":5173/"
_PORT_FROM_OUTPUT = re.compile(
    r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0)[:/](\d{2,5})"
    r"|(?:port\s+)(\d{2,5})",
    re.IGNORECASE,
)

# strip ANSI escape codes from output for clean matching
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# default timeouts
INSTALL_TIMEOUT = 120   # seconds
BOOT_TIMEOUT = 30       # seconds
PORT_POLL_INTERVAL = 0.5


class RuntimeStatus(Enum):
    IDLE = "idle"
    INSTALLING = "installing"
    INSTALL_FAILED = "install_failed"
    STARTING = "starting"
    BOOTED = "booted"
    BOOT_FAILED = "boot_failed"
    PORT_OPEN = "port_open"
    TIMED_OUT = "timed_out"
    CRASHED = "crashed"
    STOPPED = "stopped"


@dataclass
class RunResult:
    """outcome of an execution run."""
    status: RuntimeStatus = RuntimeStatus.IDLE
    install_exit_code: int | None = None
    boot_detected: bool = False
    port_reachable: bool = False
    boot_line: str = ""
    stdout_lines: list[str] = field(default_factory=list)
    stderr_lines: list[str] = field(default_factory=list)
    error: str | None = None


class ExecutionRunner:
    """
    runs an execution plan against a target repository.
    spawns subprocesses, streams output, detects boot.
    cleans up on exit.
    """

    def __init__(
        self,
        plan: ExecutionPlan,
        repo_root: Path,
        install_timeout: int = INSTALL_TIMEOUT,
        boot_timeout: int = BOOT_TIMEOUT,
        keep_alive: bool = False,
        on_stdout: Callable[[str], None] | None = None,
        on_stderr: Callable[[str], None] | None = None,
    ) -> None:
        self.plan = plan
        self.root = repo_root.resolve()
        self.install_timeout = install_timeout
        self.boot_timeout = boot_timeout
        self.keep_alive = keep_alive
        self.on_stdout = on_stdout or self._default_stdout
        self.on_stderr = on_stderr or self._default_stderr
        self.result = RunResult()
        self._app_process: asyncio.subprocess.Process | None = None
        self._app_pid: int | None = None
        self._runtime_port: int | None = None
        self._stopped = False

    def execute(self) -> RunResult:
        """synchronous entry point — runs the async pipeline."""
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._run_pipeline())
        except KeyboardInterrupt:
            out.console.print()
            out.warning("interrupted by user")
            self.result.status = RuntimeStatus.STOPPED
        finally:
            # always close transports while loop is still open
            # (prevents windows ProactorEventLoop __del__ warnings)
            if self._app_process:
                if not self.keep_alive or self.result.status != RuntimeStatus.BOOTED:
                    # not keeping alive — kill the process
                    if self._app_process.returncode is None:
                        try:
                            self._app_process.kill()
                            loop.run_until_complete(self._app_process.wait())
                        except Exception:
                            pass
                # always close transport regardless of keep_alive
                # (process keeps running as an OS process, transport is just stdio)
                transport = getattr(self._app_process, "_transport", None)
                if transport and not transport.is_closing():
                    transport.close()
                    loop.run_until_complete(asyncio.sleep(0.1))

            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                pass
            loop.close()
        return self.result

    async def _run_pipeline(self) -> None:
        """the core async pipeline: install -> start -> detect boot."""

        # step 1: install
        if self.plan.install_command != "unknown":
            success = await self._run_install()
            if not success:
                return
        else:
            out.warning("no install command — skipping dependency install")

        # step 2: start + boot detection
        if self.plan.start_command != "unknown":
            await self._run_start()
        else:
            out.failure("no start command — cannot execute")
            self.result.status = RuntimeStatus.BOOT_FAILED
            self.result.error = "start command unknown"

    # -- install -----------------------------------------------------------

    async def _run_install(self) -> bool:
        """run the install command. returns True on success."""
        cmd = self.plan.install_command
        out.console.print()
        out.console.print(f"  [phase][plan][/phase] {cmd}")
        out.info("installing dependencies...")
        self.result.status = RuntimeStatus.INSTALLING

        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.root),
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.install_timeout,
            )

            self.result.install_exit_code = proc.returncode

            if proc.returncode == 0:
                out.success("dependencies installed")
                return True
            else:
                stderr_text = stderr_bytes.decode("utf-8", errors="ignore").strip()
                last_lines = "\n".join(stderr_text.splitlines()[-5:])
                out.failure(f"install failed (exit code {proc.returncode})")
                if last_lines:
                    out.muted(f"    {last_lines}")
                self.result.status = RuntimeStatus.INSTALL_FAILED
                self.result.error = f"install exited with code {proc.returncode}"
                return False

        except asyncio.TimeoutError:
            out.failure(f"install timed out after {self.install_timeout}s")
            self.result.status = RuntimeStatus.TIMED_OUT
            self.result.error = "install timeout"
            return False
        except Exception as e:
            out.failure(f"install error: {e}")
            self.result.status = RuntimeStatus.INSTALL_FAILED
            self.result.error = str(e)
            return False

    # -- start + boot detection --------------------------------------------

    async def _run_start(self) -> None:
        """spawn the app process, stream output, detect boot."""
        cmd = self.plan.start_command
        out.console.print()
        out.console.print(f"  [phase][plan][/phase] {cmd}")
        out.info("starting application...")
        self.result.status = RuntimeStatus.STARTING

        try:
            self._app_process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.root),
            )
            self._app_pid = self._app_process.pid

            # race: stdout streaming + boot detection vs timeout
            try:
                await asyncio.wait_for(
                    self._monitor_boot(),
                    timeout=self.boot_timeout,
                )
            except asyncio.TimeoutError:
                # timeout is not always failure — check port as last resort
                if self.plan.expected_port and self._check_port(self.plan.expected_port):
                    self.result.boot_detected = True
                    self.result.port_reachable = True
                    self.result.status = RuntimeStatus.BOOTED
                    self._print_boot_success()
                else:
                    out.failure(f"boot detection timed out after {self.boot_timeout}s")
                    self.result.status = RuntimeStatus.TIMED_OUT
                    self.result.error = "boot timeout"

        except Exception as e:
            out.failure(f"start error: {e}")
            self.result.status = RuntimeStatus.BOOT_FAILED
            self.result.error = str(e)
        finally:
            if not self.keep_alive or self.result.status != RuntimeStatus.BOOTED:
                await self._cleanup_app()

    async def _monitor_boot(self) -> None:
        """read stdout/stderr lines and watch for boot signals."""
        boot_event = asyncio.Event()

        async def read_stream(stream, is_stderr: bool) -> None:
            while True:
                line_bytes = await stream.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="ignore").rstrip()
                if not line:
                    continue

                # store and emit
                if is_stderr:
                    self.result.stderr_lines.append(line)
                    self.on_stderr(line)
                else:
                    self.result.stdout_lines.append(line)
                    self.on_stdout(line)

                # strip ansi codes for clean matching
                clean = _ANSI_ESCAPE.sub("", line)

                # try to extract actual port from output
                port_match = _PORT_FROM_OUTPUT.search(clean)
                if port_match:
                    detected = port_match.group(1) or port_match.group(2)
                    if detected:
                        self._runtime_port = int(detected)

                # check for boot keywords (don't return — keep reading for port info)
                if not boot_event.is_set():
                    lower = clean.lower()
                    for keyword in _BOOT_KEYWORDS:
                        if keyword in lower:
                            self.result.boot_line = clean.strip()
                            boot_event.set()
                            break

        async def poll_port() -> None:
            """poll the expected port until it opens."""
            if not self.plan.expected_port:
                return
            while not boot_event.is_set():
                if self._check_port(self.plan.expected_port):
                    self.result.port_reachable = True
                    boot_event.set()
                    return
                await asyncio.sleep(PORT_POLL_INTERVAL)

        async def wait_for_crash() -> None:
            """detect if the process exits before boot."""
            if self._app_process:
                await self._app_process.wait()
                if not boot_event.is_set():
                    self.result.status = RuntimeStatus.CRASHED
                    self.result.error = (
                        f"process exited with code {self._app_process.returncode} "
                        "before boot was detected"
                    )
                    boot_event.set()

        # run all monitors concurrently
        tasks = [
            asyncio.create_task(read_stream(self._app_process.stdout, False)),
            asyncio.create_task(read_stream(self._app_process.stderr, True)),
            asyncio.create_task(poll_port()),
            asyncio.create_task(wait_for_crash()),
        ]

        # wait until boot is detected or all streams end
        await boot_event.wait()

        # give a moment for port lines to arrive after boot keyword
        await asyncio.sleep(1.0)

        # if boot was detected (not crash), mark success
        if self.result.status != RuntimeStatus.CRASHED:
            self.result.boot_detected = True
            self.result.status = RuntimeStatus.BOOTED

            # use runtime-detected port if available, otherwise planned port
            actual_port = getattr(self, "_runtime_port", None) or self.plan.expected_port
            if actual_port and actual_port != self.plan.expected_port:
                out.info(f"detected actual port: {actual_port}")
                self.plan.expected_port = actual_port

            # give port time to fully open if keyword detected first
            if not self.result.port_reachable and self.plan.expected_port:
                for _ in range(4):
                    await asyncio.sleep(0.5)
                    if self._check_port(self.plan.expected_port):
                        self.result.port_reachable = True
                        break

            self._print_boot_success()

        # cancel remaining tasks
        for t in tasks:
            t.cancel()

    def _print_boot_success(self) -> None:
        """print the boot success summary."""
        out.console.print()
        if self.result.boot_line:
            out.console.print(
                f"  [muted][stdout][/muted] {self.result.boot_line}"
            )
        out.console.print()
        out.success("application booted successfully")
        if self.result.port_reachable:
            out.success(f"port {self.plan.expected_port} reachable")
        elif self.plan.expected_port:
            out.warning(f"port {self.plan.expected_port} not yet reachable")
        out.success("runtime active")

    # -- port check --------------------------------------------------------

    @staticmethod
    def _check_port(port: int, host: str = "127.0.0.1") -> bool:
        """check if a port is open. non-blocking, fast."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                return s.connect_ex((host, port)) == 0
        except Exception:
            return False

    # -- cleanup -----------------------------------------------------------

    async def _cleanup_app(self) -> None:
        """gracefully terminate the app process."""
        if self._app_process is None:
            return
        if self._app_process.returncode is not None:
            return
        try:
            self._app_process.terminate()
            try:
                await asyncio.wait_for(self._app_process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._app_process.kill()
                await self._app_process.wait()
            out.muted("  application process terminated")
        except Exception:
            pass

    def shutdown(self) -> None:
        """synchronous kill of the app process. call after probing is done."""
        import os
        import signal as sig

        pid = self._app_pid
        if not pid:
            return

        try:
            if sys.platform == "win32":
                os.kill(pid, sig.SIGTERM)
            else:
                os.kill(pid, sig.SIGTERM)
        except (ProcessLookupError, OSError):
            pass

        out.muted("  application process terminated")

    def _force_cleanup(self) -> None:
        """last-resort synchronous cleanup for ctrl+c / exceptions."""
        if self._app_pid:
            import os
            import signal as sig
            try:
                os.kill(self._app_pid, sig.SIGTERM)
            except (ProcessLookupError, OSError):
                pass

    # -- default output handlers -------------------------------------------

    @staticmethod
    def _default_stdout(line: str) -> None:
        out.console.print(f"  [muted][stdout][/muted] {line}")

    @staticmethod
    def _default_stderr(line: str) -> None:
        out.console.print(f"  [muted][stderr][/muted] {line}")
