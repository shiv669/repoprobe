"""
execution plan synthesis for repoprobe.

takes a RepoFingerprint and converts it into an actionable
ExecutionPlan — the bridge between static repo analysis
and runtime verification.

all planning is deterministic. no llm calls.
each planner method is independent with its own error handling.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from repoprobe.fingerprint import RepoFingerprint
from repoprobe import console as out


# port detection pattern — matches .listen(3000) or .listen(PORT)
_LISTEN_PORT = re.compile(
    r"""\.listen\s*\(\s*(\d{2,5})""",
)
_ENV_PORT = re.compile(
    r"""(?:^|\s)PORT\s*=\s*(\d{2,5})""",
    re.MULTILINE,
)
_PYTHON_PORT = re.compile(
    r"""(?:port\s*=\s*(\d{2,5})|--port\s+(\d{2,5}))""",
    re.IGNORECASE,
)

# framework default ports
_FRAMEWORK_PORTS: dict[str, int] = {
    "express": 3000,
    "next.js": 3000,
    "nest.js": 3000,
    "fastify": 3000,
    "koa": 3000,
    "hapi": 3000,
    "flask": 5000,
    "django": 8000,
    "fastapi": 8000,
    "tornado": 8888,
    "sanic": 8000,
}

# install commands by package manager
_INSTALL_COMMANDS: dict[str, str] = {
    "npm": "npm install",
    "yarn": "yarn install",
    "pnpm": "pnpm install",
    "bun": "bun install",
    "pip": "pip install -r requirements.txt",
    "poetry": "poetry install",
    "pipenv": "pipenv install",
}

# max file size for port scanning
_MAX_SCAN = 512 * 1024

# skip dirs during port scan
_SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "coverage",
})

_SCANNABLE = frozenset({".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".py"})


@dataclass
class ExecutionPlan:
    """actionable execution plan for a repository."""
    stack: str = "unknown"
    install_command: str = "unknown"
    start_command: str = "unknown"
    expected_port: int | None = None
    port_source: str = "none"
    required_services: list[dict[str, str]] = field(default_factory=list)
    env_files: list[str] = field(default_factory=list)
    detected_routes: list[str] = field(default_factory=list)
    confidence: int = 0
    notes: list[str] = field(default_factory=list)


class RuntimePlanner:
    """
    converts a RepoFingerprint into an ExecutionPlan.
    each _plan method is independent — failures are isolated.
    """

    def __init__(self, fp: RepoFingerprint, repo_root: Path) -> None:
        self.fp = fp
        self.root = repo_root.resolve()
        self.plan = ExecutionPlan()
        self._pkg: dict | None = None

    def synthesize(self) -> ExecutionPlan:
        """run all planning steps and return the execution plan."""
        self._load_package_json()

        self._run("stack", self._plan_stack)
        self._run("install command", self._plan_install)
        self._run("start command", self._plan_start)
        self._run("port", self._plan_port)
        self._run("required services", self._plan_services)
        self._run("environment", self._plan_env)
        self._run("routes", self._plan_routes)
        self._run("confidence", self._plan_confidence)

        return self.plan

    def _run(self, name: str, fn) -> None:
        try:
            fn()
        except Exception as e:
            self.plan.notes.append(f"{name} planning failed: {e}")

    def _load_package_json(self) -> None:
        pkg_path = self.root / "package.json"
        if pkg_path.is_file():
            try:
                text = pkg_path.read_text(encoding="utf-8", errors="ignore")
                self._pkg = json.loads(text)
            except Exception:
                self._pkg = None

    # -- stack

    def _plan_stack(self) -> None:
        parts = []
        rtype = self.fp.repo_type
        if rtype in ("node", "node+python"):
            parts.append("node.js")
        if rtype in ("python", "node+python"):
            parts.append("python")
        fw = self.fp.framework
        if fw != "unknown":
            parts.append(fw)
        self.plan.stack = " + ".join(parts) if parts else "unknown"

    # -- install command

    def _plan_install(self) -> None:
        pm = self.fp.package_manager
        cmd = _INSTALL_COMMANDS.get(pm)
        if cmd:
            # for pip, check if requirements.txt actually exists
            if pm == "pip" and not (self.root / "requirements.txt").is_file():
                if (self.root / "pyproject.toml").is_file():
                    self.plan.install_command = "pip install -e ."
                else:
                    self.plan.install_command = cmd
                    self.plan.notes.append(
                        "requirements.txt not found, install may fail"
                    )
            else:
                self.plan.install_command = cmd
        else:
            self.plan.install_command = "unknown"
            self.plan.notes.append(
                "could not determine install command"
            )

    # -- start command

    def _plan_start(self) -> None:
        # node repos: try package.json scripts
        if self.fp.repo_type in ("node", "node+python") and self._pkg:
            scripts = self._pkg.get("scripts", {})

            # prefer start, then dev
            for key in ("start", "dev", "serve"):
                if key in scripts:
                    self.plan.start_command = f"npm run {key}"
                    if self.fp.package_manager == "yarn":
                        self.plan.start_command = f"yarn {key}"
                    elif self.fp.package_manager == "pnpm":
                        self.plan.start_command = f"pnpm run {key}"
                    elif self.fp.package_manager == "bun":
                        self.plan.start_command = f"bun run {key}"
                    return

        # framework heuristics
        fw = self.fp.framework
        entry = self.fp.entry_point

        if fw == "django":
            self.plan.start_command = "python manage.py runserver"
            return
        if fw == "flask":
            if entry != "none detected":
                self.plan.start_command = f"flask --app {entry} run"
            else:
                self.plan.start_command = "flask run"
            return
        if fw == "fastapi":
            if entry != "none detected":
                module = entry.replace("/", ".").replace("\\", ".").removesuffix(".py")
                self.plan.start_command = f"uvicorn {module}:app --reload"
            else:
                self.plan.start_command = "uvicorn main:app --reload"
            return
        if fw == "next.js":
            self.plan.start_command = "npx next dev"
            return
        if fw == "nest.js":
            self.plan.start_command = "npm run start:dev"
            return

        # fallback: run the entry point directly
        if entry != "none detected":
            if self.fp.repo_type in ("node", "node+python"):
                self.plan.start_command = f"node {entry}"
            elif self.fp.repo_type == "python":
                self.plan.start_command = f"python {entry}"
            return

        self.plan.start_command = "unknown"
        self.plan.notes.append(
            "could not determine start command — manual config needed"
        )

    # -- port

    def _plan_port(self) -> None:
        # 1. check env files for PORT=
        for env_rel in self.fp.env_files:
            env_path = self.root / env_rel
            if env_path.is_file():
                try:
                    text = env_path.read_text(encoding="utf-8", errors="ignore")
                    m = _ENV_PORT.search(text)
                    if m:
                        self.plan.expected_port = int(m.group(1))
                        self.plan.port_source = f"env file ({env_rel})"
                        return
                except Exception:
                    pass

        # 2. scan source files for .listen(PORT)
        port = self._scan_for_port()
        if port:
            self.plan.expected_port = port
            self.plan.port_source = "source code (.listen pattern)"
            return

        # 3. framework defaults
        fw = self.fp.framework
        if fw in _FRAMEWORK_PORTS:
            self.plan.expected_port = _FRAMEWORK_PORTS[fw]
            self.plan.port_source = f"framework default ({fw})"
            return

        # 4. repo type defaults
        if self.fp.repo_type in ("node", "node+python"):
            self.plan.expected_port = 3000
            self.plan.port_source = "fallback default (node)"
        elif self.fp.repo_type == "python":
            self.plan.expected_port = 8000
            self.plan.port_source = "fallback default (python)"

    def _scan_for_port(self) -> int | None:
        """recursive scan of source files for listen() port patterns."""
        return self._scan_dir_for_port(self.root, 0)

    def _scan_dir_for_port(self, dir_path: Path, depth: int) -> int | None:
        if depth > 8:
            return None
        try:
            for entry in sorted(dir_path.iterdir()):
                if entry.is_dir():
                    if entry.name in _SKIP_DIRS:
                        continue
                    result = self._scan_dir_for_port(entry, depth + 1)
                    if result:
                        return result
                elif entry.is_file() and entry.suffix in _SCANNABLE:
                    result = self._scan_file_for_port(entry)
                    if result:
                        return result
        except (PermissionError, OSError):
            pass
        return None

    def _scan_file_for_port(self, path: Path) -> int | None:
        try:
            if path.stat().st_size > _MAX_SCAN:
                return None
            text = path.read_text(encoding="utf-8", errors="ignore")
            # node: .listen(3000)
            m = _LISTEN_PORT.search(text)
            if m:
                return int(m.group(1))
            # python: port=8000
            m = _PYTHON_PORT.search(text)
            if m:
                val = m.group(1) or m.group(2)
                if val:
                    return int(val)
        except Exception:
            pass
        return None

    # -- services

    def _plan_services(self) -> None:
        runtime_categories = {"database", "cache", "messaging", "queue"}
        for svc in self.fp.services:
            if svc.category in runtime_categories:
                self.plan.required_services.append({
                    "name": svc.name,
                    "category": svc.category,
                })

    # -- environment

    def _plan_env(self) -> None:
        self.plan.env_files = list(self.fp.env_files)
        if not self.plan.env_files:
            self.plan.notes.append(
                "no environment files detected — app may need manual env setup"
            )

    # -- routes

    def _plan_routes(self) -> None:
        for surface in self.fp.surfaces:
            label = f"{surface.method} {surface.path}"
            if label not in self.plan.detected_routes:
                self.plan.detected_routes.append(label)

    # -- confidence score

    def _plan_confidence(self) -> None:
        score = 0

        if self.fp.repo_type != "unknown":
            score += 15
        if self.fp.framework != "unknown":
            score += 15
        if self.fp.package_manager != "unknown":
            score += 10
        if self.fp.entry_point != "none detected":
            score += 10
        if self.plan.start_command != "unknown":
            score += 20
        if self.plan.expected_port is not None:
            score += 10
        if self.plan.env_files:
            score += 10
        if self.plan.detected_routes:
            score += 10

        self.plan.confidence = score


def render_plan(plan: ExecutionPlan) -> None:
    """print the execution plan to the terminal."""
    out.console.print()
    out.console.rule("[phase]runtime plan[/phase]")
    out.console.print()

    out.console.print(f"  [info]stack[/info]              :  {plan.stack}")
    out.console.print(f"  [info]install[/info]            :  {plan.install_command}")
    out.console.print(f"  [info]start command[/info]      :  {plan.start_command}")

    if plan.expected_port:
        out.console.print(
            f"  [info]expected port[/info]     :  {plan.expected_port}"
            f"  [muted]({plan.port_source})[/muted]"
        )
    else:
        out.console.print("  [info]expected port[/info]     :  undetermined")

    # required services
    out.console.print()
    if plan.required_services:
        out.console.print(f"  [info]required services[/info] ({len(plan.required_services)})")
        for svc in plan.required_services:
            out.console.print(
                f"    [probe]{svc['name']:<20}[/probe] [muted]{svc['category']}[/muted]"
            )
    else:
        out.muted("  no runtime services required")

    # env files
    out.console.print()
    if plan.env_files:
        out.console.print(f"  [info]environment files[/info] ({len(plan.env_files)})")
        for ef in plan.env_files:
            out.muted(f"    {ef}")
    else:
        out.muted("  no environment files")

    # routes
    out.console.print()
    if plan.detected_routes:
        out.console.print(f"  [info]detected routes[/info] ({len(plan.detected_routes)})")
        for route in plan.detected_routes:
            out.console.print(f"    [probe]{route}[/probe]")
    else:
        out.muted("  no routes to probe")

    # confidence
    out.console.print()
    conf = plan.confidence
    if conf >= 70:
        style = "success"
    elif conf >= 40:
        style = "warning"
    else:
        style = "error"
    out.console.print(
        f"  [info]execution confidence[/info] :  [{style}]{conf}%[/{style}]"
    )

    # notes
    if plan.notes:
        out.console.print()
        out.console.print("  [info]notes[/info]")
        for note in plan.notes:
            out.muted(f"    - {note}")

    out.console.print()
