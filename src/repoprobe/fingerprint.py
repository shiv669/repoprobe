"""
runtime fingerprinting engine for repoprobe.

uses recursive dfs traversal over the filesystem tree to collect
signals about the repository — type, package manager, entry point,
environment files, detected surfaces, and potential services.

scope: node and python codebases only.

every detector function is independent. if one fails, the others
still produce results. the system never crashes on a single bad file.
"""

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from repoprobe import console as out


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

MAX_DEPTH = 15
MAX_SCAN_BYTES = 512 * 1024

SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "coverage", ".pytest_cache",
    ".mypy_cache", ".tox", ".eggs", "htmlcov", ".idea", ".vscode",
    ".svn", ".hg", "vendor", "bower_components", ".parcel-cache",
})

NODE_EXTENSIONS = frozenset({".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"})
PYTHON_EXTENSIONS = frozenset({".py"})

# route patterns — compiled once
_EXPRESS_ROUTE = re.compile(
    r"""(?:app|router|server)\.(get|post|put|delete|patch|all|use)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
_FLASK_ROUTE = re.compile(
    r"""@\w+\.route\s*\(\s*['"]([^'"]+)['"]""",
)
_FASTAPI_ROUTE = re.compile(
    r"""@\w+\.(get|post|put|delete|patch|options|head)\s*\(\s*['"]([^'"]+)['"]""",
)
_DJANGO_PATH = re.compile(
    r"""path\s*\(\s*['"]([^'"]+)['"]""",
)

# entry point priority lists
_NODE_ENTRY_NAMES = [
    "server.js", "server.ts", "app.js", "app.ts",
    "index.js", "index.ts", "main.js", "main.ts",
    "src/server.js", "src/server.ts", "src/app.js", "src/app.ts",
    "src/index.js", "src/index.ts", "src/main.js", "src/main.ts",
]
_PYTHON_ENTRY_NAMES = [
    "manage.py", "app.py", "main.py", "wsgi.py", "asgi.py",
    "run.py", "server.py", "src/main.py", "src/app.py",
]

# dependency-to-service mapping
_SERVICE_MAP: dict[str, tuple[str, str]] = {
    # node — databases
    "mongoose": ("mongodb", "database"), "mongodb": ("mongodb", "database"),
    "pg": ("postgresql", "database"), "pg-promise": ("postgresql", "database"),
    "mysql": ("mysql", "database"), "mysql2": ("mysql", "database"),
    "sequelize": ("sql-orm", "database"), "prisma": ("prisma-orm", "database"),
    "@prisma/client": ("prisma-orm", "database"),
    "sqlite3": ("sqlite", "database"), "better-sqlite3": ("sqlite", "database"),
    "typeorm": ("typeorm", "database"), "knex": ("knex-query-builder", "database"),
    # node — cache
    "redis": ("redis", "cache"), "ioredis": ("redis", "cache"),
    # node — auth
    "passport": ("passport", "auth"), "jsonwebtoken": ("jwt", "auth"),
    "bcrypt": ("bcrypt", "auth"), "bcryptjs": ("bcrypt", "auth"),
    # node — payment
    "stripe": ("stripe", "payment"), "razorpay": ("razorpay", "payment"),
    # node — email
    "nodemailer": ("nodemailer", "email"), "@sendgrid/mail": ("sendgrid", "email"),
    # node — cloud
    "aws-sdk": ("aws", "cloud"), "firebase-admin": ("firebase", "cloud"),
    # node — realtime
    "socket.io": ("socket.io", "realtime"),
    # node — messaging
    "amqplib": ("rabbitmq", "messaging"), "kafkajs": ("kafka", "messaging"),
    "bull": ("bull-queue", "queue"), "bullmq": ("bull-queue", "queue"),
    # python — databases
    "psycopg2": ("postgresql", "database"), "psycopg2-binary": ("postgresql", "database"),
    "asyncpg": ("postgresql", "database"),
    "pymysql": ("mysql", "database"), "mysqlclient": ("mysql", "database"),
    "pymongo": ("mongodb", "database"), "motor": ("mongodb", "database"),
    "sqlalchemy": ("sqlalchemy", "database"), "SQLAlchemy": ("sqlalchemy", "database"),
    "peewee": ("peewee-orm", "database"),
    # python — cache
    "aioredis": ("redis", "cache"),
    # python — auth
    "PyJWT": ("jwt", "auth"), "pyjwt": ("jwt", "auth"),
    "passlib": ("passlib", "auth"),
    "flask-login": ("flask-login", "auth"),
    # python — payment
    # "stripe" already covered above
    # python — cloud
    "boto3": ("aws", "cloud"), "firebase-admin": ("firebase", "cloud"),
    # python — email
    "sendgrid": ("sendgrid", "email"),
    # python — realtime
    "python-socketio": ("socket.io", "realtime"),
    # python — messaging
    "pika": ("rabbitmq", "messaging"), "kafka-python": ("kafka", "messaging"),
    "celery": ("celery", "queue"),
    # python — servers
    "uvicorn": ("uvicorn", "server"), "gunicorn": ("gunicorn", "server"),
}

# framework detection from dependencies
_FRAMEWORK_MAP: dict[str, str] = {
    "express": "express", "fastify": "fastify", "koa": "koa",
    "next": "next.js", "@nestjs/core": "nest.js", "hapi": "hapi",
    "flask": "flask", "Flask": "flask",
    "django": "django", "Django": "django",
    "fastapi": "fastapi", "FastAPI": "fastapi",
    "tornado": "tornado", "sanic": "sanic",
}


# ---------------------------------------------------------------------------
# data structures
# ---------------------------------------------------------------------------


@dataclass
class TreeNode:
    """a single node in the filesystem tree."""
    path: Path
    name: str
    is_dir: bool
    depth: int
    children: list["TreeNode"] = field(default_factory=list)


@dataclass
class Surface:
    """a detected route or endpoint."""
    method: str
    path: str
    file: str
    line: int


@dataclass
class Service:
    """a detected external service dependency."""
    name: str
    category: str
    evidence: str


@dataclass
class RepoFingerprint:
    """complete fingerprint of a repository."""
    repo_type: str = "unknown"
    framework: str = "unknown"
    package_manager: str = "unknown"
    entry_point: str = "none detected"
    env_files: list[str] = field(default_factory=list)
    surfaces: list[Surface] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    file_count: int = 0
    dir_count: int = 0
    max_depth: int = 0


# ---------------------------------------------------------------------------
# tree construction — recursive dfs
# ---------------------------------------------------------------------------


def _build_tree(path: Path, depth: int = 0) -> TreeNode:
    """
    recursive depth-first traversal of the filesystem.
    builds a tree of TreeNode objects. skips irrelevant directories.
    """
    node = TreeNode(
        path=path,
        name=path.name,
        is_dir=path.is_dir(),
        depth=depth,
    )

    if not node.is_dir:
        return node

    if node.name in SKIP_DIRS:
        return node

    if depth > MAX_DEPTH:
        return node

    try:
        entries = sorted(
            path.iterdir(),
            key=lambda p: (not p.is_dir(), p.name.lower()),
        )
        for entry in entries:
            child = _build_tree(entry, depth + 1)
            node.children.append(child)
    except PermissionError:
        pass
    except OSError:
        pass

    return node


def _flatten(node: TreeNode) -> list[TreeNode]:
    """flatten the tree into a list via recursive pre-order traversal."""
    result = [node]
    for child in node.children:
        result.extend(_flatten(child))
    return result


# ---------------------------------------------------------------------------
# file reading utility
# ---------------------------------------------------------------------------


def _safe_read(path: Path) -> str | None:
    """read a file safely. returns None on any error."""
    try:
        if path.stat().st_size > MAX_SCAN_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None


def _safe_json(path: Path) -> dict | None:
    """read and parse a json file safely."""
    text = _safe_read(path)
    if text is None:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _safe_toml(path: Path) -> dict | None:
    """read and parse a toml file safely."""
    try:
        if path.stat().st_size > MAX_SCAN_BYTES:
            return None
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# fingerprinter
# ---------------------------------------------------------------------------


class Fingerprinter:
    """
    orchestrates all detection passes over the filesystem tree.
    each _detect method is independent — wrapped in try/except
    so a failure in one never blocks the others.
    """

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.tree: TreeNode | None = None
        self.all_nodes: list[TreeNode] = []
        self.fp = RepoFingerprint()
        self._deps: dict[str, Any] = {}

    def run(self) -> RepoFingerprint:
        """execute the full fingerprinting pipeline."""
        out.info(f"target: {self.root}")
        out.info("building filesystem tree...")

        self.tree = _build_tree(self.root)
        self.all_nodes = _flatten(self.tree)

        # basic stats
        files = [n for n in self.all_nodes if not n.is_dir]
        dirs = [n for n in self.all_nodes if n.is_dir]
        self.fp.file_count = len(files)
        self.fp.dir_count = len(dirs)
        self.fp.max_depth = max((n.depth for n in self.all_nodes), default=0)

        out.info(
            f"traversed {self.fp.file_count} files, "
            f"{self.fp.dir_count} directories, "
            f"depth {self.fp.max_depth}"
        )

        # run each detector independently
        self._run_detector("repo type", self._detect_repo_type)
        self._run_detector("package manager", self._detect_package_manager)
        self._run_detector("dependencies", self._detect_dependencies)
        self._run_detector("framework", self._detect_framework)
        self._run_detector("entry point", self._detect_entry_point)
        self._run_detector("environment files", self._detect_env_files)
        self._run_detector("surfaces", self._detect_surfaces)
        self._run_detector("services", self._detect_services)

        return self.fp

    def _run_detector(self, name: str, fn) -> None:
        """run a single detector with error isolation."""
        try:
            fn()
        except Exception as e:
            out.warning(f"{name} detection failed: {e}")

    # -- repo type ---------------------------------------------------------

    def _detect_repo_type(self) -> None:
        root_names = {n.name for n in self.all_nodes if n.depth == 1}
        root_names.add(self.tree.name if self.tree else "")

        # check for root-level indicator files
        has_pkg_json = self._find_file("package.json", max_depth=1) is not None
        has_req_txt = self._find_file("requirements.txt", max_depth=1) is not None
        has_pyproject = self._find_file("pyproject.toml", max_depth=1) is not None
        has_setup_py = self._find_file("setup.py", max_depth=1) is not None
        has_pipfile = self._find_file("Pipfile", max_depth=1) is not None
        has_manage = self._find_file("manage.py", max_depth=1) is not None

        is_node = has_pkg_json
        is_python = has_req_txt or has_pyproject or has_setup_py or has_pipfile or has_manage

        if is_node and is_python:
            self.fp.repo_type = "node+python"
        elif is_node:
            self.fp.repo_type = "node"
        elif is_python:
            self.fp.repo_type = "python"
        else:
            self.fp.repo_type = "unknown"

    # -- package manager ---------------------------------------------------

    def _detect_package_manager(self) -> None:
        checks = [
            ("pnpm-lock.yaml", "pnpm"),
            ("yarn.lock", "yarn"),
            ("bun.lockb", "bun"),
            ("package-lock.json", "npm"),
            ("poetry.lock", "poetry"),
            ("Pipfile.lock", "pipenv"),
            ("requirements.txt", "pip"),
            ("pyproject.toml", "pip"),
        ]
        for filename, manager in checks:
            if self._find_file(filename, max_depth=1) is not None:
                self.fp.package_manager = manager
                return

    # -- dependencies ------------------------------------------------------

    def _detect_dependencies(self) -> None:
        """parse dependency files and store them for framework/service detection."""
        # node — package.json
        pkg_node = self._find_file("package.json", max_depth=1)
        if pkg_node:
            pkg = _safe_json(pkg_node.path)
            if pkg:
                deps = {}
                deps.update(pkg.get("dependencies", {}))
                deps.update(pkg.get("devDependencies", {}))
                self._deps.update(deps)

        # python — requirements.txt
        req_node = self._find_file("requirements.txt", max_depth=1)
        if req_node:
            text = _safe_read(req_node.path)
            if text:
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    name = re.split(r"[>=<!\[;]", line)[0].strip()
                    if name:
                        self._deps[name] = "*"

        # python — pyproject.toml
        pyp_node = self._find_file("pyproject.toml", max_depth=1)
        if pyp_node:
            toml = _safe_toml(pyp_node.path)
            if toml:
                proj_deps = toml.get("project", {}).get("dependencies", [])
                for dep in proj_deps:
                    name = re.split(r"[>=<!\[;]", dep)[0].strip()
                    if name:
                        self._deps[name] = "*"
                poetry_deps = toml.get("tool", {}).get("poetry", {}).get("dependencies", {})
                for name in poetry_deps:
                    self._deps[name] = poetry_deps[name]

        # python — Pipfile
        pip_node = self._find_file("Pipfile", max_depth=1)
        if pip_node:
            toml = _safe_toml(pip_node.path)
            if toml:
                for section in ("packages", "dev-packages"):
                    for name in toml.get(section, {}):
                        self._deps[name] = "*"

    # -- framework ---------------------------------------------------------

    def _detect_framework(self) -> None:
        for dep_name, framework in _FRAMEWORK_MAP.items():
            if dep_name in self._deps:
                self.fp.framework = framework
                return

        # fallback: check for next.js config file
        if self._find_file("next.config.js", max_depth=1) or \
           self._find_file("next.config.mjs", max_depth=1) or \
           self._find_file("next.config.ts", max_depth=1):
            self.fp.framework = "next.js"

    # -- entry point -------------------------------------------------------

    def _detect_entry_point(self) -> None:
        # node: check package.json scripts.start and main field
        pkg_node = self._find_file("package.json", max_depth=1)
        if pkg_node:
            pkg = _safe_json(pkg_node.path)
            if pkg:
                # scripts.start
                start_cmd = pkg.get("scripts", {}).get("start", "")
                if start_cmd:
                    match = re.search(r"(\S+\.(js|ts|mjs|cjs))", start_cmd)
                    if match:
                        candidate = match.group(1)
                        if (self.root / candidate).exists():
                            self.fp.entry_point = candidate
                            return

                # main field
                main = pkg.get("main", "")
                if main and (self.root / main).exists():
                    self.fp.entry_point = main
                    return

        # framework-specific
        if self.fp.framework == "next.js":
            for d in ("pages", "app", "src/pages", "src/app"):
                if (self.root / d).is_dir():
                    self.fp.entry_point = f"{d}/ (next.js app directory)"
                    return

        # fallback: check priority list
        candidates = (
            _PYTHON_ENTRY_NAMES
            if self.fp.repo_type == "python"
            else _NODE_ENTRY_NAMES
        )
        for name in candidates:
            if (self.root / name).exists():
                self.fp.entry_point = name
                return

    # -- environment files -------------------------------------------------

    def _detect_env_files(self) -> None:
        env_patterns = {
            ".env", ".env.example", ".env.sample", ".env.local",
            ".env.development", ".env.production", ".env.test",
            ".env.staging", ".flaskenv",
        }
        for node in self.all_nodes:
            if not node.is_dir and node.name in env_patterns:
                rel = node.path.relative_to(self.root)
                self.fp.env_files.append(str(rel))

    # -- surfaces (routes / endpoints) -------------------------------------

    def _detect_surfaces(self) -> None:
        for node in self.all_nodes:
            if node.is_dir:
                continue

            suffix = node.path.suffix

            # next.js api routes — file path is the route
            rel = str(node.path.relative_to(self.root)).replace("\\", "/")
            if re.match(r"(src/)?(pages|app)/api/", rel) and suffix in NODE_EXTENSIONS:
                route_path = re.sub(r"^(src/)?(pages|app)", "", rel)
                route_path = re.sub(r"\.(js|ts|jsx|tsx|mjs|cjs)$", "", route_path)
                route_path = re.sub(r"/index$", "", route_path) or "/"
                self.fp.surfaces.append(Surface(
                    method="handler",
                    path=route_path,
                    file=rel,
                    line=0,
                ))
                continue

            # scan file contents for route definitions
            if suffix in NODE_EXTENSIONS or suffix in PYTHON_EXTENSIONS:
                self._scan_file_for_routes(node, rel, suffix)

    def _scan_file_for_routes(self, node: TreeNode, rel: str, suffix: str) -> None:
        """scan a single file for route patterns."""
        text = _safe_read(node.path)
        if text is None:
            return

        lines = text.splitlines()

        if suffix in NODE_EXTENSIONS:
            for i, line in enumerate(lines, 1):
                m = _EXPRESS_ROUTE.search(line)
                if m:
                    self.fp.surfaces.append(Surface(
                        method=m.group(1).upper(),
                        path=m.group(2),
                        file=rel,
                        line=i,
                    ))

        if suffix in PYTHON_EXTENSIONS:
            for i, line in enumerate(lines, 1):
                m = _FLASK_ROUTE.search(line)
                if m:
                    self.fp.surfaces.append(Surface(
                        method="ROUTE",
                        path=m.group(1),
                        file=rel,
                        line=i,
                    ))
                    continue

                m = _FASTAPI_ROUTE.search(line)
                if m:
                    self.fp.surfaces.append(Surface(
                        method=m.group(1).upper(),
                        path=m.group(2),
                        file=rel,
                        line=i,
                    ))
                    continue

                m = _DJANGO_PATH.search(line)
                if m:
                    self.fp.surfaces.append(Surface(
                        method="PATH",
                        path=m.group(1),
                        file=rel,
                        line=i,
                    ))

    # -- services ----------------------------------------------------------

    def _detect_services(self) -> None:
        seen = set()
        for dep_name in self._deps:
            lookup = _SERVICE_MAP.get(dep_name)
            if lookup and lookup[0] not in seen:
                svc_name, category = lookup
                seen.add(svc_name)
                self.fp.services.append(Service(
                    name=svc_name,
                    category=category,
                    evidence=f"dependency: {dep_name}",
                ))

    # -- helpers -----------------------------------------------------------

    def _find_file(self, name: str, max_depth: int | None = None) -> TreeNode | None:
        """find the first file with the given name in the tree."""
        for node in self.all_nodes:
            if node.is_dir:
                continue
            if max_depth is not None and node.depth > max_depth:
                continue
            if node.name == name:
                return node
        return None


# ---------------------------------------------------------------------------
# report renderer
# ---------------------------------------------------------------------------


def render_fingerprint(fp: RepoFingerprint) -> None:
    """print the fingerprint report to the terminal."""
    out.console.print()
    out.console.rule("[phase]runtime fingerprint[/phase]")
    out.console.print()

    # summary table
    out.console.print(f"  [info]repository type[/info]     :  {fp.repo_type}")
    out.console.print(f"  [info]framework[/info]          :  {fp.framework}")
    out.console.print(f"  [info]package manager[/info]    :  {fp.package_manager}")
    out.console.print(f"  [info]entry point[/info]        :  {fp.entry_point}")

    # env files
    out.console.print()
    if fp.env_files:
        out.console.print(f"  [info]environment files[/info] ({len(fp.env_files)})")
        for ef in fp.env_files:
            out.muted(f"    {ef}")
    else:
        out.muted("  no environment files detected")

    # surfaces
    out.console.print()
    if fp.surfaces:
        out.console.print(f"  [info]detected surfaces[/info] ({len(fp.surfaces)} routes)")
        for s in fp.surfaces:
            loc = f"{s.file}:{s.line}" if s.line > 0 else s.file
            out.console.print(
                f"    [probe]{s.method:<8}[/probe] {s.path:<30} [muted]{loc}[/muted]"
            )
    else:
        out.muted("  no route surfaces detected")

    # services
    out.console.print()
    if fp.services:
        out.console.print(f"  [info]potential services[/info] ({len(fp.services)})")
        for svc in fp.services:
            out.console.print(
                f"    {svc.name:<20} [muted]{svc.category:<12} {svc.evidence}[/muted]"
            )
    else:
        out.muted("  no external services detected")

    # traversal stats
    out.console.print()
    out.console.rule("[muted]traversal stats[/muted]")
    out.console.print(f"  files scanned       :  {fp.file_count}")
    out.console.print(f"  directories         :  {fp.dir_count}")
    out.console.print(f"  tree depth          :  {fp.max_depth}")
    out.console.print()
