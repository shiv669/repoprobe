"""
runtime surface discovery for repoprobe.

after the application boots, this module probes the actual
running server to discover what is reachable at runtime.

uses httpx sync client for simplicity — no async needed here
since the app is already running as a separate process.

no gemini. no retries. deterministic probing only.
"""

import hashlib
from dataclasses import dataclass, field

import httpx

from repoprobe.planner import ExecutionPlan
from repoprobe import console as out


# common routes to discover even if not in fingerprint
_COMMON_ROUTES = [
    ("GET", "/"),
    ("GET", "/health"),
    ("GET", "/healthz"),
    ("GET", "/api"),
    ("GET", "/api/v1"),
    ("GET", "/docs"),
    ("GET", "/swagger"),
    ("GET", "/graphql"),
    ("GET", "/admin"),
    ("GET", "/favicon.ico"),
]

# request timeout per route
_PROBE_TIMEOUT = 5.0


@dataclass
class RuntimeSurface:
    """a single probed runtime surface."""
    route: str
    method: str
    status: int | None = None
    reachable: bool = False
    category: str = "unknown"
    content_length: int = 0
    content_type: str = ""
    response_hash: str = ""
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class ProbeResult:
    """complete result of runtime surface discovery."""
    surfaces: list[RuntimeSurface] = field(default_factory=list)
    reachable_count: int = 0
    total_probed: int = 0
    base_url: str = ""

    @property
    def reachable_surfaces(self) -> list[RuntimeSurface]:
        return [s for s in self.surfaces if s.reachable]

    @property
    def auth_gated(self) -> list[RuntimeSurface]:
        return [s for s in self.surfaces if s.category == "auth_gated"]

    @property
    def server_errors(self) -> list[RuntimeSurface]:
        return [s for s in self.surfaces if s.category == "server_error"]


def _classify(status: int) -> tuple[bool, str]:
    """classify an http status into reachability and category."""
    if 200 <= status <= 299:
        return True, "reachable"
    if status in (301, 302, 307, 308):
        return True, "redirect"
    if status in (401, 403):
        return True, "auth_gated"
    if status == 404:
        return False, "not_found"
    if status >= 500:
        return True, "server_error"
    # anything else (4xx)
    return True, "client_error"


def _hash_body(body: bytes) -> str:
    """short md5 hash of response body for fingerprinting."""
    return hashlib.md5(body).hexdigest()[:12]


class RuntimeProbe:
    """
    probes a running application to discover reachable surfaces.
    each route probe is independent — one failure never blocks others.
    """

    def __init__(self, plan: ExecutionPlan, port: int | None = None) -> None:
        self.port = port or plan.expected_port or 3000
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.plan = plan
        self.result = ProbeResult(base_url=self.base_url)

    def probe(self) -> ProbeResult:
        """run all route probes and return the result."""
        out.console.print()
        out.info(f"probing runtime surfaces at {self.base_url} ...")
        out.console.print()

        # collect unique routes to probe
        routes = self._build_route_list()

        # probe each route
        seen = set()
        for method, path in routes:
            key = f"{method} {path}"
            if key in seen:
                continue
            seen.add(key)

            surface = self._probe_route(method, path)
            self.result.surfaces.append(surface)
            self.result.total_probed += 1
            if surface.reachable:
                self.result.reachable_count += 1

        return self.result

    def _build_route_list(self) -> list[tuple[str, str]]:
        """merge fingerprinted routes with common discovery routes."""
        routes: list[tuple[str, str]] = []

        # add fingerprinted routes first
        for route_str in self.plan.detected_routes:
            parts = route_str.split(" ", 1)
            if len(parts) == 2:
                method, path = parts
                # normalize method for http request
                method = method.upper()
                if method in ("HANDLER", "ROUTE", "PATH"):
                    method = "GET"
                # ensure path starts with /
                if not path.startswith("/"):
                    path = f"/{path}"
                routes.append((method, path))

        # add common discovery routes
        routes.extend(_COMMON_ROUTES)

        return routes

    def _probe_route(self, method: str, path: str) -> RuntimeSurface:
        """probe a single route. never raises."""
        url = f"{self.base_url}{path}"
        surface = RuntimeSurface(route=path, method=method)

        try:
            response = httpx.request(
                method,
                url,
                timeout=_PROBE_TIMEOUT,
                follow_redirects=False,
            )

            surface.status = response.status_code
            surface.reachable, surface.category = _classify(response.status_code)
            surface.content_length = len(response.content)
            surface.content_type = response.headers.get("content-type", "")
            surface.response_hash = _hash_body(response.content)
            surface.headers = dict(response.headers)

            # print result
            self._print_surface(surface)

        except httpx.ConnectError:
            surface.category = "refused"
            out.muted(f"    {method:<6} {path:<30} refused")

        except httpx.TimeoutException:
            surface.category = "timeout"
            out.muted(f"    {method:<6} {path:<30} timeout")

        except Exception as e:
            surface.category = "error"
            out.muted(f"    {method:<6} {path:<30} error: {e}")

        return surface

    def _print_surface(self, s: RuntimeSurface) -> None:
        """print a single probed surface result."""
        status = s.status or 0
        if s.category == "reachable":
            out.console.print(
                f"  [success]+[/success] {s.method:<6} {s.route:<30} "
                f"[success]{status}[/success]  "
                f"[muted]{s.content_length}b  {s.content_type[:30]}[/muted]"
            )
        elif s.category == "auth_gated":
            out.console.print(
                f"  [warning]~[/warning] {s.method:<6} {s.route:<30} "
                f"[warning]{status}[/warning]  "
                f"[muted]auth gated[/muted]"
            )
        elif s.category == "redirect":
            location = s.headers.get("location", "")
            out.console.print(
                f"  [info]>[/info] {s.method:<6} {s.route:<30} "
                f"[info]{status}[/info]  "
                f"[muted]-> {location[:40]}[/muted]"
            )
        elif s.category == "server_error":
            out.console.print(
                f"  [error]![/error] {s.method:<6} {s.route:<30} "
                f"[error]{status}[/error]  "
                f"[muted]server error[/muted]"
            )
        elif s.category == "not_found":
            out.muted(
                f"    {s.method:<6} {s.route:<30} {status}  not found"
            )
        else:
            out.muted(
                f"    {s.method:<6} {s.route:<30} {status}  {s.category}"
            )


def render_probe_result(result: ProbeResult) -> None:
    """print the probe summary."""
    out.console.print()
    out.console.rule("[phase]surface discovery[/phase]")
    out.console.print()

    out.console.print(
        f"  [info]base url[/info]          :  {result.base_url}"
    )
    out.console.print(
        f"  [info]total probed[/info]      :  {result.total_probed}"
    )
    out.console.print(
        f"  [info]reachable[/info]         :  {result.reachable_count}"
    )

    auth = result.auth_gated
    if auth:
        out.console.print(
            f"  [info]auth gated[/info]        :  {len(auth)}"
        )

    errors = result.server_errors
    if errors:
        out.console.print(
            f"  [info]server errors[/info]     :  {len(errors)}"
        )

    # list reachable surfaces with response hashes
    reachable = result.reachable_surfaces
    if reachable:
        out.console.print()
        out.console.print("  [info]reachable surfaces[/info]")
        for s in reachable:
            out.console.print(
                f"    {s.method:<6} {s.route:<30} "
                f"[muted]{s.status}  hash:{s.response_hash}  "
                f"{s.content_length}b[/muted]"
            )

    out.console.print()
