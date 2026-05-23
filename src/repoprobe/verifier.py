"""
behavioral verification for repoprobe.

the first real verification primitive: determinism analysis.
hits candidate endpoints with randomized inputs multiple times,
compares response fingerprints, and flags invariant behavior.

if an endpoint returns the same response for wildly different
inputs, that's suspicious and gets flagged.

no gemini. no retries. hard runtime evidence only.
gemini should eventually interpret evidence, not generate it.
"""

import hashlib
import random
import string
import uuid
from dataclasses import dataclass, field

import httpx

from repoprobe.probe import RuntimeSurface, ProbeResult
from repoprobe import console as out


# keywords that identify candidate endpoints worth verifying
_AUTH_KEYWORDS = {"auth", "login", "signin", "sign-in", "signup", "sign-up", "register", "token", "session"}
_PAYMENT_KEYWORDS = {"payment", "checkout", "charge", "pay", "billing", "subscribe", "order"}
_SEARCH_KEYWORDS = {"search", "find", "query", "lookup"}
_GENERATE_KEYWORDS = {"chat", "message", "generate", "ai", "completion", "predict", "infer"}
_DATA_KEYWORDS = {"user", "users", "profile", "account", "data", "item", "items", "product", "products"}

# keywords that should be skipped
_SKIP_KEYWORDS = {"health", "healthz", "docs", "swagger", "favicon", "static", "assets", "graphql", "admin", "openapi"}

# how many randomized probes per endpoint
PROBE_RUNS = 5

# request timeout
_TIMEOUT = 5.0


@dataclass
class ProbeRun:
    """a single probe run with a specific payload."""
    run_number: int
    status: int | None = None
    response_hash: str = ""
    content_length: int = 0
    payload: dict = field(default_factory=dict)
    error: str | None = None


@dataclass
class EndpointVerdict:
    """verification result for a single endpoint."""
    route: str
    method: str
    category: str  # invariant, variant, mixed, error, skipped
    runs: list[ProbeRun] = field(default_factory=list)
    unique_hashes: int = 0
    unique_statuses: int = 0
    suspicious: bool = False
    reason: str = ""


@dataclass
class VerificationResult:
    """complete behavioral verification result."""
    verdicts: list[EndpointVerdict] = field(default_factory=list)
    total_verified: int = 0
    suspicious_count: int = 0
    clean_count: int = 0
    skipped_count: int = 0

    @property
    def suspicious_endpoints(self) -> list[EndpointVerdict]:
        return [v for v in self.verdicts if v.suspicious]


# -- payload generators

def _random_email() -> str:
    name = "".join(random.choices(string.ascii_lowercase, k=8))
    domain = random.choice(["test.com", "example.org", "fake.io", "mail.dev"])
    return f"{name}@{domain}"


def _random_string(length: int = 12) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(random.choices(chars, k=length))


def _random_password() -> str:
    return _random_string(16)


def _random_int(low: int = 1, high: int = 9999) -> int:
    return random.randint(low, high)


def _auth_payload() -> dict:
    return {
        "email": _random_email(),
        "password": _random_password(),
        "username": _random_string(8),
    }


def _payment_payload() -> dict:
    return {
        "amount": _random_int(100, 50000),
        "currency": random.choice(["usd", "eur", "gbp", "inr"]),
        "token": f"tok_{uuid.uuid4().hex[:16]}",
    }


def _search_payload() -> dict:
    words = ["python", "javascript", "react", "machine learning", "api",
             "database", "server", "deploy", "testing", "performance"]
    return {
        "query": random.choice(words),
        "q": random.choice(words),
    }


def _generate_payload() -> dict:
    prompts = [
        "explain recursion",
        "write a haiku about code",
        "what is a database",
        "how does http work",
        "describe the weather today",
    ]
    return {
        "message": random.choice(prompts),
        "prompt": random.choice(prompts),
        "input": _random_string(20),
    }


def _data_payload() -> dict:
    return {
        "name": _random_string(10),
        "email": _random_email(),
        "id": _random_int(1, 10000),
    }


def _generic_payload() -> dict:
    return {
        "input": _random_string(15),
        "value": _random_int(),
        "key": uuid.uuid4().hex[:8],
    }


def _hash_body(body: bytes) -> str:
    return hashlib.md5(body).hexdigest()[:12]


def _classify_route(path: str) -> str | None:
    """determine what kind of endpoint this is based on path keywords."""
    lower = path.lower()

    # skip known non-interesting endpoints
    for kw in _SKIP_KEYWORDS:
        if kw in lower:
            return None

    for kw in _AUTH_KEYWORDS:
        if kw in lower:
            return "auth"
    for kw in _PAYMENT_KEYWORDS:
        if kw in lower:
            return "payment"
    for kw in _SEARCH_KEYWORDS:
        if kw in lower:
            return "search"
    for kw in _GENERATE_KEYWORDS:
        if kw in lower:
            return "generate"
    for kw in _DATA_KEYWORDS:
        if kw in lower:
            return "data"

    return None


def _get_payload_fn(route_type: str):
    """return the appropriate payload generator for a route type."""
    return {
        "auth": _auth_payload,
        "payment": _payment_payload,
        "search": _search_payload,
        "generate": _generate_payload,
        "data": _data_payload,
    }.get(route_type, _generic_payload)


class BehavioralVerifier:
    """
    executes determinism analysis against candidate endpoints.
    hits each with randomized inputs, compares response fingerprints,
    flags invariant behavior as suspicious.
    """

    def __init__(self, base_url: str, probe_result: ProbeResult) -> None:
        self.base_url = base_url
        self.probe_result = probe_result
        self.result = VerificationResult()

    def verify(self) -> VerificationResult:
        """run behavioral verification on all candidate endpoints."""
        out.console.print()
        out.info("running behavioral verification...")
        out.console.print()

        candidates = self._select_candidates()

        if not candidates:
            out.muted("  no candidate endpoints for behavioral verification")
            return self.result

        out.info(f"selected {len(candidates)} candidate endpoints")
        out.console.print()

        for surface, route_type in candidates:
            verdict = self._verify_endpoint(surface, route_type)
            self.result.verdicts.append(verdict)
            self.result.total_verified += 1

            if verdict.suspicious:
                self.result.suspicious_count += 1
            elif verdict.category not in ("error", "skipped"):
                self.result.clean_count += 1

        return self.result

    def _select_candidates(self) -> list[tuple[RuntimeSurface, str]]:
        """select endpoints worth verifying based on route keywords."""
        candidates = []
        seen_routes = set()

        for surface in self.probe_result.surfaces:
            # skip non-reachable surfaces
            if not surface.reachable:
                continue

            # skip already seen routes
            if surface.route in seen_routes:
                continue
            seen_routes.add(surface.route)

            route_type = _classify_route(surface.route)
            if route_type:
                candidates.append((surface, route_type))

        return candidates

    def _verify_endpoint(self, surface: RuntimeSurface, route_type: str) -> EndpointVerdict:
        """run determinism analysis on a single endpoint."""
        verdict = EndpointVerdict(
            route=surface.route,
            method=surface.method,
            category="unknown",
        )

        payload_fn = _get_payload_fn(route_type)

        # for GET endpoints, use query params. for POST, use json body.
        # if the surface was detected as GET but it's an auth/payment endpoint,
        # try POST since that's more realistic.
        method = surface.method
        if route_type in ("auth", "payment", "data") and method == "GET":
            method = "POST"

        out.console.print(f"  [phase][verify][/phase] {method} {surface.route}")

        # execute randomized probes
        for i in range(1, PROBE_RUNS + 1):
            payload = payload_fn()
            run = self._execute_probe(method, surface.route, payload, i)
            verdict.runs.append(run)

            # print each run
            if run.error:
                out.muted(f"    run #{i} -> error: {run.error}")
            else:
                out.muted(
                    f"    run #{i} -> {run.status}  "
                    f"hash: {run.response_hash}  "
                    f"{run.content_length}b"
                )

        # analyze results
        self._analyze_verdict(verdict)

        # print verdict
        out.console.print()
        if verdict.suspicious:
            out.console.print(
                f"  [warning]-- {verdict.reason}[/warning]"
            )
        else:
            out.console.print(
                f"  [success]-- {verdict.reason}[/success]"
            )
        out.console.print()

        return verdict

    def _execute_probe(self, method: str, path: str, payload: dict, run_number: int) -> ProbeRun:
        """execute a single probe with a given payload."""
        url = f"{self.base_url}{path}"
        run = ProbeRun(run_number=run_number, payload=payload)

        try:
            if method.upper() in ("GET", "HEAD", "OPTIONS"):
                response = httpx.request(
                    method,
                    url,
                    params=payload,
                    timeout=_TIMEOUT,
                    follow_redirects=False,
                )
            else:
                response = httpx.request(
                    method,
                    url,
                    json=payload,
                    timeout=_TIMEOUT,
                    follow_redirects=False,
                )

            run.status = response.status_code
            run.content_length = len(response.content)
            run.response_hash = _hash_body(response.content)

        except httpx.ConnectError:
            run.error = "connection refused"
        except httpx.TimeoutException:
            run.error = "timeout"
        except Exception as e:
            run.error = str(e)

        return run

    def _analyze_verdict(self, verdict: EndpointVerdict) -> None:
        """analyze probe runs and determine the verdict."""
        successful_runs = [r for r in verdict.runs if r.error is None]

        if not successful_runs:
            verdict.category = "error"
            verdict.reason = "all probe runs failed"
            return

        if len(successful_runs) < 2:
            verdict.category = "insufficient"
            verdict.reason = "not enough successful runs to analyze"
            return

        # collect unique values
        hashes = {r.response_hash for r in successful_runs}
        statuses = {r.status for r in successful_runs}
        lengths = {r.content_length for r in successful_runs}

        verdict.unique_hashes = len(hashes)
        verdict.unique_statuses = len(statuses)

        # determinism analysis
        if len(hashes) == 1 and len(statuses) == 1:
            # every response is byte-identical
            verdict.category = "invariant"
            verdict.suspicious = True
            verdict.reason = (
                f"invariant response detected: "
                f"{len(successful_runs)} identical responses "
                f"(hash: {list(hashes)[0]}, status: {list(statuses)[0]})"
            )
        elif len(statuses) == 1 and len(hashes) > 1:
            # same status but different bodies — expected behavior
            verdict.category = "variant"
            verdict.suspicious = False
            verdict.reason = (
                f"variant responses: {len(hashes)} unique response bodies "
                f"across {len(successful_runs)} runs (status: {list(statuses)[0]})"
            )
        elif len(statuses) > 1:
            # different status codes — could be interesting
            status_list = ", ".join(str(s) for s in sorted(statuses))
            verdict.category = "mixed"
            verdict.suspicious = False
            verdict.reason = (
                f"mixed status codes: {status_list} "
                f"across {len(successful_runs)} runs"
            )
        else:
            verdict.category = "clean"
            verdict.suspicious = False
            verdict.reason = "behavior appears consistent with expectations"


def render_verification(result: VerificationResult) -> None:
    """print the behavioral verification summary."""
    out.console.print()
    out.console.rule("[phase]behavioral verification[/phase]")
    out.console.print()

    out.console.print(
        f"  [info]endpoints verified[/info] :  {result.total_verified}"
    )
    out.console.print(
        f"  [info]clean[/info]              :  {result.clean_count}"
    )

    if result.suspicious_count > 0:
        out.console.print(
            f"  [warning]suspicious[/warning]          :  "
            f"[warning]{result.suspicious_count}[/warning]"
        )
    else:
        out.console.print(
            f"  [info]suspicious[/info]          :  0"
        )

    # detail suspicious endpoints
    suspicious = result.suspicious_endpoints
    if suspicious:
        out.console.print()
        out.console.print("  [warning]flagged endpoints[/warning]")
        for v in suspicious:
            out.console.print(
                f"    [warning]--[/warning] {v.method} {v.route}"
            )
            out.console.print(
                f"       {v.reason}"
            )
            out.console.print(
                f"       [muted]{v.unique_hashes} unique hashes, "
                f"{v.unique_statuses} unique statuses, "
                f"{len(v.runs)} runs[/muted]"
            )

    out.console.print()
