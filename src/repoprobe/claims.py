"""
claim extraction and contradiction detection for repoprobe.

this is the core thesis layer:
  claimed reality vs observed reality.

reads the readme, extracts claims about what the software does,
then cross-references against runtime evidence to detect
behavioral contradictions.

no gemini. no embeddings. no vector search.
pure deterministic keyword extraction + rule-based contradiction logic.
hard evidence first — gemini interprets later, never generates.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

from repoprobe.probe import ProbeResult, RuntimeSurface
from repoprobe.verifier import VerificationResult, EndpointVerdict
from repoprobe.fingerprint import RepoFingerprint
from repoprobe.runner import RunResult, RuntimeStatus
from repoprobe import console as out


# -- claim category keyword maps

_AUTH_KEYWORDS = [
    "jwt", "authentication", "auth", "oauth", "login", "signup",
    "sign-in", "sign-up", "session", "authorization", "token",
    "credentials", "password", "bcrypt", "passport", "cookie",
    "access control", "role-based", "rbac", "2fa", "mfa",
    "two-factor", "multi-factor",
]

_PAYMENT_KEYWORDS = [
    "stripe", "payment", "billing", "subscription", "checkout",
    "razorpay", "paypal", "invoice", "charge", "pricing",
    "plan", "tier", "premium",
]

_API_KEYWORDS = [
    "rest api", "restful", "api endpoint", "graphql", "grpc",
    "route", "routes", "endpoint", "endpoints", "crud",
    "request", "response", "http",
]

_DATABASE_KEYWORDS = [
    "postgresql", "postgres", "mongodb", "redis", "mysql",
    "sqlite", "database", "prisma", "sequelize", "typeorm",
    "mongoose", "knex", "drizzle", "sql", "nosql", "orm",
    "migration",
]

_PRODUCTION_KEYWORDS = [
    "production ready", "production-ready", "enterprise",
    "scalable", "production grade", "production-grade",
    "battle tested", "battle-tested", "high availability",
    "fault tolerant", "reliable", "robust", "stable",
    "deployed", "deployment",
]

_SECURITY_KEYWORDS = [
    "secure", "security", "encryption", "encrypted", "https",
    "cors", "rate limit", "rate-limit", "csrf", "xss",
    "sanitize", "validate", "helmet", "ssl", "tls",
]

_AI_KEYWORDS = [
    "ai", "artificial intelligence", "machine learning", "ml",
    "model", "inference", "gpt", "llm", "openai", "gemini",
    "neural", "deep learning", "training", "prediction",
    "nlp", "computer vision", "transformer",
]

_CATEGORY_MAP = {
    "auth": _AUTH_KEYWORDS,
    "payment": _PAYMENT_KEYWORDS,
    "api": _API_KEYWORDS,
    "database": _DATABASE_KEYWORDS,
    "production": _PRODUCTION_KEYWORDS,
    "security": _SECURITY_KEYWORDS,
    "ai": _AI_KEYWORDS,
}


# -- data structures

@dataclass
class Claim:
    """a single claim extracted from the readme."""
    text: str
    category: str
    keyword_matched: str
    source_line: int = 0


@dataclass
class Contradiction:
    """a detected contradiction between claim and runtime evidence."""
    claim: Claim
    evidence: list[str]
    severity: str  # critical, high, medium, low
    explanation: str


@dataclass
class ContradictionReport:
    """complete claim-vs-reality analysis."""
    claims: list[Claim] = field(default_factory=list)
    contradictions: list[Contradiction] = field(default_factory=list)
    readme_found: bool = False
    readme_path: str = ""

    @property
    def critical(self) -> list[Contradiction]:
        return [c for c in self.contradictions if c.severity == "critical"]

    @property
    def high(self) -> list[Contradiction]:
        return [c for c in self.contradictions if c.severity == "high"]


# -- claim extractor

class ClaimExtractor:
    """
    extracts verifiable claims from a readme file.
    uses keyword matching on sentences/bullet points.
    no llm, no embeddings — deterministic only.
    """

    # readme filename patterns
    _README_NAMES = [
        "README.md", "readme.md", "Readme.md",
        "README", "README.rst", "README.txt",
    ]

    def __init__(self, repo_root: Path) -> None:
        self.root = repo_root
        self.readme_path: Path | None = None
        self.readme_content: str = ""

    def extract(self) -> list[Claim]:
        """find and parse the readme, extract claims."""
        self.readme_path = self._find_readme()
        if not self.readme_path:
            return []

        self.readme_content = self.readme_path.read_text(
            encoding="utf-8", errors="ignore"
        )

        claims: list[Claim] = []
        lines = self.readme_content.splitlines()

        for line_num, line in enumerate(lines, 1):
            # clean markdown formatting
            clean = self._strip_markdown(line).strip()
            if not clean or len(clean) < 5:
                continue

            # check each category
            lower = clean.lower()
            for category, keywords in _CATEGORY_MAP.items():
                for keyword in keywords:
                    if keyword in lower:
                        # avoid duplicate claims for the same line
                        if not any(c.source_line == line_num and c.category == category for c in claims):
                            claims.append(Claim(
                                text=clean,
                                category=category,
                                keyword_matched=keyword,
                                source_line=line_num,
                            ))
                        break

        return claims

    def _find_readme(self) -> Path | None:
        """locate the readme file in the repo root."""
        for name in self._README_NAMES:
            path = self.root / name
            if path.exists() and path.is_file():
                return path
        return None

    @staticmethod
    def _strip_markdown(line: str) -> str:
        """strip common markdown formatting from a line."""
        # remove headers
        line = re.sub(r"^#{1,6}\s+", "", line)
        # remove bold/italic
        line = re.sub(r"\*{1,3}([^*]+)\*{1,3}", r"\1", line)
        line = re.sub(r"_{1,3}([^_]+)_{1,3}", r"\1", line)
        # remove inline code
        line = re.sub(r"`([^`]+)`", r"\1", line)
        # remove links
        line = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", line)
        # remove list markers
        line = re.sub(r"^[\s]*[-*+]\s+", "", line)
        # remove numbered lists
        line = re.sub(r"^[\s]*\d+\.\s+", "", line)
        return line


# -- contradiction engine

class ContradictionEngine:
    """
    compares extracted claims against runtime evidence.
    uses deterministic rule-based logic to detect contradictions.
    no llm — just hard boolean rules against hard runtime data.
    """

    def __init__(
        self,
        claims: list[Claim],
        probe_result: ProbeResult | None,
        verification_result: VerificationResult | None,
        fingerprint: RepoFingerprint | None = None,
        run_result: RunResult | None = None,
    ) -> None:
        self.claims = claims
        self.probe = probe_result
        self.verification = verification_result
        self.fingerprint = fingerprint
        self.run_result = run_result

    def analyze(self) -> list[Contradiction]:
        """run all contradiction rules against all claims."""
        contradictions: list[Contradiction] = []

        for claim in self.claims:
            result = self._check_claim(claim)
            if result:
                contradictions.append(result)

        return contradictions

    def _check_claim(self, claim: Claim) -> Contradiction | None:
        """dispatch to the appropriate rule checker based on category."""
        checkers = {
            "auth": self._check_auth,
            "payment": self._check_payment,
            "api": self._check_api,
            "database": self._check_database,
            "production": self._check_production,
            "security": self._check_security,
            "ai": self._check_ai,
        }

        checker = checkers.get(claim.category)
        if checker:
            return checker(claim)
        return None

    # -- rule: auth claims

    def _check_auth(self, claim: Claim) -> Contradiction | None:
        """check auth claims against runtime evidence."""
        evidence = []

        # check if auth endpoints show invariant behavior
        invariant_auth = self._get_invariant_endpoints(
            ["auth", "login", "signin", "signup", "register", "token", "session"]
        )
        if invariant_auth:
            for ep in invariant_auth:
                evidence.append(
                    f"endpoint {ep.method} {ep.route} returned identical responses "
                    f"across {len(ep.runs)} randomized credential probes"
                )

        # check if auth-like routes return 500
        error_auth = self._get_error_routes(
            ["auth", "login", "signin", "signup", "register", "token", "session"]
        )
        if error_auth:
            for s in error_auth:
                evidence.append(
                    f"endpoint {s.method} {s.route} returns {s.status} server error"
                )

        # check if no auth endpoints exist at all
        auth_surfaces = self._get_surfaces_matching(
            ["auth", "login", "signin", "signup", "register", "token"]
        )
        if not auth_surfaces and not invariant_auth:
            evidence.append(
                "no authentication endpoints were discovered at runtime"
            )

        if evidence:
            return Contradiction(
                claim=claim,
                evidence=evidence,
                severity="critical" if invariant_auth else "high",
                explanation=(
                    "observed behavior is inconsistent with claimed "
                    "authentication functionality"
                ),
            )
        return None

    # -- rule: payment claims

    def _check_payment(self, claim: Claim) -> Contradiction | None:
        """check payment claims against runtime evidence."""
        evidence = []

        invariant = self._get_invariant_endpoints(
            ["payment", "checkout", "charge", "pay", "billing", "subscribe"]
        )
        if invariant:
            for ep in invariant:
                evidence.append(
                    f"endpoint {ep.method} {ep.route} returned identical responses "
                    f"across {len(ep.runs)} randomized payment probes"
                )

        errors = self._get_error_routes(
            ["payment", "checkout", "charge", "pay", "billing"]
        )
        if errors:
            for s in errors:
                evidence.append(
                    f"endpoint {s.method} {s.route} returns {s.status} server error"
                )

        surfaces = self._get_surfaces_matching(
            ["payment", "checkout", "charge", "pay", "billing"]
        )
        if not surfaces and not invariant:
            evidence.append(
                "no payment endpoints were discovered at runtime"
            )

        if evidence:
            return Contradiction(
                claim=claim,
                evidence=evidence,
                severity="critical" if invariant else "high",
                explanation=(
                    "observed behavior is inconsistent with claimed "
                    "payment processing functionality"
                ),
            )
        return None

    # -- rule: api claims

    def _check_api(self, claim: Claim) -> Contradiction | None:
        """check api claims against runtime evidence."""
        evidence = []

        if self.probe:
            if self.probe.reachable_count == 0:
                evidence.append(
                    "no reachable api surfaces were discovered at runtime"
                )

            # all routes returning same error
            if self.probe.reachable_count > 0:
                error_count = len(self.probe.server_errors)
                total = self.probe.reachable_count
                if error_count == total:
                    evidence.append(
                        f"all {total} reachable endpoints return server errors"
                    )

        if evidence:
            return Contradiction(
                claim=claim,
                evidence=evidence,
                severity="high",
                explanation=(
                    "observed runtime behavior does not match "
                    "claimed api functionality"
                ),
            )
        return None

    # -- rule: database claims

    def _check_database(self, claim: Claim) -> Contradiction | None:
        """check database claims against runtime evidence."""
        evidence = []

        if self.fingerprint:
            # check if claimed database service is in detected services
            lower_claim = claim.keyword_matched.lower()
            detected_lower = [s.lower() for s in self.fingerprint.services]

            # map keywords to service names
            db_service_map = {
                "postgresql": "postgresql", "postgres": "postgresql",
                "mongodb": "mongodb", "mongoose": "mongodb",
                "redis": "redis",
                "mysql": "mysql",
                "sqlite": "sqlite",
            }

            claimed_service = db_service_map.get(lower_claim)
            if claimed_service and claimed_service not in detected_lower:
                if not detected_lower:
                    evidence.append(
                        "no database services were detected in the codebase"
                    )

        # check if boot crashed (possibly due to missing db connection)
        if self.run_result and self.run_result.status == RuntimeStatus.CRASHED:
            evidence.append(
                "application crashed at startup — possibly missing "
                "database connection or configuration"
            )

        if evidence:
            return Contradiction(
                claim=claim,
                evidence=evidence,
                severity="medium",
                explanation=(
                    "runtime evidence suggests claimed database "
                    "integration may not be functional"
                ),
            )
        return None

    # -- rule: production claims

    def _check_production(self, claim: Claim) -> Contradiction | None:
        """check production readiness claims against runtime evidence."""
        evidence = []

        # crashed on boot
        if self.run_result and self.run_result.status == RuntimeStatus.CRASHED:
            evidence.append(
                "application crashed on startup"
            )

        # high error rate
        if self.probe and self.probe.reachable_count > 0:
            error_count = len(self.probe.server_errors)
            total = self.probe.reachable_count
            error_rate = error_count / total if total else 0

            if error_rate >= 0.5:
                evidence.append(
                    f"{error_count}/{total} endpoints return server errors "
                    f"({error_rate:.0%} error rate)"
                )

        # invariant behavior detected
        if self.verification and self.verification.suspicious_count > 0:
            evidence.append(
                f"{self.verification.suspicious_count} endpoints show "
                f"suspicious invariant behavior"
            )

        if evidence:
            return Contradiction(
                claim=claim,
                evidence=evidence,
                severity="critical" if len(evidence) >= 2 else "high",
                explanation=(
                    "observed runtime behavior does not meet "
                    "claimed production readiness standards"
                ),
            )
        return None

    # -- rule: security claims

    def _check_security(self, claim: Claim) -> Contradiction | None:
        """check security claims against runtime evidence."""
        evidence = []

        invariant_auth = self._get_invariant_endpoints(
            ["auth", "login", "token", "session"]
        )
        if invariant_auth:
            evidence.append(
                "authentication endpoints show invariant behavior — "
                "identical responses for different credentials"
            )

        if evidence:
            return Contradiction(
                claim=claim,
                evidence=evidence,
                severity="critical",
                explanation=(
                    "observed behavior contradicts claimed security properties"
                ),
            )
        return None

    # -- rule: ai claims

    def _check_ai(self, claim: Claim) -> Contradiction | None:
        """check ai/ml claims against runtime evidence."""
        evidence = []

        invariant_ai = self._get_invariant_endpoints(
            ["ai", "generate", "predict", "infer", "chat", "completion", "model"]
        )
        if invariant_ai:
            for ep in invariant_ai:
                evidence.append(
                    f"endpoint {ep.method} {ep.route} returned identical responses "
                    f"for different inputs — no evidence of model inference"
                )

        if evidence:
            return Contradiction(
                claim=claim,
                evidence=evidence,
                severity="high",
                explanation=(
                    "observed behavior is inconsistent with claimed "
                    "ai/ml functionality"
                ),
            )
        return None

    # -- helpers

    def _get_invariant_endpoints(self, keywords: list[str]) -> list[EndpointVerdict]:
        """find invariant verdicts matching any of the keywords."""
        if not self.verification:
            return []
        results = []
        for verdict in self.verification.verdicts:
            if verdict.category != "invariant":
                continue
            lower = verdict.route.lower()
            if any(kw in lower for kw in keywords):
                results.append(verdict)
        return results

    def _get_error_routes(self, keywords: list[str]) -> list[RuntimeSurface]:
        """find surfaces with server errors matching keywords."""
        if not self.probe:
            return []
        results = []
        for surface in self.probe.surfaces:
            if surface.category != "server_error":
                continue
            lower = surface.route.lower()
            if any(kw in lower for kw in keywords):
                results.append(surface)
        return results

    def _get_surfaces_matching(self, keywords: list[str]) -> list[RuntimeSurface]:
        """find any surfaces matching keywords."""
        if not self.probe:
            return []
        results = []
        for surface in self.probe.surfaces:
            lower = surface.route.lower()
            if any(kw in lower for kw in keywords):
                results.append(surface)
        return results


# -- rendering

def render_contradictions(report: ContradictionReport) -> None:
    """print the claim contradiction analysis."""
    out.console.print()
    out.console.rule("[phase]claim contradiction analysis[/phase]")
    out.console.print()

    if not report.readme_found:
        out.warning("no readme file found — skipping claim analysis")
        return

    out.console.print(
        f"  [info]readme[/info]             :  {report.readme_path}"
    )
    out.console.print(
        f"  [info]claims extracted[/info]    :  {len(report.claims)}"
    )

    if report.claims:
        # group claims by category
        categories = {}
        for c in report.claims:
            categories.setdefault(c.category, []).append(c)

        out.console.print()
        out.console.print("  [info]claim categories[/info]")
        for cat, items in sorted(categories.items()):
            out.console.print(
                f"    {cat:<16} {len(items)} claims"
            )

    out.console.print()

    if not report.contradictions:
        out.success("no contradictions detected")
        return

    out.console.print(
        f"  [warning]contradictions[/warning]     :  "
        f"[warning]{len(report.contradictions)}[/warning]"
    )
    out.console.print()

    # render each contradiction
    for i, contradiction in enumerate(report.contradictions, 1):
        severity_style = {
            "critical": "error",
            "high": "warning",
            "medium": "info",
            "low": "muted",
        }.get(contradiction.severity, "muted")

        out.console.print(
            f"  [{severity_style}]--- contradiction #{i} "
            f"[{contradiction.severity}][/{severity_style}]"
        )
        out.console.print()
        out.console.print(
            f"    [info]claim:[/info] \"{contradiction.claim.text}\""
        )
        out.console.print(
            f"    [muted]category: {contradiction.claim.category} | "
            f"keyword: {contradiction.claim.keyword_matched} | "
            f"line: {contradiction.claim.source_line}[/muted]"
        )
        out.console.print()
        out.console.print(f"    [info]runtime evidence:[/info]")
        for ev in contradiction.evidence:
            out.console.print(f"      - {ev}")
        out.console.print()
        out.console.print(
            f"    [{severity_style}]{contradiction.explanation}[/{severity_style}]"
        )
        out.console.print()
