"""
claim extraction and contradiction detection for repoprobe.

this is the core thesis layer:
  claimed reality vs observed reality.

reads the readme, extracts claims about what the software does,
then cross-references against runtime evidence to detect
behavioral contradictions.

PRECISION FIRST — only high-confidence claims generate contradictions.
noisy keyword matches (urls, setup docs, shell commands) are filtered.
contradictions are deduplicated by evidence type.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

from repoprobe.probe import ProbeResult, RuntimeSurface
from repoprobe.verifier import VerificationResult, EndpointVerdict
from repoprobe.fingerprint import RepoFingerprint
from repoprobe.runner import RunResult, RuntimeStatus
from repoprobe import console as out


# ---------------------------------------------------------------------------
# keyword maps — REFINED to avoid false positives
# ---------------------------------------------------------------------------

# removed: "token" (too generic), "session" (too generic), "cookie"
_AUTH_KEYWORDS = [
    "jwt authentication", "authentication", "oauth", "login system",
    "signup", "sign-in", "sign-up", "authorization",
    "bcrypt", "passport", "access control", "role-based", "rbac",
    "2fa", "mfa", "two-factor", "multi-factor",
]

# removed: "tier", "plan", "premium", "pricing" — these describe cost, not payment functionality
_PAYMENT_KEYWORDS = [
    "stripe integration", "payment processing", "billing system",
    "checkout", "razorpay", "paypal integration",
    "payment gateway", "secure payments", "payment endpoint",
]

# removed: "http", "request", "response", "route", "routes" — way too generic
_API_KEYWORDS = [
    "rest api", "restful api", "api endpoint", "graphql api", "grpc",
    "crud operations", "api server", "api built with",
]

# removed: generic "sql", "orm", "migration"
_DATABASE_KEYWORDS = [
    "postgresql", "postgres", "mongodb", "redis cache",
    "mysql database", "sqlite", "database integration",
    "prisma", "sequelize", "typeorm", "mongoose",
]

# removed: "deployment", "deployed", "stable" — too generic, match setup docs
_PRODUCTION_KEYWORDS = [
    "production ready", "production-ready",
    "enterprise grade", "enterprise-grade",
    "production grade", "production-grade",
    "battle tested", "battle-tested",
    "high availability", "fault tolerant",
]

_SECURITY_KEYWORDS = [
    "secure authentication", "encryption", "encrypted",
    "rate limiting", "csrf protection", "xss protection",
    "input validation", "security hardened",
]

# removed: generic "model", "prediction", "training"
_AI_KEYWORDS = [
    "ai-powered", "artificial intelligence", "machine learning pipeline",
    "ml model", "inference engine", "gpt integration", "llm integration",
    "openai integration", "gemini integration",
    "deep learning", "neural network", "nlp pipeline",
    "computer vision", "transformer model",
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


# ---------------------------------------------------------------------------
# confidence signals
# ---------------------------------------------------------------------------

# words that BOOST confidence — the line is making a real claim
_POSITIVE_SIGNALS = [
    "supports", "implements", "provides", "features",
    "built with", "built on", "includes", "enables",
    "offers", "powered by", "uses", "integrates",
    "handles", "manages", "ensures", "guarantees",
]

# patterns that REDUCE confidence — the line is noise
_NOISE_PATTERNS = [
    r"^https?://",                    # bare urls
    r"^git\s+clone",                  # git commands
    r"^npm\s+(install|run|start)",    # npm commands
    r"^pip\s+install",               # pip commands
    r"^python\s+",                   # python commands
    r"^cd\s+",                       # cd commands
    r"^docker\s+",                   # docker commands
    r"^curl\s+",                     # curl commands
    r"^\$\s+",                       # shell prompts
    r"^```",                         # code fences
    r"^\d+\.\s+(install|run|clone|create|open|navigate|enter)",  # numbered steps
    r"^step\s+\d+",                  # step N instructions
]

_NOISE_COMPILED = [re.compile(p, re.IGNORECASE) for p in _NOISE_PATTERNS]


# ---------------------------------------------------------------------------
# data structures
# ---------------------------------------------------------------------------

@dataclass
class Claim:
    """a single claim extracted from the readme."""
    text: str
    category: str
    keyword_matched: str
    confidence: float = 0.5
    source_line: int = 0


@dataclass
class Contradiction:
    """a detected contradiction between claim and runtime evidence."""
    claim: Claim
    evidence: list[str]
    severity: str  # critical, high, medium
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


# ---------------------------------------------------------------------------
# claim extractor — precision version
# ---------------------------------------------------------------------------

class ClaimExtractor:
    """
    extracts verifiable claims from a readme file.
    uses keyword matching with confidence scoring.
    filters out noise (urls, commands, setup instructions).
    """

    _README_NAMES = [
        "README.md", "readme.md", "Readme.md",
        "README", "README.rst", "README.txt",
    ]

    CONFIDENCE_THRESHOLD = 0.65

    def __init__(self, repo_root: Path) -> None:
        self.root = repo_root
        self.readme_path: Path | None = None
        self.readme_content: str = ""

    def extract(self) -> list[Claim]:
        """find and parse the readme, extract high-confidence claims only."""
        self.readme_path = self._find_readme()
        if not self.readme_path:
            return []

        self.readme_content = self.readme_path.read_text(
            encoding="utf-8", errors="ignore"
        )

        claims: list[Claim] = []
        lines = self.readme_content.splitlines()
        in_code_block = False

        for line_num, line in enumerate(lines, 1):
            # track code blocks
            if line.strip().startswith("```"):
                in_code_block = not in_code_block
                continue
            if in_code_block:
                continue

            # clean markdown formatting
            clean = self._strip_markdown(line).strip()

            # skip short or empty lines
            if not clean or len(clean) < 15:
                continue

            # skip noise lines (urls, commands, steps)
            if self._is_noise(clean):
                continue

            # check each category
            lower = clean.lower()
            for category, keywords in _CATEGORY_MAP.items():
                for keyword in keywords:
                    if keyword in lower:
                        confidence = self._compute_confidence(clean, keyword, category)

                        # only keep high-confidence claims
                        if confidence < self.CONFIDENCE_THRESHOLD:
                            continue

                        # avoid duplicate claims for the same line + category
                        if not any(
                            c.source_line == line_num and c.category == category
                            for c in claims
                        ):
                            claims.append(Claim(
                                text=clean,
                                category=category,
                                keyword_matched=keyword,
                                confidence=confidence,
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
    def _is_noise(line: str) -> bool:
        """detect lines that are noise, not claims."""
        for pattern in _NOISE_COMPILED:
            if pattern.search(line):
                return True
        # bare urls anywhere in the line (as the main content)
        if re.match(r"^https?://\S+$", line.strip()):
            return True
        return False

    @staticmethod
    def _compute_confidence(line: str, keyword: str, category: str) -> float:
        """compute confidence that this line is making a real functional claim."""
        confidence = 0.5
        lower = line.lower()

        # boost: positive signal words present
        for signal in _POSITIVE_SIGNALS:
            if signal in lower:
                confidence += 0.12
                break  # only count once

        # boost: keyword is multi-word (more specific)
        if " " in keyword:
            confidence += 0.15

        # boost: line looks like a feature statement (not too long)
        if 20 < len(line) < 150:
            confidence += 0.08

        # penalize: very long lines (likely paragraphs, not claims)
        if len(line) > 200:
            confidence -= 0.15

        # penalize: contains urls
        if "http://" in lower or "https://" in lower:
            confidence -= 0.25

        # penalize: looks like setup/installation context
        setup_words = ["install", "clone", "download", "setup", "configure", "run"]
        setup_count = sum(1 for w in setup_words if w in lower)
        if setup_count >= 2:
            confidence -= 0.20

        # penalize: looks like troubleshooting
        trouble_words = ["error", "solution", "fix", "issue", "problem", "troubleshoot"]
        if any(w in lower for w in trouble_words):
            confidence -= 0.15

        # penalize: looks like a limitation note
        if any(w in lower for w in ["limitation", "constraint", "caveat", "not yet"]):
            confidence -= 0.20

        return max(0.0, min(1.0, confidence))

    @staticmethod
    def _strip_markdown(line: str) -> str:
        """strip common markdown formatting from a line."""
        line = re.sub(r"^#{1,6}\s+", "", line)
        line = re.sub(r"\*{1,3}([^*]+)\*{1,3}", r"\1", line)
        line = re.sub(r"_{1,3}([^_]+)_{1,3}", r"\1", line)
        line = re.sub(r"`([^`]+)`", r"\1", line)
        line = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", line)
        line = re.sub(r"^[\s]*[-*+]\s+", "", line)
        line = re.sub(r"^[\s]*\d+\.\s+", "", line)
        return line


# ---------------------------------------------------------------------------
# contradiction engine — precision version
# ---------------------------------------------------------------------------

class ContradictionEngine:
    """
    compares extracted claims against runtime evidence.
    deduplicates contradictions by evidence type.
    only fires on genuine behavioral mismatches.
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
        """run contradiction rules, then deduplicate."""
        raw: list[Contradiction] = []

        for claim in self.claims:
            result = self._check_claim(claim)
            if result:
                raw.append(result)

        # deduplicate: keep highest confidence claim per (category, evidence_key)
        return self._deduplicate(raw)

    def _deduplicate(self, contradictions: list[Contradiction]) -> list[Contradiction]:
        """keep only the best contradiction per (category, evidence_signature)."""
        seen: dict[str, Contradiction] = {}

        for c in contradictions:
            # create a key from category + first evidence line
            evidence_key = c.evidence[0] if c.evidence else ""
            key = f"{c.claim.category}::{evidence_key}"

            existing = seen.get(key)
            if not existing or c.claim.confidence > existing.claim.confidence:
                seen[key] = c

        return list(seen.values())

    def _check_claim(self, claim: Claim) -> Contradiction | None:
        """dispatch to the appropriate rule checker."""
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
        return checker(claim) if checker else None

    # -- rule: auth claims

    def _check_auth(self, claim: Claim) -> Contradiction | None:
        evidence = []

        invariant_auth = self._get_invariant_endpoints(
            ["auth", "login", "signin", "signup", "register"]
        )
        if invariant_auth:
            for ep in invariant_auth:
                evidence.append(
                    f"endpoint {ep.method} {ep.route} returned identical responses "
                    f"across {len(ep.runs)} randomized credential probes"
                )

        error_auth = self._get_error_routes(
            ["auth", "login", "signin", "signup", "register"]
        )
        if error_auth:
            for s in error_auth:
                evidence.append(
                    f"endpoint {s.method} {s.route} returns {s.status} server error"
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
        evidence = []

        invariant = self._get_invariant_endpoints(
            ["payment", "checkout", "charge", "pay", "billing"]
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
        evidence = []

        if self.probe:
            if self.probe.reachable_count == 0:
                evidence.append(
                    "no reachable api surfaces were discovered at runtime"
                )
            elif self.probe.reachable_count > 0:
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
        evidence = []

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
        evidence = []

        if self.run_result and self.run_result.status == RuntimeStatus.CRASHED:
            evidence.append("application crashed on startup")

        if self.probe and self.probe.reachable_count > 0:
            error_count = len(self.probe.server_errors)
            total = self.probe.reachable_count
            error_rate = error_count / total if total else 0
            if error_rate >= 0.5:
                evidence.append(
                    f"{error_count}/{total} endpoints return server errors "
                    f"({error_rate:.0%} error rate)"
                )

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
        evidence = []

        invariant_ai = self._get_invariant_endpoints(
            ["ai", "generate", "predict", "infer", "chat", "completion"]
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
        if not self.probe:
            return []
        results = []
        for surface in self.probe.surfaces:
            lower = surface.route.lower()
            if any(kw in lower for kw in keywords):
                results.append(surface)
        return results


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

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
        categories = {}
        for c in report.claims:
            categories.setdefault(c.category, []).append(c)

        out.console.print()
        out.console.print("  [info]claim categories[/info]")
        for cat, items in sorted(categories.items()):
            avg_conf = sum(c.confidence for c in items) / len(items)
            out.console.print(
                f"    {cat:<16} {len(items):>2} claims  "
                f"(avg confidence: {avg_conf:.0%})"
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

    for i, contradiction in enumerate(report.contradictions, 1):
        severity_style = {
            "critical": "error",
            "high": "warning",
            "medium": "info",
        }.get(contradiction.severity, "muted")

        out.console.print(
            f"  [{severity_style}]━━━ contradiction #{i} "
            f"[{contradiction.severity}] "
            f"(confidence: {contradiction.claim.confidence:.0%})"
            f"[/{severity_style}]"
        )
        out.console.print()
        out.console.print(
            f"    [info]claim:[/info] \"{contradiction.claim.text}\""
        )
        out.console.print()
        out.console.print(f"    [info]runtime evidence:[/info]")
        for ev in contradiction.evidence:
            out.console.print(f"      • {ev}")
        out.console.print()
        out.console.print(
            f"    [{severity_style}]↳ {contradiction.explanation}[/{severity_style}]"
        )
        out.console.print()
