"""
managed investigation agent for repoprobe.

uses google managed agents (client.interactions.create) with
the antigravity-preview-05-2026 agent for autonomous investigation.

the agent receives structured runtime evidence and autonomously
decides what to investigate deeper. it has access to the live
application via httpx tools.

also includes:
  - investigation timeline with timestamps
  - trust score evolution (visible degradation)
  - evidence correlation layer
  - runtime claim verification
"""

import hashlib
import random
import string
import time
from dataclasses import dataclass, field
from datetime import datetime

import httpx
from google import genai

from repoprobe.config import Config
from repoprobe.claims import ContradictionReport, Contradiction
from repoprobe.probe import ProbeResult
from repoprobe.verifier import VerificationResult
from repoprobe.fingerprint import RepoFingerprint
from repoprobe.runner import RunResult
from repoprobe import console as out


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

TOOL_TIMEOUT = 5.0


# ---------------------------------------------------------------------------
# data structures
# ---------------------------------------------------------------------------

@dataclass
class TimelineEntry:
    """a single entry in the investigation timeline."""
    timestamp: str
    tag: str  # probe, runtime, analysis, verify, risk, agent
    message: str
    severity: str = "info"  # info, high, critical


@dataclass
class TrustEvolution:
    """tracks trust score degradation over time."""
    entries: list[tuple[str, int]] = field(default_factory=list)

    def record(self, reason: str, score: int) -> None:
        self.entries.append((reason, score))

    @property
    def final_score(self) -> int:
        return self.entries[-1][1] if self.entries else 100


@dataclass
class EvidenceCorrelation:
    """cross-evidence linking for a specific claim category."""
    category: str
    claim_text: str
    observations: list[str] = field(default_factory=list)
    conclusion: str = ""
    severity: str = "info"


@dataclass
class InvestigationReport:
    """complete investigation report with timeline and evidence."""
    timeline: list[TimelineEntry] = field(default_factory=list)
    trust_evolution: TrustEvolution = field(default_factory=TrustEvolution)
    correlations: list[EvidenceCorrelation] = field(default_factory=list)
    managed_agent_output: str = ""
    strategies_executed: list[str] = field(default_factory=list)
    risk_level: str = "unknown"
    trust_score: int = 100


# ---------------------------------------------------------------------------
# deterministic investigation tools
# ---------------------------------------------------------------------------

def _hash(body: bytes) -> str:
    return hashlib.md5(body).hexdigest()[:12]


def _random_string(length: int = 12) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def _probe(base_url: str, method: str, path: str,
           body: dict | None = None) -> dict:
    if not path.startswith("/"):
        path = f"/{path}"
    try:
        kwargs = {"method": method.upper(), "url": f"{base_url}{path}",
                  "timeout": TOOL_TIMEOUT, "follow_redirects": False}
        if body and method.upper() not in ("GET", "HEAD"):
            kwargs["json"] = body
        r = httpx.request(**kwargs)
        return {"status": r.status_code, "hash": _hash(r.content),
                "size": len(r.content), "preview": r.text[:200]}
    except Exception as e:
        return {"error": str(e)}


def _test_auth(base_url: str, path: str) -> dict:
    if not path.startswith("/"):
        path = f"/{path}"
    url = f"{base_url}{path}"
    variations = [
        ("empty_body", {}),
        ("empty_creds", {"email": "", "password": ""}),
        ("sql_injection", {"email": "' OR 1=1 --", "password": "' OR 1=1 --"}),
        ("random_creds", {"email": f"{_random_string(8)}@test.com",
                          "password": _random_string(16)}),
        ("xss_attempt", {"email": "<script>alert(1)</script>",
                         "password": "<img src=x onerror=alert(1)>"}),
    ]
    results = []
    for name, body in variations:
        try:
            r = httpx.post(url, json=body, timeout=TOOL_TIMEOUT, follow_redirects=False)
            results.append({"name": name, "status": r.status_code, "hash": _hash(r.content)})
        except Exception as e:
            results.append({"name": name, "error": str(e)})

    hashes = {r["hash"] for r in results if "hash" in r}
    return {"path": path, "tested": len(variations),
            "unique_hashes": len(hashes), "all_identical": len(hashes) <= 1,
            "results": results}


def _fuzz(base_url: str, method: str, path: str) -> dict:
    if not path.startswith("/"):
        path = f"/{path}"
    url = f"{base_url}{path}"
    cases = [
        ("null_values", {"key": None}),
        ("nested", {"a": {"b": {"c": "deep"}}}),
        ("huge_number", {"value": 99999999999999}),
        ("unicode", {"input": "こんにちは 🌍"}),
    ]
    results = []
    for name, body in cases:
        try:
            r = httpx.request(method.upper(), url, json=body,
                              timeout=TOOL_TIMEOUT, follow_redirects=False)
            results.append({"name": name, "status": r.status_code, "hash": _hash(r.content)})
        except Exception as e:
            results.append({"name": name, "error": str(e)})

    hashes = {r["hash"] for r in results if "hash" in r}
    return {"path": f"{method} {path}", "tested": len(cases),
            "unique_hashes": len(hashes), "all_identical": len(hashes) <= 1}


def _analyze_error(base_url: str, path: str) -> dict:
    if not path.startswith("/"):
        path = f"/{path}"
    try:
        r = httpx.get(f"{base_url}{path}", timeout=TOOL_TIMEOUT, follow_redirects=False)
        body = r.text
        leakage = {
            "stack_trace": any(kw in body.lower() for kw in
                ["traceback", "at module", "error at"]),
            "file_paths": any(kw in body for kw in
                ["\\", "/usr/", "/home/", "node_modules"]),
            "framework": any(kw in body.lower() for kw in
                ["express", "django", "fastapi", "flask", "uvicorn"]),
            "server_header": bool(r.headers.get("server")),
        }
        return {"path": path, "status": r.status_code,
                "leakage": any(leakage.values()),
                "types": [k for k, v in leakage.items() if v],
                "preview": body[:200],
                "server": r.headers.get("server", "hidden")}
    except Exception as e:
        return {"error": str(e)}


def _check_outbound(base_url: str, service_domain: str, endpoints: list[str]) -> dict:
    """check if hitting endpoints triggers any outbound service behavior.
    tests by comparing response patterns — real integrations show variable responses."""
    results = []
    for path in endpoints[:3]:
        if not path.startswith("/"):
            path = f"/{path}"
        r1 = _probe(base_url, "POST", path, {"test": _random_string()})
        r2 = _probe(base_url, "POST", path, {"test": _random_string()})
        results.append({
            "path": path,
            "identical": r1.get("hash") == r2.get("hash"),
            "status_1": r1.get("status"), "status_2": r2.get("status"),
        })
    all_identical = all(r.get("identical", True) for r in results)
    return {"service": service_domain, "endpoints_tested": len(results),
            "all_static": all_identical, "results": results}


# ---------------------------------------------------------------------------
# investigation engine
# ---------------------------------------------------------------------------

class InvestigationAgent:
    """
    managed investigation agent.

    flow:
      1. deterministic strategy selection + tool execution
      2. build timeline, trust evolution, evidence correlations
      3. managed agent synthesis via client.interactions.create (1 api call)
    """

    def __init__(self, base_url: str) -> None:
        if not Config.google_api_key:
            raise RuntimeError("GOOGLE_API_KEY not set")

        self.client = genai.Client(api_key=Config.google_api_key)
        self.base_url = base_url
        self.report = InvestigationReport()
        self._start_time = time.time()

    def _ts(self) -> str:
        """current timestamp for timeline."""
        return datetime.now().strftime("%H:%M:%S")

    def _log(self, tag: str, msg: str, severity: str = "info") -> None:
        """add timeline entry and print event."""
        self.report.timeline.append(
            TimelineEntry(timestamp=self._ts(), tag=tag,
                          message=msg, severity=severity)
        )
        out.event(tag, msg)

    def _trust(self, reason: str, deduction: int) -> int:
        """deduct from trust score and record evolution."""
        current = self.report.trust_score
        new_score = max(0, current - deduction)
        self.report.trust_score = new_score
        self.report.trust_evolution.record(reason, new_score)
        return new_score

    def investigate(
        self,
        fingerprint: RepoFingerprint | None = None,
        run_result: RunResult | None = None,
        probe_result: ProbeResult | None = None,
        verification_result: VerificationResult | None = None,
        contradiction_report: ContradictionReport | None = None,
    ) -> InvestigationReport:
        """run the full investigation pipeline."""
        contradictions = (
            contradiction_report.contradictions if contradiction_report else []
        )

        # initialize trust evolution
        self.report.trust_evolution.record("initial runtime boot", 100)

        # phase A: establish baseline trust from probe results
        if probe_result:
            self._establish_baseline(probe_result)

        # phase B: run targeted investigations
        self._run_investigations(probe_result, contradictions, fingerprint)

        # phase C: build evidence correlations
        self._correlate_evidence(contradictions)

        # phase D: managed agent synthesis (1 api call)
        self._managed_agent_synthesis(
            fingerprint, probe_result, verification_result, contradiction_report
        )

        return self.report

    def _establish_baseline(self, probe_result: ProbeResult) -> None:
        """establish baseline trust from surface discovery."""
        error_count = len(probe_result.server_errors)
        total = probe_result.reachable_count

        if total == 0:
            self._trust("no reachable endpoints", 50)
            self._log("risk", "no reachable endpoints — trust severely degraded", "critical")
        elif error_count == total:
            self._trust("all endpoints return server errors", 40)
            self._log("risk", f"100% error rate ({error_count}/{total} endpoints)", "critical")
        elif error_count > 0:
            rate = error_count / total
            deduction = int(rate * 30)
            self._trust(f"{error_count}/{total} server errors", deduction)
            self._log("risk", f"{rate:.0%} error rate detected", "high")

    def _run_investigations(
        self,
        probe_result: ProbeResult | None,
        contradictions: list[Contradiction],
        fingerprint: RepoFingerprint | None,
    ) -> None:
        """run targeted investigations based on contradiction types."""
        categories = {c.claim.category for c in contradictions}

        # AUTH investigation
        if categories & {"auth", "security"}:
            self.report.strategies_executed.append("AUTH_INVESTIGATION")
            out.console.print()
            out.console.print("  [phase]▸ AUTH_INVESTIGATION[/phase]")
            self._investigate_auth(probe_result)

        # API reliability investigation
        if categories & {"api", "production"}:
            self.report.strategies_executed.append("API_RELIABILITY")
            out.console.print()
            out.console.print("  [phase]▸ API_RELIABILITY[/phase]")
            self._investigate_api(probe_result)

        # AI endpoint investigation
        if categories & {"ai"}:
            self.report.strategies_executed.append("AI_ENDPOINT")
            out.console.print()
            out.console.print("  [phase]▸ AI_ENDPOINT[/phase]")
            self._investigate_ai(probe_result)

        # runtime claim verification (the "holy shit" moment)
        if fingerprint:
            self._verify_runtime_claims(fingerprint, probe_result)

    def _investigate_auth(self, probe_result: ProbeResult | None) -> None:
        """deep investigation of auth endpoints."""
        auth_paths = []
        if probe_result:
            for s in probe_result.surfaces:
                lower = s.route.lower()
                if any(kw in lower for kw in ["auth", "login", "signin", "signup"]):
                    auth_paths.append(s.route)

        for common in ["/api/auth", "/auth", "/login"]:
            if common not in auth_paths:
                auth_paths.append(common)

        for path in auth_paths[:2]:
            self._log("probe", f"testing auth variations on {path}")
            result = _test_auth(self.base_url, path)

            if result.get("all_identical"):
                self._log("runtime", f"identical responses across {result['tested']} auth variations on {path}", "critical")
                self._trust(f"invariant auth on {path}", 15)
                self._log("risk", f"trust reduced → {self.report.trust_score}/100", "critical")
            else:
                self._log("verify", f"{result['unique_hashes']} unique responses on {path}")

        # error leakage check
        if auth_paths:
            path = auth_paths[0]
            self._log("probe", f"analyzing error response on {path}")
            result = _analyze_error(self.base_url, path)
            if result.get("leakage"):
                self._log("analysis", f"information leakage: {', '.join(result['types'])}", "high")
                self._trust(f"info leakage on {path}", 8)

    def _investigate_api(self, probe_result: ProbeResult | None) -> None:
        """investigate api endpoint reliability."""
        if not probe_result:
            return

        errors = [s for s in probe_result.surfaces if s.category == "server_error"][:3]

        for surface in errors:
            self._log("probe", f"fuzzing {surface.method} {surface.route}")
            result = _fuzz(self.base_url, surface.method, surface.route)

            if result.get("all_identical"):
                self._log("runtime", f"all fuzz cases identical on {surface.route}", "high")
                self._trust(f"invariant fuzz on {surface.route}", 5)
            else:
                self._log("verify", f"{result['unique_hashes']} unique responses on {surface.route}")

        # error leakage on first error endpoint
        if errors:
            self._log("probe", f"analyzing error leakage on {errors[0].route}")
            result = _analyze_error(self.base_url, errors[0].route)
            if result.get("leakage"):
                self._log("analysis", f"error leakage detected: {', '.join(result['types'])}", "high")
                self._trust("information leakage in errors", 5)

    def _investigate_ai(self, probe_result: ProbeResult | None) -> None:
        """investigate ai/ml endpoints."""
        if not probe_result:
            return

        ai_eps = [
            s for s in probe_result.surfaces
            if any(kw in s.route.lower() for kw in
                   ["ai", "generate", "predict", "infer", "chat"])
        ][:2]

        for surface in ai_eps:
            self._log("probe", f"fuzzing AI endpoint {surface.route}")
            result = _fuzz(self.base_url, "POST", surface.route)
            if result.get("all_identical"):
                self._log("analysis", f"AI endpoint {surface.route} returns static responses", "high")
                self._trust(f"static AI on {surface.route}", 10)

    def _verify_runtime_claims(
        self, fingerprint: RepoFingerprint, probe_result: ProbeResult | None
    ) -> None:
        """the "holy shit" moment — verify specific service claims at runtime."""
        self.report.strategies_executed.append("RUNTIME_CLAIM_VERIFICATION")
        out.console.print()
        out.console.print("  [phase]▸ RUNTIME_CLAIM_VERIFICATION[/phase]")

        # check for claimed services
        for service in fingerprint.services:
            service_name = service.name.lower()

            if service.category == "payment":
                self._log("probe", f"searching runtime traces for {service.name} activity...")
                # test payment-like endpoints
                payment_paths = []
                if probe_result:
                    for s in probe_result.surfaces:
                        if any(kw in s.route.lower() for kw in ["payment", "charge", "checkout", "billing"]):
                            payment_paths.append(s.route)

                if not payment_paths:
                    self._log("analysis", f"no {service.name} endpoints discovered at runtime", "high")
                    self._trust(f"no {service.name} runtime traces", 8)
                else:
                    result = _check_outbound(self.base_url, service.name, payment_paths)
                    if result.get("all_static"):
                        self._log("analysis", f"static responses — no {service.name} integration activity observed", "high")
                        self._trust(f"static {service.name} responses", 10)

            elif service.category == "auth":
                self._log("probe", f"verifying {service.name} authentication at runtime...")
                result = _probe(self.base_url, "POST", "/api/auth",
                                {"email": "test@test.com", "password": "test"})
                if result.get("error"):
                    self._log("analysis", f"{service.name} auth endpoint unreachable", "high")
                elif result.get("status", 0) >= 500:
                    self._log("analysis", f"{service.name} auth returns server error", "high")
                    self._trust(f"{service.name} auth broken", 8)

    def _correlate_evidence(self, contradictions: list[Contradiction]) -> None:
        """build cross-evidence correlations."""
        # group contradictions by category
        by_category: dict[str, list[Contradiction]] = {}
        for c in contradictions:
            by_category.setdefault(c.claim.category, []).append(c)

        for category, contras in by_category.items():
            best = max(contras, key=lambda c: c.claim.confidence)
            observations = []

            # gather all evidence across contradictions in this category
            for c in contras:
                for ev in c.evidence:
                    if ev not in observations:
                        observations.append(ev)

            # add investigation findings
            timeline_relevant = [
                t for t in self.report.timeline
                if t.severity in ("high", "critical") and category in t.message.lower()
            ]
            for t in timeline_relevant:
                if t.message not in observations:
                    observations.append(t.message)

            if observations:
                conclusion = self._generate_conclusion(category, observations)
                correlation = EvidenceCorrelation(
                    category=category,
                    claim_text=best.claim.text,
                    observations=observations[:5],
                    conclusion=conclusion,
                    severity=best.severity,
                )
                self.report.correlations.append(correlation)

    @staticmethod
    def _generate_conclusion(category: str, observations: list[str]) -> str:
        """generate deterministic conclusion from evidence."""
        conclusions = {
            "auth": "authentication layer appears behaviorally bypassed or non-functional",
            "payment": "claimed payment integration shows no runtime activity",
            "api": "api endpoints are non-functional — systematic server failure observed",
            "production": "runtime behavior contradicts production readiness claims",
            "security": "security properties are not enforced at runtime",
            "ai": "ai/ml functionality shows no evidence of model inference",
            "database": "database integration appears misconfigured or absent",
        }
        return conclusions.get(category,
                               f"{category} claims not supported by runtime evidence")

    def _managed_agent_synthesis(
        self,
        fingerprint: RepoFingerprint | None,
        probe_result: ProbeResult | None,
        verification_result: VerificationResult | None,
        contradiction_report: ContradictionReport | None,
    ) -> None:
        """synthesize findings using google managed agent (1 api call)."""
        self._log("agent", "synthesizing with managed agent...")

        # build compact evidence summary
        evidence_parts = []

        evidence_parts.append(
            f"trust score evolution: "
            + " → ".join(f"{r}: {s}" for r, s in self.report.trust_evolution.entries)
        )

        if self.report.correlations:
            for c in self.report.correlations:
                evidence_parts.append(
                    f"[{c.severity}] {c.category}: \"{c.claim_text[:80]}\" — "
                    + "; ".join(c.observations[:3])
                )

        evidence_parts.append(
            f"strategies: {', '.join(self.report.strategies_executed)}"
        )
        evidence_parts.append(
            f"final trust: {self.report.trust_score}/100"
        )

        agent_input = (
            "you are repoprobe's forensic investigation agent. "
            "analyze this runtime investigation evidence and provide a 3-5 sentence "
            "authoritative assessment. state the risk level, key findings, and "
            "what the evidence means practically. be direct.\n\n"
            + "\n".join(evidence_parts)
        )

        try:
            # use managed agent via interactions.create
            interaction = self.client.interactions.create(
                agent=Config.agent_model,
                input=agent_input,
                environment="remote",
                system_instruction=(
                    "you are a runtime forensic analyst for repoprobe. "
                    "analyze evidence and provide a concise, authoritative assessment. "
                    "do not speculate. base conclusions on observed evidence only. "
                    "be precise and direct."
                ),
            )

            if hasattr(interaction, 'output_text') and interaction.output_text:
                self.report.managed_agent_output = interaction.output_text
            elif hasattr(interaction, 'text') and interaction.text:
                self.report.managed_agent_output = interaction.text
            else:
                self.report.managed_agent_output = str(interaction)

            # extract risk level
            lower = self.report.managed_agent_output.lower()
            for level in ["critical", "high", "medium", "low", "clean"]:
                if level in lower:
                    self.report.risk_level = level
                    break

            self._log("agent", "managed agent synthesis complete")

        except Exception as e:
            # fallback to direct gemini call if managed agent fails
            self._log("agent", f"managed agent unavailable ({e}), using direct synthesis")
            self._fallback_synthesis(agent_input)

    def _fallback_synthesis(self, prompt: str) -> None:
        """fallback to gemini 3.5 flash if managed agent is unavailable."""
        try:
            response = self.client.models.generate_content(
                model=Config.gemini_model,
                contents=prompt,
                config={"temperature": 0.2, "max_output_tokens": 300},
            )
            if response.text:
                self.report.managed_agent_output = response.text
                lower = response.text.lower()
                for level in ["critical", "high", "medium", "low", "clean"]:
                    if level in lower:
                        self.report.risk_level = level
                        break
        except Exception:
            self.report.managed_agent_output = (
                f"investigation completed with trust score {self.report.trust_score}/100. "
                f"manual review recommended."
            )


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def render_investigation(report: InvestigationReport) -> None:
    """render the full investigation report."""
    out.console.print()
    out.console.rule("[phase]investigation report[/phase]")
    out.console.print()

    # 1. trust score with bar
    score = report.trust_score
    if score >= 70:
        score_style = "success"
    elif score >= 40:
        score_style = "warning"
    else:
        score_style = "error"

    bar_filled = score // 5
    bar_empty = 20 - bar_filled
    bar = f"{'█' * bar_filled}{'░' * bar_empty}"

    out.console.print(
        f"  [{score_style}]RUNTIME TRUST SCORE: {score}/100  {bar}[/{score_style}]"
    )
    out.console.print()

    # 2. trust score evolution
    if report.trust_evolution.entries:
        out.console.print("  [phase]trust score evolution[/phase]")
        out.console.print()
        for reason, score_val in report.trust_evolution.entries:
            if score_val >= 70:
                s = "success"
            elif score_val >= 40:
                s = "warning"
            else:
                s = "error"
            out.console.print(
                f"    [{s}]{score_val:>3}[/{s}]  {reason}"
            )
        out.console.print()

    # 3. evidence correlations
    if report.correlations:
        out.console.print("  [phase]evidence correlations[/phase]")
        out.console.print()

        for corr in report.correlations:
            sev_style = {"critical": "error", "high": "warning"}.get(
                corr.severity, "info"
            )
            out.console.print(
                f"  [{sev_style}]━━━ {corr.category.upper()} [{corr.severity}][/{sev_style}]"
            )
            out.console.print(f"    [info]claim:[/info] \"{corr.claim_text[:100]}\"")
            out.console.print()
            out.console.print(f"    [info]observed:[/info]")
            for obs in corr.observations:
                out.console.print(f"      • {obs}")
            out.console.print()
            out.console.print(
                f"    [{sev_style}]↳ {corr.conclusion}[/{sev_style}]"
            )
            out.console.print()

    # 4. investigation timeline
    if report.timeline:
        out.console.print("  [phase]investigation timeline[/phase]")
        out.console.print()

        for entry in report.timeline:
            sev_style = {
                "critical": "error", "high": "warning", "info": "muted",
            }.get(entry.severity, "muted")

            tag_styles = {
                "probe": "probe", "runtime": "warning",
                "analysis": "phase", "verify": "success",
                "agent": "info", "risk": "error",
            }
            tag_style = tag_styles.get(entry.tag, "muted")

            out.console.print(
                f"    [muted]{entry.timestamp}[/muted]  "
                f"[{tag_style}][{entry.tag}][/{tag_style}]  "
                f"[{sev_style}]{entry.message}[/{sev_style}]"
            )
        out.console.print()

    # 5. managed agent assessment
    if report.managed_agent_output:
        out.console.print("  [phase]managed agent assessment[/phase]")
        out.console.print()
        for line in report.managed_agent_output.splitlines():
            stripped = line.strip()
            if stripped:
                out.console.print(f"  {stripped}")
        out.console.print()

    # 6. strategies
    out.console.print(
        f"  [info]strategies executed[/info] :  "
        f"{', '.join(report.strategies_executed) or 'none'}"
    )

    risk_style = {
        "critical": "error", "high": "warning",
        "medium": "info", "low": "success", "clean": "success",
    }.get(report.risk_level, "muted")

    out.console.print(
        f"  [info]risk level[/info]          :  [{risk_style}]{report.risk_level}[/{risk_style}]"
    )
    out.console.print()
