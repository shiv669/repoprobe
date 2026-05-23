"""
ai analysis layer for repoprobe.

uses gemini 3.5 flash to interpret runtime evidence.
gemini NEVER generates evidence — only interprets it.
all evidence comes from deterministic systems:
  fingerprint, probe, verifier, contradiction engine.

architectural boundary: deterministic systems generate evidence,
ai interprets evidence. that separation is non-negotiable.
"""

from google import genai

from repoprobe.config import Config
from repoprobe.claims import Claim, Contradiction, ContradictionReport
from repoprobe.probe import ProbeResult
from repoprobe.verifier import VerificationResult
from repoprobe.runner import RunResult, RuntimeStatus
from repoprobe.fingerprint import RepoFingerprint
from repoprobe import console as out


_SYSTEM_PROMPT = """you are a runtime verification analyst for repoprobe, a managed execution assurance system.

you are given:
1. claimed repository functionality (extracted from the readme)
2. observed runtime evidence (from actual execution and probing)
3. behavioral verification results (from deterministic analysis)
4. contradiction findings (from rule-based engines)

your task:
- determine whether observed runtime behavior supports or contradicts claimed functionality
- synthesize the evidence into a clear, authoritative assessment
- explain what the contradictions mean practically
- assign an overall trust assessment

rules:
- do not speculate beyond observed evidence
- base conclusions strictly on runtime observations
- be direct and precise, not verbose
- use lowercase for technical terms
- do not use emojis
- structure your response with clear sections
- if no contradictions exist, acknowledge that the evidence supports the claims
- if contradictions exist, explain their practical implications"""


def _build_evidence_prompt(
    fingerprint: RepoFingerprint | None,
    run_result: RunResult | None,
    probe_result: ProbeResult | None,
    verification_result: VerificationResult | None,
    contradiction_report: ContradictionReport | None,
) -> str:
    """build the structured evidence prompt for gemini."""
    sections = []

    # section 1: repository identity
    if fingerprint:
        services_str = ", ".join(
            f"{s.name} ({s.category})" for s in fingerprint.services
        ) or "none"
        sections.append(
            "--- repository identity ---\n"
            f"type: {fingerprint.repo_type}\n"
            f"framework: {fingerprint.framework}\n"
            f"package manager: {fingerprint.package_manager}\n"
            f"entry point: {fingerprint.entry_point}\n"
            f"services detected: {services_str}\n"
            f"files traversed: {fingerprint.file_count}\n"
        )

    # section 2: runtime execution
    if run_result:
        sections.append(
            "--- runtime execution ---\n"
            f"boot status: {run_result.status.value}\n"
            f"boot detected: {run_result.boot_detected}\n"
            f"port reachable: {run_result.port_reachable}\n"
            f"install exit code: {run_result.install_exit_code}\n"
            f"error: {run_result.error or 'none'}\n"
        )

    # section 3: surface discovery
    if probe_result:
        reachable = [
            f"  {s.method} {s.route} -> {s.status} ({s.category}, {s.content_length}b, hash:{s.response_hash})"
            for s in probe_result.surfaces if s.reachable
        ]
        unreachable = [
            f"  {s.method} {s.route} -> {s.category}"
            for s in probe_result.surfaces if not s.reachable
        ]
        sections.append(
            "--- surface discovery ---\n"
            f"total probed: {probe_result.total_probed}\n"
            f"reachable: {probe_result.reachable_count}\n"
            f"server errors: {len(probe_result.server_errors)}\n"
            f"auth gated: {len(probe_result.auth_gated)}\n\n"
            f"reachable endpoints:\n" + "\n".join(reachable or ["  none"]) + "\n\n"
            f"unreachable endpoints:\n" + "\n".join(unreachable or ["  none"]) + "\n"
        )

    # section 4: behavioral verification
    if verification_result and verification_result.total_verified > 0:
        verdicts = []
        for v in verification_result.verdicts:
            run_details = ", ".join(
                f"run#{r.run_number}: hash={r.response_hash} status={r.status}"
                for r in v.runs if not r.error
            )
            verdicts.append(
                f"  {v.method} {v.route}: {v.category} "
                f"({v.unique_hashes} unique hashes, {v.unique_statuses} unique statuses)\n"
                f"    runs: {run_details}\n"
                f"    suspicious: {v.suspicious}\n"
                f"    reason: {v.reason}"
            )
        sections.append(
            "--- behavioral verification ---\n"
            f"endpoints verified: {verification_result.total_verified}\n"
            f"suspicious: {verification_result.suspicious_count}\n"
            f"clean: {verification_result.clean_count}\n\n"
            + "\n\n".join(verdicts) + "\n"
        )

    # section 5: readme claims
    if contradiction_report and contradiction_report.claims:
        claim_lines = []
        for c in contradiction_report.claims:
            claim_lines.append(
                f"  [{c.category}] \"{c.text}\" (keyword: {c.keyword_matched}, line {c.source_line})"
            )
        sections.append(
            "--- readme claims ---\n"
            f"total claims extracted: {len(contradiction_report.claims)}\n"
            f"readme: {contradiction_report.readme_path}\n\n"
            + "\n".join(claim_lines[:30]) + "\n"  # cap at 30 to avoid token overflow
        )

    # section 6: contradictions
    if contradiction_report and contradiction_report.contradictions:
        contra_lines = []
        for c in contradiction_report.contradictions:
            evidence_str = "\n    ".join(f"- {e}" for e in c.evidence)
            contra_lines.append(
                f"  [{c.severity}] claim: \"{c.claim.text}\"\n"
                f"    category: {c.claim.category}\n"
                f"    evidence:\n    {evidence_str}\n"
                f"    explanation: {c.explanation}"
            )
        sections.append(
            "--- contradictions detected ---\n"
            f"total: {len(contradiction_report.contradictions)}\n\n"
            + "\n\n".join(contra_lines) + "\n"
        )
    elif contradiction_report:
        sections.append(
            "--- contradictions detected ---\n"
            "total: 0\n"
            "no contradictions were found between readme claims and runtime behavior.\n"
        )

    return "\n\n".join(sections)


class AIAnalyzer:
    """
    uses gemini 3.5 flash to interpret runtime evidence.
    takes structured evidence from deterministic systems and
    synthesizes an authoritative assessment.
    """

    def __init__(self) -> None:
        if not Config.google_api_key:
            raise RuntimeError(
                "GOOGLE_API_KEY not set — cannot run ai analysis. "
                "set it in .env or export it in your shell."
            )

        self.client = genai.Client(api_key=Config.google_api_key)
        self.model = Config.gemini_model

    def analyze(
        self,
        fingerprint: RepoFingerprint | None = None,
        run_result: RunResult | None = None,
        probe_result: ProbeResult | None = None,
        verification_result: VerificationResult | None = None,
        contradiction_report: ContradictionReport | None = None,
    ) -> str:
        """
        synthesize all runtime evidence into an ai assessment.
        returns the gemini response as a string.
        """
        evidence = _build_evidence_prompt(
            fingerprint=fingerprint,
            run_result=run_result,
            probe_result=probe_result,
            verification_result=verification_result,
            contradiction_report=contradiction_report,
        )

        user_prompt = (
            "analyze the following runtime verification evidence and provide:\n\n"
            "1. a brief overall assessment (2-3 sentences)\n"
            "2. for each contradiction found, explain what it means practically\n"
            "3. a trust verdict: how much should someone trust this repository's claims?\n"
            "4. specific recommendations for the repository maintainer\n\n"
            "base your analysis strictly on the observed evidence below.\n\n"
            f"{evidence}"
        )

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=user_prompt,
                config=genai.types.GenerateContentConfig(
                    system_instruction=_SYSTEM_PROMPT,
                    temperature=0.3,
                    max_output_tokens=1500,
                ),
            )
            return response.text or "no analysis generated"

        except Exception as e:
            return f"ai analysis failed: {e}"


def render_ai_analysis(analysis: str) -> None:
    """print the gemini ai analysis."""
    out.console.print()
    out.console.rule("[phase]ai analysis[/phase]")
    out.console.print()

    # render line by line, handling markdown-like formatting
    for line in analysis.splitlines():
        stripped = line.strip()
        if not stripped:
            out.console.print()
        elif stripped.startswith("# "):
            out.console.print(f"  [phase]{stripped[2:]}[/phase]")
        elif stripped.startswith("## "):
            out.console.print(f"  [info]{stripped[3:]}[/info]")
        elif stripped.startswith("### "):
            out.console.print(f"  [info]{stripped[4:]}[/info]")
        elif stripped.startswith("- "):
            out.console.print(f"    {stripped}")
        elif stripped.startswith("* "):
            out.console.print(f"    {stripped}")
        else:
            out.console.print(f"  {stripped}")

    out.console.print()
