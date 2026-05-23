"""
autonomous investigation agent for repoprobe.

this is the managed agent layer — gemini decides what to probe,
the system executes using existing deterministic tools, gemini
interprets the results, and the loop repeats.

the agent is constrained:
  - max 3 investigation steps
  - can only use pre-defined investigation tools
  - all probing is done via httpx against a live app
  - gemini orchestrates, never generates evidence

architectural boundary:
  gemini decides WHAT to investigate
  deterministic tools execute the investigation
  gemini interprets WHAT was found
"""

import hashlib
import json
import random
import string
import uuid
from dataclasses import dataclass, field

import httpx
from google import genai
from google.genai import types

from repoprobe.config import Config
from repoprobe.claims import ContradictionReport
from repoprobe.probe import ProbeResult
from repoprobe.verifier import VerificationResult
from repoprobe.fingerprint import RepoFingerprint
from repoprobe.runner import RunResult
from repoprobe import console as out


# -- constants

MAX_INVESTIGATION_STEPS = 3
TOOL_TIMEOUT = 5.0

_AGENT_SYSTEM_PROMPT = """you are a forensic runtime investigation agent for repoprobe.

you have been given runtime evidence from a live application.
your job is to investigate suspicious behavior by calling investigation tools.

available tools:
1. probe_endpoint — send a specific http request to any endpoint on the running app
2. test_auth_variations — test an auth endpoint with empty, invalid, and malformed credentials
3. fuzz_endpoint — send edge-case payloads (empty body, huge values, wrong types) to an endpoint
4. analyze_error_response — fetch and analyze an error response for information leakage

rules:
- you have a maximum of {max_steps} investigation steps total
- each tool call counts as one step
- be strategic — investigate the most suspicious findings first
- focus on behavioral contradictions (invariant responses, auth bypasses, error leakage)
- when you have enough evidence, call done_investigating with your final assessment
- base all conclusions strictly on observed runtime evidence
- do not speculate beyond what the tools return

after each tool result, decide whether to investigate further or conclude.
when concluding, call done_investigating with a structured assessment."""


# -- data structures

@dataclass
class InvestigationFinding:
    """a single finding from an investigation step."""
    step: int
    tool_used: str
    target: str
    result: dict = field(default_factory=dict)
    interpretation: str = ""


@dataclass
class InvestigationReport:
    """complete investigation report."""
    findings: list[InvestigationFinding] = field(default_factory=list)
    total_steps: int = 0
    final_assessment: str = ""
    risk_level: str = "unknown"  # critical, high, medium, low, clean


# -- investigation tools (real implementations)

def _hash(body: bytes) -> str:
    return hashlib.md5(body).hexdigest()[:12]


def _random_string(length: int = 12) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def _tool_probe_endpoint(base_url: str, method: str, path: str,
                          body: dict | None = None,
                          headers: dict | None = None) -> dict:
    """probe a specific endpoint with exact parameters."""
    if not path.startswith("/"):
        path = f"/{path}"
    url = f"{base_url}{path}"

    try:
        kwargs = {
            "method": method.upper(),
            "url": url,
            "timeout": TOOL_TIMEOUT,
            "follow_redirects": False,
        }
        if body and method.upper() not in ("GET", "HEAD", "OPTIONS"):
            kwargs["json"] = body
        elif body:
            kwargs["params"] = body
        if headers:
            kwargs["headers"] = headers

        response = httpx.request(**kwargs)

        return {
            "status": response.status_code,
            "content_length": len(response.content),
            "content_type": response.headers.get("content-type", ""),
            "response_hash": _hash(response.content),
            "body_preview": response.text[:500],
            "headers": dict(response.headers),
        }
    except httpx.ConnectError:
        return {"error": "connection refused"}
    except httpx.TimeoutException:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def _tool_test_auth_variations(base_url: str, path: str) -> dict:
    """test an auth endpoint with various invalid credential patterns."""
    if not path.startswith("/"):
        path = f"/{path}"
    url = f"{base_url}{path}"

    variations = [
        {"name": "empty_body", "body": {}},
        {"name": "empty_credentials", "body": {"email": "", "password": ""}},
        {"name": "invalid_email", "body": {"email": "notanemail", "password": "test123"}},
        {"name": "sql_injection", "body": {"email": "' OR 1=1 --", "password": "' OR 1=1 --"}},
        {"name": "random_valid_format", "body": {
            "email": f"{_random_string(8)}@test.com",
            "password": _random_string(16),
        }},
        {"name": "xss_attempt", "body": {
            "email": "<script>alert(1)</script>",
            "password": "<img src=x onerror=alert(1)>",
        }},
        {"name": "oversized_input", "body": {
            "email": _random_string(1000) + "@test.com",
            "password": _random_string(5000),
        }},
    ]

    results = []
    for var in variations:
        try:
            response = httpx.post(
                url,
                json=var["body"],
                timeout=TOOL_TIMEOUT,
                follow_redirects=False,
            )
            results.append({
                "variation": var["name"],
                "status": response.status_code,
                "response_hash": _hash(response.content),
                "content_length": len(response.content),
                "body_preview": response.text[:200],
            })
        except Exception as e:
            results.append({
                "variation": var["name"],
                "error": str(e),
            })

    # analyze: are responses identical?
    hashes = {r["response_hash"] for r in results if "response_hash" in r}
    statuses = {r["status"] for r in results if "status" in r}

    return {
        "endpoint": path,
        "variations_tested": len(variations),
        "unique_response_hashes": len(hashes),
        "unique_status_codes": len(statuses),
        "all_identical": len(hashes) == 1 and len(statuses) == 1,
        "results": results,
    }


def _tool_fuzz_endpoint(base_url: str, method: str, path: str) -> dict:
    """send edge-case payloads to discover unexpected behavior."""
    if not path.startswith("/"):
        path = f"/{path}"
    url = f"{base_url}{path}"

    fuzz_cases = [
        {"name": "empty_body", "body": None},
        {"name": "null_values", "body": {"key": None, "value": None}},
        {"name": "nested_deep", "body": {"a": {"b": {"c": {"d": {"e": "deep"}}}}}},
        {"name": "array_input", "body": [1, 2, 3]},
        {"name": "huge_number", "body": {"value": 99999999999999}},
        {"name": "special_chars", "body": {"input": "!@#$%^&*()_+{}|:<>?"}},
        {"name": "unicode", "body": {"input": "こんにちは世界 🌍"}},
        {"name": "boolean_string", "body": {"active": "true", "count": "0"}},
    ]

    results = []
    for case in fuzz_cases:
        try:
            kwargs = {
                "method": method.upper(),
                "url": url,
                "timeout": TOOL_TIMEOUT,
                "follow_redirects": False,
            }
            if case["body"] is not None:
                kwargs["json"] = case["body"]

            response = httpx.request(**kwargs)
            results.append({
                "case": case["name"],
                "status": response.status_code,
                "response_hash": _hash(response.content),
                "content_length": len(response.content),
            })
        except Exception as e:
            results.append({
                "case": case["name"],
                "error": str(e),
            })

    hashes = {r["response_hash"] for r in results if "response_hash" in r}

    return {
        "endpoint": f"{method} {path}",
        "cases_tested": len(fuzz_cases),
        "unique_response_hashes": len(hashes),
        "all_identical": len(hashes) == 1,
        "results": results,
    }


def _tool_analyze_error_response(base_url: str, path: str) -> dict:
    """analyze an error response for information leakage."""
    if not path.startswith("/"):
        path = f"/{path}"
    url = f"{base_url}{path}"

    try:
        response = httpx.get(url, timeout=TOOL_TIMEOUT, follow_redirects=False)
        body = response.text

        leakage_indicators = {
            "stack_trace": any(kw in body.lower() for kw in
                ["traceback", "at module", "at object", "error at", "stack trace"]),
            "file_paths": any(kw in body for kw in
                ["\\", "/usr/", "/home/", "/var/", "C:\\", "node_modules"]),
            "database_info": any(kw in body.lower() for kw in
                ["sql", "query", "table", "column", "database", "connection"]),
            "framework_info": any(kw in body.lower() for kw in
                ["express", "django", "fastapi", "flask", "next.js", "uvicorn"]),
            "debug_mode": any(kw in body.lower() for kw in
                ["debug", "development", "dev mode", "verbose"]),
            "sensitive_headers": bool(response.headers.get("x-powered-by")),
            "server_version": bool(response.headers.get("server")),
        }

        return {
            "endpoint": path,
            "status": response.status_code,
            "content_length": len(response.content),
            "leakage_detected": any(leakage_indicators.values()),
            "leakage_indicators": leakage_indicators,
            "body_preview": body[:500],
            "server_header": response.headers.get("server", "not disclosed"),
            "powered_by": response.headers.get("x-powered-by", "not disclosed"),
        }
    except Exception as e:
        return {"error": str(e)}


# -- gemini function declarations

_TOOL_DECLARATIONS = [
    types.FunctionDeclaration(
        name="probe_endpoint",
        description=(
            "send a specific http request to any endpoint on the running application. "
            "use this for targeted investigation of suspicious endpoints."
        ),
        parameters=types.Schema(
            type=types.Type.OBJECT,
            properties={
                "method": types.Schema(
                    type=types.Type.STRING,
                    description="http method (GET, POST, PUT, DELETE, etc.)",
                ),
                "path": types.Schema(
                    type=types.Type.STRING,
                    description="url path to probe (e.g. /api/auth)",
                ),
                "body": types.Schema(
                    type=types.Type.STRING,
                    description="optional json body as a string (e.g. '{\"email\": \"test@test.com\"}')",
                ),
            },
            required=["method", "path"],
        ),
    ),
    types.FunctionDeclaration(
        name="test_auth_variations",
        description=(
            "test an authentication endpoint with 7 different credential variations: "
            "empty body, empty credentials, invalid email, sql injection, random valid format, "
            "xss attempt, and oversized input. returns whether all responses are identical."
        ),
        parameters=types.Schema(
            type=types.Type.OBJECT,
            properties={
                "path": types.Schema(
                    type=types.Type.STRING,
                    description="path to the auth endpoint (e.g. /api/auth, /login)",
                ),
            },
            required=["path"],
        ),
    ),
    types.FunctionDeclaration(
        name="fuzz_endpoint",
        description=(
            "send 8 edge-case payloads to an endpoint: empty body, null values, "
            "deeply nested objects, arrays, huge numbers, special characters, unicode, "
            "and type-confused values. detects invariant response behavior."
        ),
        parameters=types.Schema(
            type=types.Type.OBJECT,
            properties={
                "method": types.Schema(
                    type=types.Type.STRING,
                    description="http method",
                ),
                "path": types.Schema(
                    type=types.Type.STRING,
                    description="url path to fuzz",
                ),
            },
            required=["method", "path"],
        ),
    ),
    types.FunctionDeclaration(
        name="analyze_error_response",
        description=(
            "analyze an endpoint's error response for information leakage: "
            "stack traces, file paths, database info, framework disclosure, "
            "debug mode indicators, and sensitive headers."
        ),
        parameters=types.Schema(
            type=types.Type.OBJECT,
            properties={
                "path": types.Schema(
                    type=types.Type.STRING,
                    description="path to analyze for error leakage",
                ),
            },
            required=["path"],
        ),
    ),
    types.FunctionDeclaration(
        name="done_investigating",
        description=(
            "call this when you have gathered enough evidence to conclude. "
            "provide your final structured assessment of the investigation."
        ),
        parameters=types.Schema(
            type=types.Type.OBJECT,
            properties={
                "risk_level": types.Schema(
                    type=types.Type.STRING,
                    description="overall risk level: critical, high, medium, low, or clean",
                ),
                "assessment": types.Schema(
                    type=types.Type.STRING,
                    description=(
                        "detailed final assessment of the investigation findings. "
                        "cover what was investigated, what was found, and what it means."
                    ),
                ),
            },
            required=["risk_level", "assessment"],
        ),
    ),
]


# -- evidence builder

def _build_investigation_context(
    fingerprint: RepoFingerprint | None,
    run_result: RunResult | None,
    probe_result: ProbeResult | None,
    verification_result: VerificationResult | None,
    contradiction_report: ContradictionReport | None,
) -> str:
    """build the initial evidence context for the agent."""
    parts = []

    if fingerprint:
        services_str = ", ".join(f"{s.name} ({s.category})" for s in fingerprint.services) or "none"
        parts.append(
            f"repository: {fingerprint.repo_type} + {fingerprint.framework}\n"
            f"services: {services_str}\n"
            f"entry point: {fingerprint.entry_point}"
        )

    if run_result:
        parts.append(
            f"boot status: {run_result.status.value}\n"
            f"port reachable: {run_result.port_reachable}"
        )

    if probe_result:
        surfaces = []
        for s in probe_result.surfaces:
            surfaces.append(
                f"  {s.method} {s.route} -> {s.status} ({s.category}, hash:{s.response_hash})"
            )
        parts.append(
            f"surface discovery: {probe_result.reachable_count} reachable / {probe_result.total_probed} probed\n"
            f"server errors: {len(probe_result.server_errors)}\n"
            "endpoints:\n" + "\n".join(surfaces)
        )

    if verification_result and verification_result.total_verified > 0:
        verdicts = []
        for v in verification_result.verdicts:
            verdicts.append(
                f"  {v.method} {v.route}: {v.category} "
                f"(suspicious: {v.suspicious}, reason: {v.reason})"
            )
        parts.append(
            f"behavioral verification: {verification_result.suspicious_count} suspicious\n"
            + "\n".join(verdicts)
        )

    if contradiction_report and contradiction_report.contradictions:
        contras = []
        # cap at 10 to avoid token overflow
        for c in contradiction_report.contradictions[:10]:
            evidence = "; ".join(c.evidence)
            contras.append(
                f"  [{c.severity}] \"{c.claim.text[:100]}\" -> {evidence}"
            )
        total = len(contradiction_report.contradictions)
        parts.append(
            f"contradictions: {total} total (showing top 10)\n"
            + "\n".join(contras)
        )

    return "\n\n".join(parts)


# -- the agent

class InvestigationAgent:
    """
    autonomous investigation agent.
    gemini decides what to investigate, deterministic tools execute,
    gemini interprets results. constrained to max 3 steps.
    """

    def __init__(self, base_url: str) -> None:
        if not Config.google_api_key:
            raise RuntimeError("GOOGLE_API_KEY not set")

        self.client = genai.Client(api_key=Config.google_api_key)
        self.model = Config.gemini_model
        self.base_url = base_url
        self.report = InvestigationReport()

        # tool dispatch
        self._tool_dispatch = {
            "probe_endpoint": self._exec_probe,
            "test_auth_variations": self._exec_auth_test,
            "fuzz_endpoint": self._exec_fuzz,
            "analyze_error_response": self._exec_error_analysis,
            "done_investigating": self._exec_done,
        }

    def investigate(
        self,
        fingerprint: RepoFingerprint | None = None,
        run_result: RunResult | None = None,
        probe_result: ProbeResult | None = None,
        verification_result: VerificationResult | None = None,
        contradiction_report: ContradictionReport | None = None,
    ) -> InvestigationReport:
        """run the autonomous investigation loop."""
        context = _build_investigation_context(
            fingerprint, run_result, probe_result,
            verification_result, contradiction_report,
        )

        system_prompt = _AGENT_SYSTEM_PROMPT.format(max_steps=MAX_INVESTIGATION_STEPS)

        # build initial message
        initial_message = (
            "here is the runtime evidence from the application under investigation. "
            "analyze the evidence and decide what to investigate first. "
            "you have 3 investigation steps. be strategic.\n\n"
            f"{context}"
        )

        # conversation history for the agent loop
        contents = [
            types.Content(
                role="user",
                parts=[types.Part.from_text(text=initial_message)],
            )
        ]

        tools = [types.Tool(function_declarations=_TOOL_DECLARATIONS)]
        done = False

        for step in range(1, MAX_INVESTIGATION_STEPS + 1):
            if done:
                break

            out.console.print(f"  [phase]step {step}/{MAX_INVESTIGATION_STEPS}[/phase]")
            out.muted("    agent reasoning...")

            try:
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=contents,
                    config=types.GenerateContentConfig(
                        system_instruction=system_prompt,
                        tools=tools,
                        temperature=0.2,
                        max_output_tokens=600,
                    ),
                )
            except Exception as e:
                out.warning(f"agent reasoning failed: {e}")
                break

            # process response
            if not response.candidates:
                out.warning("agent returned empty response")
                break

            candidate = response.candidates[0]

            # add assistant response to history
            contents.append(candidate.content)

            # check for function calls
            function_calls = [
                part for part in candidate.content.parts
                if part.function_call
            ]

            if not function_calls:
                # model responded with text (reasoning), extract and continue
                text = "".join(
                    part.text for part in candidate.content.parts if part.text
                )
                if text:
                    out.muted(f"  agent: {text[:200]}")
                break

            # execute each function call
            function_responses = []
            for fc in function_calls:
                tool_name = fc.function_call.name
                tool_args = dict(fc.function_call.args) if fc.function_call.args else {}

                out.info(f"  agent calls: {tool_name}({', '.join(f'{k}={v}' for k, v in tool_args.items())})")

                # check for done
                if tool_name == "done_investigating":
                    self.report.final_assessment = tool_args.get("assessment", "")
                    self.report.risk_level = tool_args.get("risk_level", "unknown")
                    done = True
                    function_responses.append(
                        types.Part.from_function_response(
                            name=tool_name,
                            response={"status": "investigation concluded"},
                        )
                    )
                    continue

                # execute tool
                handler = self._tool_dispatch.get(tool_name)
                if handler:
                    result = handler(tool_args)

                    # record finding
                    finding = InvestigationFinding(
                        step=step,
                        tool_used=tool_name,
                        target=tool_args.get("path", tool_args.get("method", "")),
                        result=result,
                    )
                    self.report.findings.append(finding)
                    self.report.total_steps = step

                    # print result summary
                    self._print_finding(finding)

                    function_responses.append(
                        types.Part.from_function_response(
                            name=tool_name,
                            response=result,
                        )
                    )
                else:
                    function_responses.append(
                        types.Part.from_function_response(
                            name=tool_name,
                            response={"error": f"unknown tool: {tool_name}"},
                        )
                    )

            # add function responses to history
            if function_responses:
                contents.append(
                    types.Content(
                        role="user",
                        parts=function_responses,
                    )
                )

        # if agent didn't call done_investigating, get a final assessment
        if not done and not self.report.final_assessment:
            out.muted("    agent concluding...")
            self._get_final_assessment(contents)

        return self.report

    def _get_final_assessment(self, contents) -> None:
        """ask gemini for a final assessment if the loop ended without done_investigating."""
        # build a compact summary instead of replaying full conversation
        findings_summary = []
        for f in self.report.findings:
            tool = f.tool_used
            result = f.result
            if "error" in result:
                findings_summary.append(f"step {f.step}: {tool} -> error: {result['error']}")
            elif tool == "test_auth_variations":
                findings_summary.append(
                    f"step {f.step}: {tool}({f.target}) -> "
                    f"identical={result.get('all_identical')}, "
                    f"unique_hashes={result.get('unique_response_hashes')}"
                )
            elif tool == "analyze_error_response":
                findings_summary.append(
                    f"step {f.step}: {tool}({f.target}) -> "
                    f"leakage={result.get('leakage_detected')}"
                )
            elif tool == "fuzz_endpoint":
                findings_summary.append(
                    f"step {f.step}: {tool}({f.target}) -> "
                    f"identical={result.get('all_identical')}"
                )
            else:
                findings_summary.append(
                    f"step {f.step}: {tool}({f.target}) -> "
                    f"status={result.get('status')}, hash={result.get('response_hash')}"
                )

        summary_prompt = (
            "you have completed all investigation steps. here are the findings:\n\n"
            + "\n".join(findings_summary) + "\n\n"
            "provide a final assessment: what risk level (critical/high/medium/low/clean) "
            "and a 2-3 sentence summary of what the investigation revealed."
        )

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=summary_prompt,
                config=types.GenerateContentConfig(
                    system_instruction="you are a runtime forensic analyst. be concise and direct.",
                    temperature=0.2,
                    max_output_tokens=400,
                ),
            )

            if response.text:
                self.report.final_assessment = response.text
                # try to extract risk level from text
                text_lower = response.text.lower()
                for level in ["critical", "high", "medium", "low", "clean"]:
                    if level in text_lower:
                        self.report.risk_level = level
                        break
        except Exception:
            self.report.final_assessment = (
                f"investigation completed with {len(self.report.findings)} findings. "
                f"manual review recommended."
            )
            self.report.risk_level = "unknown"

    # -- tool executors

    def _exec_probe(self, args: dict) -> dict:
        """execute probe_endpoint tool."""
        body = None
        if "body" in args and args["body"]:
            try:
                body = json.loads(args["body"])
            except (json.JSONDecodeError, TypeError):
                body = {"raw": args["body"]}

        return _tool_probe_endpoint(
            self.base_url,
            method=args.get("method", "GET"),
            path=args.get("path", "/"),
            body=body,
        )

    def _exec_auth_test(self, args: dict) -> dict:
        """execute test_auth_variations tool."""
        return _tool_test_auth_variations(
            self.base_url,
            path=args.get("path", "/auth"),
        )

    def _exec_fuzz(self, args: dict) -> dict:
        """execute fuzz_endpoint tool."""
        return _tool_fuzz_endpoint(
            self.base_url,
            method=args.get("method", "POST"),
            path=args.get("path", "/"),
        )

    def _exec_error_analysis(self, args: dict) -> dict:
        """execute analyze_error_response tool."""
        return _tool_analyze_error_response(
            self.base_url,
            path=args.get("path", "/"),
        )

    def _exec_done(self, args: dict) -> dict:
        """handle done_investigating — no real execution needed."""
        return {"status": "concluded"}

    # -- output

    def _print_finding(self, finding: InvestigationFinding) -> None:
        """print a single investigation finding."""
        result = finding.result

        if "error" in result:
            out.muted(f"    result: {result['error']}")
            return

        if finding.tool_used == "test_auth_variations":
            identical = result.get("all_identical", False)
            unique = result.get("unique_response_hashes", 0)
            if identical:
                out.console.print(
                    f"    [warning]-- all {result.get('variations_tested', 0)} auth variations "
                    f"returned identical responses[/warning]"
                )
            else:
                out.console.print(
                    f"    [success]-- {unique} unique responses across "
                    f"{result.get('variations_tested', 0)} variations[/success]"
                )

        elif finding.tool_used == "fuzz_endpoint":
            identical = result.get("all_identical", False)
            if identical:
                out.console.print(
                    f"    [warning]-- all fuzz cases returned identical responses[/warning]"
                )
            else:
                out.console.print(
                    f"    [success]-- {result.get('unique_response_hashes', 0)} unique responses "
                    f"across {result.get('cases_tested', 0)} fuzz cases[/success]"
                )

        elif finding.tool_used == "analyze_error_response":
            leakage = result.get("leakage_detected", False)
            if leakage:
                indicators = result.get("leakage_indicators", {})
                active = [k for k, v in indicators.items() if v]
                out.console.print(
                    f"    [warning]-- information leakage detected: "
                    f"{', '.join(active)}[/warning]"
                )
            else:
                out.console.print(
                    f"    [success]-- no information leakage detected[/success]"
                )

        elif finding.tool_used == "probe_endpoint":
            status = result.get("status", "?")
            hash_val = result.get("response_hash", "?")
            out.console.print(
                f"    [muted]-- {status}  hash:{hash_val}  "
                f"{result.get('content_length', 0)}b[/muted]"
            )

        out.console.print()


def render_investigation(report: InvestigationReport) -> None:
    """print the investigation summary."""
    out.console.print()
    out.console.rule("[phase]investigation report[/phase]")
    out.console.print()

    out.console.print(
        f"  [info]investigation steps[/info] :  {report.total_steps}"
    )
    out.console.print(
        f"  [info]findings[/info]            :  {len(report.findings)}"
    )

    risk_style = {
        "critical": "error",
        "high": "warning",
        "medium": "info",
        "low": "success",
        "clean": "success",
    }.get(report.risk_level, "muted")

    out.console.print(
        f"  [info]risk level[/info]          :  [{risk_style}]{report.risk_level}[/{risk_style}]"
    )

    if report.final_assessment:
        out.console.print()
        out.console.print("  [phase]agent assessment[/phase]")
        out.console.print()
        for line in report.final_assessment.splitlines():
            stripped = line.strip()
            if stripped:
                out.console.print(f"  {stripped}")
        out.console.print()
