# repoprobe

repoprobe is a cli-based managed execution assurance system for ai-generated software. it does not statically analyze repositories — it executes them, observes their runtime behavior, compares claimed functionality against observed reality, and then reports the truth. the project is being built for the google deepmind × cerebral valley hackathon at google i/o 2026.

## the problem

software generation has become cheap, but verification has not. modern ai coding systems optimize for plausibility — convincing readmes, valid syntax, polished interfaces, and believable architecture. but plausibility is not correctness. a repository can compile successfully, boot successfully, render a polished frontend, and return http 200 responses while still being behaviorally false. authentication may always succeed regardless of input. payment systems may never actually contact stripe. database writes may silently never occur. claimed features may only exist in the readme. repoprobe exists because code authorship is now decoupled from code verification, and the industry lacks runtime-level tooling to bridge that gap.

## how it works

a developer runs `repoprobe run ./target-repo` and the system takes over from there. repoprobe syncs the repository into a managed antigravity sandbox, uses gemini 3.5 flash to infer the minimum executable environment required for runtime observation, boots the application, discovers executable surfaces like routes and services and ports, probes runtime behavior through controlled interrogation, compares observed behavior against claimed behavior extracted from readmes and configs and api surfaces, detects behavioral contradictions, and generates a final verification report. the repository remains completely immutable throughout this process — repoprobe never rewrites application logic. it observes, it interrogates, it verifies.

## the core verification primitive

the central innovation is behavioral contradiction analysis. repoprobe extracts claims from readmes, endpoint descriptions, configuration files, and api surfaces. then it validates whether observed runtime behavior contradicts those claims. for example, if a readme claims "production ready stripe integration" but the system observes zero outbound requests to stripe apis, no payment persistence, and a static success payload being returned — that is a behavioral contradiction. the final output includes a readme trust score, a list of verified behaviors, unverifiable claims, runtime failures, and behavioral contradictions.

## architecture

repoprobe intentionally relies on aggressive platform abstraction. the local codebase remains extremely small. google infrastructure handles sandbox isolation, process management, execution environments, persistent runtime state, and model inference. repoprobe itself focuses exclusively on execution assurance, behavioral verification, contradiction detection, and runtime interrogation. the cli is built with typer, the terminal ui uses textual and rich for real-time streaming of agent reasoning, shell execution, runtime probes, and contradiction reports. the system intentionally avoids web dashboards — the terminal creates lower implementation overhead, higher perceived technical credibility, faster iteration, and live execution visibility.

## runtime phases

repoprobe executes in four phases. phase one is environment construction, where gemini infers the runtime stack, startup commands, required services, and missing environment assumptions to construct the minimum executable environment for runtime observation. phase two is runtime discovery, where the system identifies routes, services, ports, execution surfaces, and persistence layers. phase three is behavioral interrogation, where the system tests endpoint consistency, network activity, persistence mutations, authentication validity, and runtime side effects to identify behavioral contradictions. phase four is verification synthesis, where repoprobe produces the final report containing verified behaviors, unverifiable claims, runtime failures, and behavioral contradictions along with a readme trust score.

## why existing tools fail

static analysis tools like semgrep and sonarqube analyze syntax and patterns but cannot determine whether stripe calls actually occur, whether auth is behaviorally correct, whether endpoints are fake, whether persistence exists, or whether the readme is truthful. ci/cd pipelines assume the repository author already knows how the system should run, but ai-generated repositories often do not — missing services, environment assumptions, binaries, dependencies, and orchestration flows cause ci systems to fail immediately without understanding why. most ai coding agents optimize for repairing software, but repoprobe optimizes for measuring software — the moment a system rewrites application logic, runtime evidence becomes contaminated.

## tech stack

the core runtime uses python 3.12+ with asyncio. the cli layer uses typer. the terminal ui uses textual and rich. model and runtime infrastructure is powered by the google-genai sdk, gemini 3.5 flash, the managed agents api, and the antigravity sandbox.

## what repoprobe is not

repoprobe is not another coding copilot, not another static analyzer, not another ci pipeline, not another ai agent wrapper, and not another autonomous coding framework. it does not generate software. it verifies whether generated software behaves consistently with its claims. repoprobe belongs to a new category called managed execution assurance, which exists because ai-generated software increasingly separates believable appearance from behavioral correctness. repoprobe is infrastructure designed to close that gap.

## license

this project is currently under development for the google i/o 2026 hackathon.
