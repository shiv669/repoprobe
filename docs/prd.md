# product requirements document — repoprobe

## 1. product overview

repoprobe is a cli-based managed execution assurance system that verifies whether ai-generated software behaves consistently with its claimed functionality. it executes target repositories inside isolated sandboxes, observes runtime behavior, and detects behavioral contradictions between what a repository claims to do and what it actually does at runtime.

## 2. problem statement

ai coding systems now generate repositories that appear complete — valid syntax, polished uis, convincing readmes — but are often behaviorally incomplete or outright false at runtime. authentication may always succeed. payment integrations may never contact external apis. database writes may never persist. there is currently no tooling category that addresses this verification gap through runtime execution and behavioral observation. existing static analyzers, ci/cd pipelines, and ai coding agents are structurally incapable of detecting these behavioral contradictions.

## 3. target users

- **developers receiving ai-generated code** who need to verify that delivered repositories actually work as described before integrating or deploying them.
- **engineering managers and tech leads** evaluating ai-generated pull requests or vendor-delivered codebases who need an objective behavioral assessment.
- **hackathon judges and reviewers** who need to quickly determine whether a submitted project's claimed features are real or cosmetic.
- **open source maintainers** receiving ai-generated contributions who want runtime verification before merging.

## 4. product goals

- provide a single cli command (`repoprobe run ./target-repo`) that produces a complete behavioral verification report.
- detect behavioral contradictions between claimed and observed functionality.
- produce a quantified readme trust score.
- execute entirely within an isolated sandbox — never modify the target repository.
- stream real-time verification progress through a rich terminal ui.

## 5. core features

### 5.1 automated environment inference
the system uses gemini 3.5 flash to analyze the target repository and infer the minimum executable environment — runtime stack, startup commands, required services, and dependencies — without any user configuration.

### 5.2 runtime discovery
after booting the application, repoprobe automatically discovers executable surfaces including http routes, services, ports, persistence layers, and background processes.

### 5.3 behavioral interrogation
the system performs controlled probing of discovered surfaces — testing endpoint consistency, monitoring network activity, checking persistence mutations, validating authentication flows, and observing runtime side effects.

### 5.4 behavioral contradiction analysis
repoprobe extracts claims from readmes, configuration files, endpoint descriptions, and api surfaces, then compares them against observed runtime evidence. contradictions are flagged with detailed evidence.

### 5.5 verification report generation
the final output includes a readme trust score (0-100), verified behaviors, unverifiable claims, runtime failures, and behavioral contradictions with supporting runtime evidence.

### 5.6 real-time terminal ui
all verification phases stream live to the terminal using textual and rich — agent reasoning, shell execution, runtime probes, and contradiction analysis are visible in real time.

## 6. user flow

1. user runs `repoprobe run ./target-repo` from their terminal.
2. repoprobe syncs the repository into an antigravity sandbox (read-only mount).
3. gemini 3.5 flash infers the execution environment and boots the application.
4. the system discovers executable surfaces and begins behavioral interrogation.
5. claims are extracted from readme and config files and compared against runtime observations.
6. behavioral contradictions are detected and flagged.
7. a final verification report with readme trust score is generated and displayed.

## 7. non-functional requirements

- **isolation**: target repositories must never be modified. all execution happens inside the antigravity sandbox.
- **determinism**: repeated runs against the same repository should produce consistent behavioral verdicts.
- **performance**: full verification should complete within 3-5 minutes for typical repositories.
- **streaming**: all phases must stream progress to the terminal in real time — no silent waiting periods.

## 8. success metrics

- behavioral contradiction detection accuracy (target: >85% for known-false repositories).
- readme trust score correlation with actual functionality (validated against manually audited repos).
- time to first verdict under 60 seconds.
- full verification completion under 5 minutes for repositories with <50 endpoints.

## 9. out of scope

- web dashboard or browser-based ui.
- code generation or code repair functionality.
- self-healing or auto-fixing of detected issues.
- support for non-containerizable applications.
- paid api integrations beyond google-genai sdk.

## 10. constraints and dependencies

- requires python 3.12+ runtime.
- depends on google-genai sdk for model inference (gemini 3.5 flash).
- depends on antigravity sandbox for isolated execution.
- depends on managed agents api for agent orchestration.
- terminal ui depends on textual and rich libraries.
- cli depends on typer.

## 11. timeline

this is a hackathon project targeting google i/o 2026 (google deepmind × cerebral valley). the initial working prototype must be demo-ready within the hackathon timeframe.
