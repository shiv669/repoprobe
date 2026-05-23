# architecture requirements document — repoprobe

## 1. system overview

repoprobe is a cli application written in python that orchestrates runtime verification of ai-generated repositories. it operates as a thin local client that delegates heavy execution to google's antigravity sandbox infrastructure and uses gemini 3.5 flash for intelligent environment inference and behavioral analysis. the architecture is deliberately minimal on the local side — platform abstraction is aggressive, and the local codebase focuses exclusively on cli orchestration, event stream consumption, and terminal ui rendering.

## 2. high-level architecture

```
┌─────────────────────────────────────────────────────┐
│                   local machine                      │
│                                                      │
│  ┌─────────────┐    ┌──────────────────────────┐     │
│  │  typer cli   │───▶│  textual/rich terminal ui │    │
│  └─────────────┘    └──────────────────────────┘     │
│         │                        ▲                    │
│         │                        │ event stream       │
│         ▼                        │                    │
│  ┌──────────────────────────────────────────────┐    │
│  │         event stream consumer                 │    │
│  │  • agent reasoning events                     │    │
│  │  • shell execution events                     │    │
│  │  • runtime probe results                      │    │
│  │  • contradiction reports                      │    │
│  └──────────────────────────────────────────────┘    │
└────────────────────────┬────────────────────────────┘
                         │ google-genai sdk
                         ▼
┌─────────────────────────────────────────────────────┐
│              antigravity sandbox                      │
│                                                      │
│  ┌──────────────────────────────────────────────┐    │
│  │     gemini 3.5 flash managed agent            │    │
│  │                                                │    │
│  │  responsibilities:                             │    │
│  │  • infer execution environment                 │    │
│  │  • boot target application                     │    │
│  │  • discover executable surfaces                │    │
│  │  • probe runtime behavior                      │    │
│  │  • audit network egress                        │    │
│  │  • validate behavioral claims                  │    │
│  │  • stream verification events                  │    │
│  └──────────────────────────────────────────────┘    │
│                                                      │
│  ┌──────────────────────────────────────────────┐    │
│  │     target repository (read-only mount)        │    │
│  └──────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

## 3. component architecture

### 3.1 cli layer (typer)
- entry point for all user interactions.
- parses the target repository path and any configuration flags.
- initializes the sandbox session via google-genai sdk.
- delegates execution to the orchestration layer.
- responsible for graceful error handling and user-facing messaging.

### 3.2 orchestration layer
- manages the four-phase verification pipeline: environment construction → runtime discovery → behavioral interrogation → verification synthesis.
- coordinates communication between the local client and the antigravity sandbox.
- maintains session state and phase progression.
- handles retry logic for transient sandbox failures.

### 3.3 event stream consumer
- consumes the real-time event stream from the antigravity sandbox.
- deserializes events into typed python objects.
- routes events to the appropriate terminal ui component for rendering.
- event types include: agent reasoning, shell execution, probe results, contradiction detections, phase transitions, and final verdicts.

### 3.4 terminal ui layer (textual + rich)
- renders all verification activity in real time.
- displays agent reasoning, shell execution output, runtime probe results, and contradiction analysis as they occur.
- presents the final verification report with readme trust score, verified behaviors, contradictions, and unverifiable claims.
- designed to feel alive, observational, and forensic — not conversational.

### 3.5 managed agent (gemini 3.5 flash in antigravity sandbox)
- the core intelligence of the system, running entirely within the sandbox.
- uses the managed agents api to operate autonomously within the sandbox.
- has access to shell execution, file system reading (read-only for target repo), network monitoring, and process management.
- responsible for all four verification phases.

## 4. data flow

```
user command
    │
    ▼
typer cli parses input
    │
    ▼
google-genai sdk creates sandbox session
    │
    ▼
target repository synced to sandbox (read-only)
    │
    ▼
managed agent begins phase 1: environment construction
    │ (events streamed back)
    ▼
managed agent begins phase 2: runtime discovery
    │ (events streamed back)
    ▼
managed agent begins phase 3: behavioral interrogation
    │ (events streamed back)
    ▼
managed agent begins phase 4: verification synthesis
    │ (final report streamed back)
    ▼
terminal ui renders final verification report
```

## 5. security model

- **sandbox isolation**: all target code executes inside the antigravity sandbox, completely isolated from the user's local machine. no target code ever runs locally.
- **read-only repository mount**: the target repository is mounted as read-only inside the sandbox. repoprobe never modifies application logic, ensuring forensic neutrality and reproducibility.
- **no credential exposure**: repoprobe does not require or accept credentials for the target application. behavioral probing uses synthetic inputs only.
- **network containment**: outbound network traffic from the target application is monitored but contained within the sandbox. network egress patterns are used as verification evidence.

## 6. key technical decisions

### 6.1 why python
python 3.12+ provides native asyncio support for concurrent event stream handling, has first-class support for the google-genai sdk, and the textual/rich ecosystem provides the most capable terminal ui framework available.

### 6.2 why typer over argparse/click
typer provides automatic type validation, help generation, and a cleaner api surface. it is built on top of click but reduces boilerplate significantly.

### 6.3 why textual + rich over plain terminal output
the verification process involves multiple concurrent streams of information (agent reasoning, shell output, probe results). textual provides a full tui framework with layouts, live updates, and widgets. rich provides formatting primitives. together they enable the "alive, forensic" terminal experience that is core to the product identity.

### 6.4 why antigravity sandbox over local docker
local docker execution would require users to have docker installed, would expose the host machine to target code, and would require repoprobe to manage container lifecycle. the antigravity sandbox abstracts all of this — isolation, process management, and execution environments are handled by google infrastructure.

### 6.5 why gemini 3.5 flash over other models
gemini 3.5 flash is optimized for speed, supports the managed agents api natively, and operates within the antigravity sandbox. this tight integration eliminates the need for external api calls or custom agent frameworks.

## 7. dependency map

| component | dependency | purpose |
|---|---|---|
| cli | typer | command parsing and help generation |
| terminal ui | textual | tui framework with layouts and widgets |
| terminal ui | rich | text formatting and styling |
| model inference | google-genai sdk | gemini 3.5 flash access and sandbox management |
| runtime | python 3.12+ | async execution and type hints |
| runtime | asyncio | concurrent event stream handling |

## 8. deployment model

repoprobe is distributed as a python cli tool, installable via pip. all heavy execution happens server-side in the antigravity sandbox. the local installation footprint is minimal — only the cli client, event stream consumer, and terminal ui dependencies are installed locally. no docker, no local containers, no heavy runtime dependencies.

## 9. scalability considerations

the current architecture is designed for single-repository verification per invocation. future considerations include batch verification mode (multiple repos in sequence), persistent verification history, and ci/cd integration where repoprobe runs as a pipeline step. the sandbox-based architecture means scaling compute is entirely server-side and managed by google infrastructure.

## 10. error handling strategy

- **sandbox creation failure**: retry with exponential backoff, then fail with actionable error message.
- **application boot failure**: report as verification evidence (application cannot boot = critical failure in claims).
- **model inference timeout**: retry the current phase, report partial results if retries exhausted.
- **event stream disconnection**: attempt reconnection, resume from last known event, report gap in observation window.
- **unrecoverable failures**: always produce a partial verification report with whatever evidence was collected before failure.
