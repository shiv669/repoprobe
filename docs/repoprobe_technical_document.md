# REPOPROBE — MANAGED EXECUTION ASSURANCE

## Google DeepMind × Cerebral Valley — Google I/O 2026 Hackathon

> “The UI is beautiful. The code is lying.”

---

# Product Thesis

Software generation has become cheap.

Verification has not.

Modern AI coding systems optimize for plausibility:
• convincing READMEs
• valid syntax
• polished interfaces
• believable architecture

But plausibility is not correctness.

A repository can:
• compile successfully
• boot successfully
• render a polished frontend
• return HTTP 200 responses

while still being behaviorally false.

Authentication may always succeed.
Payment systems may never contact Stripe.
Database writes may never occur.
Claimed features may only exist in the README.

The software industry is entering a new phase where:
code authorship is decoupled from code verification.

RepoProbe exists to solve that problem.

RepoProbe is a CLI based Managed Execution Assurance system for AI generated software.

It does not statically analyze repositories.

It executes them.

It observes runtime behavior.

It compares claimed functionality against observed reality.

Then it reports the truth.

---

# Core Idea

A developer runs:

```bash
repoprobe run ./target-repo
```

RepoProbe:

1. Syncs the repository into a managed Antigravity sandbox.
2. Uses Gemini 3.5 Flash to infer the minimum executable environment required for runtime observation.
3. Boots the application.
4. Discovers executable surfaces.
5. Probes runtime behavior.
6. Compares observed behavior against claimed behavior.
7. Detects behavioral contradictions.
8. Generates a final verification report.

The system acts as:
• a runtime observer
• a behavioral verifier
• an execution assurance engine

NOT:
• a coding assistant
• a self healing agent
• a code generation tool

The repository remains immutable throughout the process.

RepoProbe never rewrites application logic.

It observes.
It interrogates.
It verifies.

---

# Why Existing Tools Fail

## Static Analysis

Tools like:
• Semgrep
• SonarQube

analyze syntax and patterns.

They cannot determine:
• whether Stripe calls actually occur
• whether auth is behaviorally correct
• whether endpoints are fake
• whether persistence exists
• whether the README is truthful

---

## CI/CD Pipelines

CI assumes:
the repository author already knows how the system should run.

AI generated repositories often do not.

Missing:
• services
• environment assumptions
• binaries
• dependencies
• orchestration flows

cause CI systems to fail immediately without understanding why.

---

## AI Coding Agents

Most agent systems optimize for:
repairing software.

RepoProbe optimizes for:
measuring software.

This distinction is critical.

The moment a system rewrites application logic:
runtime evidence becomes contaminated.

RepoProbe preserves:
• determinism
• reproducibility
• forensic neutrality

The repository is mounted read only.

---

# Core Insight

Execution evidence is ground truth.

Not:
• generated confidence
• static analysis
• architectural appearance
• README claims

Observed runtime behavior is the only reliable verification surface.

---

# The Core Verification Primitive

The central innovation is:
Behavioral Contradiction Analysis.

RepoProbe extracts claims from:
• READMEs
• endpoint descriptions
• configuration files
• API surfaces

Then validates whether observed runtime behavior contradicts those claims.

Example:

README claim:
> “Production ready Stripe integration”

Observed behavior:
• endpoint returns 200 OK
• zero outbound requests to Stripe APIs
• no payment persistence observed

Final verdict:

```text
✗ Behavioral Contradiction Detected

Claim:
Production Stripe integration

Observed Runtime Evidence:
• 0 outbound requests to api.stripe.com
• no transaction persistence
• static success payload returned

Conclusion:
Payment system behavior is inconsistent with claimed functionality.
```

This is the core product moment.

---

# Why This Matters

AI generated software increasingly produces:
behaviorally inconsistent systems.

The code looks complete.
The runtime reality is incomplete.

This creates a verification crisis.

RepoProbe is designed as infrastructure for that new reality.

---

# Architecture Overview

RepoProbe intentionally relies on aggressive platform abstraction.

The local codebase remains extremely small.

Google infrastructure handles:
• sandbox isolation
• process management
• execution environments
• persistent runtime state
• model inference

RepoProbe focuses exclusively on:
• execution assurance
• behavioral verification
• contradiction detection
• runtime interrogation

---

# System Architecture

```text
┌────────────────────────────────────────────────────────────┐
│                    REPOPROBE CLI                           │
│                                                            │
│  ┌──────────────┐   ┌────────────────────┐                 │
│  │ Typer CLI    │──▶│ Textual Runtime UI │                 │
│  └──────────────┘   └────────────────────┘                 │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Event Stream Consumer                               │  │
│  │ • agent reasoning                                   │  │
│  │ • shell execution                                   │  │
│  │ • runtime probes                                    │  │
│  │ • contradiction reports                             │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────┬───────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────┐
│              GOOGLE ANTIGRAVITY SANDBOX                   │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Gemini 3.5 Flash Managed Agent                      │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  Runtime Responsibilities:                                │
│  • infer execution environment                            │
│  • boot application                                       │
│  • probe runtime surfaces                                 │
│  • audit network egress                                   │
│  • validate behavioral claims                             │
│  • stream verification events                             │
└────────────────────────────────────────────────────────────┘
```

---

# The Runtime Model

RepoProbe executes in four phases.

---

## Phase 1 — Environment Construction

Gemini infers:
• runtime stack
• startup commands
• required services
• missing environment assumptions

The system constructs:
the minimum executable environment required for runtime observation.

This is not “self healing.”

The repository itself is never modified.

---

## Phase 2 — Runtime Discovery

RepoProbe identifies:
• routes
• services
• ports
• execution surfaces
• persistence layers

Then begins controlled probing.

---

## Phase 3 — Behavioral Interrogation

The system tests:
• endpoint consistency
• network activity
• persistence mutations
• authentication validity
• runtime side effects

This phase exists specifically to identify:
behavioral contradictions.

---

## Phase 4 — Verification Synthesis

RepoProbe produces:
• verified behaviors
• unverifiable claims
• runtime failures
• behavioral contradictions

Final output example:

```text
README TRUST SCORE: 18 / 100

✓ Frontend booted successfully
✓ User creation persisted to database

✗ Claimed JWT authentication contradicted by runtime behavior
  Invalid tokens accepted successfully

✗ Claimed Stripe integration contradicted by runtime behavior
  No outbound Stripe traffic observed

⚠ README references Redis
  No Redis dependency detected during execution
```

---

# Why The Terminal Matters

RepoProbe intentionally avoids web dashboards.

The terminal creates:
• lower implementation overhead
• higher perceived technical credibility
• faster iteration
• live execution visibility

The UI is built with:
• Typer
• Textual
• Rich

The interface streams:
• agent reasoning
• runtime traces
• shell execution
• contradiction analysis
• final verdicts

in real time.

The system should feel:
alive,
observational,
forensic.

Not conversational.

---

# The Demo Narrative

Most hackathon demos will show:
AI generating software.

RepoProbe demonstrates:
why generated software cannot automatically be trusted.

The demo flow:

1. Run RepoProbe against a polished AI generated SaaS repository.
2. Allow the system to boot the application.
3. Show successful HTTP responses.
4. Trigger contradiction analysis.
5. Reveal that claimed functionality does not exist behaviorally.

Critical moment:

```text
✓ POST /api/charge returned 200 OK

✗ Behavioral Contradiction Detected

Claim:
Production Stripe billing

Observed Runtime Evidence:
• zero outbound Stripe traffic
• no payment persistence
• static success payload

Conclusion:
Payment system is behaviorally inconsistent with claimed functionality.
```

That moment explains the entire product instantly.

---

# Technical Stack

## Core Runtime

• Python 3.12+
• asyncio

## CLI Layer

• Typer

## Terminal UI

• Textual
• Rich

## Model + Runtime Infrastructure

• google-genai SDK
• Gemini 3.5 Flash
• Managed Agents API
• Antigravity Sandbox

---

# What RepoProbe Is NOT

RepoProbe is NOT:
• another coding copilot
• another static analyzer
• another CI pipeline
• another AI agent wrapper
• another autonomous coding framework

It does not generate software.

It verifies whether generated software behaves consistently with its claims.

---

# Category Definition

RepoProbe belongs to a new category:

Managed Execution Assurance.

The category exists because:
AI generated software increasingly separates:
• believable appearance
from
• behavioral correctness

RepoProbe is infrastructure designed to close that gap.

---

# Final Thesis

The next software bottleneck is not generation.

It is trust.

AI systems can already generate convincing repositories at scale.

The missing layer is:
runtime verification infrastructure capable of determining whether those systems are behaviorally real.

RepoProbe is designed to become that layer.