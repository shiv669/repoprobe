"""
event stream consumer for repoprobe.

normalizes raw sdk events into a clean internal format
that the terminal ui can render without knowing anything
about the google-genai sdk internals.

each event type is handled independently — an unrecognized
event is logged and skipped, never crashes the consumer.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# event types
# ---------------------------------------------------------------------------


class EventKind(Enum):
    """all event kinds the system understands."""

    PHASE_START = "phase_start"
    PHASE_END = "phase_end"
    AGENT_THOUGHT = "agent_thought"
    AGENT_TEXT = "agent_text"
    SHELL_EXEC = "shell_exec"
    PROBE_RESULT = "probe_result"
    CONTRADICTION = "contradiction"
    VERDICT = "verdict"
    ERROR = "error"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# normalized event
# ---------------------------------------------------------------------------


@dataclass
class ProbeEvent:
    """
    a single normalized event from the verification pipeline.
    this is the only event type the ui layer ever sees.
    """

    kind: EventKind
    content: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: Any = None


# ---------------------------------------------------------------------------
# event normalizer
# ---------------------------------------------------------------------------


def normalize_event(raw_event: dict) -> ProbeEvent:
    """
    convert a raw sandbox event dict into a ProbeEvent.

    raw_event is the dict yielded by sandbox.run_in_sandbox().
    this function never raises — unknown events become EventKind.UNKNOWN.
    """
    event_type = raw_event.get("event_type", "unknown")
    delta_type = raw_event.get("delta_type")
    content = raw_event.get("content", "")
    raw = raw_event.get("raw")

    # map sdk event types to our internal kinds
    if event_type == "error":
        return ProbeEvent(
            kind=EventKind.ERROR,
            content=content,
            raw=raw,
        )

    if event_type == "step.start":
        return ProbeEvent(
            kind=EventKind.SHELL_EXEC,
            content="step started",
            metadata={"event_type": event_type},
            raw=raw,
        )

    if event_type == "step.delta":
        if delta_type == "thought_summary":
            return ProbeEvent(
                kind=EventKind.AGENT_THOUGHT,
                content=content,
                raw=raw,
            )
        if delta_type == "text":
            return ProbeEvent(
                kind=EventKind.AGENT_TEXT,
                content=content,
                raw=raw,
            )

    if event_type == "interaction.completed":
        return ProbeEvent(
            kind=EventKind.PHASE_END,
            content="interaction completed",
            metadata={"event_type": event_type},
            raw=raw,
        )

    # fallback — never crash on unknown events
    return ProbeEvent(
        kind=EventKind.UNKNOWN,
        content=content or f"unhandled event: {event_type}",
        raw=raw,
    )


# ---------------------------------------------------------------------------
# event log (optional in-memory collector)
# ---------------------------------------------------------------------------


class EventLog:
    """
    collects ProbeEvents during a run so we can
    produce a summary / report at the end.
    independent of the streaming display.
    """

    def __init__(self) -> None:
        self._events: list[ProbeEvent] = []

    def append(self, event: ProbeEvent) -> None:
        """add an event to the log."""
        self._events.append(event)

    @property
    def events(self) -> list[ProbeEvent]:
        """all logged events."""
        return list(self._events)

    def filter(self, kind: EventKind) -> list[ProbeEvent]:
        """return only events of a specific kind."""
        return [e for e in self._events if e.kind == kind]

    @property
    def errors(self) -> list[ProbeEvent]:
        """shortcut for all error events."""
        return self.filter(EventKind.ERROR)

    @property
    def contradictions(self) -> list[ProbeEvent]:
        """shortcut for all contradiction events."""
        return self.filter(EventKind.CONTRADICTION)

    def clear(self) -> None:
        """reset the log."""
        self._events.clear()
