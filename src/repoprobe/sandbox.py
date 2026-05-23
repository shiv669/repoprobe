"""
antigravity sandbox manager for repoprobe.

handles creating sandbox sessions, syncing repositories into them,
and managing the lifecycle of the isolated execution environment.
each function is independent — if one fails, the rest of the system
can still operate or report meaningful errors.
"""

from google import genai
from repoprobe.config import Config
from repoprobe import console as out


# ---------------------------------------------------------------------------
# client singleton
# ---------------------------------------------------------------------------

_client: genai.Client | None = None


def get_client() -> genai.Client:
    """
    return the google genai client, creating it on first call.
    raises RuntimeError if the api key is not configured.
    """
    global _client
    if _client is None:
        if not Config.google_api_key:
            raise RuntimeError(
                "cannot create genai client — GOOGLE_API_KEY is not set."
            )
        _client = genai.Client(api_key=Config.google_api_key)
        out.info("genai client initialized")
    return _client


# ---------------------------------------------------------------------------
# sandbox session management
# ---------------------------------------------------------------------------


def create_sandbox_session(repo_path: str) -> dict:
    """
    create a new antigravity sandbox session.

    this provisions an isolated linux environment where the target
    repository will be executed. the repo itself is synced read-only.

    returns a dict with session metadata:
        {
            "interaction_id": str,
            "environment_id": str,
            "status": "created" | "error",
            "error": str | None,
        }
    """
    try:
        client = get_client()

        # the agent will clone/sync the repo inside the sandbox
        # via a git clone or direct file copy in the prompt
        interaction = client.interactions.create(
            agent=Config.agent_model,
            input=(
                f"a repository has been provided at path: {repo_path}\n"
                "clone or copy this repository into the sandbox. "
                "do not modify any files in the repository. "
                "confirm when the repository is available."
            ),
            environment=Config.sandbox_environment,
        )

        out.success("sandbox session created")
        return {
            "interaction_id": getattr(interaction, "id", None),
            "environment_id": getattr(interaction, "environment_id", None),
            "status": "created",
            "error": None,
        }

    except Exception as e:
        out.failure(f"sandbox creation failed: {e}")
        return {
            "interaction_id": None,
            "environment_id": None,
            "status": "error",
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# streaming interaction
# ---------------------------------------------------------------------------


def run_in_sandbox(
    prompt: str,
    system_instruction: str | None = None,
    previous_interaction_id: str | None = None,
):
    """
    run a prompt inside the antigravity sandbox and yield streaming events.

    this is the core primitive — every verification phase calls this
    with a different prompt. the caller iterates over events and
    decides what to display / record.

    yields dicts shaped like:
        {
            "event_type": str,     # step.start | step.delta | interaction.completed
            "delta_type": str,     # text | thought_summary | tool_call | None
            "content": str,        # the actual content
            "raw": object,         # the raw sdk event for advanced use
        }
    """
    try:
        client = get_client()

        kwargs = {
            "agent": Config.agent_model,
            "input": prompt,
            "environment": Config.sandbox_environment,
            "stream": True,
        }

        if system_instruction:
            kwargs["system_instruction"] = system_instruction

        if previous_interaction_id:
            kwargs["previous_interaction_id"] = previous_interaction_id

        stream = client.interactions.create(**kwargs)

        for event in stream:
            event_type = getattr(event, "event_type", "unknown")
            delta = getattr(event, "delta", None)
            delta_type = getattr(delta, "type", None) if delta else None

            content = ""
            if delta_type == "text":
                content = getattr(delta, "text", "")
            elif delta_type == "thought_summary":
                inner = getattr(delta, "content", None)
                content = getattr(inner, "text", "") if inner else ""

            yield {
                "event_type": event_type,
                "delta_type": delta_type,
                "content": content,
                "raw": event,
            }

    except Exception as e:
        out.failure(f"sandbox execution error: {e}")
        yield {
            "event_type": "error",
            "delta_type": None,
            "content": str(e),
            "raw": None,
        }
