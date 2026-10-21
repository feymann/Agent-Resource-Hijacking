"""Small, explicit state holder for the OpenClaw CLI adapter.

The historical external helper was not included in the source distribution.
This adapter supplies only the contract exercised by resource_hijack_runner:
command arguments, process environment, workspace, and session storage. It does
not claim equivalence with the unavailable helper or load private user profiles.
"""

from pathlib import Path


class OpenClawRuntime:
    def __init__(self):
        self.ENV = {}
        self.OPENCLAW_CMD = []
        self.WORKSPACE = None
        self.WORKSPACE_BAK = None
        self.SESSIONS_DIR = None
        self.AGENT_TIMEOUT = 180

    def validate_isolation(self):
        """Fail before invoking the CLI if per-case state was not configured."""
        state = self.ENV.get("OPENCLAW_STATE_DIR")
        config = self.ENV.get("OPENCLAW_CONFIG_PATH")
        if not state or not config or self.SESSIONS_DIR is None:
            raise ValueError("A case-specific OpenClaw state and explicit config are required")
        state_path = Path(state).resolve()
        config_path = Path(config).resolve()
        sessions_path = Path(self.SESSIONS_DIR).resolve()
        if config_path.parent != state_path or not config_path.is_file():
            raise ValueError("OpenClaw config must be a file in the isolated case state")
        if state_path not in sessions_path.parents:
            raise ValueError("OpenClaw sessions must remain inside the isolated case state")

