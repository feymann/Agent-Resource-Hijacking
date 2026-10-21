#!/usr/bin/env python3
"""Defense experiment entry point sharing baseline category scheduling and retries."""
from defense_orchestration import main

if __name__ == "__main__":
    raise SystemExit(main("prompt", "v2"))
