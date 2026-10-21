#!/usr/bin/env python3
"""Run LlamaFirewall v5 cases with a configured model and original external runner."""

from llamafirewall_release import launch


def main() -> int:
    return launch("case", "v5")


if __name__ == "__main__":
    raise SystemExit(main())
