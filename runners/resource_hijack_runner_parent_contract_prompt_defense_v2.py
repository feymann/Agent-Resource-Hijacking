#!/usr/bin/env python3
"""Thin entry point for a supplied defense protocol using the shared runner."""
from defense_adapters import run_prompt

if __name__ == "__main__":
    raise SystemExit(run_prompt("v2"))
