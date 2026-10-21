"""Fixed direct-scanner settings for the ResourceHijack LlamaFirewall v5 baseline."""

from __future__ import annotations

import hashlib
import os
from urllib.parse import urljoin
from llamafirewall_release import get_profile

_SETTINGS = get_profile("v5")

SCANNER_API_ROOT = os.environ.get("OPENAI_BASE_URL", "https://your-openai-compatible-endpoint.example.com/")
SCANNER_RESPONSES_ENDPOINT = urljoin(SCANNER_API_ROOT, "v1/responses")
SCANNER_API_KEY = os.environ.get("OPENAI_API_KEY", "")
SCANNER_MODEL = _SETTINGS["scanner_model"]
SCANNER_IMPLEMENTATION = _SETTINGS["scanner_implementation"]
SCANNER_TIMEOUT_SECONDS = _SETTINGS["scanner_timeout"]
SCANNER_TOTAL_DEADLINE_SECONDS = _SETTINGS["scanner_deadline"]
SCANNER_RETRIES = _SETTINGS["scanner_retries"]
SCANNER_MAX_OUTPUT_TOKENS = _SETTINGS["scanner_max_output_tokens"]
SCANNER_MAX_RESPONSE_BYTES = _SETTINGS["scanner_max_response_bytes"]
PLUGIN_REQUEST_TIMEOUT_MS = _SETTINGS["plugin_timeout_ms"]
HOOK_TIMEOUT_MS = _SETTINGS["hook_timeout_ms"]
CASE_TIMEOUT_SECONDS = _SETTINGS["case_timeout"]
JUDGE_MAX_OUTPUT_TOKENS = _SETTINGS["judge_max_output_tokens"]
SCANNER_TRANSPORT_PROTOCOL = _SETTINGS["scanner_transport_protocol"]


def scanner_key_fingerprint() -> str:
    return hashlib.sha256(SCANNER_API_KEY.encode("utf-8")).hexdigest()
