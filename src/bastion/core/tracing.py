"""Optional tracing to a self-hosted Phoenix (OpenTelemetry).

Traces contain telemetry from the Mac, so they only ever go to the collector named in
PHOENIX_COLLECTOR_ENDPOINT (the Phoenix container on this machine). If the variable is
unset or the tracing packages are missing, tracing is simply off.
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)


def setup_tracing() -> bool:
    endpoint = os.environ.get("PHOENIX_COLLECTOR_ENDPOINT")
    if not endpoint:
        return False
    try:
        from openinference.instrumentation.anthropic import AnthropicInstrumentor
        from openinference.instrumentation.langchain import LangChainInstrumentor
        from phoenix.otel import register
    except ImportError as exc:
        log.warning("tracing disabled: %s", exc)
        return False
    provider = register(project_name="bastion", endpoint=endpoint.rstrip("/") + "/v1/traces",
                        batch=True, set_global_tracer_provider=True)
    LangChainInstrumentor().instrument(tracer_provider=provider)   # graph and node spans
    AnthropicInstrumentor().instrument(tracer_provider=provider)   # model calls and tokens
    log.info("tracing to %s", endpoint)
    return True
