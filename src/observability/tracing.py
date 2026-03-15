import os
from contextlib import contextmanager
from typing import Iterator, Optional

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
except ImportError:
    trace = None
    Resource = None
    TracerProvider = None
    BatchSpanProcessor = None
    ConsoleSpanExporter = None

try:
    from azure.monitor.opentelemetry.exporter import AzureMonitorTraceExporter
except ImportError:
    AzureMonitorTraceExporter = None

_CONFIGURED = False


def _is_placeholder_secret(value: str) -> bool:
    """Return True when a secret-like setting is empty or still templated.

    This prevents accidental attempts to initialize exporters with placeholder
    values copied from sample `.env` files.
    """
    normalized = str(value or "").strip()
    if not normalized:
        return True
    upper = normalized.upper()
    return upper.startswith("REPLACE_WITH_") or "YOUR_" in upper


class _NoOpSpan:
    """Minimal span object used when OpenTelemetry is unavailable.

    Methods mirror the subset used by the app so instrumentation calls remain
    safe and side-effect free in environments without tracing dependencies.
    """

    def __enter__(self):
        """Enter no-op span context manager."""
        return self

    def __exit__(self, exc_type, exc, tb):
        """Exit no-op span context manager without suppressing exceptions."""
        return False

    def set_attribute(self, key, value):
        """No-op attribute setter to keep tracing call sites uniform."""
        return None

    def add_event(self, name, attributes=None):
        """No-op event writer to preserve instrumentation compatibility."""
        return None

    def record_exception(self, exception):
        """No-op exception recorder used by traced workflows."""
        return None


class _NoOpTracer:
    """Tracer shim that yields no-op spans when tracing backend is absent."""

    @contextmanager
    def start_as_current_span(self, name: str) -> Iterator[_NoOpSpan]:
        """Provide an API-compatible context manager for traced code blocks."""
        yield _NoOpSpan()


def configure_observability() -> None:
    """Initialize OpenTelemetry provider and optional exporters once per process.

    Behavior:
    - Creates a tracer provider with service resource metadata.
    - Enables Azure Monitor exporter when connection string and package exist.
    - Optionally enables console exporter via `TRACE_TO_CONSOLE=true`.
    - Falls back gracefully when SDK packages are missing.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    if trace is None or TracerProvider is None or Resource is None:
        print("[TRACE] OpenTelemetry packages unavailable; tracing disabled")
        _CONFIGURED = True
        return

    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": os.getenv("OTEL_SERVICE_NAME", "release-intelligence-ri"),
                "service.version": os.getenv("OTEL_SERVICE_VERSION", "2026.1"),
            }
        )
    )

    # Support either App Insights or generic Azure Monitor connection string names.
    connection_string = os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING") or os.getenv("AZURE_MONITOR_CONNECTION_STRING")
    if _is_placeholder_secret(connection_string):
        connection_string = ""
    if connection_string and AzureMonitorTraceExporter is not None:
        try:
            azure_exporter = AzureMonitorTraceExporter(connection_string=connection_string)
            provider.add_span_processor(BatchSpanProcessor(azure_exporter))
            print("[TRACE] Azure Monitor exporter enabled")
        except Exception as error:
            print(f"[TRACE] Failed to enable Azure Monitor exporter: {error}")
    elif connection_string:
        print("[TRACE] Azure Monitor connection string set but exporter package unavailable")

    if os.getenv("TRACE_TO_CONSOLE", "false").lower() == "true" and ConsoleSpanExporter is not None:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        print("[TRACE] Console trace exporter enabled")

    trace.set_tracer_provider(provider)
    _CONFIGURED = True


def get_tracer(name: str):
    """Return a configured tracer, or a no-op tracer when SDK is unavailable."""
    configure_observability()
    if trace is None:
        return _NoOpTracer()
    return trace.get_tracer(name)


def current_trace_id() -> Optional[str]:
    """Return current span trace ID as 32-char hex string, if available."""
    if trace is None:
        return None
    span = trace.get_current_span()
    context = span.get_span_context()
    if not context or not context.is_valid:
        return None
    return format(context.trace_id, "032x")
