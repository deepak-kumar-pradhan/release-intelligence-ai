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
    normalized = str(value or "").strip()
    if not normalized:
        return True
    upper = normalized.upper()
    return upper.startswith("REPLACE_WITH_") or "YOUR_" in upper


class _NoOpSpan:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def set_attribute(self, key, value):
        return None

    def add_event(self, name, attributes=None):
        return None

    def record_exception(self, exception):
        return None


class _NoOpTracer:
    @contextmanager
    def start_as_current_span(self, name: str) -> Iterator[_NoOpSpan]:
        yield _NoOpSpan()


def configure_observability() -> None:
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
    configure_observability()
    if trace is None:
        return _NoOpTracer()
    return trace.get_tracer(name)


def current_trace_id() -> Optional[str]:
    if trace is None:
        return None
    span = trace.get_current_span()
    context = span.get_span_context()
    if not context or not context.is_valid:
        return None
    return format(context.trace_id, "032x")
