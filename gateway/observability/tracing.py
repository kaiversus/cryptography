"""Distributed tracing (OpenTelemetry → Jaeger) cho API Gateway — C-D7.

Mỗi request đi qua Gateway sinh 1 trace gửi sang Jaeger qua OTLP/HTTP.
Trong các middleware Auth, ta gắn thêm span attribute để soi được:
- auth.method   : jwt | hmac
- auth.result   : success | failure
- auth.user_id  : sub của token (nếu có)
- auth.latency_ms: thời gian xử lý auth

Thiết kế an toàn: nếu Jaeger không sẵn sàng, BatchSpanProcessor chỉ drop span
(log warning) chứ KHÔNG làm sập Gateway. Có thể tắt hẳn bằng OTEL_SDK_DISABLED=true.
"""
import os
import logging
from contextlib import contextmanager

# OpenTelemetry là optional: nếu chưa cài (môi trường dev/test tối giản) thì
# module vẫn import được và mọi hàm trở thành no-op an toàn.
try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    _OTEL_AVAILABLE = True
except ImportError:  # pragma: no cover - chỉ chạy khi thiếu dependency
    _OTEL_AVAILABLE = False

log = logging.getLogger("gateway")

# Endpoint collector OTLP/HTTP của Jaeger (all-in-one mở cổng 4318).
OTLP_ENDPOINT = os.getenv(
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "http://jaeger:4318/v1/traces",
)
SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "secure-api-gateway")

# Cho phép tắt hẳn tracing trong môi trường test/CI (không có Jaeger).
_DISABLED = os.getenv("OTEL_SDK_DISABLED", "false").lower() in ("1", "true", "yes")

_tracer = None


def setup_tracing(app) -> None:
    """Khởi tạo TracerProvider + instrument FastAPI app. Gọi 1 lần trong main.py."""
    global _tracer

    if _DISABLED or not _OTEL_AVAILABLE:
        reason = "disabled" if _DISABLED else "otel_not_installed"
        log.info(json_safe("tracing_off", reason=reason, endpoint=OTLP_ENDPOINT))
        return

    resource = Resource.create(
        {
            "service.name": SERVICE_NAME,
            "service.namespace": "nt219",
            "deployment.environment": os.getenv("ENV", "dev"),
        }
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=OTLP_ENDPOINT))
    )
    trace.set_tracer_provider(provider)

    # Tự động sinh 1 server span cho mỗi HTTP request.
    # server_request_hook: ghi nhãn demo.kb từ header X-Demo-KB (neu co) lên server span
    # -> Jaeger loc duoc tung kich ban demo bang tag demo.kb=KB1..KB6 (chuoi gon, khong mang).
    def _server_request_hook(span, scope):
        if span is None or not span.is_recording():
            return
        for k, v in scope.get("headers", []):
            if k == b"x-demo-kb":
                span.set_attribute("demo.kb", v.decode("latin-1"))
                break

    FastAPIInstrumentor.instrument_app(app, server_request_hook=_server_request_hook)

    _tracer = trace.get_tracer(__name__)
    log.info(json_safe("tracing_enabled", endpoint=OTLP_ENDPOINT, service=SERVICE_NAME))


def annotate_auth_span(
    method: str,
    result: str,
    user_id: str = "",
    latency_ms: float | None = None,
    reason: str = "",
) -> None:
    """Gắn các attribute auth.* lên span hiện hành (server span do FastAPI tạo).

    No-op an toàn khi tracing tắt hoặc không có span đang active.
    """
    if not _OTEL_AVAILABLE or _DISABLED:
        return
    span = trace.get_current_span()
    if span is None or not span.is_recording():
        return
    span.set_attribute("auth.method", method)
    span.set_attribute("auth.result", result)
    if user_id:
        span.set_attribute("auth.user_id", user_id)
    if latency_ms is not None:
        span.set_attribute("auth.latency_ms", round(latency_ms, 3))
    if reason:
        span.set_attribute("auth.failure_reason", reason)


@contextmanager
def checkpoint_span(name: str):
    """Tạo 1 span CON cho mỗi chốt trong pipeline auth → Jaeger vẽ luồng dạng CÂY.

    Dùng:  with checkpoint_span("jwt.verify_signature") as sp: ...
    - No-op an toàn khi tracing tắt / chưa init (yield None) → không ảnh hưởng test.
    - Nếu khối lệnh ném exception (vd HMACInvalid), span tự đánh dấu fail + lý do.
    Span con tự nối vào server span đang active (đã active nhờ đặt setup_tracing
    NGOÀI cùng trong main.py).
    """
    if not _OTEL_AVAILABLE or _DISABLED or _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(name) as span:
        try:
            yield span
        except Exception as exc:  # noqa: BLE001 - chỉ để gắn nhãn, vẫn re-raise
            try:
                span.set_attribute("checkpoint.result", "fail")
                span.set_attribute("checkpoint.reason", str(exc).split(":")[0])
            except Exception:  # pragma: no cover
                pass
            raise


def mark_checkpoint(span, result: str, reason: str = "") -> None:
    """Gắn kết quả cho checkpoint span khi chốt 'fail' bằng cách RETURN (không raise)."""
    if span is None:
        return
    span.set_attribute("checkpoint.result", result)
    if reason:
        span.set_attribute("checkpoint.reason", reason)


def json_safe(event: str, **kw) -> str:
    """Format log gọn cho module này (logger gateway dùng JSONFormatter ở chỗ khác)."""
    parts = " ".join(f"{k}={v}" for k, v in kw.items())
    return f"{event} {parts}".strip()
