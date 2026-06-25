import time
from fastapi import FastAPI, Request
from prometheus_fastapi_instrumentator import Instrumentator

# Import Rate Limit & Logger
from gateway.middleware.rate_limit import setup_rate_limit, limiter
from gateway.observability.logger import gateway_logger
from gateway.observability.tracing import setup_tracing

# Import Auth Middlewares
from gateway.middleware.auth import jwt_auth_middleware
from gateway.middleware.hmac_auth import hmac_auth_middleware
from gateway.routes.auth import router as auth_router

app = FastAPI(title="Secure API Gateway")
app.include_router(auth_router)

# Kích hoạt Rate Limit
setup_rate_limit(app)

# /metrics endpoint cho Prometheus scrape.
Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

# Distributed tracing (OpenTelemetry -> Jaeger). Tự no-op nếu OTEL_SDK_DISABLED=true.
setup_tracing(app)

# === MIDDLEWARE GHI LOG JSON (STRUCTURED LOGGING) ===
@app.middleware("http")
async def structured_logging_middleware(request: Request, call_next):
    start_time = time.time()
    
    # Đẩy request đi tiếp qua các lớp Auth
    response = await call_next(request)
    
    # Tính toán độ trễ
    process_time_ms = round((time.time() - start_time) * 1000, 2)
    
    # Ghi log tập trung chuẩn JSON
    gateway_logger.info(
        "API Traffic",
        extra={
            "extra_info": {
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "client_ip": request.client.host if request.client else "127.0.0.1",
                "latency_ms": process_time_ms
            }
        }
    )
    return response

# Middleware FastAPI chạy LIFO (đăng ký sau -> chạy TRƯỚC)
app.middleware("http")(hmac_auth_middleware)
app.middleware("http")(jwt_auth_middleware)

# ==========================================
# CÁC ENDPOINT VÀ CẤU HÌNH RATE LIMIT
# ==========================================

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/api/public")
@limiter.limit("10/minute")  # Tối đa 10 request/phút
def public(request: Request): # Bắt buộc phải có tham số request
    return {"message": "public, no auth"}

@app.get("/api/protected")
@limiter.limit("5/minute")   # Tối đa 5 request/phút
def protected(request: Request):
    username = request.state.user.get("preferred_username") if hasattr(request.state, "user") else "Unknown"
    roles = request.state.user.get("realm_access", {}).get("roles", []) if hasattr(request.state, "user") else []
    return {"user": username, "roles": roles}

@app.get("/api/admin")
@limiter.limit("5/minute")
def admin(request: Request):
    # Chỉ tới được đây khi đã qua authentication VÀ có role "admin" (chốt 7).
    username = request.state.user.get("preferred_username") if hasattr(request.state, "user") else "Unknown"
    return {"message": "admin area", "user": username}

@app.post("/api/service")
@limiter.limit("100/minute") # M2M gọi nhiều nên cho giới hạn cao hơn
def service(request: Request):
    return {"message": "HMAC signature verified successfully"}

@app.get("/audit/recent")
@limiter.limit("30/minute")
def audit_recent(request: Request, limit: int = 20):
    # Sổ audit gần nhất — minh chứng chống chối bỏ (MT-NONREP). Bản ghi chỉ chứa
    # định danh (key-id/sub), KHÔNG chứa secret.
    # DEV/DEBUG: production nên gate sau role admin (chốt 7) trước khi phơi endpoint này.
    from gateway.observability.audit import RECENT_AUDIT
    items = list(RECENT_AUDIT)[-max(1, min(limit, 200)):]
    return {"count": len(items), "records": items}
