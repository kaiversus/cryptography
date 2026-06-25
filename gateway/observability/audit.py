"""Audit trail — bằng chứng chống chối bỏ (MT-NONREP).

Mỗi quyết định xác thực (cho qua / từ chối) được ghi lại một dòng JSON
append-only: ai (actor) gọi gì (method+path) lúc nào (ts), kết quả ra sao
(decision) và vì sao (reason). Nhờ vậy một service M2M KHÔNG thể chối "tôi
không gửi" — danh tính của nó (X-Key-Id, hoặc sub/jti với JWT) đã nằm trong sổ.

Sổ này tách khỏi log traffic thường (logger "gateway") để không lẫn và để có
thể đẩy riêng sang kho log bất biến ở production.
"""
import json
import logging
import os
from collections import deque
from datetime import datetime, timezone

# Logger riêng cho audit.
audit_logger = logging.getLogger("gateway.audit")
audit_logger.setLevel(logging.INFO)

# Bộ đệm bản ghi gần nhất trong RAM — để test/endpoint debug đọc trực tiếp,
# không phụ thuộc file IO hay cấu hình logging.
RECENT_AUDIT: deque = deque(maxlen=1000)

# Ghi append-only ra file (artifact trình bày được). Tắt được bằng AUDIT_LOG_FILE="".
_AUDIT_FILE = os.getenv("AUDIT_LOG_FILE", "logs/audit.log")


def record_audit(*, channel: str, actor: str, decision: str,
                 method: str, path: str, reason: str = "") -> dict:
    """Ghi một bản ghi audit. Trả về dict bản ghi (tiện cho test kiểm tra).

    channel  : "hmac" (M2M) hoặc "jwt" (user)
    actor    : danh tính người gọi — X-Key-Id (HMAC) hoặc sub/jti (JWT)
    decision : "allow" hoặc "deny"
    reason   : lý do từ chối (rỗng nếu allow)
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "channel": channel,
        "actor": actor or "unknown",
        "method": method,
        "path": path,
        "decision": decision,
        "reason": reason,
    }
    line = json.dumps(record, ensure_ascii=False)
    RECENT_AUDIT.append(record)
    # Phát qua logging (handler/observability bắt được)
    audit_logger.info("AUDIT %s", line)
    # Ghi append-only ra file; lỗi IO không bao giờ làm hỏng request
    if _AUDIT_FILE:
        try:
            os.makedirs(os.path.dirname(_AUDIT_FILE), exist_ok=True)
            with open(_AUDIT_FILE, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass
    return record
